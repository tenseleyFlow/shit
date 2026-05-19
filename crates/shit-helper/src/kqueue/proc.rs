// SPDX-License-Identifier: AGPL-3.0-or-later

//! `EVFILT_PROC` — process-lifecycle event subscription.
//!
//! S23.2 (DR-06): wires NOTE_FORK | NOTE_EXEC | NOTE_EXIT for a single
//! pid via [`track_pid`], and the descendant-tracking variant
//! ([`track_descendants`]) that adds NOTE_TRACK so the kernel
//! auto-registers fork children. The returned [`TrackedPid`] owns
//! the registration: dropping it issues `EV_DELETE` for the pid.
//!
//! Unlike vnode subscriptions, there's no fd to close that would
//! implicitly remove the filter — pids aren't descriptors. So Drop
//! does an explicit `EV_DELETE` round-trip. On a closed kqueue the
//! kernel returns `EBADF`; we ignore it (we're in Drop, no recovery
//! to do).
//!
//! **Cross-BSD caveat:** OpenBSD does not deliver NOTE_EXEC.
//! `BsdProbe.kqueue.note_exec` advertises this. Callers that rely on
//! exec-driven tree expansion (e.g. preload-shim coverage gates)
//! must check the probe before assuming coverage.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::os::fd::AsRawFd;

use super::error::KqueueError;
use super::init::KqueueFd;

/// Process-lifecycle event kind delivered by EVFILT_PROC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcEventKind {
    Fork,
    Exec,
    Exit,
}

impl ProcEventKind {
    /// Pick the most-actionable event kind a single delivery represents.
    /// Order: Exit > Exec > Fork — Exit is terminal and the most-
    /// load-bearing for capture bookkeeping; Exec is the "command
    /// switched identity" signal; Fork is the most frequent and
    /// least specific.
    pub fn from_fflags(fflags: u32) -> Option<Self> {
        if fflags & libc::NOTE_EXIT != 0 {
            Some(Self::Exit)
        } else if fflags & libc::NOTE_EXEC != 0 {
            Some(Self::Exec)
        } else if fflags & libc::NOTE_FORK != 0 {
            Some(Self::Fork)
        } else {
            None
        }
    }
}

/// fflags subscribed by [`track_descendants`]. NOTE_TRACK asks the
/// kernel to auto-register EVFILT_PROC on every forked child of the
/// tracked pid; child kevents arrive with NOTE_CHILD set. OpenBSD
/// silently ignores NOTE_TRACK; we still set it for the cross-BSD
/// callers, and the per-BSD probe surfaces the actual coverage.
pub const PROC_FFLAGS_DESCENDANTS: u32 =
    libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT | libc::NOTE_TRACK;

/// fflags subscribed by [`track_pid`] — same lifecycle bits, no
/// descendant auto-tracking.
pub const PROC_FFLAGS_SINGLE: u32 = libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT;

/// Ownership handle for a per-pid EVFILT_PROC registration. Drop
/// issues EV_DELETE so the registration doesn't leak past the
/// lifetime of the tracker.
#[derive(Debug)]
pub struct TrackedPid {
    kq_fd: std::os::fd::RawFd,
    pid: u32,
}

impl TrackedPid {
    /// The pid this handle holds a registration for.
    pub fn pid(&self) -> u32 {
        self.pid
    }
}

impl Drop for TrackedPid {
    fn drop(&mut self) {
        let ev = libc::kevent {
            ident: self.pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_DELETE,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
            ext: [0; 4],
        };
        // SAFETY: kq_fd was valid when we recorded it. If the owner
        // closed the kqueue first, kevent returns EBADF — we're in
        // Drop, nothing to recover. EV_DELETE on a not-found pid
        // returns ENOENT; same posture.
        unsafe {
            libc::kevent(
                self.kq_fd,
                &ev,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            );
        }
    }
}

/// Register EVFILT_PROC on a single pid for fork/exec/exit
/// notifications. Returns a [`TrackedPid`] whose Drop removes the
/// registration.
pub fn track_pid(kq: &KqueueFd, pid: u32) -> Result<TrackedPid, KqueueError> {
    register_pid(kq, pid, PROC_FFLAGS_SINGLE)?;
    Ok(TrackedPid {
        kq_fd: kq.as_raw_fd(),
        pid,
    })
}

/// Register EVFILT_PROC on a root pid with NOTE_TRACK, so the kernel
/// auto-registers each forked descendant. Effective for capturing the
/// full process tree spawned by a tracked shell or build invocation.
pub fn track_descendants(kq: &KqueueFd, root_pid: u32) -> Result<TrackedPid, KqueueError> {
    register_pid(kq, root_pid, PROC_FFLAGS_DESCENDANTS)?;
    Ok(TrackedPid {
        kq_fd: kq.as_raw_fd(),
        pid: root_pid,
    })
}

fn register_pid(kq: &KqueueFd, pid: u32, fflags: u32) -> Result<(), KqueueError> {
    let ev = libc::kevent {
        ident: pid as libc::uintptr_t,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_CLEAR,
        fflags,
        data: 0,
        udata: std::ptr::null_mut(),
        ext: [0; 4],
    };
    // SAFETY: kq is owned for the call; changelist is a 1-element
    // const ptr; eventlist=NULL, nevents=0 → registration only.
    let rc = unsafe {
        libc::kevent(
            kq.as_raw_fd(),
            &ev,
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(KqueueError::Kevent(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kqueue::init;

    #[test]
    fn from_fflags_picks_most_specific() {
        assert_eq!(
            ProcEventKind::from_fflags(libc::NOTE_FORK),
            Some(ProcEventKind::Fork)
        );
        assert_eq!(
            ProcEventKind::from_fflags(libc::NOTE_EXEC),
            Some(ProcEventKind::Exec)
        );
        assert_eq!(
            ProcEventKind::from_fflags(libc::NOTE_EXIT),
            Some(ProcEventKind::Exit)
        );
        // Exit outranks Exec outranks Fork.
        assert_eq!(
            ProcEventKind::from_fflags(libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT),
            Some(ProcEventKind::Exit)
        );
        assert_eq!(
            ProcEventKind::from_fflags(libc::NOTE_FORK | libc::NOTE_EXEC),
            Some(ProcEventKind::Exec)
        );
        assert_eq!(ProcEventKind::from_fflags(0), None);
    }

    /// Drain kevents from `kq` with a 500ms deadline; return the
    /// vector of events surfaced.
    fn drain(kq: &KqueueFd, deadline_ms: i64) -> Vec<libc::kevent> {
        let mut events: [libc::kevent; 16] = unsafe { std::mem::zeroed() };
        let ts = libc::timespec {
            tv_sec: deadline_ms / 1000,
            tv_nsec: (deadline_ms % 1000) * 1_000_000,
        };
        // SAFETY: kq is owned; events is a writable buffer; ts ptr
        // is valid.
        let n = unsafe {
            libc::kevent(
                kq.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                &ts,
            )
        };
        if n < 0 {
            return Vec::new();
        }
        events.iter().take(n as usize).copied().collect()
    }

    #[test]
    fn track_pid_surfaces_note_exit() {
        let kq = init().expect("kqueue");
        // Spawn a child that sleeps long enough for us to register a
        // kevent on its pid; then kill it and assert NOTE_EXIT fires.
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep");
        let child_pid = child.id();
        let _tracker = track_pid(&kq, child_pid).expect("track child");
        child.kill().expect("kill child");
        let _ = child.wait();
        let evs = drain(&kq, 500);
        let saw_exit = evs.iter().any(|e| {
            e.filter == libc::EVFILT_PROC
                && e.ident == child_pid as libc::uintptr_t
                && e.fflags & libc::NOTE_EXIT != 0
        });
        assert!(
            saw_exit,
            "expected NOTE_EXIT on child pid {child_pid}: {evs:?}"
        );
    }

    #[test]
    fn track_descendants_surfaces_note_fork_on_root() {
        let kq = init().expect("kqueue");
        let self_pid = std::process::id();
        let _tracker = track_descendants(&kq, self_pid).expect("track self");
        // Spawn a short-lived child *after* registration — kqueue
        // only surfaces events after the filter is attached.
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn /usr/bin/true");
        let _ = child.wait();
        let evs = drain(&kq, 500);
        let saw_fork = evs.iter().any(|e| {
            e.filter == libc::EVFILT_PROC
                && e.ident == self_pid as libc::uintptr_t
                && e.fflags & libc::NOTE_FORK != 0
        });
        assert!(
            saw_fork,
            "expected NOTE_FORK on self pid {self_pid}: {evs:?}"
        );
    }

    #[test]
    fn track_descendants_auto_registers_child_via_note_track() {
        let kq = init().expect("kqueue");
        let self_pid = std::process::id();
        let _tracker = track_descendants(&kq, self_pid).expect("track self");
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn /usr/bin/true");
        let child_pid = child.id();
        let _ = child.wait();
        // NOTE_TRACK auto-registers each fork child; the child should
        // surface NOTE_EXIT (and possibly NOTE_CHILD, NOTE_EXEC) on
        // its own pid even though we never directly track_pid'd it.
        let evs = drain(&kq, 500);
        let saw_child_exit = evs.iter().any(|e| {
            e.filter == libc::EVFILT_PROC
                && e.ident == child_pid as libc::uintptr_t
                && e.fflags & libc::NOTE_EXIT != 0
        });
        assert!(
            saw_child_exit,
            "expected auto-registered child NOTE_EXIT on pid {child_pid}: {evs:?}"
        );
    }

    #[test]
    fn track_pid_drop_removes_registration() {
        let kq = init().expect("kqueue");
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep");
        let child_pid = child.id();
        {
            let _tracker = track_pid(&kq, child_pid).expect("track");
            // Tracker drops here → EV_DELETE issued.
        }
        child.kill().expect("kill");
        let _ = child.wait();
        let evs = drain(&kq, 200);
        let saw_exit = evs.iter().any(|e| {
            e.filter == libc::EVFILT_PROC
                && e.ident == child_pid as libc::uintptr_t
                && e.fflags & libc::NOTE_EXIT != 0
        });
        assert!(
            !saw_exit,
            "registration should have been removed by Drop; got {evs:?}"
        );
    }
}
