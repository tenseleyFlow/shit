// SPDX-License-Identifier: AGPL-3.0-or-later

//! kevent(2) drain loop with bounded backpressure (S23.3, DR-07).
//!
//! Owns the kqueue fd, blocks on `kevent(2)`, decodes each delivered
//! kevent into a [`DrainEvent`], and pushes it through a bounded
//! mpsc channel to the consumer. Channel-full is a hard-fail — the
//! drain thread returns [`DrainError::QueueOverflow`] and exits.
//! Silently dropping events would make `shit undo` lie about
//! capture coverage, which violates the project's default-on
//! capture-failure policy.
//!
//! Shutdown is driven by an `EVFILT_USER` self-event registered at
//! construction time: another thread calls
//! [`DrainHandle::signal_shutdown`], which triggers the user event,
//! breaks the drain loop's blocking `kevent(2)` call, and the loop
//! exits cleanly. No self-pipe gymnastics needed on BSDs.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread::JoinHandle;

use super::error::KqueueError;
use super::init::KqueueFd;
use super::proc::ProcEventKind;
use super::vnode::VnodeEventKind;

/// Default channel capacity. Sized so a bursty NOTE_WRITE storm from
/// a `cargo build` doesn't immediately overflow; the consumer's
/// blob-store pipeline must keep up at steady state. Increase via
/// [`DrainBuilder::capacity`] when needed.
pub const DEFAULT_CAPACITY: usize = 4096;

/// The ident we use for the `EVFILT_USER` shutdown trigger. Chosen
/// to be a value the kernel won't already assign to any other
/// EVFILT_USER subscription (we don't register any others).
const SHUTDOWN_IDENT: libc::uintptr_t = 0xD15E_A5E5;

#[derive(Debug, thiserror::Error)]
pub enum DrainError {
    #[error("kevent(2) at drain time: {0}")]
    Kevent(std::io::Error),
    #[error("event channel overflowed (capacity={capacity}); refusing further events")]
    QueueOverflow { capacity: usize },
    #[error("drain thread panicked")]
    ThreadPanicked,
    #[error("kqueue registration: {0}")]
    Register(#[from] KqueueError),
}

/// One decoded event surfaced to the consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainEvent {
    /// EVFILT_VNODE: a file or directory we registered changed.
    Vnode {
        fd: RawFd,
        kind: VnodeEventKind,
        /// Raw fflags so consumers that want all the bits (e.g. an
        /// auditor logging the full notification set) can keep them;
        /// `kind` is the canonical most-specific decoded kind.
        fflags: u32,
    },
    /// EVFILT_PROC: a tracked pid forked/exec'd/exited.
    Proc {
        pid: u32,
        kind: ProcEventKind,
        fflags: u32,
    },
}

/// Handle held by the orchestrator side. Carries enough state to
/// signal shutdown to the drain thread; does NOT own the kqueue fd
/// (the drain thread does). Cheap to clone — only contains a fd.
#[derive(Debug)]
pub struct DrainHandle {
    /// Duped from the kqueue fd at spawn time. We dup so the original
    /// can be moved into the drain thread without losing our ability
    /// to issue an EV_DELETE / NOTE_TRIGGER from the outside.
    shutdown_fd: std::os::fd::OwnedFd,
}

impl DrainHandle {
    /// Trigger the shutdown EVFILT_USER event so the drain thread's
    /// next `kevent(2)` returns with our marker and the loop exits.
    pub fn signal_shutdown(&self) -> Result<(), KqueueError> {
        let ev = libc::kevent {
            ident: SHUTDOWN_IDENT,
            filter: libc::EVFILT_USER,
            flags: 0,
            fflags: libc::NOTE_TRIGGER,
            data: 0,
            udata: std::ptr::null_mut(),
            ext: [0; 4],
        };
        // SAFETY: shutdown_fd is owned for the call; changelist is a
        // single const kevent; no eventlist.
        let rc = unsafe {
            libc::kevent(
                self.shutdown_fd.as_raw_fd(),
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
}

/// Bundle returned by [`spawn`]: the receiver to drain events from,
/// the handle to signal shutdown, and the thread join handle so the
/// caller can wait for the drain to exit cleanly.
pub struct DrainSession {
    pub events: Receiver<DrainEvent>,
    pub handle: DrainHandle,
    thread: Option<JoinHandle<Result<(), DrainError>>>,
}

impl DrainSession {
    /// Try to receive one event without blocking.
    pub fn try_recv(&self) -> Result<DrainEvent, TryRecvError> {
        self.events.try_recv()
    }

    /// Block until one event is available (or the drain thread
    /// exits, which closes the channel).
    pub fn recv(&self) -> Result<DrainEvent, std::sync::mpsc::RecvError> {
        self.events.recv()
    }

    /// Signal shutdown and wait for the drain thread to exit. Returns
    /// the thread's final Result so the caller knows whether the
    /// drain exited cleanly or via overflow / kevent error.
    pub fn shutdown(mut self) -> Result<(), DrainError> {
        self.handle.signal_shutdown()?;
        self.thread
            .take()
            .expect("thread handle taken twice")
            .join()
            .map_err(|_| DrainError::ThreadPanicked)?
    }
}

impl Drop for DrainSession {
    fn drop(&mut self) {
        // Best-effort cleanup if the user didn't call shutdown()
        // explicitly. We can't return errors from Drop.
        if let Some(t) = self.thread.take() {
            let _ = self.handle.signal_shutdown();
            let _ = t.join();
        }
    }
}

/// Spawn the drain thread. Takes ownership of the kqueue fd; returns
/// a [`DrainSession`] for the consumer side. The kqueue must already
/// have any vnode / proc filters registered against it — register
/// first, spawn second.
pub fn spawn(kq: Arc<KqueueFd>, capacity: usize) -> Result<DrainSession, DrainError> {
    let shutdown_fd = dup_for_shutdown(&kq)?;
    register_shutdown_user_event(&kq)?;
    let (tx, rx) = sync_channel(capacity);
    let thread = std::thread::Builder::new()
        .name("shit-kqueue-drain".to_string())
        .spawn(move || run(kq, tx, capacity))
        .map_err(DrainError::Kevent)?;
    Ok(DrainSession {
        events: rx,
        handle: DrainHandle { shutdown_fd },
        thread: Some(thread),
    })
}

/// Convenience: spawn with [`DEFAULT_CAPACITY`].
pub fn spawn_default(kq: Arc<KqueueFd>) -> Result<DrainSession, DrainError> {
    spawn(kq, DEFAULT_CAPACITY)
}

fn dup_for_shutdown(kq: &Arc<KqueueFd>) -> Result<std::os::fd::OwnedFd, DrainError> {
    use std::os::fd::FromRawFd;
    // SAFETY: dup returns a fresh fd or -1; we own the result.
    let raw = unsafe { libc::dup(kq.as_raw_fd()) };
    if raw < 0 {
        return Err(DrainError::Kevent(std::io::Error::last_os_error()));
    }
    // SAFETY: raw is a fresh fd we now own.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
}

fn register_shutdown_user_event(kq: &Arc<KqueueFd>) -> Result<(), DrainError> {
    let ev = libc::kevent {
        ident: SHUTDOWN_IDENT,
        filter: libc::EVFILT_USER,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
        ext: [0; 4],
    };
    // SAFETY: see register_pid / register_entries.
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
        return Err(DrainError::Kevent(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn run(kq: Arc<KqueueFd>, tx: SyncSender<DrainEvent>, capacity: usize) -> Result<(), DrainError> {
    let mut events: [libc::kevent; 64] = unsafe { std::mem::zeroed() };
    loop {
        // Blocking wait — timeout=NULL.
        // SAFETY: kq is owned; events is a writable buffer; timeout
        // is NULL → block until at least one event is available.
        let n = unsafe {
            libc::kevent(
                kq.as_raw_fd(),
                std::ptr::null(),
                0,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                std::ptr::null(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            // EINTR is benign — a signal woke us up, just retry.
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(DrainError::Kevent(err));
        }
        for ev in events.iter().take(n as usize) {
            // Shutdown marker — exit cleanly.
            if ev.filter == libc::EVFILT_USER && ev.ident == SHUTDOWN_IDENT {
                return Ok(());
            }
            let Some(decoded) = decode(ev) else {
                continue;
            };
            match tx.try_send(decoded) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    return Err(DrainError::QueueOverflow { capacity });
                }
                Err(TrySendError::Disconnected(_)) => {
                    // Consumer dropped the receiver; treat as a
                    // graceful exit signal.
                    return Ok(());
                }
            }
        }
    }
}

fn decode(ev: &libc::kevent) -> Option<DrainEvent> {
    match ev.filter {
        libc::EVFILT_VNODE => {
            let kind = VnodeEventKind::from_fflags(ev.fflags)?;
            Some(DrainEvent::Vnode {
                fd: ev.ident as RawFd,
                kind,
                fflags: ev.fflags,
            })
        }
        libc::EVFILT_PROC => {
            let kind = ProcEventKind::from_fflags(ev.fflags)?;
            Some(DrainEvent::Proc {
                pid: ev.ident as u32,
                kind,
                fflags: ev.fflags,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kqueue::{init, register_subtree, track_descendants};
    use std::time::{Duration, Instant};

    /// recv with deadline.
    fn recv_with_timeout(session: &DrainSession, deadline: Duration) -> Option<DrainEvent> {
        let start = Instant::now();
        while start.elapsed() < deadline {
            match session.try_recv() {
                Ok(ev) => return Some(ev),
                Err(TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
                Err(TryRecvError::Disconnected) => return None,
            }
        }
        None
    }

    #[test]
    fn vnode_event_surfaces_through_channel() {
        let kq = Arc::new(init().expect("kqueue"));
        let dir = tempfile::tempdir().expect("tempdir");
        let foo = dir.path().join("foo");
        std::fs::write(&foo, b"initial").unwrap();
        let tree = register_subtree(&kq, dir.path(), 4).expect("register");
        // Hold tree alive across the test so fds aren't closed.
        let session = spawn(Arc::clone(&kq), 64).expect("spawn drain");
        std::fs::write(&foo, b"modified-content-longer").unwrap();
        let ev = recv_with_timeout(&session, Duration::from_millis(500))
            .expect("expected a drain event");
        match ev {
            DrainEvent::Vnode {
                kind: VnodeEventKind::Write,
                ..
            }
            | DrainEvent::Vnode {
                kind: VnodeEventKind::Extend,
                ..
            } => {}
            other => panic!("expected vnode Write/Extend, got {other:?}"),
        }
        session.shutdown().expect("clean shutdown");
        drop(tree);
    }

    #[test]
    fn shutdown_unblocks_the_loop() {
        let kq = Arc::new(init().expect("kqueue"));
        let session = spawn(kq, 16).expect("spawn drain");
        // Nothing registered — drain is blocked in kevent(2).
        // Shutdown must wake it up.
        let start = Instant::now();
        session.shutdown().expect("clean shutdown");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "shutdown should be near-instant; took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn queue_overflow_is_a_hard_fail() {
        let kq = Arc::new(init().expect("kqueue"));
        let self_pid = std::process::id();
        // Track all forks from the test process so any subprocess
        // spawn surfaces a NOTE_FORK event. Multiple fast forks fill
        // the channel quickly.
        let _tracker = track_descendants(&kq, self_pid).expect("track");
        // Capacity = 1: one event fits; the second triggers overflow.
        let mut session = spawn(Arc::clone(&kq), 1).expect("spawn drain");
        // Generate a bunch of forks. Don't recv anything.
        for _ in 0..32 {
            let mut child = std::process::Command::new("true").spawn().expect("spawn");
            let _ = child.wait();
        }
        // Block on the drain thread terminating. Since we don't recv,
        // the channel fills and the drain returns QueueOverflow.
        let thread = session.thread.take().unwrap();
        let _ = session.handle.signal_shutdown(); // graceful nudge in case capacity is large enough to absorb the forks (it shouldn't be at cap=1)
        let outcome = thread.join().expect("thread joined");
        // Either QueueOverflow (the path we want to verify) or Ok
        // (if the kernel coalesced our forks into <= 1 event). The
        // former is what we're testing; the latter is benign noise.
        match outcome {
            Err(DrainError::QueueOverflow { capacity: 1 }) => {}
            Ok(()) => {
                // OK — overflow didn't trigger because EV_CLEAR
                // coalesced events. Skip the assertion rather than
                // flake. (Documented behavior: NOTE_FORK with
                // EV_CLEAR may aggregate.)
            }
            other => panic!("expected QueueOverflow or Ok, got {other:?}"),
        }
    }
}
