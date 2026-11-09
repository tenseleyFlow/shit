// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux capability sets for the helper (#226).
//!
//! The helper is installed with file capabilities
//! (`cap_sys_admin,cap_bpf,cap_perfmon,cap_mknod=ep`). Capability sets
//! are per thread, and a new thread copies its creator's sets, so the
//! drop happens in two steps on the main thread before any worker
//! thread exists:
//!
//! 1. [`drop_to_minimum`], before kernel-tier setup: the bounding set
//!    keeps only [`STARTUP_CAPS`] and [`RUNTIME_CAPS`] (best effort:
//!    `PR_CAPBSET_DROP` needs `CAP_SETPCAP`, which a setcap helper does
//!    not have; `no_new_privs` covers exec either way), the ambient and
//!    inheritable sets are cleared, permitted keeps only those two
//!    groups, and only [`STARTUP_CAPS`] stay effective.
//! 2. [`finish_startup`], once the BPF programs are attached and the
//!    fanotify fd is open, before any reader thread is spawned:
//!    permitted keeps only [`RUNTIME_CAPS`] and nothing is effective.
//!    It then reads every thread's sets from `/proc/self/task` and fails
//!    if any thread holds more.
//!
//! Which operation needs which capability:
//!
//! | capability      | operation                                       | when    |
//! |-----------------|-------------------------------------------------|---------|
//! | `CAP_SYS_ADMIN` | `fanotify_init` (pre-content class); legacy BPF | startup |
//! | `CAP_BPF`       | load and attach the BPF-LSM programs            | startup |
//! | `CAP_PERFMON`   | attach the BPF-LSM programs (with `CAP_BPF`)    | startup |
//! | `CAP_MKNOD`     | `mknodat` of a block/char node (`apply_mknod`)  | runtime |
//!
//! At runtime a capability is effective only inside [`with_cap`], on
//! the calling thread, for one syscall. Nothing else needs one:
//! `fanotify_mark` on an inode, reading fanotify events and ring
//! buffers, and fifo/socket restores all work without. `CAP_CHOWN` is
//! neither granted nor kept: the startup sets strip it from permitted,
//! so `apply_chown` calls `fchownat` with no capability and the kernel
//! allows only what the invoking user could do.
//!
//! One exception: on kernels before 6.5 with
//! `kernel.unprivileged_bpf_disabled` set, every `bpf(2)` call needs
//! `CAP_BPF`, including the ring-buffer loss counter reads. There,
//! `CAP_BPF` stays permitted (never effective outside [`with_cap`]) so
//! drops can still be counted. See [`runtime_bpf_needs_cap`]; the
//! answer is computed once, in [`finish_startup`], and read through
//! [`bpf_cap_kept`].

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum PrivError {
    #[error("refusing to run with full root inherited (uid 0 + all caps)")]
    FullRootInherited,
    #[error("capability syscall failed: {0}")]
    Capset(String),
    #[error("threads hold capabilities after the drop: {0}")]
    ThreadsKeepCaps(String),
}

/// Numeric capability constants. Values are pinned by the kernel ABI
/// (`include/uapi/linux/capability.h`); libc does not export them.
/// Only tests name it: they check it is never permitted.
#[cfg(test)]
pub const CAP_CHOWN: u32 = 0;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_MKNOD: u32 = 27;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;

const fn bit(cap: u32) -> u64 {
    1u64 << cap
}

/// Needed only while the kernel tier is set up.
pub const STARTUP_CAPS: u64 = bit(CAP_SYS_ADMIN) | bit(CAP_BPF) | bit(CAP_PERFMON);
/// Kept permitted (not effective) after startup, raised per call.
pub const RUNTIME_CAPS: u64 = bit(CAP_MKNOD);

/// One thread's capability sets, as 64-bit masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapSets {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// The calling thread's capability sets.
pub fn capget() -> io::Result<CapSets> {
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut hdr as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let join = |lo: u32, hi: u32| u64::from(lo) | (u64::from(hi) << 32);
    Ok(CapSets {
        effective: join(data[0].effective, data[1].effective),
        permitted: join(data[0].permitted, data[1].permitted),
        inheritable: join(data[0].inheritable, data[1].inheritable),
    })
}

/// Set the calling thread's capability sets. The kernel refuses any
/// set that is not within the current permitted set.
pub fn capset(sets: &CapSets) -> io::Result<()> {
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let split = |m: u64| (m as u32, (m >> 32) as u32);
    let (e0, e1) = split(sets.effective);
    let (p0, p1) = split(sets.permitted);
    let (i0, i1) = split(sets.inheritable);
    let data = [
        CapData {
            effective: e0,
            permitted: p0,
            inheritable: i0,
        },
        CapData {
            effective: e1,
            permitted: p1,
            inheritable: i1,
        },
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &mut hdr as *mut CapHeader, data.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Sets for the startup phase: permitted keeps only the startup and
/// runtime capabilities, only the startup ones are effective, and
/// inheritable is empty.
pub fn startup_sets(cur: CapSets) -> CapSets {
    let permitted = cur.permitted & (STARTUP_CAPS | RUNTIME_CAPS);
    CapSets {
        effective: permitted & STARTUP_CAPS,
        permitted,
        inheritable: 0,
    }
}

/// Sets for the rest of the helper's life: permitted keeps only the
/// runtime capabilities (plus `CAP_BPF` when `keep_bpf`), nothing is
/// effective, and inheritable is empty.
pub fn runtime_sets(cur: CapSets, keep_bpf: bool) -> CapSets {
    CapSets {
        effective: 0,
        permitted: cur.permitted & runtime_allowed(keep_bpf),
        inheritable: 0,
    }
}

fn runtime_allowed(keep_bpf: bool) -> u64 {
    RUNTIME_CAPS | if keep_bpf { bit(CAP_BPF) } else { 0 }
}

/// Startup drop. Runs on the main thread before any other thread
/// exists and before kernel-tier setup, which keeps working: the
/// startup capabilities stay effective until [`finish_startup`].
pub fn drop_to_minimum() -> Result<(), PrivError> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 && full_capset() {
        return Err(PrivError::FullRootInherited);
    }

    // Bounding set first, while CAP_SETPCAP may still be effective (only
    // when started as root; a setcap helper gets EPERM and the bounding
    // set stays as it was, which no_new_privs makes moot). Capabilities
    // above the kernel's CAP_LAST_CAP return EINVAL.
    for cap in 0..=63u32 {
        if (STARTUP_CAPS | RUNTIME_CAPS) & bit(cap) != 0 {
            continue;
        }
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc != 0 {
            let e = io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::EPERM)) {
                continue;
            }
            return Err(PrivError::Capset(format!("PR_CAPBSET_DROP cap={cap}: {e}")));
        }
    }

    clear_ambient()?;
    let cur = capget().map_err(|e| PrivError::Capset(format!("capget: {e}")))?;
    let next = startup_sets(cur);
    capset(&next).map_err(|e| PrivError::Capset(format!("capset (startup): {e}")))?;

    // NO_NEW_PRIVS: required for the unprivileged seccomp install later,
    // and no exec from here on can gain capabilities.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
    if rc != 0 {
        return Err(PrivError::Capset(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            io::Error::last_os_error()
        )));
    }

    tracing::info!(
        effective = format!("{:#x}", next.effective),
        permitted = format!("{:#x}", next.permitted),
        "capabilities dropped to the startup set"
    );
    Ok(())
}

/// Clear the ambient set. EINVAL means a kernel without ambient
/// capabilities (before 4.3), where there is nothing to clear.
fn clear_ambient() -> Result<(), PrivError> {
    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINVAL) {
            return Err(PrivError::Capset(format!("PR_CAP_AMBIENT_CLEAR_ALL: {e}")));
        }
    }
    Ok(())
}

static STARTUP_FINISHED: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// Whether [`finish_startup`] kept `CAP_BPF` permitted for map reads.
static BPF_CAP_KEPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True when `CAP_BPF` was kept permitted so map reads can raise it.
/// Fixed once startup finishes; false before.
pub fn bpf_cap_kept() -> bool {
    BPF_CAP_KEPT.load(std::sync::atomic::Ordering::Relaxed)
}

/// End of startup: drop to [`runtime_sets`] on this thread, then check
/// that no thread of the process holds more. Call it on the main thread
/// after the kernel tier is set up and before any worker thread starts.
/// Calls after the first successful one do nothing.
pub fn finish_startup() -> Result<(), PrivError> {
    let mut done = STARTUP_FINISHED.lock().unwrap_or_else(|p| p.into_inner());
    if *done {
        return Ok(());
    }
    let keep_bpf = runtime_bpf_needs_cap();
    let cur = capget().map_err(|e| PrivError::Capset(format!("capget: {e}")))?;
    let next = runtime_sets(cur, keep_bpf);
    capset(&next).map_err(|e| PrivError::Capset(format!("capset (runtime): {e}")))?;
    clear_ambient()?;
    let bad = thread_cap_violations(runtime_allowed(keep_bpf))
        .map_err(|e| PrivError::Capset(format!("read /proc/self/task: {e}")))?;
    if !bad.is_empty() {
        return Err(PrivError::ThreadsKeepCaps(bad.join("; ")));
    }
    *done = true;
    BPF_CAP_KEPT.store(keep_bpf, std::sync::atomic::Ordering::Relaxed);
    tracing::info!(
        permitted = format!("{:#x}", next.permitted),
        keep_bpf,
        "startup capabilities dropped; nothing effective"
    );
    Ok(())
}

/// Every thread of this process whose sets go beyond "nothing
/// effective, inheritable or ambient; permitted within `allowed`", as
/// `tid: reason` strings.
pub fn thread_cap_violations(allowed: u64) -> io::Result<Vec<String>> {
    let mut bad = Vec::new();
    for entry in std::fs::read_dir("/proc/self/task")? {
        let entry = entry?;
        let tid = entry.file_name().to_string_lossy().into_owned();
        let status = match std::fs::read_to_string(entry.path().join("status")) {
            Ok(s) => s,
            // The thread exited between readdir and open.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if let Some(reason) = status_violation(&status, allowed) {
            bad.push(format!("{tid}: {reason}"));
        }
    }
    Ok(bad)
}

/// Why a `/proc/<pid>/status` text shows more capabilities than
/// allowed, or `None`.
pub fn status_violation(status: &str, allowed: u64) -> Option<String> {
    let field = |name: &str| -> Option<u64> {
        status.lines().find_map(|l| {
            l.strip_prefix(name)
                .and_then(|r| u64::from_str_radix(r.trim(), 16).ok())
        })
    };
    let mut why = Vec::new();
    match field("CapEff:") {
        Some(0) => {}
        Some(m) => why.push(format!("CapEff {m:#x}")),
        None => why.push("no CapEff".to_string()),
    }
    match field("CapPrm:") {
        Some(m) if m & !allowed == 0 => {}
        Some(m) => why.push(format!("CapPrm {m:#x}")),
        None => why.push("no CapPrm".to_string()),
    }
    match field("CapInh:") {
        Some(0) => {}
        Some(m) => why.push(format!("CapInh {m:#x}")),
        None => why.push("no CapInh".to_string()),
    }
    // CapAmb is absent before 4.3, where there is no ambient set.
    if let Some(m) = field("CapAmb:")
        && m != 0
    {
        why.push(format!("CapAmb {m:#x}"));
    }
    (!why.is_empty()).then(|| why.join(", "))
}

/// True when `bpf(2)` map reads need `CAP_BPF` here: a kernel before
/// 6.5 (which checked `unprivileged_bpf_disabled` for every command,
/// not only map and program creation) with that sysctl set.
pub fn runtime_bpf_needs_cap() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let sysctl =
        std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled").unwrap_or_default();
    bpf_needs_cap(&release, &sysctl)
}

fn bpf_needs_cap(release: &str, sysctl: &str) -> bool {
    let mut parts = release.trim().split(['.', '-']);
    let major: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    // An unreadable sysctl counts as set.
    (major, minor) < (6, 5) && sysctl.trim() != "0"
}

/// Run `f` with `cap` effective on the calling thread, then lower it
/// again. When `cap` is not permitted, `f` runs without it and the
/// kernel decides. Capability sets are per thread, so no other thread
/// sees it raised.
pub fn with_cap<T>(cap: u32, f: impl FnOnce() -> T) -> T {
    let raised = match capget() {
        Ok(cur) if cur.permitted & bit(cap) != 0 && cur.effective & bit(cap) == 0 => {
            let up = CapSets {
                effective: cur.effective | bit(cap),
                ..cur
            };
            capset(&up).ok().map(|()| cur)
        }
        _ => None,
    };
    let out = f();
    if let Some(prev) = raised
        && let Err(e) = capset(&prev)
    {
        // Lowering only clears a bit in the effective set. If even that
        // fails, the thread is in a state this code does not understand.
        tracing::error!(cap, err = %e, "could not lower a raised capability; aborting");
        std::process::abort();
    }
    out
}

/// Set the filesystem uid and gid to the real ones, on this thread and
/// every thread it later creates. On a setcap install they already are
/// (euid is the invoking user). On a setuid-root install the euid is 0,
/// and this makes path lookups, opens and the ptrace access check
/// behave as the invoking user, so the WatchTree scope checks (#230)
/// ask what the peer could do. Call on the main thread before the
/// request loop starts.
pub fn act_as_real_user() -> Result<(), PrivError> {
    let (ruid, rgid) = unsafe { (libc::getuid(), libc::getgid()) };
    unsafe {
        libc::setfsgid(rgid);
        libc::setfsuid(ruid);
    }
    // setfsuid/setfsgid report no error; an invalid id (-1) changes
    // nothing and returns the current value, which is checked here.
    let (fsuid, fsgid) = unsafe {
        (
            libc::setfsuid(libc::uid_t::MAX) as u32,
            libc::setfsgid(libc::gid_t::MAX) as u32,
        )
    };
    if (fsuid, fsgid) != (ruid, rgid) {
        return Err(PrivError::Capset(format!(
            "filesystem ids are {fsuid}:{fsgid}, not the real ids {ruid}:{rgid}"
        )));
    }
    Ok(())
}

/// Best-effort detection of "full root inherited": UID 0 and an
/// effective set with (essentially) every capability. The real test is
/// "did the operator launch us via sudo without our file-cap install".
fn full_capset() -> bool {
    use std::io::Read;
    let mut s = String::new();
    if std::fs::File::open("/proc/self/status")
        .and_then(|mut f| f.read_to_string(&mut s))
        .is_err()
    {
        return false;
    }
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let trimmed = rest.trim();
            return trimmed == "0000003fffffffff"
                || trimmed == "00000000ffffffff"
                || trimmed.starts_with("ffffffff");
        }
    }
    false
}

/// Which capabilities the current thread holds in its effective set.
/// `None` if the sets cannot be read.
pub fn effective_caps_contain(cap: u32) -> Option<bool> {
    capget().ok().map(|c| c.effective & bit(cap) != 0)
}

/// Snapshot of the BPF-LSM-relevant capabilities. Used by the helper
/// during startup probe + `shit doctor` reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BpfCapState {
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    pub cap_sys_admin: bool,
}

impl BpfCapState {
    /// True when we have what `aya::Bpf::load` would need to load an
    /// LSM program on a modern kernel: either `CAP_BPF + CAP_PERFMON`
    /// (preferred, 5.8+) or `CAP_SYS_ADMIN` (legacy fallback).
    pub fn can_load_lsm(&self) -> bool {
        (self.cap_bpf && self.cap_perfmon) || self.cap_sys_admin
    }
}

pub fn probe_bpf_caps() -> BpfCapState {
    BpfCapState {
        cap_bpf: effective_caps_contain(CAP_BPF).unwrap_or(false),
        cap_perfmon: effective_caps_contain(CAP_PERFMON).unwrap_or(false),
        cap_sys_admin: effective_caps_contain(CAP_SYS_ADMIN).unwrap_or(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u64 = (1u64 << 41) - 1;

    #[test]
    fn probe_bpf_caps_returns_a_state() {
        let c = probe_bpf_caps();
        let _ = c.can_load_lsm();
    }

    #[test]
    fn empty_cap_state_cannot_load() {
        let c = BpfCapState::default();
        assert!(!c.can_load_lsm());
    }

    #[test]
    fn cap_bpf_plus_perfmon_can_load() {
        let c = BpfCapState {
            cap_bpf: true,
            cap_perfmon: true,
            cap_sys_admin: false,
        };
        assert!(c.can_load_lsm());
    }

    #[test]
    fn cap_sys_admin_alone_can_load_legacy() {
        let c = BpfCapState {
            cap_bpf: false,
            cap_perfmon: false,
            cap_sys_admin: true,
        };
        assert!(c.can_load_lsm());
    }

    #[test]
    fn cap_bpf_alone_cannot_load_on_modern() {
        let c = BpfCapState {
            cap_bpf: true,
            cap_perfmon: false,
            cap_sys_admin: false,
        };
        assert!(!c.can_load_lsm());
    }

    #[test]
    fn full_capset_is_false_in_normal_test_run() {
        assert!(!full_capset());
    }

    /// #226: whatever setcap granted, the startup sets keep only the
    /// startup and runtime capabilities, with only the startup ones
    /// effective and nothing inheritable.
    #[test]
    fn startup_sets_keep_only_what_startup_needs() {
        let granted = CapSets {
            effective: ALL,
            permitted: ALL,
            inheritable: ALL,
        };
        let s = startup_sets(granted);
        assert_eq!(s.permitted, STARTUP_CAPS | RUNTIME_CAPS);
        assert_eq!(s.effective, STARTUP_CAPS);
        assert_eq!(s.inheritable, 0);
        assert_eq!(s.effective & bit(CAP_MKNOD), 0, "mknod is raised per call");
        assert_eq!(s.permitted & bit(CAP_CHOWN), 0);
        // Nothing is added that was not granted.
        let none = startup_sets(CapSets::default());
        assert_eq!(none, CapSets::default());
    }

    /// #226: after startup nothing is effective and permitted holds only
    /// CAP_MKNOD (and CAP_BPF only where the kernel needs it for map
    /// reads).
    #[test]
    fn runtime_sets_hold_nothing_effective() {
        let granted = CapSets {
            effective: ALL,
            permitted: ALL,
            inheritable: ALL,
        };
        let r = runtime_sets(granted, false);
        assert_eq!(
            r,
            CapSets {
                effective: 0,
                permitted: bit(CAP_MKNOD),
                inheritable: 0,
            }
        );
        let r = runtime_sets(granted, true);
        assert_eq!(r.permitted, bit(CAP_MKNOD) | bit(CAP_BPF));
        assert_eq!(r.effective, 0);
        // Without cap_mknod granted there is nothing to keep.
        let r = runtime_sets(
            CapSets {
                permitted: STARTUP_CAPS,
                effective: STARTUP_CAPS,
                inheritable: 0,
            },
            false,
        );
        assert_eq!(r, CapSets::default());
    }

    /// The thread check flags a thread that kept anything the runtime
    /// sets do not allow.
    #[test]
    fn status_violation_flags_extra_capabilities() {
        let ok = "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t0000000008000000\n\
                  CapEff:\t0000000000000000\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
        assert_eq!(status_violation(ok, RUNTIME_CAPS), None);
        let eff = ok.replace("CapEff:\t0000000000000000", "CapEff:\t0000000008000000");
        assert!(
            status_violation(&eff, RUNTIME_CAPS)
                .unwrap()
                .contains("CapEff")
        );
        let prm = ok.replace("CapPrm:\t0000000008000000", "CapPrm:\t0000000008200000");
        assert!(
            status_violation(&prm, RUNTIME_CAPS)
                .unwrap()
                .contains("CapPrm")
        );
        let inh = ok.replace("CapInh:\t0000000000000000", "CapInh:\t0000000000000001");
        assert!(
            status_violation(&inh, RUNTIME_CAPS)
                .unwrap()
                .contains("CapInh")
        );
        let amb = ok.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000200000");
        assert!(
            status_violation(&amb, RUNTIME_CAPS)
                .unwrap()
                .contains("CapAmb")
        );
        assert!(status_violation("Name:\tx\n", RUNTIME_CAPS).is_some());
    }

    /// An unprivileged test process holds nothing, so every thread
    /// passes, including the one this test spawns.
    #[test]
    fn unprivileged_threads_pass_the_check() {
        if capget().unwrap() != CapSets::default() {
            return; // the test runner holds capabilities; nothing to assert
        }
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || rx.recv().ok());
        assert_eq!(thread_cap_violations(0).unwrap(), Vec::<String>::new());
        tx.send(()).unwrap();
        t.join().unwrap();
    }

    /// with_cap on a capability that is not permitted runs the closure
    /// without it and leaves the sets as they were.
    #[test]
    fn with_cap_without_permission_changes_nothing() {
        let before = capget().unwrap();
        if before.permitted & bit(CAP_MKNOD) != 0 {
            return;
        }
        let inside = with_cap(CAP_MKNOD, || capget().unwrap());
        assert_eq!(inside, before);
        assert_eq!(capget().unwrap(), before);
    }

    #[test]
    fn capset_round_trips_the_current_sets() {
        let cur = capget().unwrap();
        capset(&cur).unwrap();
        assert_eq!(capget().unwrap(), cur);
        // Asking for a capability outside permitted is refused.
        if cur.permitted & bit(CAP_SYS_ADMIN) == 0 {
            let more = CapSets {
                effective: cur.effective | bit(CAP_SYS_ADMIN),
                ..cur
            };
            assert!(capset(&more).is_err());
        }
    }

    #[test]
    fn act_as_real_user_sets_the_real_filesystem_ids() {
        act_as_real_user().unwrap();
        let fsuid = unsafe { libc::setfsuid(libc::uid_t::MAX) } as u32;
        assert_eq!(fsuid, unsafe { libc::getuid() });
    }

    #[test]
    fn bpf_cap_is_kept_only_on_old_kernels_with_the_sysctl_set() {
        assert!(bpf_needs_cap("5.15.0-91-generic\n", "2\n"));
        assert!(bpf_needs_cap("6.4.16", "1"));
        assert!(bpf_needs_cap("6.1.0", ""));
        assert!(!bpf_needs_cap("6.1.0", "0"));
        assert!(!bpf_needs_cap("6.5.0", "2"));
        assert!(!bpf_needs_cap("6.8.0-31-generic", "2"));
        assert!(!bpf_needs_cap("7.2.14-arch1-1", "2"));
    }
}
