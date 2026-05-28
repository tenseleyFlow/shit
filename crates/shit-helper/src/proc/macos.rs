// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS process enumeration via libproc + KERN_PROCARGS2 sysctl
//! (DR-48 + DR-49 / M06.2).
//!
//! Linux's `/proc/<pid>/*` doesn't exist on macOS, so we cobble
//! together the same `ProcSnapshot` shape from three sources:
//!
//! - `proc_pidinfo(pid, PROC_PIDTBSDINFO, ...)` → comm, ppid,
//!   start time, pgid.
//! - `proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, ...)` → cwd.
//! - `sysctl([CTL_KERN, KERN_PROCARGS2, pid])` → argv + envp
//!   block (KERN_PROCARGS2 returns argc-prefixed, NUL-terminated
//!   strings: 4-byte argc, exec_path, argv[0..argc], envp[]).
//!
//! No `cap_*` / `audit_session_self` / `task_for_pid`-style
//! privileged calls — everything here works as the unprivileged
//! user against own + same-uid processes. (Other-user processes
//! return ENOMEM/EPERM from libproc; the helper logs + drops.)

use shit_proto::ProcSnapshot;

use super::enumerate::summarize_env;

/// `PROC_ALL_PIDS` — kernel constant from `<sys/proc_info.h>`
/// (libproc.h on macOS). Not exported by libc-rs as of 0.2.186;
/// hardcoded here. Stable across macOS 10.x → 15.x.
const PROC_ALL_PIDS: u32 = 1;

/// Snapshot a single pid. Returns a `ProcSnapshot` populated from
/// libproc + KERN_PROCARGS2. Best-effort: individual fields fall
/// back to empty/zero values rather than failing the whole call,
/// matching the Linux branch's robustness posture.
pub fn snapshot(pid: u32) -> anyhow::Result<ProcSnapshot> {
    let bsd = read_bsdinfo(pid).ok();
    let comm = bsd
        .as_ref()
        .map(|b| cstr_to_string(&b.pbi_comm))
        .unwrap_or_default();
    let parent_pid = bsd.as_ref().map(|b| b.pbi_ppid).unwrap_or(0);
    let start_time_secs = bsd.as_ref().map(|b| b.pbi_start_tvsec).unwrap_or(0);

    let cwd = read_cwd(pid).unwrap_or_default();

    let (argv, env_block) = read_procargs2(pid).unwrap_or_default();
    let env_summary = summarize_env(&env_block);

    Ok(ProcSnapshot {
        pid,
        comm,
        argv,
        cwd,
        env_summary,
        parent_pid,
        start_time_secs,
        // No reliable libproc path to fetch controlling tty as
        // the unprivileged caller; the kernel's `proc_bsdinfo.e_tdev`
        // is a dev_t (raw device number) not a path, and converting
        // requires walking /dev. Leaving None matches the FreeBSD
        // helper's posture and the planner doesn't gate on it.
        tty: None,
    })
}

/// Walk every visible pid via `proc_listpids(PROC_ALL_PIDS, ...)`.
/// Two-call pattern: first sized at 0 to learn the buffer size,
/// then with a buffer of that size. macOS docs recommend
/// over-allocating slightly to cover races where new pids appear
/// between the two calls.
#[allow(dead_code)] // M06.x followup: pgrep -f pattern resolution
pub fn enumerate_all_pids() -> anyhow::Result<Vec<u32>> {
    // Size the buffer.
    let sz_bytes = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if sz_bytes <= 0 {
        return Ok(Vec::new());
    }
    // Over-allocate by 20% to absorb races; the syscall just
    // ignores trailing zeros.
    let count_hint = (sz_bytes as usize / std::mem::size_of::<i32>()) + 64;
    let mut pids = vec![0i32; count_hint];
    let got = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast(),
            (pids.len() * std::mem::size_of::<i32>()) as i32,
        )
    };
    if got <= 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let actual = got as usize / std::mem::size_of::<i32>();
    pids.truncate(actual);
    Ok(pids
        .into_iter()
        .filter(|&p| p > 0)
        .map(|p| p as u32)
        .collect())
}

/// `proc_pidinfo(pid, PROC_PIDTBSDINFO)`. Returns the populated
/// `proc_bsdinfo` struct on success.
fn read_bsdinfo(pid: u32) -> std::io::Result<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let sz = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: info is a properly-sized zeroed struct; libc::PROC_PIDTBSDINFO
    // is a valid flavor; pid is u32 cast to i32 (libproc's pid type).
    let rc = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast(),
            sz,
        )
    };
    if rc <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    if rc < sz {
        return Err(std::io::Error::other(format!(
            "proc_pidinfo PIDTBSDINFO short read: got {rc} want {sz}"
        )));
    }
    Ok(info)
}

/// `proc_pidinfo(pid, PROC_PIDVNODEPATHINFO)`. Returns the cwd
/// extracted from the vnode info block.
fn read_cwd(pid: u32) -> std::io::Result<String> {
    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let sz = std::mem::size_of::<libc::proc_vnodepathinfo>() as i32;
    let rc = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            (&raw mut info).cast(),
            sz,
        )
    };
    if rc <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    // pvi_cdir.vip_path is [[c_char; 32]; 32] = MAXPATHLEN bytes.
    // Flatten + NUL-truncate.
    let flat: Vec<u8> = info
        .pvi_cdir
        .vip_path
        .iter()
        .flatten()
        .map(|&c| c as u8)
        .take_while(|&b| b != 0)
        .collect();
    Ok(String::from_utf8_lossy(&flat).into_owned())
}

/// Read the KERN_PROCARGS2 sysctl block for `pid` and split it
/// into (argv, envp_block).
///
/// The KERN_PROCARGS2 buffer layout (per `sysctl.h` + kernel
/// source — `kern_kerninfo.c::sysctl_procargsx`):
///
/// ```text
///   [u32 argc        ] (host byte order)
///   [exec_path  \0   ] (NUL-terminated; may be empty)
///   [pad to alignment]
///   [argv[0]    \0   ]
///   [argv[1]    \0   ]
///   ...
///   [argv[argc-1] \0 ]
///   [envp[0]    \0   ] (zero or more NUL-terminated env vars)
///   [envp[1]    \0   ]
///   ...
/// ```
///
/// We read the buffer, skip past argc + exec_path, peel `argc`
/// NUL-terminated argv strings, then collect whatever's left as
/// the env block. Returns empty (vec, vec) on any error — the
/// caller's `unwrap_or_default()` produces an empty-fields snapshot
/// rather than failing the whole probe.
fn read_procargs2(pid: u32) -> std::io::Result<(Vec<String>, Vec<u8>)> {
    // Get KERN_ARGMAX as the max buffer size.
    let mut argmax: libc::c_int = 0;
    let mut argmax_len = std::mem::size_of::<libc::c_int>();
    let mib_argmax = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let rc = unsafe {
        libc::sysctl(
            mib_argmax.as_ptr() as *mut _,
            mib_argmax.len() as u32,
            (&raw mut argmax).cast(),
            &mut argmax_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if argmax <= 0 {
        return Err(std::io::Error::other("KERN_ARGMAX returned non-positive"));
    }

    // Fetch the actual KERN_PROCARGS2 block. mib = [CTL_KERN,
    // KERN_PROCARGS2, pid].
    let mut buf = vec![0u8; argmax as usize];
    let mut buf_len = buf.len();
    let mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            mib.len() as u32,
            buf.as_mut_ptr().cast(),
            &mut buf_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(buf_len);

    // Parse.
    if buf.len() < std::mem::size_of::<u32>() {
        return Err(std::io::Error::other("PROCARGS2 buffer too small for argc"));
    }
    let argc = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut cursor = 4;

    // Skip exec_path (NUL-terminated, possibly empty).
    while cursor < buf.len() && buf[cursor] != 0 {
        cursor += 1;
    }
    // Skip the NUL + any trailing padding NULs (kernel aligns to
    // word boundary).
    while cursor < buf.len() && buf[cursor] == 0 {
        cursor += 1;
    }

    // Peel argc NUL-terminated argv strings.
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        if cursor >= buf.len() {
            break;
        }
        let start = cursor;
        while cursor < buf.len() && buf[cursor] != 0 {
            cursor += 1;
        }
        argv.push(String::from_utf8_lossy(&buf[start..cursor]).into_owned());
        if cursor < buf.len() {
            cursor += 1; // skip NUL terminator
        }
    }

    // What's left is the envp block (still NUL-separated; the
    // shared `summarize_env` handles parsing).
    let env_block = buf[cursor..].to_vec();
    Ok((argv, env_block))
}

/// Convert a NUL-terminated `[c_char]` field to a Rust String,
/// truncating at the first NUL. Tolerant of non-UTF-8.
fn cstr_to_string(field: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = field
        .iter()
        .map(|&c| c as u8)
        .take_while(|&b| b != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_self_returns_argv() {
        // Snapshot the test process itself. The test runner's argv
        // varies (cargo / rustc / etc.) but it must be non-empty +
        // include "shit_helper" or "shit-helper" somewhere in the
        // first arg's path, since that's the test binary's name.
        let me = std::process::id();
        let snap = snapshot(me).expect("snapshot self");
        assert_eq!(snap.pid, me);
        assert!(!snap.argv.is_empty(), "argv should not be empty");
        // The first argv element is the test binary path. It's in
        // a target/debug/deps/* directory and contains the crate
        // name "shit_helper" with the hash suffix.
        assert!(
            snap.argv[0].contains("shit_helper") || snap.argv[0].contains("shit-helper"),
            "argv[0]={:?} should contain shit_helper",
            snap.argv[0]
        );
    }

    #[test]
    fn snapshot_self_returns_parent_pid() {
        let me = std::process::id();
        let snap = snapshot(me).expect("snapshot self");
        // parent_pid should be non-zero (cargo, the shell, etc.)
        assert!(snap.parent_pid > 0, "parent_pid should be > 0");
        // and shouldn't be the pid itself (defense against init-
        // loop confusion).
        assert_ne!(snap.parent_pid, me);
    }

    #[test]
    fn snapshot_self_returns_cwd() {
        let me = std::process::id();
        let snap = snapshot(me).expect("snapshot self");
        // cwd should match what std::env reports for the test process.
        let expected = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .unwrap_or_default();
        if !expected.is_empty() {
            // macOS canonicalizes /tmp → /private/tmp etc.; compare
            // canonicalized forms so symlink layers don't trip the test.
            let want_canon = std::fs::canonicalize(&expected)
                .ok()
                .and_then(|p| p.to_str().map(str::to_string))
                .unwrap_or_default();
            let got_canon = std::fs::canonicalize(&snap.cwd)
                .ok()
                .and_then(|p| p.to_str().map(str::to_string))
                .unwrap_or_default();
            assert_eq!(got_canon, want_canon, "cwd mismatch");
        }
    }

    #[test]
    fn snapshot_nonexistent_pid_returns_err_or_empty() {
        // A pid that almost certainly doesn't exist. snapshot()
        // returns Ok with empty fields rather than Err on
        // PROCARGS2 EPERM/ESRCH — both shapes are fine, but the
        // result must be well-formed.
        let bogus = 999_999_u32;
        match snapshot(bogus) {
            Ok(snap) => {
                assert_eq!(snap.pid, bogus);
                // comm/cwd/argv may all be empty since libproc rejected.
            }
            Err(_) => {} // fine
        }
    }

    #[test]
    fn enumerate_all_pids_includes_self() {
        let me = std::process::id();
        let pids = enumerate_all_pids().expect("enumerate");
        assert!(
            pids.iter().any(|&p| p == me),
            "self pid {me} not in enumeration"
        );
    }

    #[test]
    fn enumerate_all_pids_returns_nonempty() {
        let pids = enumerate_all_pids().expect("enumerate");
        // System always has init (1), kernel_task (0 — filtered),
        // launchd, etc. At least a dozen on any non-pathological
        // macOS install.
        assert!(pids.len() > 5, "expected >5 pids, got {}", pids.len());
    }
}
