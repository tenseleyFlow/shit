// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process enumeration (S18.4 wires per-OS implementations).

use shit_proto::ProcSnapshot;

/// True if a pid is still alive. Cheap probe via `kill(pid, 0)`.
/// (Signal 0 doesn't actually send a signal; it returns success
/// when the pid exists and we have permission to signal it.)
/// Consumed by the Post-phase re-enumeration once S18.6 wires it
/// through; allowed-dead for now.
#[allow(dead_code)]
pub fn is_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) is the canonical "does this pid exist"
    // syscall on POSIX. It's safe regardless of arguments.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Snapshot a single process by pid. Stage-1 stub returns an
/// empty-ish snapshot; S18.4 wires the real /proc walk (Linux),
/// libproc (macOS), and sysctl (BSD).
pub fn read_proc_snapshot(pid: u32) -> anyhow::Result<ProcSnapshot> {
    Ok(ProcSnapshot {
        pid,
        comm: String::new(),
        argv: Vec::new(),
        cwd: String::new(),
        env_summary: std::collections::BTreeMap::new(),
        parent_pid: 0,
        start_time_secs: 0,
        tty: None,
    })
}
