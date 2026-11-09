// SPDX-License-Identifier: AGPL-3.0-or-later

//! #230 - who a `WatchTree` may watch. Linux-only.
//!
//! Any local user can run the helper, and the peer that sends
//! `WatchTree` runs as that user, so `root_pid` and `cwd_path` are
//! attacker-controlled. Watching starts privileged capture: the
//! fanotify tier opens event fds for the marked directory with the
//! group's rights, and both tiers read and ship pre-images of what the
//! watched tree touches. So the helper watches a process only when:
//!
//! - the helper's euid is the peer's uid (it acts for its own user),
//! - every uid of the process (real, effective, saved, fs) is the
//!   peer's uid,
//! - the helper, holding no effective capability after startup (#226),
//!   may inspect the process (`/proc/<pid>/root` resolves; this is the
//!   kernel's ptrace read check, which also refuses a process that is
//!   non-dumpable, has other gids, or holds capabilities the helper
//!   does not),
//! - the process is still the same one after these reads (same start
//!   time), and
//! - it is the process the session first watched (its shell) or a
//!   descendant of it.
//!
//! The watch root is opened with the helper's own credentials, which
//! is the check that the peer could open it (see `open_watch_dir` in
//! main.rs); everything after that uses the held fd.

use std::collections::HashMap;
use uuid::Uuid;

/// Most sessions pinned at once. Pins of processes that have exited are
/// dropped when the map is full; past that, new sessions are refused.
const MAX_PINS: usize = 4096;

/// Bound on the parent walk from a process to its session's shell.
const MAX_ANCESTRY: usize = 256;

/// What the helper reads about a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcIdent {
    /// Real, effective, saved and filesystem uid.
    pub uids: [u32; 4],
    pub ppid: u32,
    /// Start time in clock ticks since boot (`/proc/<pid>/stat` field
    /// 22). With the pid it names one process.
    pub start: u64,
}

/// Read `/proc/<pid>/status` and `/proc/<pid>/stat`.
pub fn proc_ident(pid: u32) -> Result<ProcIdent, String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|e| format!("pid {pid} is not readable: {e}"))?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| format!("pid {pid} is not readable: {e}"))?;
    parse_ident(&status, &stat).ok_or_else(|| format!("pid {pid}: unexpected /proc format"))
}

fn parse_ident(status: &str, stat: &str) -> Option<ProcIdent> {
    let line = |name: &str| status.lines().find_map(|l| l.strip_prefix(name));
    let mut uids = [0u32; 4];
    let mut it = line("Uid:")?.split_whitespace();
    for u in &mut uids {
        *u = it.next()?.parse().ok()?;
    }
    let ppid = line("PPid:")?.trim().parse().ok()?;
    // The command name in field 2 may hold spaces and parentheses; the
    // fields after the last ')' start at field 3 (state).
    let rest = &stat[stat.rfind(')')? + 1..];
    let start = rest.split_whitespace().nth(19)?.parse().ok()?;
    Some(ProcIdent { uids, ppid, start })
}

/// Per-connection watch authorization state.
pub struct WatchScope {
    peer_uid: u32,
    helper_euid: u32,
    /// Session -> (pid, start time) of the first process it watched.
    pins: HashMap<Uuid, (u32, u64)>,
}

impl WatchScope {
    pub fn new(peer_uid: u32) -> Self {
        Self::with_euid(peer_uid, unsafe { libc::geteuid() })
    }

    fn with_euid(peer_uid: u32, helper_euid: u32) -> Self {
        Self {
            peer_uid,
            helper_euid,
            pins: HashMap::new(),
        }
    }

    /// Decide whether `session` may watch `pid`. On success the session
    /// is pinned to `pid` if it was not pinned yet.
    pub fn authorize(&mut self, session: Uuid, pid: u32) -> Result<(), String> {
        if self.helper_euid != self.peer_uid {
            return Err(format!(
                "the helper runs as uid {} and the daemon as uid {}; the helper watches only \
                 for its own user",
                self.helper_euid, self.peer_uid
            ));
        }
        if pid <= 1 {
            return Err(format!("pid {pid} is not a user process"));
        }
        let before = proc_ident(pid)?;
        if before.uids.iter().any(|&u| u != self.peer_uid) {
            return Err(format!(
                "pid {pid} is not owned by uid {} (uids {:?})",
                self.peer_uid, before.uids
            ));
        }
        std::fs::read_link(format!("/proc/{pid}/root"))
            .map_err(|e| format!("uid {} may not inspect pid {pid}: {e}", self.peer_uid))?;
        let after = proc_ident(pid)?;
        if after != before {
            return Err(format!("pid {pid} changed while it was checked"));
        }
        match self.pins.get(&session) {
            Some(&(p, st)) if (p, st) == (pid, before.start) => Ok(()),
            Some(&(p, st)) => {
                if descends_from(before, (p, st)) {
                    Ok(())
                } else {
                    Err(format!(
                        "pid {pid} is neither the session's shell (pid {p}) nor a descendant \
                         of it"
                    ))
                }
            }
            None => {
                if self.pins.len() >= MAX_PINS {
                    self.pins
                        .retain(|_, &mut (p, st)| proc_ident(p).is_ok_and(|i| i.start == st));
                }
                if self.pins.len() >= MAX_PINS {
                    return Err("too many watched sessions".to_string());
                }
                self.pins.insert(session, (pid, before.start));
                Ok(())
            }
        }
    }
}

/// True when the process `ident` has `(pid, start)` among its
/// ancestors.
fn descends_from(ident: ProcIdent, anc: (u32, u64)) -> bool {
    let mut cur = ident;
    for _ in 0..MAX_ANCESTRY {
        let ppid = cur.ppid;
        if ppid <= 1 {
            return false;
        }
        let Ok(parent) = proc_ident(ppid) else {
            return false;
        };
        if (ppid, parent.start) == anc {
            return true;
        }
        cur = parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn session(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn parses_status_and_stat() {
        let status = "Name:\tx\nPPid:\t41\nUid:\t1000\t1000\t1000\t1000\n";
        let stat = "42 (a) b) c) S 41 42 42 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0";
        assert_eq!(
            parse_ident(status, stat),
            Some(ProcIdent {
                uids: [1000; 4],
                ppid: 41,
                start: 12345,
            })
        );
        assert_eq!(parse_ident("Name:\tx\n", stat), None);
    }

    #[test]
    fn own_process_is_allowed_and_pins_the_session() {
        let mut s = WatchScope::new(me());
        let pid = std::process::id();
        assert_eq!(s.authorize(session(1), pid), Ok(()));
        assert_eq!(s.authorize(session(1), pid), Ok(()));
    }

    /// The peer names a process of another user (pid 1 is root's init,
    /// and any root-owned process will do).
    #[test]
    fn another_users_process_is_refused() {
        if me() == 0 {
            return;
        }
        let mut s = WatchScope::new(me());
        let err = s.authorize(session(2), 1).unwrap_err();
        assert!(err.contains("not a user process"), "{err}");
        // A root-owned process other than init, when one is visible.
        let root_pid = std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u32>().ok())
            .find(|&p| p > 1 && proc_ident(p).is_ok_and(|i| i.uids == [0; 4]));
        if let Some(p) = root_pid {
            let err = s.authorize(session(2), p).unwrap_err();
            assert!(err.contains("not owned by uid"), "{err}");
        }
    }

    /// The peer claims a uid the process does not have.
    #[test]
    fn process_of_a_uid_other_than_the_peer_is_refused() {
        let other = me().wrapping_add(1);
        let mut s = WatchScope::with_euid(other, other);
        let err = s.authorize(session(3), std::process::id()).unwrap_err();
        assert!(err.contains("not owned by uid"), "{err}");
    }

    /// A helper started as another user than its peer watches nothing.
    #[test]
    fn helper_euid_other_than_the_peer_is_refused() {
        let mut s = WatchScope::with_euid(me(), me().wrapping_add(1));
        let err = s.authorize(session(4), std::process::id()).unwrap_err();
        assert!(err.contains("watches only for its own user"), "{err}");
    }

    #[test]
    fn missing_process_is_refused() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        let mut s = WatchScope::new(me());
        assert!(s.authorize(session(5), pid).is_err());
    }

    /// Once a session is pinned to its shell, it may watch the shell's
    /// descendants but no other process, even one of the same user.
    #[test]
    fn a_pinned_session_watches_only_its_shell_and_descendants() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let cpid = child.id();
        let mut s = WatchScope::new(me());
        // Pinned to this process: its child is a descendant.
        assert_eq!(s.authorize(session(6), std::process::id()), Ok(()));
        assert_eq!(s.authorize(session(6), cpid), Ok(()));
        // Pinned to the child: this process is its parent, not a
        // descendant, so it is refused.
        let err = s
            .authorize(session(7), cpid)
            .and_then(|()| s.authorize(session(7), std::process::id()));
        child.kill().unwrap();
        child.wait().unwrap();
        let err = err.unwrap_err();
        assert!(err.contains("neither the session's shell"), "{err}");
    }

    /// The session's shell exited and its pid was reused: the start
    /// time differs, so the pin no longer matches.
    #[test]
    fn a_reused_pid_does_not_match_the_pin() {
        let mut s = WatchScope::new(me());
        let pid = std::process::id();
        let start = proc_ident(pid).unwrap().start;
        s.pins.insert(session(8), (pid, start + 1));
        let err = s.authorize(session(8), pid).unwrap_err();
        assert!(err.contains("neither the session's shell"), "{err}");
    }
}
