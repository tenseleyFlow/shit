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
//! - the helper acts for the peer's user: its real uid is the peer's
//!   uid, and its euid is that uid too, or 0 on a setuid-root install;
//! - every uid of the process (real, effective, saved, fs) is the
//!   peer's uid;
//! - the helper, holding no effective capability after startup (#226)
//!   and with its filesystem ids set to its real ids
//!   (`priv_linux::act_as_real_user`), may inspect the process:
//!   `/proc/<pid>/root` resolves. This is the kernel's ptrace read
//!   check, which also refuses a process that is non-dumpable, has other
//!   gids, or holds capabilities the helper does not;
//! - the process is still the same one after these reads (same start
//!   time); and
//! - it is the session's shell (the first process the session watched)
//!   or a descendant of it. When that shell has exited, the session is
//!   pinned again to the new process.
//!
//! The watch root is opened with the same credentials, which is the
//! check that the peer could open it (see `open_watch_dir` in main.rs);
//! everything after that uses the held fd. The caller checks with
//! [`still_same`] after that open that `root_pid` is still the process
//! authorized here.

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

/// `pid` is still the process that started at `start`. #230: called
/// after the watch root is opened (possibly through `/proc/<pid>/cwd`),
/// so a pid reused since [`WatchScope::authorize`] is refused.
pub fn still_same(pid: u32, start: u64) -> Result<(), String> {
    match proc_ident(pid) {
        Ok(i) if i.start == start => Ok(()),
        _ => Err(format!(
            "pid {pid} exited or was reused while its watch was set up"
        )),
    }
}

/// Per-connection watch authorization state.
pub struct WatchScope {
    peer_uid: u32,
    helper_ruid: u32,
    helper_euid: u32,
    /// Session -> (pid, start time) of its shell.
    pins: HashMap<Uuid, (u32, u64)>,
}

impl WatchScope {
    pub fn new(peer_uid: u32) -> Self {
        Self::with_ids(peer_uid, unsafe { libc::getuid() }, unsafe {
            libc::geteuid()
        })
    }

    fn with_ids(peer_uid: u32, helper_ruid: u32, helper_euid: u32) -> Self {
        Self {
            peer_uid,
            helper_ruid,
            helper_euid,
            pins: HashMap::new(),
        }
    }

    /// Decide whether `session` may watch `pid`. On success the session
    /// is pinned to `pid` if it had no live shell, and the process's
    /// identity is returned for [`still_same`].
    pub fn authorize(&mut self, session: Uuid, pid: u32) -> Result<ProcIdent, String> {
        let euid_ok = self.helper_euid == self.peer_uid || self.helper_euid == 0;
        if self.helper_ruid != self.peer_uid || !euid_ok {
            return Err(format!(
                "the helper runs as uid {} (euid {}) and the daemon as uid {}; the helper \
                 watches only for the user that started it",
                self.helper_ruid, self.helper_euid, self.peer_uid
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
        let here = (pid, before.start);
        match self.pins.get(&session).copied() {
            Some(pin) if pin == here => {}
            Some((p, st)) if still_same(p, st).is_ok() => {
                if !descends_from(before, (p, st)) {
                    return Err(format!(
                        "session {session} belongs to shell pid {p}, which is still running; \
                         pid {pid} is neither that shell nor a descendant of it"
                    ));
                }
            }
            Some((p, _)) => {
                // The pinned shell exited (or its pid was reused): the
                // session continues in a new shell.
                tracing::info!(%session, old = p, new = pid, "session shell changed; re-pinned");
                self.pins.insert(session, here);
            }
            None => {
                if self.pins.len() >= MAX_PINS {
                    self.pins
                        .retain(|_, &mut (p, st)| still_same(p, st).is_ok());
                }
                if self.pins.len() >= MAX_PINS {
                    return Err("too many watched sessions".to_string());
                }
                self.pins.insert(session, here);
            }
        }
        Ok(before)
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

    fn scope() -> WatchScope {
        WatchScope::with_ids(me(), me(), me())
    }

    fn sleeper() -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap()
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
        let mut s = scope();
        let pid = std::process::id();
        let ident = s.authorize(session(1), pid).unwrap();
        assert_eq!(still_same(pid, ident.start), Ok(()));
        assert!(s.authorize(session(1), pid).is_ok());
    }

    /// The peer names a process of another user (pid 1 is root's init,
    /// and any root-owned process will do).
    #[test]
    fn another_users_process_is_refused() {
        if me() == 0 {
            return;
        }
        let mut s = scope();
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
        let mut s = WatchScope::with_ids(other, other, other);
        let err = s.authorize(session(3), std::process::id()).unwrap_err();
        assert!(err.contains("not owned by uid"), "{err}");
    }

    /// A helper started by another user than its peer watches nothing,
    /// whatever its euid.
    #[test]
    fn helper_started_by_another_user_is_refused() {
        let other = me().wrapping_add(1);
        for euid in [me(), other, 0] {
            let mut s = WatchScope::with_ids(me(), other, euid);
            let err = s.authorize(session(4), std::process::id()).unwrap_err();
            assert!(err.contains("watches only for the user"), "{err}");
        }
        // Right real uid, but an euid that is neither it nor root.
        if other != 0 {
            let mut s = WatchScope::with_ids(me(), me(), other);
            let err = s.authorize(session(4), std::process::id()).unwrap_err();
            assert!(err.contains("watches only for the user"), "{err}");
        }
    }

    /// Review item 2: on a setuid-root install the helper's euid is 0
    /// and its real uid is the peer's. Watches are still allowed, with
    /// every process check in place.
    #[test]
    fn setuid_root_helper_watches_for_its_real_user() {
        if me() == 0 {
            return;
        }
        let mut s = WatchScope::with_ids(me(), me(), 0);
        assert!(s.authorize(session(9), std::process::id()).is_ok());
        let err = s.authorize(session(10), 1).unwrap_err();
        assert!(err.contains("not a user process"), "{err}");
        let other = me().wrapping_add(1);
        let mut s = WatchScope::with_ids(other, other, 0);
        let err = s.authorize(session(11), std::process::id()).unwrap_err();
        assert!(err.contains("not owned by uid"), "{err}");
    }

    #[test]
    fn missing_process_is_refused() {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        let mut s = scope();
        assert!(s.authorize(session(5), pid).is_err());
    }

    /// Once a session is pinned to its shell, it may watch the shell's
    /// descendants but no other process, even one of the same user,
    /// while that shell runs. The refusal says so.
    #[test]
    fn a_session_with_a_live_shell_watches_only_it_and_descendants() {
        let mut child = sleeper();
        let cpid = child.id();
        let mut s = scope();
        // Pinned to this process: its child is a descendant.
        assert!(s.authorize(session(6), std::process::id()).is_ok());
        assert!(s.authorize(session(6), cpid).is_ok());
        // Pinned to the child: this process is its parent, not a
        // descendant, and the child is alive.
        let err = s
            .authorize(session(7), cpid)
            .and_then(|_| s.authorize(session(7), std::process::id()));
        child.kill().unwrap();
        child.wait().unwrap();
        let err = err.unwrap_err();
        assert!(err.contains("which is still running"), "{err}");
        assert!(err.contains("neither that shell nor a descendant"), "{err}");
    }

    /// Review item 3: the session's shell exited. A new shell with the
    /// same session id is pinned in its place.
    #[test]
    fn a_session_whose_shell_exited_is_pinned_to_the_new_shell() {
        let mut old = sleeper();
        let opid = old.id();
        let mut s = scope();
        assert!(s.authorize(session(12), opid).is_ok());
        old.kill().unwrap();
        old.wait().unwrap();
        let pid = std::process::id();
        assert!(s.authorize(session(12), pid).is_ok());
        assert_eq!(s.pins[&session(12)].0, pid);
    }

    /// The pinned pid was reused by another process (start time
    /// differs): the old shell is gone, so the session re-pins.
    #[test]
    fn a_reused_pinned_pid_re_pins_the_session() {
        let mut s = scope();
        let pid = std::process::id();
        let start = proc_ident(pid).unwrap().start;
        s.pins.insert(session(8), (pid, start + 1));
        assert!(s.authorize(session(8), pid).is_ok());
        assert_eq!(s.pins[&session(8)], (pid, start));
    }

    #[test]
    fn still_same_refuses_a_changed_or_missing_process() {
        let pid = std::process::id();
        let start = proc_ident(pid).unwrap().start;
        assert_eq!(still_same(pid, start), Ok(()));
        assert!(still_same(pid, start + 1).is_err());
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        assert!(still_same(dead, 0).is_err());
    }
}
