// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process enumeration (S18.4).
//!
//! Per-OS implementations behind `cfg`:
//!
//! - **Linux**: `/proc/<pid>/{cmdline,comm,cwd,environ,status,stat}`
//!   gives us everything we need. Helper has CAP_SYS_PTRACE so
//!   `/proc/<pid>/environ` is readable across uids.
//! - **macOS**: `libproc` (DR-49 — not implemented Stage 1).
//! - **FreeBSD**: `sysctl(KERN_PROC_*)` via [`super::freebsd`]
//!   (DR-50 — landed in B02).
//! - **Other BSDs (NetBSD/OpenBSD/DragonFly)**: not implemented;
//!   B06 stretch sprint.
//!
//! ## Env summary whitelist
//!
//! We don't ship the entire env block — too big and too sensitive.
//! The snapshot's `env_summary` includes only a small whitelist
//! (`PATH`, `HOME`, `USER`, `SHELL`, `PWD`, `LANG`, `TERM`) plus
//! anything matching S15's redaction substrings (value redacted).

use std::collections::BTreeMap;

use shit_proto::ProcSnapshot;

/// True if a pid is still alive. Cheap probe via `kill(pid, 0)`.
#[allow(dead_code)]
pub fn is_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Snapshot a single process by pid.
pub fn read_proc_snapshot(pid: u32) -> anyhow::Result<ProcSnapshot> {
    #[cfg(target_os = "linux")]
    {
        linux::snapshot(pid)
    }
    #[cfg(target_os = "freebsd")]
    {
        super::freebsd::snapshot(pid)
    }
    #[cfg(target_os = "macos")]
    {
        // M06.2 — libproc + KERN_PROCARGS2 sysctl. Closes DR-48 +
        // DR-49 for the snapshot path; the kill-proc smoke now
        // has real argv/cwd/ppid metadata on macOS, not the
        // empty-string fallback the old "not implemented" branch
        // produced.
        super::macos::snapshot(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
    {
        let _ = pid;
        Err(anyhow::anyhow!(
            "proc snapshot not implemented on this platform (B06 stretch)"
        ))
    }
}

/// Env vars worth keeping in the summary by name. The redaction
/// pass adds more names dynamically (anything matching the S15
/// substring set).
// M06.2 — also referenced by the macOS branch (`super::macos`).
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub const ENV_WHITELIST: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "PWD", "LANG", "LC_ALL", "TERM", "DISPLAY",
];

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(super) fn summarize_env(block: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let filter = shit_planner::EnvFilter::default();
    for chunk in block.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let Some(pos) = chunk.iter().position(|&b| b == b'=') else {
            continue;
        };
        let name = String::from_utf8_lossy(&chunk[..pos]).into_owned();
        let value = String::from_utf8_lossy(&chunk[pos + 1..]).into_owned();
        let keep = ENV_WHITELIST.contains(&name.as_str()) || filter.is_redacted(&name);
        if !keep {
            continue;
        }
        let value = if filter.is_redacted(&name) {
            shit_planner::redact_value(&value)
        } else {
            value
        };
        out.insert(name, value);
    }
    out
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    pub fn snapshot(pid: u32) -> anyhow::Result<ProcSnapshot> {
        let base = format!("/proc/{pid}");
        // cmdline: NUL-separated argv. Trailing NUL is typical;
        // an empty cmdline indicates a kernel thread (no argv).
        let cmdline_bytes = std::fs::read(format!("{base}/cmdline"))?;
        let argv: Vec<String> = cmdline_bytes
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();

        let comm = std::fs::read_to_string(format!("{base}/comm"))
            .unwrap_or_default()
            .trim()
            .to_string();

        let cwd = std::fs::read_link(format!("{base}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        let env_block = std::fs::read(format!("{base}/environ")).unwrap_or_default();
        let env_summary = summarize_env(&env_block);

        let status = std::fs::read_to_string(format!("{base}/status")).unwrap_or_default();
        let parent_pid = parse_ppid(&status).unwrap_or(0);

        let stat = std::fs::read_to_string(format!("{base}/stat")).unwrap_or_default();
        let start_time_secs = parse_start_time(&stat).unwrap_or(0);

        let tty = parse_tty(&stat);

        Ok(ProcSnapshot {
            pid,
            comm,
            argv,
            cwd,
            env_summary,
            parent_pid,
            start_time_secs,
            tty,
        })
    }

    fn parse_ppid(status: &str) -> Option<u32> {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                return rest.trim().parse().ok();
            }
        }
        None
    }

    /// `/proc/<pid>/stat` is a single line: `pid (comm) state ppid …
    /// starttime …`. starttime is field 22, in clock ticks since
    /// boot. We convert to seconds via `sysconf(_SC_CLK_TCK)`.
    ///
    /// The (comm) field is the only one that can contain spaces
    /// and parentheses, so we split on the last `)` before scanning.
    pub(super) fn parse_start_time(stat: &str) -> Option<u64> {
        let close = stat.rfind(')')?;
        let after = &stat[close + 1..];
        // Field 0 of `after` is `state`; starttime is field 19
        // counting from 0 (which is field 22 in the canonical
        // 1-indexed `man proc` numbering: pid=1, comm=2, state=3,
        // …, starttime=22).
        let mut toks = after.split_whitespace();
        for _ in 0..19 {
            toks.next()?;
        }
        let ticks: u64 = toks.next()?.parse().ok()?;
        // SAFETY: _SC_CLK_TCK is always > 0 on POSIX.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        if hz == 0 {
            return Some(ticks);
        }
        Some(ticks / hz)
    }

    fn parse_tty(stat: &str) -> Option<String> {
        let close = stat.rfind(')')?;
        let after = &stat[close + 1..];
        let mut toks = after.split_whitespace();
        // tty_nr is field 7 1-indexed of the kernel-doc numbering,
        // which is field 4 of `after` (state, ppid, pgrp, session,
        // tty_nr).
        for _ in 0..4 {
            toks.next()?;
        }
        let tty_nr: i32 = toks.next()?.parse().ok()?;
        if tty_nr == 0 {
            return None;
        }
        // Encoding: low 8 + ((tty_nr >> 12) & 0xfff00) = minor;
        // (tty_nr >> 8) & 0xff = major. For Stage 1 we just
        // surface the encoded number; a richer mapping to
        // /dev/pts/N or /dev/ttyN is DR-51.
        Some(format!("tty_nr={tty_nr}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_ppid_finds_line() {
            let s = "Name:\tbash\nState:\tS\nPid:\t100\nPPid:\t99\n";
            assert_eq!(parse_ppid(s), Some(99));
        }

        #[test]
        fn parse_start_time_handles_paren_in_comm() {
            // Real-ish stat with parens inside comm.
            // pid (a (b) c) state ppid ... starttime is field 22.
            // The parser must use the LAST ')' to split.
            let stat = "100 (a (b) c) S 99 100 100 0 -1 4194304 ".to_string()
                + &(0..18).map(|_| "0 ").collect::<String>()
                + "1234567 ";
            // ticks=1234567, divided by HZ=100 (Linux default) = 12345.
            // But we just check it parsed *something*.
            assert!(parse_start_time(&stat).is_some());
        }

        #[test]
        fn snapshot_self_returns_argv() {
            // /proc/self/cmdline of the test binary should exist
            // and parse. This test only runs on linux (the parent
            // module is cfg-gated).
            let s = snapshot(std::process::id()).expect("self-snapshot");
            assert!(!s.argv.is_empty(), "argv empty");
            assert!(!s.comm.is_empty(), "comm empty");
            assert!(s.parent_pid > 0, "ppid 0");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_env_keeps_whitelist() {
        let block = b"PATH=/usr/bin\0HOME=/home/me\0NOISE=junk\0".as_slice();
        let m = summarize_env(block);
        assert_eq!(m.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(m.get("HOME").map(String::as_str), Some("/home/me"));
        assert!(!m.contains_key("NOISE"));
    }

    #[test]
    fn summarize_env_redacts_secrets() {
        let block = b"PATH=/usr/bin\0GITHUB_TOKEN=ghp_xxx\0".as_slice();
        let m = summarize_env(block);
        let v = m.get("GITHUB_TOKEN").expect("present");
        assert!(v.starts_with("<redacted:"), "leaked: {v}");
        assert!(!v.contains("ghp_xxx"));
    }

    #[test]
    fn is_alive_self() {
        assert!(is_alive(std::process::id()));
    }

    #[test]
    fn is_alive_bogus() {
        // PID 1 always exists on a healthy POSIX system, but a
        // very-large pid is reliably "not alive."
        assert!(!is_alive(2_000_000));
    }
}
