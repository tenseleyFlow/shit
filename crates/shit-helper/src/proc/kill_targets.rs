// SPDX-License-Identifier: AGPL-3.0-or-later

//! Kill-target resolution (S18.5).
//!
//! Pure-rust helpers that map [`shit_planner::KillTarget`] variants
//! to concrete pids:
//!
//! - **JobSpec** (`%1` / `%+` / `%-`): consults the
//!   `SHIT_JOB_TABLE` env var the shell hook publishes.
//! - **Pid (negative)**: process group. Linux: walk `/proc/*/stat`
//!   and match field 5 (pgrp). macOS/BSD: deferred (DR-49/DR-50).
//! - **Pattern** (pkill/killall): walk `/proc/*/comm` and
//!   `/proc/*/cmdline`; match against the user's pattern. Filters
//!   honored: `user` (effective uid), `group` (pgrp).

use std::collections::BTreeMap;

pub const SHIT_JOB_TABLE_ENV: &str = "SHIT_JOB_TABLE";

pub fn resolve_job_spec(spec: &str) -> Option<u32> {
    let table = std::env::var(SHIT_JOB_TABLE_ENV).ok()?;
    resolve_job_spec_in(&table, spec)
}

/// Pure resolver — given an explicit `SHIT_JOB_TABLE` body, look up
/// the pid for `spec`. Split out so the unit tests don't race on the
/// process-global env var (cargo test runs tests in parallel; one
/// test setting and another clearing the env was a flaky-on-Linux
/// failure mode the macOS scheduler happened not to expose).
fn resolve_job_spec_in(table: &str, spec: &str) -> Option<u32> {
    let key = spec.strip_prefix('%').unwrap_or(spec);
    for entry in table.split(',') {
        let (k, v) = entry.split_once(':')?;
        if k == key {
            return v.parse().ok();
        }
    }
    None
}

pub fn resolve_pgroup(pgid: u32) -> Option<Vec<u32>> {
    #[cfg(target_os = "linux")]
    {
        linux::pids_in_pgroup(pgid)
    }
    #[cfg(target_os = "freebsd")]
    {
        super::freebsd::pids_in_pgroup(pgid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        let _ = pgid;
        None
    }
}

pub fn resolve_pattern(pattern: &str, filters: &BTreeMap<String, String>) -> Vec<u32> {
    #[cfg(target_os = "linux")]
    {
        linux::pids_matching(pattern, filters)
    }
    #[cfg(target_os = "freebsd")]
    {
        super::freebsd::pids_matching(pattern, filters)
    }
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (pattern, filters);
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;

    /// Walk `/proc/*` and collect pids whose pgrp (stat field 5)
    /// matches `pgid`.
    pub fn pids_in_pgroup(pgid: u32) -> Option<Vec<u32>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir("/proc").ok()? {
            let Ok(entry) = entry else {
                continue;
            };
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };
            let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if let Some(p) = pgrp_from_stat(&stat)
                && p == pgid
            {
                out.push(pid);
            }
        }
        Some(out)
    }

    /// Walk `/proc/*` and collect pids whose `comm` or `cmdline`
    /// matches `pattern` (substring), subject to filters.
    pub fn pids_matching(pattern: &str, filters: &BTreeMap<String, String>) -> Vec<u32> {
        let mut out = Vec::new();
        let user_filter = filters.get("user").and_then(|u| resolve_uid(u));
        let group_filter = filters.get("group").and_then(|g| g.parse::<u32>().ok());
        let entries = match std::fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => return out,
        };
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let cmdline_str = String::from_utf8_lossy(&cmdline);
            if !comm.contains(pattern) && !cmdline_str.contains(pattern) {
                continue;
            }
            if let Some(uid) = user_filter
                && uid_from_status(pid) != Some(uid)
            {
                continue;
            }
            if let Some(g) = group_filter {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
                if pgrp_from_stat(&stat) != Some(g) {
                    continue;
                }
            }
            out.push(pid);
        }
        out
    }

    fn pgrp_from_stat(stat: &str) -> Option<u32> {
        // pid (comm) state ppid pgrp ...
        let close = stat.rfind(')')?;
        let after = &stat[close + 1..];
        let mut toks = after.split_whitespace();
        toks.next()?; // state
        toks.next()?; // ppid
        let pgrp: u32 = toks.next()?.parse().ok()?;
        Some(pgrp)
    }

    fn uid_from_status(pid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                // Uid: <real> <effective> <saved> <fsuid>
                let effective = rest.split_whitespace().nth(1)?;
                return effective.parse().ok();
            }
        }
        None
    }

    fn resolve_uid(name_or_num: &str) -> Option<u32> {
        if let Ok(n) = name_or_num.parse::<u32>() {
            return Some(n);
        }
        // Fall back to /etc/passwd lookup. cheap enough for the
        // one-shot wrapper invocation.
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        for line in passwd.lines() {
            let mut fields = line.split(':');
            let n = fields.next()?;
            let _pw = fields.next();
            let uid = fields.next()?;
            if n == name_or_num {
                return uid.parse().ok();
            }
        }
        None
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn pgrp_from_stat_parses_simple() {
            let stat =
                "100 (bash) S 99 100 100 ".to_string() + &(0..20).map(|_| "0 ").collect::<String>();
            assert_eq!(pgrp_from_stat(&stat), Some(100));
        }

        #[test]
        fn pids_matching_finds_self() {
            // Look for the test binary's own comm — should match
            // because comm contains the binary name.
            let self_pid = std::process::id();
            let comm = std::fs::read_to_string(format!("/proc/{self_pid}/comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if comm.is_empty() {
                return; // skip when /proc isn't /proc-like
            }
            let found = pids_matching(&comm, &BTreeMap::new());
            assert!(
                found.contains(&self_pid),
                "expected to find self pid {self_pid} via comm {comm:?}: got {found:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_spec_resolves_from_table() {
        let table = "1:1234,2:5678,+:5678,-:1234";
        assert_eq!(resolve_job_spec_in(table, "%1"), Some(1234));
        assert_eq!(resolve_job_spec_in(table, "%+"), Some(5678));
        assert_eq!(resolve_job_spec_in(table, "%-"), Some(1234));
        assert_eq!(resolve_job_spec_in(table, "%99"), None);
    }

    #[test]
    fn job_spec_empty_table_is_none() {
        assert_eq!(resolve_job_spec_in("", "%1"), None);
    }
}
