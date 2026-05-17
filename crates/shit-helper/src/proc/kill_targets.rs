// SPDX-License-Identifier: AGPL-3.0-or-later

//! Kill-target resolution (S18.5 wires the real lookups).

use std::collections::BTreeMap;

/// Name of the env var the shell hook uses to publish its job
/// table to `shit-helper proc-event`. The shell writes
/// `1:1234,2:5678,+:5678,-:1234\n` (job-spec → pid pairs).
pub const SHIT_JOB_TABLE_ENV: &str = "SHIT_JOB_TABLE";

/// Resolve a job-control spec like `%1` or `%+` against the shell
/// job table published in `SHIT_JOB_TABLE`. Stage-1 implementation
/// is real (no shell-out needed).
pub fn resolve_job_spec(spec: &str) -> Option<u32> {
    let table = std::env::var(SHIT_JOB_TABLE_ENV).ok()?;
    let key = spec.strip_prefix('%').unwrap_or(spec);
    for entry in table.split(',') {
        let (k, v) = entry.split_once(':')?;
        if k == key {
            return v.parse().ok();
        }
    }
    None
}

/// Enumerate processes in a process group. Stage-1 stub returns
/// just the leader pid; S18.5 wires the real walk.
pub fn resolve_pgroup(pgid: u32) -> Option<Vec<u32>> {
    Some(vec![pgid])
}

/// Resolve a pkill/killall pattern + filters. Stage-1 stub
/// returns empty; S18.5 wires the real walk.
pub fn resolve_pattern(_pattern: &str, _filters: &BTreeMap<String, String>) -> Vec<u32> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_spec_resolves_from_env() {
        // SAFETY: tests in this binary run with --test-threads=1
        // is not enforced — guard with the local lock pattern
        // proven in S15's color tests if this turns out flaky.
        unsafe { std::env::set_var(SHIT_JOB_TABLE_ENV, "1:1234,2:5678,+:5678,-:1234") };
        assert_eq!(resolve_job_spec("%1"), Some(1234));
        assert_eq!(resolve_job_spec("%+"), Some(5678));
        assert_eq!(resolve_job_spec("%-"), Some(1234));
        assert_eq!(resolve_job_spec("%99"), None);
        unsafe { std::env::remove_var(SHIT_JOB_TABLE_ENV) };
    }

    #[test]
    fn job_spec_no_table_is_none() {
        unsafe { std::env::remove_var(SHIT_JOB_TABLE_ENV) };
        assert_eq!(resolve_job_spec("%1"), None);
    }
}
