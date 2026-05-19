// SPDX-License-Identifier: AGPL-3.0-or-later

//! ZFS snapshot-based capture helper (S10 stage 1).
//!
//! On FreeBSD-with-ZFS — the recommended setup per the sprint plan —
//! we prefer per-command dataset snapshots over per-file capture.
//! The math: a `zfs snapshot` is constant-time and atomic; comparable
//! coverage via per-file COW would mean opening every file the user
//! touches before they touch it, which doesn't scale on `make`-like
//! workloads.
//!
//! ## Stage 1 contract
//!
//! Probe-only. We can:
//! - Detect ZFS availability (via `shit_capture::bsd_probe::probe_zfs`).
//! - Resolve a path to its containing dataset.
//! - Generate a deterministic snapshot name for a (session, seq).
//!
//! We do **not** take snapshots, list them, or attempt rollback —
//! those require a real ZFS host and an `.docs/audits/zfs-flows.md`
//! review of failure modes (out-of-quota mid-snapshot, snapshot of a
//! mounted filesystem with active writers, etc.) that we'd write
//! against a live FreeBSD VM in a follow-up sprint.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
// Stage-1: probe-only API; DR-09 wires the snapshot/list/rollback
// callers. Until then the public functions have no in-crate callers
// and trip dead_code under `-D warnings`.
#![allow(dead_code)]

use std::path::Path;

use shit_capture::bsd_probe::{ZfsProbe, dataset_for_path, probe_zfs};

/// Build a deterministic snapshot name from a session UUID and a
/// command sequence number. Same shape as `shit-<session>-<seq>` per
/// the sprint plan. ZFS snapshot names are constrained to a limited
/// character set; we use only `[a-zA-Z0-9_-]` and `:` (allowed) to
/// stay safely inside that set.
pub fn snapshot_name(session_uuid: &str, command_seq: u64) -> String {
    // UUIDs come in with dashes which ZFS accepts; truncate to the
    // first 8 chars so snapshot lists are scannable when N gets big.
    let short = session_uuid.split('-').next().unwrap_or(session_uuid);
    format!("shit-{short}-{command_seq:08}")
}

/// Resolve a path to the dataset it lives on. Returns None on non-ZFS
/// paths or when `zfs` isn't on PATH.
pub fn resolve_dataset(path: &Path) -> Option<String> {
    dataset_for_path(path)
}

/// Re-probe ZFS — the daemon may want to refresh after a tier flip
/// (pool import/export between commands, etc.).
pub fn refresh() -> ZfsProbe {
    probe_zfs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_name_is_stable() {
        let n = snapshot_name("01970000-deca-dafb-ad00-000000000000", 42);
        assert_eq!(n, "shit-01970000-00000042");
    }

    #[test]
    fn snapshot_name_with_no_dashes_uses_full_input() {
        // Pathological input — still terminates cleanly.
        let n = snapshot_name("nouuid", 7);
        assert_eq!(n, "shit-nouuid-00000007");
    }

    #[test]
    fn snapshot_name_pads_seq_to_eight_digits() {
        // 8-digit zero pad gives us lexicographic ordering on snapshot
        // listings up to 99,999,999 commands per session. After that
        // ordering drifts but uniqueness holds.
        assert_eq!(snapshot_name("abcd", 1), "shit-abcd-00000001");
        assert_eq!(snapshot_name("abcd", 12345678), "shit-abcd-12345678");
    }
}
