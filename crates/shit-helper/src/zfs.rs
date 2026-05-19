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

/// Errors from the `zfs(8)` shell-outs. The helper logs these and
/// the daemon decides whether to refuse the watch (hard-fail) or fall
/// back to per-file capture (degraded), per the project's default-on
/// capture-failure policy.
#[derive(Debug, thiserror::Error)]
pub enum ZfsError {
    #[error("zfs(8) not on PATH and not at /sbin/zfs")]
    NotInstalled,
    #[error("zfs invocation failed: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("zfs exited with status {status}: {stderr}")]
    NonZero { status: i32, stderr: String },
}

/// Path the BSD base system installs `zfs(8)` at. Same on FreeBSD and
/// the major Linux ZFS-on-Linux packages; we shell out to the
/// absolute path so PATH manipulation can't redirect us mid-undo.
const ZFS_BIN: &str = "/sbin/zfs";

fn zfs_exec(args: &[&str]) -> Result<std::process::Output, ZfsError> {
    if !std::path::Path::new(ZFS_BIN).exists() {
        return Err(ZfsError::NotInstalled);
    }
    let out = std::process::Command::new(ZFS_BIN).args(args).output()?;
    if !out.status.success() {
        return Err(ZfsError::NonZero {
            status: out.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(out)
}

/// Create a snapshot of `dataset` named `name`. Equivalent to
/// `zfs snapshot dataset@name`. Recursive (`-r`) is intentionally
/// *not* set — the planner explicitly picks one dataset per command,
/// and `-r` would silently snapshot children that may belong to a
/// different command's watch tree.
pub fn snapshot_create(dataset: &str, name: &str) -> Result<(), ZfsError> {
    let snap = format!("{dataset}@{name}");
    zfs_exec(&["snapshot", &snap]).map(|_| ())
}

/// List snapshots under `dataset` matching the prefix `shit-`. The
/// planner uses this for inventory at undo time. `-H` strips the
/// header so the first line is data; `-o name` returns just the
/// snapshot name column.
pub fn snapshot_list(dataset: &str) -> Result<Vec<String>, ZfsError> {
    let out = zfs_exec(&["list", "-t", "snapshot", "-H", "-o", "name", "-r", dataset])?;
    let names = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            // Drop snapshots that aren't ours — other tooling shares
            // the dataset.
            line.split_once('@')
                .and_then(|(_ds, snap)| snap.starts_with("shit-").then_some(line.to_string()))
        })
        .collect();
    Ok(names)
}

/// Roll the dataset back to `snap` (full `dataset@name`). The `-r`
/// flag deletes any snapshots newer than the target — required for
/// a clean rollback when intermediate `shit-...` snapshots from
/// subsequent commands are present.
pub fn snapshot_rollback(snap: &str) -> Result<(), ZfsError> {
    zfs_exec(&["rollback", "-r", snap]).map(|_| ())
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

    #[test]
    fn zfs_not_installed_is_surfaced() {
        // Only run when /sbin/zfs really isn't there — most dev hosts
        // (macOS, generic Linux) don't have it. Skip otherwise so this
        // test doesn't false-fail on a ZFS-on-Linux box.
        if std::path::Path::new(ZFS_BIN).exists() {
            return;
        }
        let err = snapshot_create("rpool/test", "shit-probe-1").unwrap_err();
        assert!(matches!(err, ZfsError::NotInstalled));
    }
}
