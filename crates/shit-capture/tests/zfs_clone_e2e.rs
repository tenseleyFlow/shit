// SPDX-License-Identifier: AGPL-3.0-or-later

//! AU01.A engine-wire integration tests.
//!
//! Compiled only on BSDs; gated behind `#[ignore]` because they
//! require:
//!   - `/sbin/zfs` installed
//!   - a writable ZFS-backed dir at `SHIT_ZFS_TEST_DIR`
//!   - root (sudo / doas) to take snapshots and clone
//!
//! Driven by `tests/smoke/zfs-clone-engine-fbsd.sh`, which sets up
//! the dataset and invokes:
//!
//!   cargo test -p shit-capture --test zfs_clone_e2e -- \
//!     --ignored --nocapture
//!
//! under privilege.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

use shit_capture::cow::zfs_clone::capture_zfs_clone;
use shit_capture::{CaptureOpts, CowEngine, CowTier, DefaultEngine};
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

fn require_env(var: &str) -> PathBuf {
    let v = std::env::var(var).unwrap_or_else(|_| {
        panic!("test requires {var} env var pointing to a writable ZFS-backed dir")
    });
    PathBuf::from(v)
}

#[test]
#[ignore]
fn capture_zfs_clone_returns_zfs_clone_tier_with_matching_bytes() {
    let src_dir = require_env("SHIT_ZFS_TEST_DIR");
    let blob_root = tempfile::tempdir_in(&src_dir).unwrap();
    let src_path = src_dir.join(format!("au01a-engine-{}.txt", std::process::id()));
    let payload = b"AU01.A engine-wire test content\n".repeat(64);

    {
        let mut f = File::create(&src_path).unwrap();
        f.write_all(&payload).unwrap();
        f.flush().unwrap();
    }
    let f = File::open(&src_path).unwrap();

    let outcome = capture_zfs_clone(f.as_raw_fd(), &src_path, blob_root.path())
        .expect("capture_zfs_clone failed");

    assert_eq!(
        outcome.tier,
        CowTier::ZfsClone,
        "expected ZfsClone tier, got {:?}",
        outcome.tier
    );

    let expected = shit_planner::BlobHash::from_bytes(*blake3::hash(&payload).as_bytes());
    assert_eq!(
        outcome.hash, expected,
        "captured blob hash != streaming hash"
    );

    let store = shit_store::BlobStore::open(blob_root.path()).unwrap();
    let bytes = store.get(outcome.hash).unwrap();
    assert_eq!(bytes, payload);

    std::fs::remove_file(&src_path).ok();
}

#[test]
#[ignore]
fn default_engine_picks_zfs_clone_on_zfs_backed_source() {
    let src_dir = require_env("SHIT_ZFS_TEST_DIR");
    let blob_root = tempfile::tempdir_in(&src_dir).unwrap();
    let src_path = src_dir.join(format!("au01a-default-{}.txt", std::process::id()));
    std::fs::write(&src_path, b"default engine zfs pick").unwrap();
    let f = File::open(&src_path).unwrap();

    let engine = DefaultEngine::new();
    let outcome = engine
        .capture(
            f.as_raw_fd(),
            &src_path,
            blob_root.path(),
            CaptureOpts::default(),
        )
        .expect("default engine capture failed");

    assert_eq!(
        outcome.tier,
        CowTier::ZfsClone,
        "DefaultEngine should pick ZfsClone first on ZFS; got {:?}",
        outcome.tier
    );

    std::fs::remove_file(&src_path).ok();
}
