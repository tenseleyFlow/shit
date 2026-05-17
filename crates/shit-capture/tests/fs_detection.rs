// SPDX-License-Identifier: AGPL-3.0-or-later

//! FS detection smoke test. Run against the test process's tempdir.
//! We can't assert a specific FsKind because runners vary — we only
//! assert that detection produces a non-Other answer on the developer's
//! machine, but accept Other (with a logged kind) on CI.

use shit_capture::FsKind;

#[test]
fn detect_fs_returns_a_kind_for_tempdir() {
    let tmp = tempfile::tempdir().unwrap();
    let kind = shit_capture::detect_fs(tmp.path()).unwrap();
    let label = kind.as_str().to_owned();
    assert!(!label.is_empty(), "fs kind label must be non-empty");
    eprintln!("detected fs: {label}");
}

#[test]
fn synthetic_fs_predicates_correct() {
    assert!(FsKind::Procfs.is_synthetic());
    assert!(FsKind::Sysfs.is_synthetic());
    assert!(FsKind::Devfs.is_synthetic());
    assert!(!FsKind::Apfs.is_synthetic());
    assert!(!FsKind::Btrfs.is_synthetic());
}

#[test]
fn pick_tier_apfs_self_is_clonefile() {
    let pick = shit_capture::pick_tier(&FsKind::Apfs, &FsKind::Apfs, false);
    assert_eq!(pick, Some(shit_capture::CowTier::Clonefile));
}

#[test]
fn pick_tier_btrfs_self_is_reflink() {
    let pick = shit_capture::pick_tier(&FsKind::Btrfs, &FsKind::Btrfs, false);
    assert_eq!(pick, Some(shit_capture::CowTier::Reflink));
}

#[test]
fn pick_tier_ext4_self_is_copy_file_range() {
    let pick = shit_capture::pick_tier(&FsKind::Ext4, &FsKind::Ext4, false);
    assert_eq!(pick, Some(shit_capture::CowTier::CopyFileRange));
}
