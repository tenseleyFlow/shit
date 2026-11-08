// SPDX-License-Identifier: AGPL-3.0-or-later

//! #222: every rename-family notification carries `from\tto`, so the
//! daemon can journal a TreeOp::Rename even when the destination
//! existed and its pre-image rides along.

use super::policy::test_capture;
use std::ffi::CString;
use std::os::unix::io::AsRawFd;

/// The notes `f` sends before its calls run: every note but the
/// outcomes the shim sends after a rename-family call returns.
fn capture_pre(f: impl FnOnce()) -> Vec<shit_proto::ShimNotification> {
    test_capture::capture(f)
        .into_iter()
        .filter(|n| n.outcome.is_none())
        .collect()
}

fn rename_abs(from: &std::path::Path, to: &std::path::Path) -> i32 {
    let cf = CString::new(from.to_str().unwrap()).unwrap();
    let ct = CString::new(to.to_str().unwrap()).unwrap();
    unsafe { super::interposers::rename(cf.as_ptr(), ct.as_ptr()) }
}

/// L5 PR B: every rename-family call sends its outcome under the same
/// call id as its pre-call note, with the source's inode before the call
/// and the destination's after it. Two calls get two ids.
#[test]
fn each_rename_call_reports_its_outcome_under_its_own_id() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::write(dir.join("a"), b"a").unwrap();
    std::fs::write(dir.join("c"), b"c").unwrap();
    let a_ino = std::fs::metadata(dir.join("a")).unwrap().ino();
    let notes = test_capture::capture(|| {
        assert_eq!(rename_abs(&dir.join("a"), &dir.join("b")), 0);
        assert_eq!(rename_abs(&dir.join("c"), &dir.join("d")), 0);
    });
    assert_eq!(notes.len(), 4, "{notes:#?}");
    assert!(notes[0].outcome.is_none() && notes[2].outcome.is_none());
    let out = notes[1].outcome.expect("outcome");
    assert_eq!(out.errno, 0);
    assert_eq!((out.source_inode, out.dest_inode), (a_ino, a_ino));
    assert_ne!(notes[0].call_id, 0);
    assert_eq!(notes[0].call_id, notes[1].call_id);
    assert_eq!(notes[2].call_id, notes[3].call_id);
    assert_ne!(notes[0].call_id, notes[2].call_id);
    assert_eq!(notes[1].arg, notes[0].arg);
}

/// A failed rename reports its errno, keeps it for the caller, and names
/// no destination.
#[test]
fn failed_rename_reports_its_errno() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::write(dir.join("a"), b"a").unwrap();
    std::fs::create_dir(dir.join("b")).unwrap();
    std::fs::write(dir.join("b/x"), b"x").unwrap();
    let mut errno = None;
    let notes = test_capture::capture(|| {
        assert_eq!(rename_abs(&dir.join("a"), &dir.join("b")), -1);
        errno = std::io::Error::last_os_error().raw_os_error();
    });
    let out = notes.last().unwrap().outcome.expect("outcome");
    assert_eq!(Some(out.errno), errno);
    assert_eq!(out.errno, libc::EISDIR);
    assert_eq!((out.dest_dev, out.dest_inode), (0, 0));
}

#[test]
fn renameat_with_real_dirfd_over_existing_file_keeps_from_and_to() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::write(dir.join(".alpha.txt.X"), b"new").unwrap();
    std::fs::write(dir.join("alpha.txt"), b"old").unwrap();
    let dfd = std::fs::File::open(&dir).unwrap();
    let from = CString::new(".alpha.txt.X").unwrap();
    let to = CString::new("alpha.txt").unwrap();
    let mut rc = -1;
    let notes = capture_pre(|| {
        rc = unsafe {
            super::interposers::renameat(
                dfd.as_raw_fd(),
                from.as_ptr(),
                dfd.as_raw_fd(),
                to.as_ptr(),
            )
        };
    });
    assert_eq!(rc, 0);
    assert_eq!(std::fs::read(dir.join("alpha.txt")).unwrap(), b"new");
    let renames: Vec<_> = notes.iter().filter(|n| n.syscall == "renameat").collect();
    assert_eq!(renames.len(), 1, "{notes:#?}");
    let n = renames[0];
    let want_to = dir.join("alpha.txt");
    assert_eq!(
        n.arg,
        format!(
            "{}\t{}",
            dir.join(".alpha.txt.X").display(),
            want_to.display()
        )
    );
    let pre = n.pre_image.as_ref().expect("destination pre-image");
    assert_eq!(pre.path, want_to.to_str().unwrap());
    assert_eq!(pre.bytes, b"old");
}

#[test]
fn rename_with_absolute_paths_over_existing_file_keeps_from_and_to() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().canonicalize().unwrap();
    let (a, b) = (dir.join("a"), dir.join("b"));
    std::fs::write(&a, b"new").unwrap();
    std::fs::write(&b, b"old").unwrap();
    let ca = CString::new(a.to_str().unwrap()).unwrap();
    let cb = CString::new(b.to_str().unwrap()).unwrap();
    let notes = capture_pre(|| unsafe {
        assert_eq!(super::interposers::rename(ca.as_ptr(), cb.as_ptr()), 0);
    });
    let n = notes
        .iter()
        .find(|n| n.syscall == "rename")
        .expect("rename");
    assert_eq!(n.arg, format!("{}\t{}", a.display(), b.display()));
    assert_eq!(n.pre_image.as_ref().unwrap().path, b.to_str().unwrap());
}

/// Review round 2, item 2: `unlinkat(dirfd, name, AT_REMOVEDIR)` is a
/// removal like `rmdir`: reported after it succeeds, with the pre-call
/// stat, and not at all when it fails.
#[test]
fn unlinkat_removedir_of_a_non_empty_dir_sends_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::create_dir(dir.join("full")).unwrap();
    std::fs::write(dir.join("full/f"), b"f").unwrap();
    let dfd = std::fs::File::open(&dir).unwrap();
    let name = CString::new("full").unwrap();
    let notes = capture_pre(|| {
        let rc = unsafe {
            super::interposers::unlinkat(dfd.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
        };
        assert_eq!(rc, -1);
    });
    assert!(notes.is_empty(), "{notes:#?}");
}

#[test]
fn unlinkat_removedir_reports_after_success_with_the_pre_call_stat() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::create_dir(dir.join("e")).unwrap();
    std::fs::set_permissions(dir.join("e"), std::fs::Permissions::from_mode(0o750)).unwrap();
    let dfd = std::fs::File::open(&dir).unwrap();
    let name = CString::new("e").unwrap();
    let notes = capture_pre(|| {
        let rc = unsafe {
            super::interposers::unlinkat(dfd.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
        };
        assert_eq!(rc, 0);
    });
    assert_eq!(notes.len(), 1, "{notes:#?}");
    assert_eq!(notes[0].syscall, "unlinkat_dir");
    assert_eq!(notes[0].arg, dir.join("e").to_str().unwrap());
    assert_eq!(notes[0].pre_stat.as_ref().map(|s| s.mode), Some(0o040750));
}

/// Review round 5, item 3: renaming a symlink to a directory moves the
/// link. The note names the link and its new name, and the directory is
/// not walked.
#[test]
fn rename_of_a_symlink_to_a_dir_names_the_link() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::create_dir(dir.join("real")).unwrap();
    std::fs::write(dir.join("real/f"), b"f").unwrap();
    std::os::unix::fs::symlink("real", dir.join("link")).unwrap();
    let from = CString::new(dir.join("link").to_str().unwrap()).unwrap();
    let to = CString::new(dir.join("moved").to_str().unwrap()).unwrap();
    let notes = capture_pre(|| {
        assert_eq!(
            unsafe { super::interposers::rename(from.as_ptr(), to.as_ptr()) },
            0
        );
    });
    assert_eq!(notes.len(), 1, "{notes:#?}");
    assert_eq!(
        notes[0].arg,
        format!(
            "{}\t{}",
            dir.join("link").display(),
            dir.join("moved").display()
        )
    );
    assert!(notes[0].extra_pre_images.is_empty(), "{notes:#?}");
    assert!(dir.join("real/f").exists());
}

/// The same through renameat with a real dirfd, onto an existing link.
/// Review of #232, item 3: the replaced link travels as the
/// destination's lstat with its target, so undo can recreate it (the
/// daemon side is `rename_over_a_symlink_is_undone_by_recreating_the_link`).
#[test]
fn renameat_over_a_symlink_names_the_link_and_sends_its_target() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::write(dir.join("target"), b"keep").unwrap();
    std::fs::write(dir.join("new"), b"new").unwrap();
    std::os::unix::fs::symlink("target", dir.join("link")).unwrap();
    let dfd = std::fs::File::open(&dir).unwrap();
    let from = CString::new("new").unwrap();
    let to = CString::new("link").unwrap();
    let notes = capture_pre(|| {
        let rc = unsafe {
            super::interposers::renameat(
                dfd.as_raw_fd(),
                from.as_ptr(),
                dfd.as_raw_fd(),
                to.as_ptr(),
            )
        };
        assert_eq!(rc, 0);
    });
    assert_eq!(notes.len(), 1, "{notes:#?}");
    assert_eq!(
        notes[0].arg,
        format!(
            "{}\t{}",
            dir.join("new").display(),
            dir.join("link").display()
        )
    );
    assert!(notes[0].pre_image.is_none(), "{notes:#?}");
    assert!(notes[0].failure.is_none(), "{notes:#?}");
    let st = notes[0].pre_stat.as_ref().expect("the link's lstat");
    assert_eq!(st.mode & 0o170000, 0o120000);
    assert_eq!(st.link_target.as_deref(), Some("target"));
}

/// Review of #232, item 3: a destination the shim cannot read is a
/// capture gap, never silence.
#[test]
fn rename_over_an_uncapturable_file_sends_a_gap_marker() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    let big = vec![b'x'; shit_proto::SHIM_INLINE_PREIMAGE_CAP as usize + 1];
    std::fs::write(dir.join("big"), &big).unwrap();
    std::fs::write(dir.join("new"), b"new").unwrap();
    let from = CString::new(dir.join("new").to_str().unwrap()).unwrap();
    let to = CString::new(dir.join("big").to_str().unwrap()).unwrap();
    let notes = capture_pre(|| {
        assert_eq!(
            unsafe { super::interposers::rename(from.as_ptr(), to.as_ptr()) },
            0
        );
    });
    assert_eq!(notes.len(), 1, "{notes:#?}");
    assert!(notes[0].pre_image.is_none());
    assert!(
        matches!(
            &notes[0].failure,
            Some(shit_proto::ShimFailure::PreImageUncaptured { path, .. })
                if path == dir.join("big").to_str().unwrap()
        ),
        "{notes:#?}"
    );
}

/// Review of #232 round 2, item 5: a rename over a symlink that fails
/// (here ENOTDIR, a directory onto a link; EXDEV across filesystems is
/// the same shape) sends nothing, so no replaced link is journaled.
#[test]
fn failed_rename_over_a_symlink_sends_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::write(dir.join("target"), b"keep").unwrap();
    std::fs::create_dir(dir.join("d")).unwrap();
    std::os::unix::fs::symlink("target", dir.join("link")).unwrap();
    let from = CString::new(dir.join("d").to_str().unwrap()).unwrap();
    let to = CString::new(dir.join("link").to_str().unwrap()).unwrap();
    let notes = capture_pre(|| {
        assert_eq!(
            unsafe { super::interposers::rename(from.as_ptr(), to.as_ptr()) },
            -1
        );
    });
    assert!(notes.is_empty(), "{notes:#?}");
    assert_eq!(
        std::fs::read_link(dir.join("link")).unwrap().to_str(),
        Some("target")
    );
}

/// Review of #232 round 2, item 4: a `from` the shim could not key and
/// a destination it could not read are both reported.
#[test]
fn canonicalize_marker_and_destination_gap_are_both_sent() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    let big = vec![b'x'; shit_proto::SHIM_INLINE_PREIMAGE_CAP as usize + 1];
    std::fs::write(dir.join("big"), &big).unwrap();
    let from = CString::new("/no-such-dir-l5/missing/x").unwrap();
    let to = CString::new(dir.join("big").to_str().unwrap()).unwrap();
    let notes = capture_pre(|| {
        unsafe { super::interposers::rename(from.as_ptr(), to.as_ptr()) };
    });
    let failures: Vec<_> = notes.iter().filter_map(|n| n.failure.as_ref()).collect();
    assert!(
        failures
            .iter()
            .any(|f| matches!(f, shit_proto::ShimFailure::CanonicalizeFailed { .. })),
        "{notes:#?}"
    );
    assert!(
        failures.iter().any(|f| matches!(
            f,
            shit_proto::ShimFailure::PreImageUncaptured { path, .. }
                if path == dir.join("big").to_str().unwrap()
        )),
        "{notes:#?}"
    );
}

/// Review of #232 round 2, item 6: the entry resolver used for unlink on
/// macOS (and renames everywhere) keeps a symlink as the link.
#[test]
fn entry_resolution_keys_a_symlink_to_the_link() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::write(dir.join("target"), b"t").unwrap();
    std::os::unix::fs::symlink("target", dir.join("link")).unwrap();
    let (abs, failure) =
        super::policy::entry_or_raw(tmp.path().join("link").to_str().unwrap(), "path");
    assert!(failure.is_none());
    assert_eq!(abs, dir.join("link").to_str().unwrap());
}

/// Review of #232 round 2, item 8: a muted shim (`SHIT_SHIM_DISABLE`, as
/// `shit undo` runs) reports no removal after the call.
#[test]
fn muted_removal_sends_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::create_dir(dir.join("d")).unwrap();
    let pending =
        super::policy::removal_pending("rmdir", dir.join("d").to_str().unwrap().to_string(), None);
    std::fs::remove_dir(dir.join("d")).unwrap();
    let notes = capture_pre(|| {
        super::policy::test_mute::with_muted(|| super::policy::removal_end(pending, 0));
    });
    assert!(notes.is_empty(), "{notes:#?}");
}

/// Review of #232 medium review, item 4: a removal whose name could not
/// be keyed carries no stat (`src` here exists relative to the test's
/// cwd, which is not the dirfd's directory), and a muted shim records
/// nothing for it at all.
#[test]
fn unkeyed_removal_carries_no_stat_and_honors_the_mute() {
    let marker = || shit_proto::ShimFailure::CanonicalizeFailed {
        which_arg: "path".into(),
        attempted_path: "src".into(),
        error_chain: "dirfd 9 could not be resolved".into(),
    };
    assert!(std::path::Path::new("src").exists());
    let notes = capture_pre(|| {
        let p = super::policy::removal_pending("unlinkat_dir", "src".into(), Some(marker()));
        super::policy::removal_end(p, 0);
    });
    assert_eq!(notes.len(), 1, "{notes:#?}");
    assert!(notes[0].pre_stat.is_none(), "{notes:#?}");
    assert!(notes[0].failure.is_some());
    let muted = super::policy::test_mute::with_muted(|| {
        super::policy::removal_pending("unlinkat_dir", "src".into(), Some(marker()))
    });
    assert!(muted.is_none());
}
