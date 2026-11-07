// SPDX-License-Identifier: AGPL-3.0-or-later

//! #222: every rename-family notification carries `from\tto`, so the
//! daemon can journal a TreeOp::Rename even when the destination
//! existed and its pre-image rides along.

use super::policy::test_capture;
use std::ffi::CString;
use std::os::unix::io::AsRawFd;

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
    let notes = test_capture::capture(|| {
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
    let notes = test_capture::capture(|| unsafe {
        assert_eq!(super::interposers::rename(ca.as_ptr(), cb.as_ptr()), 0);
    });
    let n = notes
        .iter()
        .find(|n| n.syscall == "rename")
        .expect("rename");
    assert_eq!(n.arg, format!("{}\t{}", a.display(), b.display()));
    assert_eq!(n.pre_image.as_ref().unwrap().path, b.to_str().unwrap());
}
