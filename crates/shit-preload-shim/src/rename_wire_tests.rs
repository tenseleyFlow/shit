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
    let renames: Vec<_> = notes
        .iter()
        .filter(|n| n.syscall == "renameat" && n.outcome.is_none())
        .collect();
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

// L5: the rename walk's records and the post-syscall outcome.

fn rename_abs(from: &std::path::Path, to: &std::path::Path) -> (i32, Option<i32>) {
    let cf = CString::new(from.to_str().unwrap()).unwrap();
    let ct = CString::new(to.to_str().unwrap()).unwrap();
    let rc = unsafe { super::interposers::rename(cf.as_ptr(), ct.as_ptr()) };
    (rc, std::io::Error::last_os_error().raw_os_error())
}

fn mode_of(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(p).unwrap().mode()
}

#[test]
fn dir_rename_sends_a_complete_walk_then_its_outcome() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    let d = dir.join("d");
    std::fs::create_dir_all(d.join("sub")).unwrap();
    std::fs::create_dir(d.join("empty")).unwrap();
    std::fs::write(d.join("f"), b"f").unwrap();
    std::fs::write(d.join("sub/g"), b"g").unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    // The shim reads xattrs on Linux only (the daemon reads them on BSD).
    #[cfg(target_os = "linux")]
    let xattr_ok = {
        let p = CString::new(d.join("f").to_str().unwrap()).unwrap();
        let n = CString::new("user.l5").unwrap();
        unsafe { libc::setxattr(p.as_ptr(), n.as_ptr(), b"v".as_ptr().cast(), 1, 0) == 0 }
    };
    #[cfg(not(target_os = "linux"))]
    let xattr_ok = false;
    let d_ino = std::fs::metadata(&d).unwrap().ino();
    let t = dir.join("t");
    let notes = test_capture::capture(|| assert_eq!(rename_abs(&d, &t).0, 0));
    assert_eq!(notes.len(), 2, "{notes:#?}");
    let walk = notes[0].walk.as_ref().expect("walk");
    assert!(walk.complete, "{walk:#?}");
    assert_eq!(walk.files, 2);
    assert_eq!(notes[0].extra_pre_images.len(), 2);
    assert_eq!(walk.entries[0].path, d.to_str().unwrap());
    assert_eq!(walk.entries[0].mode & 0o7777, 0o700);
    assert_eq!(walk.entries[0].inode, d_ino);
    let dirs = walk
        .entries
        .iter()
        .filter(|e| e.mode & 0o170000 == 0o040000)
        .count();
    assert_eq!(dirs, 3, "{walk:#?}");
    if xattr_ok {
        let f = walk
            .entries
            .iter()
            .find(|e| e.path == d.join("f").to_str().unwrap())
            .unwrap();
        assert_eq!(
            f.xattrs.as_deref(),
            Some(&[("user.l5".to_string(), b"v".to_vec())][..])
        );
    }
    let out = notes[1].outcome.expect("outcome");
    assert_eq!(out.errno, 0);
    assert_eq!((out.source_inode, out.dest_inode), (d_ino, d_ino));
    assert_eq!(notes[1].arg, notes[0].arg);
    assert_eq!(mode_of(&t) & 0o7777, 0o700);
}

#[test]
fn walk_with_a_symlink_is_incomplete_and_has_no_dir_records() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    let d = dir.join("d");
    std::fs::create_dir_all(d.join("sub")).unwrap();
    std::fs::write(d.join("f"), b"f").unwrap();
    std::os::unix::fs::symlink("f", d.join("sub/link")).unwrap();
    let notes = test_capture::capture(|| assert_eq!(rename_abs(&d, &dir.join("t")).0, 0));
    let walk = notes[0].walk.as_ref().expect("walk");
    assert!(!walk.complete);
    assert!(
        walk.entries.iter().all(|e| e.mode & 0o170000 != 0o040000),
        "{walk:#?}"
    );
    assert_eq!(notes[0].extra_pre_images.len(), 1);
}

#[test]
fn failed_dir_rename_reports_its_errno_and_keeps_it_for_the_caller() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    let (d, t) = (dir.join("d"), dir.join("t"));
    std::fs::create_dir(&d).unwrap();
    std::fs::write(d.join("a"), b"d-a").unwrap();
    std::fs::create_dir(&t).unwrap();
    std::fs::write(t.join("a"), b"t-a").unwrap();
    let mut got = (0, None);
    let notes = test_capture::capture(|| got = rename_abs(&d, &t));
    assert_eq!(got.0, -1);
    assert!(
        matches!(got.1, Some(libc::ENOTEMPTY) | Some(libc::EEXIST)),
        "{got:?}"
    );
    let out = notes.last().unwrap().outcome.expect("outcome");
    assert_eq!(Some(out.errno), got.1);
    assert_eq!((out.dest_dev, out.dest_inode), (0, 0));
}

#[test]
fn outcomes_only_for_directory_and_failed_renames() {
    // Review round 2, item 3: a successful file rename (an atomic save)
    // pays no second round trip; a directory rename and any failure
    // report, under the call's id.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::write(dir.join("a"), b"a").unwrap();
    std::fs::create_dir(dir.join("d")).unwrap();
    let notes = test_capture::capture(|| {
        assert_eq!(rename_abs(&dir.join("a"), &dir.join("b")).0, 0);
        assert_eq!(rename_abs(&dir.join("d"), &dir.join("e")).0, 0);
        assert_eq!(rename_abs(&dir.join("gone"), &dir.join("x")).0, -1);
    });
    let outcomes: Vec<_> = notes.iter().filter(|n| n.outcome.is_some()).collect();
    assert_eq!(outcomes.len(), 2, "{notes:#?}");
    assert!(outcomes[0].arg.starts_with(dir.join("d").to_str().unwrap()));
    assert_eq!(outcomes[1].outcome.unwrap().errno, libc::ENOENT);
    for o in outcomes {
        let pre = notes
            .iter()
            .find(|n| n.outcome.is_none() && n.arg == o.arg)
            .expect("its pre-call note");
        assert_ne!(o.call_id, 0);
        assert_eq!(pre.call_id, o.call_id);
    }
}

#[test]
fn oversized_walk_frame_keeps_every_pre_image_and_the_rename() {
    // Review item 7: the resend drops only the walk record, sending the
    // bytes in chunks of their own first.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    let d = dir.join("d");
    std::fs::create_dir(&d).unwrap();
    for n in ["a", "b", "c"] {
        std::fs::write(d.join(n), vec![b'x'; 1024]).unwrap();
    }
    test_capture::set_frame_limit(Some(2500));
    let notes = test_capture::capture(|| assert_eq!(rename_abs(&d, &dir.join("t")).0, 0));
    test_capture::set_frame_limit(None);
    let chunks: Vec<_> = notes
        .iter()
        .filter(|n| n.syscall == "rename_walk")
        .collect();
    assert!(chunks.len() >= 2, "{notes:#?}");
    let carried: usize = chunks.iter().map(|n| n.extra_pre_images.len()).sum();
    assert_eq!(carried, 3, "{notes:#?}");
    assert!(
        chunks
            .iter()
            .all(|n| n.call_id == notes.last().unwrap().call_id)
    );
    let rename = notes
        .iter()
        .find(|n| n.syscall == "rename" && n.outcome.is_none())
        .expect("the Rename is still sent");
    assert!(rename.walk.is_none() && rename.extra_pre_images.is_empty());
    assert!(notes.last().unwrap().outcome.is_some());
}

#[test]
fn failed_file_rename_sends_an_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    std::fs::write(dir.join("a"), b"a").unwrap();
    std::fs::create_dir(dir.join("b")).unwrap();
    std::fs::write(dir.join("b/x"), b"x").unwrap();
    let notes =
        test_capture::capture(|| assert_eq!(rename_abs(&dir.join("a"), &dir.join("b")).0, -1));
    let out = notes.last().unwrap().outcome.expect("outcome");
    assert_eq!(out.errno, libc::EISDIR);
}

/// Review item 9: what the post-syscall outcome adds to a directory
/// rename, against a stand-in daemon that acks each frame after
/// `SHIT_L5_BENCH_ACK_US` microseconds (default 0). Run alone:
/// `cargo test -p shit-preload-shim --lib -- --ignored --exact
/// rename_wire_tests::bench_dir_rename_outcome_latency --nocapture`.
#[test]
#[ignore]
#[cfg(target_os = "linux")]
fn bench_dir_rename_outcome_latency() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    // The env first: the shim caches its socket path on first use, and
    // creating the tempdir already goes through the mkdir interposer.
    let dir = std::env::temp_dir().join(format!("l5-bench-{}", std::process::id()));
    // SAFETY: the test runs alone (see above); nothing else reads the env.
    unsafe { std::env::set_var("XDG_RUNTIME_DIR", &dir) };
    std::fs::create_dir_all(&dir).unwrap();
    let dir = dir.canonicalize().unwrap();
    let sock = dir.join("shit-shim.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    static CONNS: AtomicUsize = AtomicUsize::new(0);
    let ack_delay = std::time::Duration::from_micros(
        std::env::var("SHIT_L5_BENCH_ACK_US")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    );
    std::thread::spawn(move || {
        let ack = shit_proto::encode_frame(&shit_proto::ShimAck::Allow).unwrap();
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            CONNS.fetch_add(1, Ordering::Relaxed);
            let mut len = [0u8; 4];
            if s.read_exact(&mut len).is_err() {
                continue;
            }
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            let _ = s.read_exact(&mut body);
            std::thread::sleep(ack_delay);
            let _ = s.write_all(&ack);
        }
    });
    let n = 300;
    let (mut pre, mut post) = (Vec::new(), Vec::new());
    for i in 0..n {
        let d = dir.join(format!("d{i}"));
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("f"), b"f").unwrap();
        let t = dir.join(format!("t{i}"));
        let t0 = std::time::Instant::now();
        let pending = super::policy::notify_rename_with_dst_preimage(
            "rename",
            d.to_str().unwrap(),
            t.to_str().unwrap(),
        );
        let t1 = std::time::Instant::now();
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                CString::new(d.to_str().unwrap()).unwrap().as_ptr(),
                libc::AT_FDCWD,
                CString::new(t.to_str().unwrap()).unwrap().as_ptr(),
                0,
            ) as i32
        };
        let t2 = std::time::Instant::now();
        super::policy::finish_rename(pending, rc);
        let t3 = std::time::Instant::now();
        assert_eq!(rc, 0);
        pre.push((t1 - t0).as_micros());
        post.push((t3 - t2).as_micros());
    }
    pre.sort_unstable();
    post.sort_unstable();
    let med = |v: &[u128]| v[v.len() / 2];
    let p95 = |v: &[u128]| v[v.len() * 95 / 100];
    println!(
        "ack delay {:?}: pre-call notify median {} us p95 {} us; outcome median {} us p95 {} us (n={n}, connections {})",
        ack_delay,
        med(&pre),
        p95(&pre),
        med(&post),
        p95(&post),
        CONNS.load(Ordering::Relaxed)
    );
    let _ = std::fs::remove_dir_all(&dir);
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
    let notes = test_capture::capture(|| {
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
    let notes = test_capture::capture(|| {
        let rc = unsafe {
            super::interposers::unlinkat(dfd.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
        };
        assert_eq!(rc, 0);
    });
    assert_eq!(notes.len(), 1, "{notes:#?}");
    assert_eq!(notes[0].syscall, "unlinkat");
    assert_eq!(notes[0].arg, dir.join("e").to_str().unwrap());
    assert_eq!(notes[0].pre_stat.map(|s| s.mode), Some(0o040750));
}

/// Review round 2, item 7: the split resend is for a frame too big to
/// send, not for a daemon that is down or slow.
#[test]
fn walk_resend_only_for_an_oversized_frame() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().canonicalize().unwrap();
    let d = dir.join("d");
    std::fs::create_dir(&d).unwrap();
    std::fs::write(d.join("a"), b"a").unwrap();
    test_capture::set_fail_with(Some(std::io::ErrorKind::ConnectionRefused));
    let notes = test_capture::capture(|| assert_eq!(rename_abs(&d, &dir.join("t")).0, 0));
    test_capture::set_fail_with(None);
    assert!(
        notes.iter().all(|n| n.syscall != "rename_walk"),
        "{notes:#?}"
    );
    let pre_calls = notes
        .iter()
        .filter(|n| n.syscall == "rename" && n.outcome.is_none())
        .count();
    assert_eq!(pre_calls, 1, "{notes:#?}");
}
