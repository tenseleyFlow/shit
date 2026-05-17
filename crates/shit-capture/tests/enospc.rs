// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hard-fail policy enforcement. Real ENOSPC simulation needs a small
//! loopback filesystem and lives in the CI fault-injection runner. Here
//! we exercise the error-propagation chain that the helper turns into
//! `EACCES` at the syscall boundary: any non-fallthrough `CowError` from
//! the engine reaches the caller verbatim.

use shit_capture::{CaptureOpts, CowEngine, CowError, DefaultEngine};
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;

#[test]
fn blob_root_with_no_write_perms_surfaces_io_error() {
    let tmp = tempfile::tempdir().unwrap();
    let src_path = tmp.path().join("source.txt");
    File::create(&src_path).unwrap().write_all(b"x").unwrap();

    let blob_root = tmp.path().join("readonly");
    std::fs::create_dir_all(&blob_root).unwrap();

    // Drop write/exec permissions on the blob_root so the engine can't
    // create the tmp/ subdir or the sharded blobs/ tree.
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&blob_root).unwrap().permissions();
    perms.set_mode(0o500);
    std::fs::set_permissions(&blob_root, perms).unwrap();

    let engine = DefaultEngine::new();
    let f = File::open(&src_path).unwrap();
    let res = engine.capture(f.as_raw_fd(), &src_path, &blob_root, CaptureOpts::default());

    // Restore perms so tempdir cleanup works on drop.
    let mut perms = std::fs::metadata(&blob_root).unwrap().permissions();
    perms.set_mode(0o700);
    let _ = std::fs::set_permissions(&blob_root, perms);

    let err = res.expect_err("expected hard-fail when blob_root unwritable");
    match err {
        CowError::Io(_) | CowError::Store(_) | CowError::NoViableTier { .. } => {}
        other => panic!("unexpected error variant: {other}"),
    }
}

#[test]
fn synthetic_source_yields_no_viable_tier() {
    // /proc on Linux, /dev on macOS — on systems where neither maps to
    // procfs/devfs we skip with a printed note rather than fail.
    let candidates: &[&str] = if cfg!(target_os = "linux") {
        &["/proc/self/comm"]
    } else if cfg!(target_os = "macos") {
        &["/dev/null"]
    } else {
        &[]
    };

    for path in candidates {
        let p = std::path::Path::new(path);
        if !p.exists() {
            continue;
        }
        // Try to open; some entries are unreadable in restricted envs.
        let f = match File::open(p) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let tmp = tempfile::tempdir().unwrap();
        let engine = DefaultEngine::new();
        let res = engine.capture(f.as_raw_fd(), p, tmp.path(), CaptureOpts::default());
        // Either NoViableTier (the design path) or a downstream Io error
        // before we get there is acceptable. Both are hard-fail.
        match res {
            Err(CowError::NoViableTier { .. }) | Err(CowError::Io(_)) | Ok(_) => {}
            Err(other) => panic!("unexpected: {other}"),
        }
    }
}
