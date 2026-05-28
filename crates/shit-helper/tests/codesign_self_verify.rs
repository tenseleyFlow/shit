// SPDX-License-Identifier: AGPL-3.0-or-later
//
// M07.C.4 — integration test for `codesign --verify --strict
// --deep` against a deliberately-corrupted copy of the helper
// binary. Confirms that the verify call detects on-disk tamper
// and surfaces it via the SelfVerifyReport shape the daemon
// relies on to refuse the helper.

#![cfg(target_os = "macos")]

use shit_helper::codesign_verify;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

fn helper_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_shit-helper"))
}

/// Sanity check: the helper as cargo built it (ad-hoc signed by
/// the rustc/clang linker) should pass verify. If this fails
/// the test environment is broken before we even get to the
/// corruption case.
#[test]
fn verify_path_on_uncorrupted_helper_succeeds() {
    let bin = helper_bin();
    assert!(bin.exists(), "helper bin not built at {}", bin.display());
    let report = codesign_verify::verify_path(&bin);
    assert!(
        report.ok,
        "verify of uncorrupted helper failed unexpectedly: {:?}",
        report.reason
    );
}

/// The interesting case: corrupt one byte of the helper Mach-O
/// (in the middle of the file, well past the Mach-O header so
/// we definitely hit signed content), copy the result to a
/// temp path, then run verify_path on the corrupted copy.
/// codesign should detect the signature mismatch and we should
/// surface `ok=false` with a reason that mentions the failure.
#[test]
fn verify_path_on_corrupted_copy_returns_ok_false() {
    let bin = helper_bin();
    let original = std::fs::read(&bin).expect("read helper bin");
    assert!(
        original.len() > 4096,
        "helper bin too small to corrupt meaningfully ({} bytes)",
        original.len()
    );

    let tmp = tempfile::tempdir().expect("mktempdir");
    let corrupt = tmp.path().join("shit-helper-corrupt");
    std::fs::write(&corrupt, &original).expect("write corrupt copy");
    // Preserve exec bit so codesign's load doesn't bail on
    // perms before it gets to the signature check.
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&corrupt).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&corrupt, perm).unwrap();
    }

    // Flip one byte deep enough into the file to land in signed
    // content (not in the unsigned slack that codesign accepts).
    // The middle of the binary is reliably in __TEXT,__text on
    // any non-trivial Mach-O.
    let offset = original.len() / 2;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(&corrupt)
        .expect("open corrupt copy for write");
    f.seek(SeekFrom::Start(offset as u64)).expect("seek");
    let target_byte = [original[offset] ^ 0xFF];
    f.write_all(&target_byte).expect("write flipped byte");
    drop(f);

    let report = codesign_verify::verify_path(&corrupt);
    assert!(
        !report.ok,
        "expected verify to fail on corrupted binary; got ok=true (reason={:?})",
        report.reason
    );
    let reason = report
        .reason
        .as_deref()
        .expect("failed verify must surface a reason");
    // codesign's exact wording varies across OS versions
    // (`code object is not signed at all`, `invalid signature`,
    // `seal resource missing`, ...). We assert the response
    // mentions the codesign tool so the daemon's log includes
    // actionable context, without pinning to a specific phrase.
    assert!(
        reason.contains("codesign"),
        "reason should reference codesign for daemon-side log clarity; got: {reason:?}"
    );
}
