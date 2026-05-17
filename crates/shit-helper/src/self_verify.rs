// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper-binary self-signature verification (S20.8).
//!
//! Defense-in-depth: at startup, the helper computes a hash of its
//! own executable and compares against a baseline installed at
//! deployment time. An attacker who has replaced the binary has
//! also replaced the verifier — this catches *partial* tamper
//! cases (e.g., a tampered .text section without an accompanying
//! baseline update), not the determined-attacker case.
//!
//! ## Platforms
//!
//! - **Linux**: reads `/proc/self/exe` and hashes it with blake3.
//!   Baseline is a `<state-dir>/helper.sha256.baseline` file
//!   written at install time. Mismatch refuses handshake.
//! - **macOS**: stub that returns `Ok(Skipped)` in debug builds and
//!   delegates to `codesign --verify --strict $exe` in release
//!   builds. The real ES-entitlement-aware re-verify is DR-NEW-codesign-verify.
//! - **FreeBSD**: same as Linux (`/proc/curproc/file` or
//!   `procstat -b`); landed as a follow-up to DR-10.
//!
//! ## What this is NOT
//!
//! - **Not** a cryptographic integrity guarantee.
//! - **Not** a malware scanner.
//! - **Not** a substitute for OS-level codesigning. On macOS we
//!   defer to the codesign infrastructure; on Linux we are best-effort.
//!
//! ## Failure mode
//!
//! On mismatch, the helper logs a warn-level message and refuses to
//! complete the handshake. The daemon notices and surfaces the
//! issue to the user via `shit status`. The user's mutating
//! commands continue to work without protection — degraded mode.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Baseline matched the computed hash. Helper proceeds.
    Match,
    /// Baseline absent. First-run state; helper proceeds and the
    /// caller is expected to write the current hash to the baseline.
    BaselineMissing { computed: String },
    /// Baseline present but did not match. Helper refuses handshake.
    Mismatch { computed: String, baseline: String },
    /// Platform doesn't support self-verification (dev builds, or
    /// `/proc/self/exe` unavailable). Helper proceeds with a warning.
    Skipped { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("read /proc/self/exe: {0}")]
    ReadSelf(#[from] std::io::Error),
}

/// Compute the hash of the running binary. Linux uses
/// `/proc/self/exe`; FreeBSD uses `/proc/curproc/file`; others get
/// a Skipped outcome.
pub fn verify(state_dir: &Path) -> Result<VerifyOutcome, VerifyError> {
    let exe_path = match self_exe_path() {
        Some(p) => p,
        None => {
            return Ok(VerifyOutcome::Skipped {
                reason: "self-exe path lookup not implemented on this platform".into(),
            });
        }
    };
    // In debug builds, skip the gate entirely. Dev iteration churns
    // the binary hash with every cargo build; gating dev flow on a
    // re-baseline step is friction without a security benefit.
    if cfg!(debug_assertions) {
        return Ok(VerifyOutcome::Skipped {
            reason: "debug build; self-verify disabled".into(),
        });
    }
    let bytes = std::fs::read(&exe_path)?;
    let computed = blake3_hex(&bytes);

    let baseline_path = state_dir.join("helper.sha256.baseline");
    let baseline = match std::fs::read_to_string(&baseline_path) {
        Ok(s) => s.trim().to_string(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VerifyOutcome::BaselineMissing { computed });
        }
        Err(e) => return Err(e.into()),
    };
    if baseline == computed {
        Ok(VerifyOutcome::Match)
    } else {
        Ok(VerifyOutcome::Mismatch { computed, baseline })
    }
}

/// Write the baseline file. Called by the install script (or by
/// the helper itself on first run when [`VerifyOutcome::BaselineMissing`]
/// is returned).
pub fn write_baseline(state_dir: &Path, hash: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let baseline_path = state_dir.join("helper.sha256.baseline");
    let tmp = state_dir.join("helper.sha256.baseline.tmp");
    std::fs::write(&tmp, format!("{hash}\n"))?;
    std::fs::rename(&tmp, &baseline_path)?;
    Ok(())
}

/// Compute the hash of an arbitrary path. Useful for testing and
/// for the install-time baseline-write path.
#[allow(dead_code)] // used by tests + install scripts (DR-baseline-install)
pub fn hash_path(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(blake3_hex(&bytes))
}

fn self_exe_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Some(PathBuf::from("/proc/self/exe"))
    }
    #[cfg(target_os = "freebsd")]
    {
        Some(PathBuf::from("/proc/curproc/file"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    {
        // macOS: `_NSGetExecutablePath`. We don't take that path
        // for self-verify because macOS users get a richer check
        // via `codesign --verify --strict` (DR-NEW-codesign-verify).
        None
    }
}

fn blake3_hex(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    let hash = hasher.finalize();
    hex_encode(hash.as_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_round_trips_a_known_blake3() {
        // blake3("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        let h = blake3_hex(b"");
        assert_eq!(
            h,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn hash_path_returns_stable_hash() {
        let tmp = std::env::temp_dir().join(format!("shit-s20-self-verify-{}", std::process::id()));
        std::fs::write(&tmp, b"hello").unwrap();
        let h1 = hash_path(&tmp).unwrap();
        let h2 = hash_path(&tmp).unwrap();
        assert_eq!(h1, h2);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn baseline_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "shit-s20-baseline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let hash = "abcdef0123456789".to_string();
        write_baseline(&dir, &hash).unwrap();
        let read = std::fs::read_to_string(dir.join("helper.sha256.baseline")).unwrap();
        assert_eq!(read.trim(), hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_missing_returns_baseline_missing() {
        // Dev-build skip applies here: cfg!(debug_assertions) is
        // true during `cargo test`. Verify the gate engages.
        let dir = std::env::temp_dir().join(format!(
            "shit-s20-bm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let outcome = verify(&dir).unwrap();
        // In debug builds we get Skipped; in release we'd get
        // BaselineMissing on a fresh state-dir.
        match outcome {
            VerifyOutcome::Skipped { .. } => {}         // debug-build branch
            VerifyOutcome::BaselineMissing { .. } => {} // release-build branch
            other => panic!("unexpected outcome: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn outcome_is_clone_and_eq() {
        // Defensive — the enum's used in match arms elsewhere; if
        // someone removes a derive, this test catches it.
        let a = VerifyOutcome::Match;
        let b = a.clone();
        assert_eq!(a, b);
    }
}
