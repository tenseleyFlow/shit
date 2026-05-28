// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS code-signature self-verification (M07.C.1).
//!
//! At helper startup, before accepting the daemon handshake, we
//! run `codesign --verify --strict --deep` on our own binary and
//! extract Team ID + signature kind via `codesign -d --verbose=4`.
//! The result rides on the handshake ack as a
//! [`SelfVerifyReport`].
//!
//! Why this exists: the helper is the privileged surface. An
//! attacker who has swapped the binary on disk between install
//! and exec can't impersonate Apple's signature, so a startup-
//! time codesign check catches the "binary tampered after
//! install" case. macOS already enforces signature at exec via
//! AMFI when the binary has hardened-runtime; this is a second
//! layer that surfaces the failure to the daemon (and via
//! `shit doctor` to the user) rather than silently exec-failing.
//!
//! The check is fast (~200 ms on Apple Silicon) and only runs
//! at startup, not per-event.
//!
//! Failure mode: when the verify fails, the helper proceeds
//! with `ok=false` in the handshake. The daemon side
//! (`shitd::helper_link`) refuses the helper and logs at ERROR.
//! On non-hardened-runtime dev builds (`flags=0x0`) the verify
//! passes with `signature_kind=AdHoc`.

use std::path::PathBuf;
use std::process::Command;

use shit_proto::{SelfVerifyReport, SignatureKind};

/// Entry point. Resolves self-exe path, runs `codesign
/// --verify`, then `codesign -d --verbose=4` for metadata.
/// Returns a populated [`SelfVerifyReport`] on success; on
/// failure returns a report with `ok=false` + a `reason`
/// string the daemon can log + surface to the user.
pub fn verify_self() -> SelfVerifyReport {
    let exe = match self_exe_path() {
        Some(p) => p,
        None => {
            return SelfVerifyReport {
                ok: false,
                reason: Some("self-exe path lookup failed (_NSGetExecutablePath)".into()),
                team_id: None,
                signature_kind: SignatureKind::Unsigned,
            };
        }
    };
    verify_path(&exe)
}

/// Verify an arbitrary path via the same codesign call chain
/// [`verify_self`] uses. Exposed for integration tests that
/// corrupt a copy of the binary on disk and want to assert the
/// failure shape end-to-end; not called from production code.
pub fn verify_path(exe: &std::path::Path) -> SelfVerifyReport {
    match run_verify(exe) {
        Ok(()) => {}
        Err(e) => {
            return SelfVerifyReport {
                ok: false,
                reason: Some(e),
                team_id: None,
                signature_kind: SignatureKind::Unsigned,
            };
        }
    }

    let meta = run_display(exe).unwrap_or_else(CodesignMeta::unsigned_fallback);
    SelfVerifyReport {
        ok: true,
        reason: None,
        team_id: meta.team_id,
        signature_kind: meta.signature_kind,
    }
}

/// Resolve the current executable path via Apple's
/// `_NSGetExecutablePath`. Returns `None` on failure (shouldn't
/// happen for a well-formed Mach-O process).
fn self_exe_path() -> Option<PathBuf> {
    // Try std first — `std::env::current_exe()` on macOS
    // calls `_NSGetExecutablePath` under the hood and resolves
    // symlinks. Good enough; the path we hand to `codesign`
    // doesn't need to be the literal argv[0].
    std::env::current_exe().ok()
}

fn run_verify(exe: &std::path::Path) -> Result<(), String> {
    let output = Command::new("codesign")
        .args(["--verify", "--strict", "--deep", "-v"])
        .arg(exe)
        .output()
        .map_err(|e| format!("spawn codesign --verify: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_err_line = stderr
        .lines()
        .chain(stdout.lines())
        .find(|l| !l.trim().is_empty())
        .unwrap_or("codesign --verify failed with no output")
        .to_string();
    Err(format!(
        "codesign --verify: {} (rc={})",
        first_err_line,
        output.status.code().unwrap_or(-1)
    ))
}

struct CodesignMeta {
    team_id: Option<String>,
    signature_kind: SignatureKind,
}

impl CodesignMeta {
    fn unsigned_fallback() -> Self {
        Self {
            team_id: None,
            signature_kind: SignatureKind::AdHoc,
        }
    }
}

fn run_display(exe: &std::path::Path) -> Option<CodesignMeta> {
    let output = Command::new("codesign")
        .args(["-d", "--verbose=4"])
        .arg(exe)
        .output()
        .ok()?;
    // codesign writes metadata to stderr (success exit code).
    let text = String::from_utf8_lossy(&output.stderr).into_owned();
    Some(parse_display(&text))
}

/// Parse the output of `codesign -d --verbose=4`. Looks for
/// `TeamIdentifier=...`, `flags=0x?(adhoc)`, and the
/// `Authority=...` chain to discriminate signature kinds.
fn parse_display(text: &str) -> CodesignMeta {
    let mut team_id: Option<String> = None;
    let mut is_adhoc = false;
    let mut authority_developer_id = false;
    let mut authority_apple = false;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("TeamIdentifier=") {
            // codesign emits `TeamIdentifier=not set` for ad-hoc.
            if rest != "not set" && !rest.is_empty() {
                team_id = Some(rest.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("flags=") {
            // e.g. `flags=0x2(adhoc)` or `flags=0x10000(runtime)`.
            if rest.contains("adhoc") {
                is_adhoc = true;
            }
        } else if let Some(rest) = line.strip_prefix("Authority=") {
            let auth = rest.trim();
            if auth.starts_with("Developer ID Application:") {
                authority_developer_id = true;
            } else if auth.starts_with("Apple ") || auth == "Apple Root CA" {
                authority_apple = true;
            }
        }
    }
    let signature_kind = if authority_developer_id {
        SignatureKind::DeveloperIdApplication
    } else if is_adhoc {
        SignatureKind::AdHoc
    } else if authority_apple {
        // Apple-internal cert — unusual for third-party tools but
        // we name it explicitly rather than lumping into Unknown.
        SignatureKind::UnknownAuthority
    } else if team_id.is_some() {
        // Has a team ID but no recognized authority chain — odd
        // shape, flag for the daemon.
        SignatureKind::UnknownAuthority
    } else {
        SignatureKind::AdHoc
    };
    CodesignMeta {
        team_id,
        signature_kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_adhoc_yields_adhoc_kind() {
        let text = "\
Executable=/usr/local/bin/shit-helper
Identifier=shit-helper
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=2045 flags=0x2(adhoc,linker-signed) hashes=61+0 location=embedded
TeamIdentifier=not set
";
        let m = parse_display(text);
        assert!(m.team_id.is_none());
        assert_eq!(m.signature_kind, SignatureKind::AdHoc);
    }

    #[test]
    fn parse_developer_id_yields_developer_id() {
        let text = "\
Executable=/usr/local/bin/shit-helper
Identifier=com.tenseleyflow.shit-helper
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=4096 flags=0x10000(runtime) hashes=120+2 location=embedded
TeamIdentifier=Q6JHJ53S9C
Authority=Developer ID Application: TenseleyFlow LLC (Q6JHJ53S9C)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
";
        let m = parse_display(text);
        assert_eq!(m.team_id.as_deref(), Some("Q6JHJ53S9C"));
        assert_eq!(m.signature_kind, SignatureKind::DeveloperIdApplication);
    }

    #[test]
    fn parse_empty_yields_adhoc_fallback() {
        // Empty input shouldn't panic; treat as ad-hoc fallback
        // (the verify call would have failed first if the binary
        // really were unsigned, so reaching here implies SOME
        // signature exists).
        let m = parse_display("");
        assert!(m.team_id.is_none());
        assert_eq!(m.signature_kind, SignatureKind::AdHoc);
    }

    #[test]
    fn parse_apple_internal_authority_yields_unknown_authority() {
        // Apple-internal signatures (Apple Operating System,
        // Software Update, etc.) shouldn't ever appear on our
        // helper but if they did we'd want to surface it.
        let text = "\
Executable=/usr/bin/something
Identifier=com.apple.something
TeamIdentifier=not set
Authority=Apple iPhone OS Application Signing
Authority=Apple Root CA
";
        let m = parse_display(text);
        assert_eq!(m.signature_kind, SignatureKind::UnknownAuthority);
    }

    #[test]
    fn run_display_returns_meta_for_real_codesign_binary() {
        // codesign itself is signed on macOS. This is an end-to-end
        // sanity check that run_display can parse a real codesign
        // output without panic. We don't assert specifics because
        // the codesign authority chain can change across OS revs.
        let codesign = std::path::Path::new("/usr/bin/codesign");
        if !codesign.exists() {
            return; // not a macOS host
        }
        let _ = run_display(codesign);
    }

    #[test]
    fn verify_self_returns_a_populated_report() {
        // We don't assert ok=true because the test binary may be
        // entirely unsigned (debug build, no ad-hoc step). We
        // assert the report is well-formed — `ok` is set, and on
        // failure `reason` is populated.
        let report = verify_self();
        if report.ok {
            // Successful — kind is meaningful, no reason needed.
            assert!(report.reason.is_none());
        } else {
            // Failed — reason must be populated for the daemon to
            // log something useful.
            assert!(
                report.reason.is_some(),
                "failed verify must surface a reason"
            );
        }
    }
}
