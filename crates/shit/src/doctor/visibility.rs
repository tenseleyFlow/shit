// SPDX-License-Identifier: AGPL-3.0-or-later

//! AU12 — scan a watched path for binaries whose mutations bypass the
//! LD_PRELOAD / DYLD_INSERT_LIBRARIES shim, so doctor can warn the
//! user about lost coverage.
//!
//! ## Scope (tight)
//!
//! Today this module detects **setuid** binaries via `stat(2)` — the
//! cheap, high-value 80% of the bypass problem. setuid binaries
//! strip `LD_PRELOAD` (and `DYLD_INSERT_LIBRARIES`) on `execve(2)`
//! per `rtld(1)` / `dyld(1)` documented behavior; their mutations
//! are then captured post-hoc only via the kernel tier (LSM on
//! Linux, ZFS-clone on FreeBSD where ZFS is set up; nothing on
//! macOS without EndpointSecurity).
//!
//! ## Out of scope (AU12.A followup)
//!
//! Statically-linked binaries also bypass the shim but detecting
//! them needs ELF / Mach-O header parsing (no `PT_INTERP` segment
//! on ELF, no `LC_LOAD_DYLINKER` on Mach-O). That's a `goblin` lift
//! and lives in the followup.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Hard cap on files visited per `scan_path` call. Beyond this the
/// scan returns what it has + sets `truncated=true`; the user gets
/// "at least N" rather than an exhaustive list. Doctor is a fast
/// path, not a forensic tool.
const SCAN_FILE_CAP: usize = 500;

/// Max directory-recursion depth. Doctor scans the user's cwd plus
/// one level (e.g. `./bin/`, `./target/`); deeper recursion turns
/// the doctor into a `find(1)` substitute and burns time on each
/// invocation.
const SCAN_MAX_DEPTH: usize = 2;

/// JSON-serializable visibility report. Populated by
/// `shit doctor --visibility <path>`; `None` on the default
/// doctor invocation so the envelope stays small.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityReport {
    /// Root of the scan (the path the user passed).
    pub watched_path: PathBuf,
    /// Total executable-bit files visited. Bounded by
    /// `SCAN_FILE_CAP`.
    pub executables_scanned: u32,
    /// Count of setuid binaries found. The user-facing signal that
    /// "at least one of your binaries here is shim-invisible."
    pub setuid_bypassing_shim: u32,
    /// First N bypass entries for the user to inspect (cap small
    /// to keep JSON tight). Sorted by path.
    #[serde(default)]
    pub details: Vec<BypassEntry>,
    /// True iff the scan hit `SCAN_FILE_CAP` and stopped early.
    /// JSON consumers should treat `setuid_bypassing_shim` as a
    /// lower bound in that case.
    pub truncated: bool,
}

/// One bypass binary's path + classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassEntry {
    pub path: PathBuf,
    pub kind: BypassKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BypassKind {
    /// `mode & S_ISUID != 0`.
    Setuid,
    // Static — reserved for AU12.A.
}

/// True iff `path` has the setuid bit set. Returns `false` for
/// missing / unreadable / non-file paths; the doctor never fails
/// hard on a permission denied during the walk.
///
/// `scan_path` doesn't call this — it works off the metadata it
/// already has from the directory walk so it doesn't re-stat. This
/// is part of the public API for callers (and AU12.A) that have a
/// single path in hand and don't need a tree walk.
#[allow(dead_code)]
pub fn is_setuid(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(md) if md.is_file() => (md.mode() & 0o4000) != 0,
        _ => false,
    }
}

/// Walk `root` up to `SCAN_MAX_DEPTH` levels deep, collecting setuid
/// executables. Honors `SCAN_FILE_CAP`. Symlinks are followed via
/// `std::fs::metadata` (vs. `symlink_metadata`) since the visibility
/// question is about the file the user-facing binary actually
/// resolves to.
///
/// Returns Ok even when the root is missing — the report just shows
/// zero scanned files. The CLI's `--visibility` handler is responsible
/// for bailing on user-facing "no such path" before calling this.
pub fn scan_path(root: &Path) -> std::io::Result<VisibilityReport> {
    let mut report = VisibilityReport {
        watched_path: root.to_path_buf(),
        executables_scanned: 0,
        setuid_bypassing_shim: 0,
        details: Vec::new(),
        truncated: false,
    };
    if !root.exists() {
        return Ok(report);
    }
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            // Unreadable dir — skip silently. The user pointed doctor
            // at the parent; us bailing on a single inaccessible
            // subdir would be more confusing than the empty result.
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            if report.executables_scanned as usize >= SCAN_FILE_CAP {
                report.truncated = true;
                stack.clear();
                break;
            }
            let path = entry.path();
            let md = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if md.is_dir() {
                if depth < SCAN_MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !md.is_file() {
                continue;
            }
            use std::os::unix::fs::MetadataExt;
            let mode = md.mode();
            // Only count files that are executable by *someone*. A
            // setuid-bit on a non-executable file is meaningless
            // (kernel only honors the bit on exec(2)).
            if mode & 0o111 == 0 {
                continue;
            }
            report.executables_scanned += 1;
            if mode & 0o4000 != 0 {
                report.setuid_bypassing_shim += 1;
                report.details.push(BypassEntry {
                    path,
                    kind: BypassKind::Setuid,
                });
            }
        }
    }
    report.details.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn touch(path: &Path, mode: u32) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn is_setuid_detects_bit() {
        let tmp = tempfile::tempdir().unwrap();
        let suid = tmp.path().join("sudo-fake");
        let plain = tmp.path().join("ls-fake");
        touch(&suid, 0o4755);
        touch(&plain, 0o755);
        assert!(is_setuid(&suid));
        assert!(!is_setuid(&plain));
    }

    #[test]
    fn is_setuid_false_for_nonfile() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        // Even though directories can have the sticky/setuid bits
        // set on some unices, the bypass question doesn't apply —
        // exec(2) doesn't fire on a directory.
        let mut perm = std::fs::metadata(&dir).unwrap().permissions();
        perm.set_mode(0o4755);
        std::fs::set_permissions(&dir, perm).unwrap();
        assert!(!is_setuid(&dir));
        assert!(!is_setuid(&tmp.path().join("missing")));
    }

    #[test]
    fn scan_finds_one_setuid() {
        let tmp = tempfile::tempdir().unwrap();
        touch(&tmp.path().join("a"), 0o755);
        touch(&tmp.path().join("b-setuid"), 0o4755);
        touch(&tmp.path().join("c"), 0o644); // not executable — skipped
        let r = scan_path(tmp.path()).unwrap();
        assert_eq!(r.executables_scanned, 2);
        assert_eq!(r.setuid_bypassing_shim, 1);
        assert_eq!(r.details.len(), 1);
        assert_eq!(r.details[0].kind, BypassKind::Setuid);
        assert!(r.details[0].path.ends_with("b-setuid"));
        assert!(!r.truncated);
    }

    #[test]
    fn scan_honors_max_depth() {
        let tmp = tempfile::tempdir().unwrap();
        // depth 0 (root)
        touch(&tmp.path().join("root-bin"), 0o4755);
        let d1 = tmp.path().join("sub");
        std::fs::create_dir(&d1).unwrap();
        // depth 1
        touch(&d1.join("sub-bin"), 0o4755);
        let d2 = d1.join("sub2");
        std::fs::create_dir(&d2).unwrap();
        // depth 2
        touch(&d2.join("d2-bin"), 0o4755);
        let d3 = d2.join("sub3");
        std::fs::create_dir(&d3).unwrap();
        // depth 3 — should NOT be visited
        touch(&d3.join("d3-bin"), 0o4755);
        let r = scan_path(tmp.path()).unwrap();
        // Three setuid files at depths 0, 1, 2; the depth-3 one is
        // skipped because the walker bumps depth before pushing the
        // dir and refuses to push at SCAN_MAX_DEPTH.
        assert_eq!(r.setuid_bypassing_shim, 3);
    }

    #[test]
    fn scan_handles_missing_root() {
        let r = scan_path(Path::new("/nonexistent-au12-au12")).unwrap();
        assert_eq!(r.executables_scanned, 0);
        assert_eq!(r.setuid_bypassing_shim, 0);
    }

    #[test]
    fn scan_skips_nonexecutable_setuid() {
        // S_ISUID on a non-executable file is meaningless — exec(2)
        // never reads it. Don't pollute the count.
        let tmp = tempfile::tempdir().unwrap();
        touch(&tmp.path().join("weird"), 0o4644);
        let r = scan_path(tmp.path()).unwrap();
        assert_eq!(r.executables_scanned, 0);
        assert_eq!(r.setuid_bypassing_shim, 0);
    }
}
