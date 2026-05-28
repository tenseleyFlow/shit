// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit dyld-hooks {install,uninstall,status}` (M07.A.4) —
//! installs the macOS DYLD_INSERT_LIBRARIES export that wires
//! the user's interactive shell to the shim dylib built by
//! `shit-preload-shim`.
//!
//! Same UX shape as `container-hooks`, `net-hooks`, etc., but
//! the delivery mechanism is a shell-rc snippet rather than a
//! `$PATH` wrapper. The snippet is marker-delimited so
//! `uninstall` is exact and `install` is idempotent (re-running
//! it replaces in place rather than appending duplicates).
//!
//! Resolution order for the dylib path baked into the snippet:
//!
//! 1. `$SHIT_PRELOAD_SHIM` env var (explicit user override).
//! 2. `/usr/local/lib/libshit_preload_shim.dylib` (Homebrew x86_64).
//! 3. `/opt/homebrew/lib/libshit_preload_shim.dylib` (Homebrew arm64).
//! 4. `target/release/libshit_preload_shim.dylib` (dev tree, release build).
//! 5. `target/debug/libshit_preload_shim.dylib` (dev tree, debug build).
//!
//! The runtime snippet itself has a `[ -f "<path>" ]` guard so
//! a stale install survives a `cargo clean` (it just becomes a
//! no-op rather than tripping on a missing dylib at every shell
//! start).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

const SNIPPET_BEGIN: &str = "# >>> shit dyld-hooks (begin) >>>";
const SNIPPET_END: &str = "# <<< shit dyld-hooks (end) <<<";

#[derive(Debug, Clone, Args)]
pub struct DyldHooksArgs {
    #[command(subcommand)]
    pub action: DyldHooksAction,

    /// Explicit shim dylib path. Overrides the auto-resolution
    /// chain. Useful for staged installs or non-standard layouts.
    #[arg(long, global = true)]
    pub shim_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum DyldHooksAction {
    /// Append a marker-delimited DYLD_INSERT_LIBRARIES export to
    /// the user's `~/.zshrc` and `~/.bashrc`. Idempotent.
    Install,
    /// Remove the marker-delimited section from the user's rc
    /// files. Leaves the rest of the file untouched.
    Uninstall,
    /// Print whether the snippet is currently installed in each
    /// rc file and which dylib path resolves now.
    Status,
}

pub fn run(args: DyldHooksArgs) -> Result<()> {
    match args.action {
        DyldHooksAction::Install => install(args.shim_path.as_deref()),
        DyldHooksAction::Uninstall => uninstall(),
        DyldHooksAction::Status => status(args.shim_path.as_deref()),
    }
}

fn install(explicit: Option<&Path>) -> Result<()> {
    let dylib =
        resolve_shim_path(explicit).context("could not locate libshit_preload_shim.dylib")?;
    let snippet = render_snippet(&dylib);

    let mut installed_any = false;
    for rc in target_rc_files() {
        upsert_snippet(&rc, &snippet)?;
        println!("  installed: {}", rc.display());
        installed_any = true;
    }
    if !installed_any {
        println!("no shell rc files found (~/.zshrc, ~/.bashrc)");
        return Ok(());
    }

    println!();
    println!("Dylib path baked in: {}", dylib.display());
    println!("Restart your shell (or `source` the rc file) for the export to take effect.");
    println!();
    println!(
        "Loud reminder: DYLD_INSERT_LIBRARIES is stripped from SIP-protected binaries by design."
    );
    println!("Apple platform binaries in /System and /usr/bin will NOT be shimmed. Use power-user");
    println!("mode (shit setup-es-mode) if you need that coverage.");
    Ok(())
}

fn uninstall() -> Result<()> {
    for rc in target_rc_files() {
        let removed = remove_snippet(&rc)?;
        if removed {
            println!("removed snippet from: {}", rc.display());
        }
    }
    Ok(())
}

fn status(explicit: Option<&Path>) -> Result<()> {
    println!("Shim dylib resolution:");
    match resolve_shim_path(explicit) {
        Some(p) => println!("  resolves to: {}", p.display()),
        None => println!("  NOT FOUND (set SHIT_PRELOAD_SHIM or install via packaging)"),
    }
    println!();
    println!("Shell-rc snippet state:");
    for rc in target_rc_files() {
        let present = rc.exists() && snippet_present(&rc)?;
        println!(
            "  {}: {}",
            rc.display(),
            if present {
                "installed"
            } else {
                "not installed"
            }
        );
    }
    Ok(())
}

fn target_rc_files() -> Vec<PathBuf> {
    let home = match std::env::var_os("HOME") {
        Some(h) => PathBuf::from(h),
        None => return Vec::new(),
    };
    vec![home.join(".zshrc"), home.join(".bashrc")]
}

fn resolve_shim_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.exists().then(|| p.to_path_buf());
    }
    if let Some(env) = std::env::var_os("SHIT_PRELOAD_SHIM") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    for candidate in [
        "/usr/local/lib/libshit_preload_shim.dylib",
        "/opt/homebrew/lib/libshit_preload_shim.dylib",
        "target/release/libshit_preload_shim.dylib",
        "target/debug/libshit_preload_shim.dylib",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn render_snippet(dylib: &Path) -> String {
    // Guard via `[ -f "<path>" ]` so a `cargo clean` (or any
    // path-changing uninstall) silently no-ops at shell start
    // rather than tripping a missing-file error. The
    // SHIT_DURING_UNDO guard prevents the shim re-entering on
    // undo-time syscalls.
    format!(
        "{begin}\n\
# Installed by `shit dyld-hooks install`. Undo via `shit dyld-hooks uninstall`.\n\
if [ -z \"${{SHIT_DURING_UNDO:-}}\" ] && [ -f \"{path}\" ]; then\n\
    export DYLD_INSERT_LIBRARIES=\"{path}${{DYLD_INSERT_LIBRARIES:+:$DYLD_INSERT_LIBRARIES}}\"\n\
fi\n\
{end}\n",
        begin = SNIPPET_BEGIN,
        end = SNIPPET_END,
        path = dylib.display(),
    )
}

fn upsert_snippet(rc: &Path, snippet: &str) -> Result<()> {
    let existing = if rc.exists() {
        std::fs::read_to_string(rc).with_context(|| format!("read {}", rc.display()))?
    } else {
        String::new()
    };
    let next = match find_marker_span(&existing) {
        Some((start, end)) => {
            // Replace the existing marker section in place.
            let mut s = String::with_capacity(existing.len() + snippet.len());
            s.push_str(&existing[..start]);
            s.push_str(snippet);
            s.push_str(&existing[end..]);
            s
        }
        None => {
            // Append, separating from prior content with a newline
            // if the file didn't end with one.
            let mut s = existing;
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(snippet);
            s
        }
    };
    std::fs::write(rc, next).with_context(|| format!("write {}", rc.display()))?;
    Ok(())
}

fn remove_snippet(rc: &Path) -> Result<bool> {
    if !rc.exists() {
        return Ok(false);
    }
    let existing = std::fs::read_to_string(rc).with_context(|| format!("read {}", rc.display()))?;
    let Some((start, end)) = find_marker_span(&existing) else {
        return Ok(false);
    };
    let mut next = String::with_capacity(existing.len());
    next.push_str(&existing[..start]);
    next.push_str(&existing[end..]);
    std::fs::write(rc, next).with_context(|| format!("write {}", rc.display()))?;
    Ok(true)
}

fn snippet_present(rc: &Path) -> Result<bool> {
    let content = std::fs::read_to_string(rc).with_context(|| format!("read {}", rc.display()))?;
    Ok(find_marker_span(&content).is_some())
}

/// Locate the `(begin..end_after_newline)` byte span of the
/// marker section in `content`. Returns `None` if either marker
/// is missing or out of order.
fn find_marker_span(content: &str) -> Option<(usize, usize)> {
    let start = content.find(SNIPPET_BEGIN)?;
    let end_marker = content[start..].find(SNIPPET_END)?;
    let abs_end_marker = start + end_marker + SNIPPET_END.len();
    // Include the trailing newline if present so removal doesn't
    // leave a blank line.
    let end = if content.as_bytes().get(abs_end_marker).copied() == Some(b'\n') {
        abs_end_marker + 1
    } else {
        abs_end_marker
    };
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_contains_both_markers_and_dylib_path() {
        let s = render_snippet(Path::new("/usr/local/lib/libshit_preload_shim.dylib"));
        assert!(s.contains(SNIPPET_BEGIN));
        assert!(s.contains(SNIPPET_END));
        assert!(s.contains("/usr/local/lib/libshit_preload_shim.dylib"));
        assert!(s.contains("DYLD_INSERT_LIBRARIES"));
        assert!(s.contains("SHIT_DURING_UNDO"));
    }

    #[test]
    fn snippet_uses_appendable_export_form() {
        // The `${DYLD_INSERT_LIBRARIES:+:$DYLD_INSERT_LIBRARIES}` shape
        // means we prepend our shim WITHOUT a stray trailing colon when
        // the user has no prior DYLD_INSERT_LIBRARIES, AND append-with-
        // colon when they do. Regression-gate the literal form.
        let s = render_snippet(Path::new("/x"));
        assert!(
            s.contains("${DYLD_INSERT_LIBRARIES:+:$DYLD_INSERT_LIBRARIES}"),
            "snippet must use the colon-conditional appendable form"
        );
    }

    #[test]
    fn find_marker_span_returns_none_when_unmarked() {
        assert!(find_marker_span("# just a normal rc file\nalias ll='ls -l'\n").is_none());
    }

    #[test]
    fn find_marker_span_includes_trailing_newline() {
        let content = format!("prefix\n{SNIPPET_BEGIN}\nbody\n{SNIPPET_END}\nsuffix\n");
        let (start, end) = find_marker_span(&content).expect("marker found");
        // Removing [start..end] should leave "prefix\nsuffix\n".
        let after: String = format!("{}{}", &content[..start], &content[end..]);
        assert_eq!(after, "prefix\nsuffix\n");
    }

    #[test]
    fn find_marker_span_returns_none_when_only_begin() {
        // Only begin marker without end is an incomplete state we don't
        // try to recover from automatically — install will append a
        // fresh block alongside, status will report absent. Keeps the
        // implementation small + the failure mode visible to the user.
        let content = format!("{SNIPPET_BEGIN}\n# truncated\n");
        assert!(find_marker_span(&content).is_none());
    }

    #[test]
    fn upsert_then_uninstall_round_trips_to_original() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        let original = "# user's existing config\nalias ll='ls -l'\n";
        std::fs::write(&rc, original).unwrap();

        let snippet = render_snippet(Path::new("/x/y/libshit_preload_shim.dylib"));
        upsert_snippet(&rc, &snippet).unwrap();

        let after_install = std::fs::read_to_string(&rc).unwrap();
        assert!(after_install.contains(SNIPPET_BEGIN));
        assert!(after_install.starts_with(original));

        let removed = remove_snippet(&rc).unwrap();
        assert!(removed);
        let after_uninstall = std::fs::read_to_string(&rc).unwrap();
        assert_eq!(
            after_uninstall, original,
            "uninstall must round-trip to the pre-install state byte-for-byte"
        );
    }

    #[test]
    fn install_is_idempotent_does_not_duplicate_snippet() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        std::fs::write(&rc, "existing\n").unwrap();

        let snippet = render_snippet(Path::new("/x"));
        upsert_snippet(&rc, &snippet).unwrap();
        upsert_snippet(&rc, &snippet).unwrap();

        let content = std::fs::read_to_string(&rc).unwrap();
        let begin_count = content.matches(SNIPPET_BEGIN).count();
        assert_eq!(begin_count, 1, "install must be idempotent");
    }

    #[test]
    fn install_replaces_in_place_on_path_change() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        std::fs::write(&rc, "existing\n").unwrap();

        let s1 = render_snippet(Path::new("/old/path/libshit_preload_shim.dylib"));
        upsert_snippet(&rc, &s1).unwrap();

        let s2 = render_snippet(Path::new("/new/path/libshit_preload_shim.dylib"));
        upsert_snippet(&rc, &s2).unwrap();

        let content = std::fs::read_to_string(&rc).unwrap();
        assert!(content.contains("/new/path/"));
        assert!(!content.contains("/old/path/"));
    }

    #[test]
    fn snippet_present_false_for_unmarked_file() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        std::fs::write(&rc, "just config\n").unwrap();
        assert!(!snippet_present(&rc).unwrap());
    }

    #[test]
    fn snippet_present_true_after_install() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = tmp.path().join(".zshrc");
        std::fs::write(&rc, "").unwrap();
        let s = render_snippet(Path::new("/x"));
        upsert_snippet(&rc, &s).unwrap();
        assert!(snippet_present(&rc).unwrap());
    }

    #[test]
    fn resolve_returns_none_when_nothing_found() {
        // Force-isolate from the dev tree by passing an explicit
        // bad path. SHIT_PRELOAD_SHIM env is checked only when
        // explicit is None.
        let bogus = PathBuf::from("/definitely/does/not/exist/libshit_preload_shim.dylib");
        assert!(resolve_shim_path(Some(&bogus)).is_none());
    }

    #[test]
    fn resolve_honors_explicit_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let stub = tmp.path().join("libshit_preload_shim.dylib");
        std::fs::write(&stub, b"stub").unwrap();
        let resolved = resolve_shim_path(Some(&stub));
        assert_eq!(resolved.as_deref(), Some(stub.as_path()));
    }
}
