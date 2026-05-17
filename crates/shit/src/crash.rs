// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash log writer for the `shit` CLI. Same format as the daemon
//! and helper (owned by [`shit_proto::crash`]); written under
//! `$XDG_STATE_HOME/shit/crashes/` so all three components co-locate.
//!
//! Why install in a short-lived CLI: subcommands that drive file ops
//! (undo, redo) can panic deep inside the planner or executor and
//! the user benefits from a one-file artifact instead of scrolling
//! their terminal. The hook is best-effort — if state_dir isn't
//! writable, the install silently no-ops (the CLI may be invoked in
//! sandboxed contexts where it shouldn't write).

use std::backtrace::Backtrace;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use shit_proto::crash::{CrashFacts, CrashPanic, TracingRing, crash_filename, format_crash_record};

const RING_CAPACITY: usize = 100;

static CRASH_DIR: OnceLock<PathBuf> = OnceLock::new();
static RING: OnceLock<Arc<TracingRing>> = OnceLock::new();

const CLI_FACTS: CrashFacts = CrashFacts {
    component: "shit",
    version: env!("CARGO_PKG_VERSION"),
    commit: env!("VERGEN_GIT_SHA"),
    built: env!("VERGEN_BUILD_TIMESTAMP"),
    rustc: env!("VERGEN_RUSTC_SEMVER"),
    target: env!("VERGEN_CARGO_TARGET_TRIPLE"),
};

/// Resolve `$XDG_STATE_HOME/shit` the same way shitd does, falling
/// back to `$HOME/.local/state/shit`. Returns `None` if `$HOME`
/// can't be resolved either — in that case the CLI runs without a
/// crash log (the panic still prints to stderr; no functional loss).
fn default_state_dir() -> Option<PathBuf> {
    if let Some(s) = std::env::var_os("XDG_STATE_HOME") {
        return Some(PathBuf::from(s).join("shit"));
    }
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("shit"),
    )
}

/// Install the panic hook. Looks up state_dir via the same XDG
/// convention shitd uses; silently no-ops on unresolvable paths.
pub fn install_panic_hook() {
    let Some(state_dir) = default_state_dir() else {
        return;
    };
    install_panic_hook_at(&state_dir);
}

fn install_panic_hook_at(state_dir: &Path) {
    let dir = state_dir.join("crashes");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let _ = CRASH_DIR.set(dir);
    let _ = RING.set(Arc::new(TracingRing::new(RING_CAPACITY)));
    static INSTALLED: OnceLock<()> = OnceLock::new();
    if INSTALLED.set(()).is_err() {
        return;
    }
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        write_record(info);
        prev(info);
    }));
}

#[allow(dead_code)]
pub fn ring() -> Option<Arc<TracingRing>> {
    RING.get().cloned()
}

fn write_record(info: &std::panic::PanicHookInfo<'_>) {
    let Some(dir) = CRASH_DIR.get() else {
        return;
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pid = std::process::id();
    let path = dir.join(crash_filename(CLI_FACTS.component, ts, pid));

    let panic = panic_from_info(info);
    let events = RING.get().map(|r| r.snapshot()).unwrap_or_default();
    let payload = format_crash_record(&CLI_FACTS, &panic, pid, ts, &events);
    let _ = std::fs::write(&path, payload);
}

fn panic_from_info(info: &std::panic::PanicHookInfo<'_>) -> CrashPanic {
    let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    };
    let location = info
        .location()
        .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
        .unwrap_or_default();
    let backtrace = Backtrace::force_capture().to_string();
    CrashPanic {
        message,
        location,
        backtrace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_panic_hook_at_creates_crashes_dir() {
        let tmp = tempfile::tempdir().unwrap();
        install_panic_hook_at(tmp.path());
        assert!(tmp.path().join("crashes").is_dir());
    }

    #[test]
    fn install_panic_hook_at_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        install_panic_hook_at(tmp.path());
        install_panic_hook_at(tmp.path());
    }

    #[test]
    fn install_panic_hook_silently_skips_unwritable_state_dir() {
        // Pointing at /proc/1 (read-only, owned by root) — create_dir_all
        // fails, and the install must no-op without panicking.
        install_panic_hook_at(Path::new("/proc/1/this-cannot-exist"));
        // No assertion; just verify no panic.
    }
}
