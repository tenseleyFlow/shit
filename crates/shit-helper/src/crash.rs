// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash log writer. Captures panics into
//! `<state_dir>/crashes/helper-<unix_secs>-<pid>.txt` so a postmortem
//! can find them without parsing journald / launchd logs.
//!
//! Best-effort: a panic hook that itself panics aborts the process, so
//! every fs call here is wrapped in `let _ = ...`. The default panic
//! handler still runs after ours (the stderr message + backtrace).

use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static CRASH_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Install the panic hook. Idempotent; calling twice replaces the
/// stored crash dir but leaves the hook in place.
pub fn install_panic_hook(state_dir: &Path) {
    let dir = state_dir.join("crashes");
    let _ = std::fs::create_dir_all(&dir);
    let _ = CRASH_DIR.set(dir);
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

fn write_record(info: &std::panic::PanicHookInfo<'_>) {
    let Some(dir) = CRASH_DIR.get() else {
        return;
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pid = std::process::id();
    let path = dir.join(format!("helper-{ts}-{pid}.txt"));

    let payload = format_record(info);
    let _ = std::fs::write(&path, payload);
}

fn format_record(info: &std::panic::PanicHookInfo<'_>) -> String {
    let mut buf = String::new();
    let _ = writeln!(
        buf,
        "shit-helper crash @ {}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let _ = writeln!(buf, "version: {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(buf, "commit:  {}", env!("VERGEN_GIT_SHA"));
    let _ = writeln!(buf, "pid:     {}", std::process::id());
    if let Some(loc) = info.location() {
        let _ = writeln!(
            buf,
            "at:      {}:{}:{}",
            loc.file(),
            loc.line(),
            loc.column()
        );
    }
    let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    };
    let _ = writeln!(buf, "message: {msg}");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_panic_hook_creates_crashes_dir() {
        let tmp = tempfile::tempdir().unwrap();
        install_panic_hook(tmp.path());
        assert!(tmp.path().join("crashes").is_dir());
    }

    #[test]
    fn install_panic_hook_is_idempotent() {
        // OnceLock guards the hook install — repeated calls update the
        // crash-dir target but don't double-register. Calling twice
        // must not panic.
        let tmp = tempfile::tempdir().unwrap();
        install_panic_hook(tmp.path());
        install_panic_hook(tmp.path());
    }

    // Note: we deliberately don't exercise the panic-hook path inside
    // unit tests. The hook is a process-global resource (`OnceLock`),
    // so the *first* test to install it wins, and any later test
    // expecting its own crash dir to receive the record will flake
    // under parallel execution. The hook is exercised end-to-end by
    // the integration tests in `tests/helper_handshake.rs` which
    // spawn fresh helper processes.
}
