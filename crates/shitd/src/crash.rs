// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash log writer for `shitd`. Same format as
//! [`crate::log_setup`]-driven runtime logs, but written at panic
//! time so the user has a stable artifact even if the structured
//! log layer was torn down before the panic completed.
//!
//! Format owned by [`shit_proto::crash`]; this module owns the
//! install + ring-buffer wiring.

use std::backtrace::Backtrace;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use shit_proto::crash::{CrashFacts, CrashPanic, TracingRing, crash_filename, format_crash_record};

const RING_CAPACITY: usize = 100;

static CRASH_DIR: OnceLock<PathBuf> = OnceLock::new();
static RING: OnceLock<Arc<TracingRing>> = OnceLock::new();

const DAEMON_FACTS: CrashFacts = CrashFacts {
    component: "shitd",
    version: env!("CARGO_PKG_VERSION"),
    commit: env!("VERGEN_GIT_SHA"),
    built: env!("VERGEN_BUILD_TIMESTAMP"),
    rustc: env!("VERGEN_RUSTC_SEMVER"),
    target: env!("VERGEN_CARGO_TARGET_TRIPLE"),
};

pub fn install_panic_hook(state_dir: &Path) {
    let dir = state_dir.join("crashes");
    let _ = std::fs::create_dir_all(&dir);
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
    let path = dir.join(crash_filename(DAEMON_FACTS.component, ts, pid));

    let panic = panic_from_info(info);
    let events = RING.get().map(|r| r.snapshot()).unwrap_or_default();
    let payload = format_crash_record(&DAEMON_FACTS, &panic, pid, ts, &events);
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
    fn install_panic_hook_creates_crashes_dir() {
        let tmp = tempfile::tempdir().unwrap();
        install_panic_hook(tmp.path());
        assert!(tmp.path().join("crashes").is_dir());
    }

    #[test]
    fn install_panic_hook_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        install_panic_hook(tmp.path());
        install_panic_hook(tmp.path());
    }
}
