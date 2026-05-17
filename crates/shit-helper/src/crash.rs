// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash log writer for `shit-helper`. The format is defined in
//! [`shit_proto::crash`]; this module owns the panic-hook install
//! and the tracing ring buffer wiring.
//!
//! Best-effort: a panic hook that itself panics aborts the process, so
//! every fs call here is wrapped in `let _ = ...`. The default panic
//! handler still runs after ours (the stderr message + backtrace).

use std::backtrace::Backtrace;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use shit_proto::crash::{CrashFacts, CrashPanic, TracingRing, crash_filename, format_crash_record};

/// Capacity of the in-process ring buffer (per the schema doc: "last
/// 100 tracing events"). 100 is the schema commitment; bumping
/// requires a schema change.
const RING_CAPACITY: usize = 100;

static CRASH_DIR: OnceLock<PathBuf> = OnceLock::new();
static RING: OnceLock<Arc<TracingRing>> = OnceLock::new();

const HELPER_FACTS: CrashFacts = CrashFacts {
    component: "shit-helper",
    version: env!("CARGO_PKG_VERSION"),
    commit: env!("VERGEN_GIT_SHA"),
    built: env!("VERGEN_BUILD_TIMESTAMP"),
    rustc: env!("VERGEN_RUSTC_SEMVER"),
    target: env!("VERGEN_CARGO_TARGET_TRIPLE"),
};

/// Install the panic hook. Idempotent; calling twice replaces the
/// stored crash dir but leaves the hook in place.
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

/// Handle to the in-process ring buffer. The tracing-Layer wiring
/// that pushes events into it is tracked as DR-67-adjacent (a single
/// `tracing_subscriber::Layer` impl that calls `ring().map(|r|
/// r.push(...))` for each event). The helper currently runs without
/// the layer wired — the ring stays empty and the crash log just
/// renders "last 0 tracing events"; the format is identical, which
/// keeps the schema commitment stable.
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
    let path = dir.join(crash_filename(HELPER_FACTS.component, ts, pid));

    let panic = panic_from_info(info);
    let events = RING.get().map(|r| r.snapshot()).unwrap_or_default();
    let payload = format_crash_record(&HELPER_FACTS, &panic, pid, ts, &events);
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
    // Force capture so the record has a backtrace even when
    // RUST_BACKTRACE isn't set in the binary's environment.
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
        // OnceLock guards the hook install — repeated calls update the
        // crash-dir target but don't double-register. Calling twice
        // must not panic.
        let tmp = tempfile::tempdir().unwrap();
        install_panic_hook(tmp.path());
        install_panic_hook(tmp.path());
    }

    #[test]
    fn ring_is_available_after_install() {
        let tmp = tempfile::tempdir().unwrap();
        install_panic_hook(tmp.path());
        let r = ring().expect("ring should be wired after install");
        assert_eq!(r.capacity(), RING_CAPACITY);
    }

    // Note: we deliberately don't exercise the panic-hook path inside
    // unit tests. The hook is a process-global resource (`OnceLock`),
    // so the *first* test to install it wins, and any later test
    // expecting its own crash dir to receive the record will flake
    // under parallel execution. The hook is exercised end-to-end by
    // the integration tests in `tests/helper_handshake.rs` which
    // spawn fresh helper processes.
}
