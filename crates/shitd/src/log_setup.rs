// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tracing-subscriber setup for the daemon (S21.3).
//!
//! Stage 1 behavior:
//!
//! - **JSON layer** writes structured events to
//!   `$XDG_STATE_HOME/shit/log/daemon.jsonl.<date>` via
//!   tracing-appender's `rolling::daily`. A 7-day retention is
//!   enforced by [`sweep_old_logs`] (the appender itself doesn't
//!   prune).
//! - **Stderr fallback layer** writes pretty-format `warn`+ events
//!   to stderr so operators reading `journalctl -u shit-user.service`
//!   still see the loud lines without having to tail the JSON file.
//! - **EnvFilter** honors `RUST_LOG`; default is the resolved config's
//!   `log_level` (typically `info`).
//!
//! Span context (the `component=daemon` root span opened in `run`)
//! propagates into the JSON record because the JSON formatter
//! flattens the active span stack into the event's fields by default.

use std::path::Path;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Where the JSON log lands relative to `state_dir`.
pub const LOG_SUBDIR: &str = "log";
pub const LOG_FILE_PREFIX: &str = "daemon";
pub const LOG_FILE_SUFFIX: &str = "jsonl";
pub const RETENTION_DAYS: u64 = 7;

/// Initialize the daemon's logging stack. Returns a `WorkerGuard`
/// that the caller must hold until shutdown — dropping it shuts
/// the appender's worker thread and flushes the queue.
pub fn init(state_dir: &Path, log_level_default: &str) -> WorkerGuard {
    let log_dir = state_dir.join(LOG_SUBDIR);
    let _ = std::fs::create_dir_all(&log_dir);

    let file_appender = rolling::daily(&log_dir, format!("{LOG_FILE_PREFIX}.{LOG_FILE_SUFFIX}"));
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level_default));

    let json_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_writer(non_blocking);

    let stderr_filter = EnvFilter::new("warn");
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false);

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(json_layer)
        .with(stderr_layer.with_filter(stderr_filter));
    let _ = subscriber.try_init();

    guard
}

/// Sweep `log/` for files older than `RETENTION_DAYS`. Best-effort;
/// returns the count of files deleted. The daemon's existing janitor
/// tick calls this on the same cadence as the per-stash sweeps.
pub fn sweep_old_logs(state_dir: &Path) -> usize {
    let log_dir = state_dir.join(LOG_SUBDIR);
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(
            RETENTION_DAYS * 24 * 60 * 60,
        ))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let Ok(entries) = std::fs::read_dir(&log_dir) else {
        return 0;
    };
    let mut deleted = 0;
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if modified < cutoff
            && entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with(LOG_FILE_PREFIX))
            && std::fs::remove_file(entry.path()).is_ok()
        {
            deleted += 1;
        }
    }
    deleted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_returns_zero_when_log_dir_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let deleted = sweep_old_logs(tmp.path());
        assert_eq!(deleted, 0);
    }

    #[test]
    fn sweep_preserves_recent_files() {
        // A just-created file has a now-mtime; sweep should leave it.
        let tmp = tempfile::tempdir().unwrap();
        let log_dir = tmp.path().join(LOG_SUBDIR);
        std::fs::create_dir_all(&log_dir).unwrap();
        let fresh = log_dir.join(format!("{LOG_FILE_PREFIX}.{LOG_FILE_SUFFIX}.2099-12-31"));
        std::fs::write(&fresh, b"fresh log").unwrap();
        let deleted = sweep_old_logs(tmp.path());
        assert_eq!(deleted, 0);
        assert!(fresh.exists());
    }

    #[test]
    fn sweep_ignores_unrelated_files_even_when_old() {
        // Touch a file with a mtime well before the cutoff via a
        // raw utimes-equivalent. We rely on filesystem-level mtime
        // adjustment via std::fs only — we cannot backdate from std,
        // so the assertion here is the *names* path: an old-looking
        // file whose mtime is fresh should still be ignored when it
        // doesn't match LOG_FILE_PREFIX.
        let tmp = tempfile::tempdir().unwrap();
        let log_dir = tmp.path().join(LOG_SUBDIR);
        std::fs::create_dir_all(&log_dir).unwrap();
        let unrelated = log_dir.join("unrelated.txt");
        std::fs::write(&unrelated, b"not our log").unwrap();
        let deleted = sweep_old_logs(tmp.path());
        assert_eq!(deleted, 0);
        assert!(unrelated.exists());
    }

    #[test]
    fn init_does_not_panic_on_missing_state_dir() {
        // Even if the state dir doesn't exist, init creates the
        // subdir and returns a guard. The subscriber may fail to
        // install if one is already set (other tests) — we accept
        // either outcome here. The function MUST NOT panic.
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().join("doesnt-exist-yet");
        let _guard = init(&state_dir, "info");
        assert!(state_dir.join(LOG_SUBDIR).exists());
    }
}
