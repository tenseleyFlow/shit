// SPDX-License-Identifier: AGPL-3.0-or-later

//! Background GC task (S13.6).
//!
//! The algorithm lives in `shit-store::gc`. This module is the
//! daemon-side wrapper that runs it on a schedule:
//!
//! - **idle interval** (default 5 min) when the daemon hasn't seen a
//!   capture event recently;
//! - **active interval** (default 30 min) under load — gives the
//!   capture path most of the CPU.
//!
//! The pass runs in a `spawn_blocking` since `run_pass` does sync
//! sqlite work and can hold a connection for tens of seconds on a
//! large reduction. Wrapping in `spawn_blocking` keeps the tokio
//! runtime responsive.
//!
//! ## Cancellation
//!
//! The daemon shutdown path notifies our `shutdown` channel; we set
//! the `cancel` flag, the in-flight pass (if any) returns
//! `GcError::Cancelled`, and we exit cleanly. The pass itself
//! checks the flag only between batches and between phases — never
//! mid-transaction — so cancellation never leaves the store
//! inconsistent.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use shit_store::{BlobStore, GcConfig, GcError, Index, RetentionNow, run_pass};
use tokio::sync::Notify;

/// Runtime configuration for the GC task. Resolved from the daemon's
/// `config.toml`.
#[derive(Debug, Clone)]
pub struct GcTaskConfig {
    pub idle_interval: Duration,
    pub active_interval: Duration,
    pub pass: GcConfig,
}

impl Default for GcTaskConfig {
    fn default() -> Self {
        Self {
            idle_interval: Duration::from_secs(5 * 60),
            active_interval: Duration::from_secs(30 * 60),
            pass: GcConfig::default(),
        }
    }
}

/// Shared signal: every capture write bumps this timestamp. The GC
/// task uses "how recent was the last capture?" to pick the idle vs.
/// active interval.
///
/// Stage 1 ships the field; the capture path will wire its
/// `update_last_capture` call in once the helper→daemon event
/// pipeline lights up (see DEFERRED-RUNTIME.md).
#[derive(Debug)]
pub struct GcSignal {
    last_capture: Mutex<Option<Instant>>,
}

impl Default for GcSignal {
    fn default() -> Self {
        Self {
            last_capture: Mutex::new(None),
        }
    }
}

impl GcSignal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called by the capture path on every accepted event.
    /// Unused in stage 1 — wired up once the helper→daemon event
    /// pipeline lands (gated on capture-runtime DR items).
    #[allow(dead_code)]
    pub fn note_capture(&self) {
        *self
            .last_capture
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Instant::now());
    }

    /// True when the most recent capture is older than `idle_after`.
    pub fn is_idle(&self, idle_after: Duration) -> bool {
        self.last_capture
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none_or(|last| last.elapsed() >= idle_after)
    }
}

/// Drive the GC loop. Returns when `shutdown` fires.
///
/// `retention_now_fn` supplies one checked sample per pass. The same sample is
/// used for command expiry and stash pruning, so a clock sanity failure cannot
/// race two independently sampled cutoffs.
pub async fn run_loop(
    index: Arc<Index>,
    blob_store: Arc<BlobStore>,
    config: GcTaskConfig,
    signal: Arc<GcSignal>,
    shutdown: Arc<Notify>,
    retention_now_fn: Arc<dyn Fn() -> RetentionNow + Send + Sync>,
    stats: Arc<crate::stats::Stats>,
) {
    let cancel = Arc::new(AtomicBool::new(false));

    // First pass: 30s after daemon boot. Gives time for the first
    // capture events to flush before we start sweeping.
    let mut delay = Duration::from_secs(30);
    loop {
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            _ = shutdown.notified() => {
                cancel.store(true, Ordering::Release);
                tracing::info!("gc loop: shutdown received");
                return;
            }
        }

        let pass_config = config.pass.clone();
        let cancel_for_pass = Arc::clone(&cancel);
        let index_for_pass = Arc::clone(&index);
        let blobs_for_pass = Arc::clone(&blob_store);
        let retention_now = (retention_now_fn)();

        let report = tokio::task::spawn_blocking(move || {
            run_pass(
                &index_for_pass,
                &blobs_for_pass,
                &pass_config,
                cancel_for_pass,
                retention_now,
            )
        })
        .await;

        match report {
            Ok(Ok(r)) => {
                tracing::info!(
                    commands_dropped = r.commands_dropped,
                    container_stashes_pruned = r.container_stashes_pruned,
                    blobs_swept = r.blobs_swept,
                    bytes_reclaimed = r.bytes_reclaimed,
                    duration_ms = r.duration.as_millis() as u64,
                    aggressive = r.aggressive_mode_used,
                    vacuumed = r.vacuumed,
                    age_expiry_suppressed = r.age_expiry_suppressed,
                    "gc pass complete"
                );
                if r.age_expiry_suppressed {
                    tracing::warn!(
                        "gc retained age-expired commands and container stashes because wall-clock sanity is quarantined"
                    );
                }
                // S21.4 — surface the summary via `shit metrics`.
                stats.note_gc(
                    r.duration.as_millis() as u64,
                    r.bytes_reclaimed,
                    retention_now.unix_secs,
                    r.age_expiry_suppressed,
                );
            }
            Ok(Err(GcError::Cancelled)) => {
                tracing::info!("gc pass cancelled mid-pass (shutdown)");
                return;
            }
            Ok(Err(e)) => {
                tracing::warn!(err = %e, "gc pass error");
            }
            Err(join_err) => {
                tracing::error!(err = %join_err, "gc spawn_blocking panicked");
            }
        }

        // Pick the next interval based on capture activity.
        delay = if signal.is_idle(config.idle_interval) {
            config.idle_interval
        } else {
            config.active_interval
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn signal_default_is_idle() {
        let s = GcSignal::new();
        assert!(s.is_idle(Duration::from_secs(60)));
    }

    #[test]
    fn signal_not_idle_right_after_capture() {
        let s = GcSignal::new();
        s.note_capture();
        // 60s threshold: we just bumped, so we're active.
        assert!(!s.is_idle(Duration::from_secs(60)));
        // Zero-second threshold: anything counts as idle.
        assert!(s.is_idle(Duration::from_secs(0)));
    }
}
