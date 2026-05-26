// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-side perf counters (S21.4).
//!
//! Shape:
//!
//! - Cheap atomics for hot-path counters (`hook_msgs`, `hook_decode_errors`).
//! - A `Mutex<Histogram<u64>>` for hook-handling latency. The daemon's
//!   hook path is one tokio task per UDS recv — the Mutex contention
//!   is moot at realistic event rates. If hook ingest ever exceeds
//!   ~100k events/s we revisit (DR-66 tracks the lock-free swap).
//! - GC summary fields written once per pass by `gc::run_loop`.
//! - Kernel-tier classifier set once at daemon-startup once the
//!   capture tier resolves.
//!
//! A snapshot() method renders the [`shit_proto::MetricsSnapshot`]
//! for the ctl handler. The snapshot reads from the store at query
//! time (size, blob/command counts) rather than caching — the
//! sqlite query is cheap (≤1ms typical) and we'd rather not duplicate
//! the source of truth.

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hdrhistogram::Histogram;
use shit_proto::{HelperLinkState, MetricsSnapshot};

/// Hook-latency histogram: u64 microseconds, 1us..60s range,
/// 3 significant figures (~0.1% resolution at p99). HdrHistogram
/// `new_with_bounds` returns an error only on impossible bounds;
/// the daemon panics on construction failure (which is fine
/// because it's a one-shot at startup).
fn new_latency_histogram() -> Histogram<u64> {
    Histogram::new_with_bounds(1, 60_000_000, 3).expect("histogram bounds are valid")
}

/// Shared, lock-light counters the ctl handler reads to render
/// `shit status` and `shit metrics`.
#[derive(Debug)]
pub struct Stats {
    pub started_at: Instant,
    pub last_activity: Mutex<Instant>,
    pub hook_msgs: AtomicU64,
    pub hook_decode_errors: AtomicU64,
    /// Hook-handling latency in microseconds. Recorded by
    /// `note_hook_latency_us` from `server::handle`.
    pub hook_latency_us: Mutex<Histogram<u64>>,
    /// Last completed GC pass summary. Zero if no pass has run.
    pub last_gc: Mutex<LastGc>,
    /// Kernel-tier classifier set once at startup.
    pub kernel_tier: Mutex<String>,
    /// B03.A — helper link liveness. Stored as `AtomicU8` so the
    /// dispatch loop's `HelperExited` branch can flip it without
    /// taking a lock. Discriminant mapping matches the proto enum:
    /// 0 = NeverConnected, 1 = Connected, 2 = Disconnected.
    pub helper_link_state: AtomicU8,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LastGc {
    pub duration_ms: u64,
    pub bytes_reclaimed: u64,
    /// Wall-clock seconds since the epoch when the pass closed.
    pub at_unix_secs: u64,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            started_at: now,
            last_activity: Mutex::new(now),
            hook_msgs: AtomicU64::new(0),
            hook_decode_errors: AtomicU64::new(0),
            hook_latency_us: Mutex::new(new_latency_histogram()),
            last_gc: Mutex::new(LastGc::default()),
            kernel_tier: Mutex::new(String::new()),
            helper_link_state: AtomicU8::new(0),
        })
    }

    pub fn note_hook_msg(&self) {
        self.hook_msgs.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.last_activity.lock() {
            *g = Instant::now();
        }
    }

    pub fn note_decode_error(&self) {
        self.hook_decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a hook-handling latency in microseconds. Clamps to
    /// the histogram's upper bound so a one-off slow request can't
    /// abort recording. Called from `server::handle` after the
    /// handle() body returns.
    pub fn note_hook_latency_us(&self, micros: u64) {
        if let Ok(mut h) = self.hook_latency_us.lock() {
            // saturating_record clamps to the high bound; we prefer
            // that to record's error on overflow.
            h.saturating_record(micros);
        }
    }

    pub fn note_gc(&self, duration_ms: u64, bytes_reclaimed: u64) {
        if let Ok(mut g) = self.last_gc.lock() {
            *g = LastGc {
                duration_ms,
                bytes_reclaimed,
                at_unix_secs: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };
        }
    }

    /// Set the capture tier classifier reported in
    /// [`MetricsSnapshot::kernel_tier`]. The daemon learns this from
    /// the helper handshake; wiring lands when the
    /// `helper-link::HandshakeAck` carries the tier (DR-66).
    #[allow(dead_code)]
    pub fn set_kernel_tier(&self, tier: &str) {
        if let Ok(mut g) = self.kernel_tier.lock() {
            *g = tier.to_string();
        }
    }

    /// B03.A — record that a helper link is currently alive. Called
    /// after a successful handshake (paired with `set_kernel_tier`).
    pub fn note_helper_connected(&self) {
        self.helper_link_state.store(1, Ordering::Relaxed);
    }

    /// B03.A — record that the dispatch loop has seen `HelperExited`
    /// (helper crashed, was killed, or exited cleanly). The daemon
    /// keeps running in degraded mode; doctor surfaces this so the
    /// operator notices capture coverage is lost.
    pub fn note_helper_disconnected(&self) {
        self.helper_link_state.store(2, Ordering::Relaxed);
    }

    fn helper_link_state(&self) -> HelperLinkState {
        match self.helper_link_state.load(Ordering::Relaxed) {
            1 => HelperLinkState::Connected,
            2 => HelperLinkState::Disconnected,
            _ => HelperLinkState::NeverConnected,
        }
    }

    pub fn idle_for(&self) -> std::time::Duration {
        match self.last_activity.lock() {
            Ok(g) => g.elapsed(),
            Err(_) => std::time::Duration::ZERO,
        }
    }

    /// Render the wire-side [`MetricsSnapshot`]. Store-side gauges
    /// (size, blob/command counts) are populated from caller-supplied
    /// closures so the test surface doesn't need a live sqlite handle.
    pub fn snapshot(
        &self,
        pid: u32,
        store_size_bytes: u64,
        store_blob_count: u64,
        store_command_count: u64,
    ) -> MetricsSnapshot {
        let (p50, p99, samples) = match self.hook_latency_us.lock() {
            Ok(h) => (
                h.value_at_quantile(0.50),
                h.value_at_quantile(0.99),
                h.len(),
            ),
            Err(_) => (0, 0, 0),
        };
        let last_gc = self.last_gc.lock().map(|g| *g).unwrap_or_default();
        let kernel_tier = self
            .kernel_tier
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();
        MetricsSnapshot {
            uptime_secs: self.started_at.elapsed().as_secs(),
            pid,
            hook_messages_received: self.hook_msgs.load(Ordering::Relaxed),
            hook_decode_errors: self.hook_decode_errors.load(Ordering::Relaxed),
            hook_latency_us_p50: p50,
            hook_latency_us_p99: p99,
            hook_latency_samples: samples,
            store_size_bytes,
            store_blob_count,
            store_command_count,
            last_gc_duration_ms: last_gc.duration_ms,
            last_gc_bytes_reclaimed: last_gc.bytes_reclaimed,
            last_gc_at_unix_secs: last_gc.at_unix_secs,
            kernel_tier,
            helper_link_state: self.helper_link_state(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_initial_values() {
        let s = Stats::new();
        let snap = s.snapshot(1234, 0, 0, 0);
        assert_eq!(snap.pid, 1234);
        assert_eq!(snap.hook_messages_received, 0);
        assert_eq!(snap.hook_latency_samples, 0);
        assert_eq!(snap.kernel_tier, "");
        assert_eq!(snap.last_gc_at_unix_secs, 0);
    }

    #[test]
    fn hook_latency_percentiles_track_recorded_samples() {
        let s = Stats::new();
        // Record a synthetic distribution: 1000 samples spread
        // from 100us to 1000us, plus one outlier at 50_000us.
        for i in 1..=1000u64 {
            s.note_hook_latency_us(i);
        }
        s.note_hook_latency_us(50_000);
        let snap = s.snapshot(1, 0, 0, 0);
        // p50 should land near 500us; p99 near 990 (the bulk) but
        // skewed toward the outlier. HdrHistogram's 3-sig-fig
        // bucketing means we can only assert order-of-magnitude.
        assert!(snap.hook_latency_us_p50 >= 480 && snap.hook_latency_us_p50 <= 520);
        assert!(snap.hook_latency_us_p99 >= 900);
        assert_eq!(snap.hook_latency_samples, 1001);
    }

    #[test]
    fn note_gc_populates_last_gc_fields() {
        let s = Stats::new();
        s.note_gc(42, 1024 * 1024);
        let snap = s.snapshot(1, 0, 0, 0);
        assert_eq!(snap.last_gc_duration_ms, 42);
        assert_eq!(snap.last_gc_bytes_reclaimed, 1024 * 1024);
        // at_unix_secs is now-ish; just check non-zero.
        assert!(snap.last_gc_at_unix_secs > 0);
    }

    #[test]
    fn note_hook_msg_increments_counter() {
        let s = Stats::new();
        s.note_hook_msg();
        s.note_hook_msg();
        s.note_hook_msg();
        let snap = s.snapshot(1, 0, 0, 0);
        assert_eq!(snap.hook_messages_received, 3);
    }

    #[test]
    fn helper_link_state_defaults_to_never_connected() {
        let s = Stats::new();
        let snap = s.snapshot(1, 0, 0, 0);
        assert_eq!(snap.helper_link_state, HelperLinkState::NeverConnected);
    }

    #[test]
    fn note_helper_connected_flips_snapshot_state() {
        let s = Stats::new();
        s.note_helper_connected();
        let snap = s.snapshot(1, 0, 0, 0);
        assert_eq!(snap.helper_link_state, HelperLinkState::Connected);
    }

    #[test]
    fn note_helper_disconnected_after_connected_reports_disconnected() {
        let s = Stats::new();
        s.note_helper_connected();
        s.note_helper_disconnected();
        let snap = s.snapshot(1, 0, 0, 0);
        // kernel_tier stays sticky; the state field is what doctor
        // reads now — verify they can disagree.
        s.set_kernel_tier("kqueue");
        let snap2 = s.snapshot(1, 0, 0, 0);
        assert_eq!(snap.helper_link_state, HelperLinkState::Disconnected);
        assert_eq!(snap2.helper_link_state, HelperLinkState::Disconnected);
        assert_eq!(snap2.kernel_tier, "kqueue");
    }

    #[test]
    fn set_kernel_tier_renders_in_snapshot() {
        let s = Stats::new();
        s.set_kernel_tier("fanotify");
        let snap = s.snapshot(1, 0, 0, 0);
        assert_eq!(snap.kernel_tier, "fanotify");
    }

    #[test]
    fn store_gauges_are_passed_through_unmodified() {
        let s = Stats::new();
        let snap = s.snapshot(1, 999_999, 42, 17);
        assert_eq!(snap.store_size_bytes, 999_999);
        assert_eq!(snap.store_blob_count, 42);
        assert_eq!(snap.store_command_count, 17);
    }

    #[test]
    fn latency_record_saturates_at_upper_bound() {
        // A value larger than the histogram's 60s upper bound should
        // saturate rather than panic/error.
        let s = Stats::new();
        s.note_hook_latency_us(u64::MAX);
        // Snapshot still works; the sample landed at the upper bound.
        let snap = s.snapshot(1, 0, 0, 0);
        assert_eq!(snap.hook_latency_samples, 1);
        assert!(snap.hook_latency_us_p50 >= 1);
    }

    #[test]
    fn concurrent_hook_msg_and_latency_records_do_not_lose_data() {
        let s = Stats::new();
        let s_clone = Arc::clone(&s);
        let handle = std::thread::spawn(move || {
            for i in 1..=500u64 {
                s_clone.note_hook_msg();
                s_clone.note_hook_latency_us(i);
            }
        });
        for i in 501..=1000u64 {
            s.note_hook_msg();
            s.note_hook_latency_us(i);
        }
        handle.join().unwrap();
        let snap = s.snapshot(1, 0, 0, 0);
        assert_eq!(snap.hook_messages_received, 1000);
        assert_eq!(snap.hook_latency_samples, 1000);
    }
}
