// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-lifetime wall clock used by journal timestamps and retention.
//!
//! Wall-clock time is useful for display and age retention, but it can jump
//! while the daemon is running.  We therefore take one `SystemTime` anchor at
//! startup and advance it only with `Instant`.  Fresh raw wall-clock samples
//! are sanity checks, never the source of elapsed time.  A suspicious sample
//! permanently disables age-based deletion for this daemon lifetime; keeping
//! extra history is safer than treating a clock correction as elapsed age.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Runtime wall-clock drift tolerated before age expiry is disabled.
///
/// NTP slews and ordinary clock discipline stay well inside five minutes,
/// while a manual clock correction or broken RTC is caught quickly.
pub(crate) const MAX_RUNTIME_RAW_SKEW: Duration = Duration::from_secs(5 * 60);

/// Maximum plausible wall-clock advance between daemon lifetimes.
///
/// There is no monotonic clock that survives reboot.  A gap larger than this
/// may be legitimate downtime, but retaining history for that run is the
/// conservative choice.  Explicit/size-driven GC remains available.
pub(crate) const MAX_RESTART_FORWARD_GAP: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClockSample {
    pub(crate) unix_nanos: u64,
    pub(crate) age_expiry_safe: bool,
}

impl ClockSample {
    pub(crate) fn unix_secs(self) -> u64 {
        self.unix_nanos / 1_000_000_000
    }

    pub(crate) fn retention_now(self) -> shit_store::RetentionNow {
        shit_store::RetentionNow {
            unix_secs: self.unix_secs(),
            age_expiry_safe: self.age_expiry_safe,
        }
    }
}

#[derive(Debug)]
pub(crate) struct TrustedClock {
    anchor_unix_nanos: u64,
    anchor_instant: Instant,
    age_expiry_safe: AtomicBool,
}

impl TrustedClock {
    /// Build the process clock from the startup raw wall time and the newest
    /// persisted timestamp that can own or age data.
    pub(crate) fn start(latest_durable_unix_nanos: Option<u64>) -> Self {
        Self::from_start_observations(raw_unix_nanos(), latest_durable_unix_nanos)
    }

    fn from_start_observations(
        raw_start_unix_nanos: Option<u64>,
        latest_durable_unix_nanos: Option<u64>,
    ) -> Self {
        let runtime_bound = duration_nanos(MAX_RUNTIME_RAW_SKEW);
        let restart_forward_bound = duration_nanos(MAX_RESTART_FORWARD_GAP);

        let (anchor_unix_nanos, starts_safe) =
            match (raw_start_unix_nanos, latest_durable_unix_nanos) {
                (Some(raw), None) => (raw, true),
                (None, Some(latest)) => (latest, false),
                (None, None) => (0, false),
                (Some(raw), Some(latest)) if raw < latest => {
                    (latest, latest - raw <= runtime_bound)
                }
                (Some(raw), Some(latest)) if raw - latest > restart_forward_bound => {
                    // Do not stamp the suspect future epoch into durable rows.
                    // Otherwise one restart would make that epoch look like
                    // established history and incorrectly re-enable age GC.
                    (latest, false)
                }
                (Some(raw), Some(_)) => (raw, true),
            };

        Self {
            anchor_unix_nanos,
            anchor_instant: Instant::now(),
            age_expiry_safe: AtomicBool::new(starts_safe),
        }
    }

    pub(crate) fn sample(&self) -> ClockSample {
        self.sample_observations(self.anchor_instant.elapsed(), raw_unix_nanos())
    }

    fn sample_observations(
        &self,
        elapsed: Duration,
        raw_now_unix_nanos: Option<u64>,
    ) -> ClockSample {
        let trusted = self
            .anchor_unix_nanos
            .saturating_add(duration_nanos(elapsed));
        let within_bound = raw_now_unix_nanos
            .is_some_and(|raw| raw.abs_diff(trusted) <= duration_nanos(MAX_RUNTIME_RAW_SKEW));
        if !within_bound {
            // Sticky by design: a later clock correction cannot prove that no
            // age-based deletion would have happened during the bad interval.
            self.age_expiry_safe.store(false, Ordering::Release);
        }
        ClockSample {
            unix_nanos: trusted,
            age_expiry_safe: self.age_expiry_safe.load(Ordering::Acquire),
        }
    }
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn raw_unix_nanos() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_nanos()).ok())
}

static CLOCK: OnceLock<TrustedClock> = OnceLock::new();

/// Install the daemon clock before any producer is constructed.
pub(crate) fn init(latest_durable_unix_nanos: Option<u64>) -> &'static TrustedClock {
    CLOCK.get_or_init(|| TrustedClock::start(latest_durable_unix_nanos))
}

/// Sample the one daemon-lifetime clock.
pub(crate) fn now() -> ClockSample {
    // Production initializes explicitly after opening the index.  Lazy init
    // keeps focused unit tests that call event builders directly ergonomic.
    init(None).sample()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn forward_raw_jump_disables_age_expiry_but_not_anchored_progress() {
        let clock = TrustedClock::from_start_observations(Some(1_000 * SECOND), None);
        let sample = clock.sample_observations(
            Duration::from_secs(10),
            Some((1_000 + 24 * 60 * 60) * SECOND),
        );
        assert_eq!(sample.unix_nanos, 1_010 * SECOND);
        assert!(!sample.age_expiry_safe);

        let corrected = clock.sample_observations(Duration::from_secs(20), Some(1_020 * SECOND));
        assert_eq!(corrected.unix_nanos, 1_020 * SECOND);
        assert!(!corrected.age_expiry_safe, "unsafe state must be sticky");
    }

    #[test]
    fn backward_raw_jump_disables_age_expiry_without_reversing_timestamps() {
        let clock = TrustedClock::from_start_observations(Some(5_000 * SECOND), None);
        let first = clock.sample_observations(Duration::from_secs(10), Some(5_010 * SECOND));
        let jumped = clock.sample_observations(Duration::from_secs(20), Some(1_000 * SECOND));
        assert!(first.age_expiry_safe);
        assert_eq!(jumped.unix_nanos, 5_020 * SECOND);
        assert!(jumped.unix_nanos > first.unix_nanos);
        assert!(!jumped.age_expiry_safe);
    }

    #[test]
    fn restart_anchors_at_durable_future_and_suppresses_age_expiry() {
        let clock =
            TrustedClock::from_start_observations(Some(1_000 * SECOND), Some(2_000 * SECOND));
        let sample = clock.sample_observations(Duration::ZERO, Some(1_000 * SECOND));
        assert_eq!(sample.unix_nanos, 2_000 * SECOND);
        assert!(!sample.age_expiry_safe);
    }

    #[test]
    fn implausibly_large_forward_restart_gap_is_conservative() {
        let durable = 1_000 * SECOND;
        let raw = durable + duration_nanos(MAX_RESTART_FORWARD_GAP) + SECOND;
        let clock = TrustedClock::from_start_observations(Some(raw), Some(durable));
        let sample = clock.sample_observations(Duration::ZERO, Some(raw));
        assert_eq!(sample.unix_nanos, durable);
        assert!(!sample.age_expiry_safe);
    }

    #[test]
    fn suspect_forward_clock_stays_quarantined_across_restart() {
        let durable = 1_000 * SECOND;
        let suspect_raw = durable + duration_nanos(MAX_RESTART_FORWARD_GAP) + SECOND;
        let first = TrustedClock::from_start_observations(Some(suspect_raw), Some(durable));
        let first_sample = first.sample_observations(Duration::from_secs(10), Some(suspect_raw));
        assert_eq!(first_sample.unix_nanos, durable + 10 * SECOND);
        assert!(!first_sample.age_expiry_safe);

        // Model a recovered command/event written with the first clock and an
        // immediate second daemon lifetime while the RTC is still far ahead.
        let second = TrustedClock::from_start_observations(
            Some(suspect_raw + 10 * SECOND),
            Some(first_sample.unix_nanos),
        );
        let second_sample =
            second.sample_observations(Duration::ZERO, Some(suspect_raw + 10 * SECOND));
        assert_eq!(second_sample.unix_nanos, first_sample.unix_nanos);
        assert!(!second_sample.age_expiry_safe);
    }
}
