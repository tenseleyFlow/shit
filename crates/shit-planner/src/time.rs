// SPDX-License-Identifier: AGPL-3.0-or-later

//! Logical-clock time model for the planner.
//!
//! Wallclock alone is insufficient: clock skew (NTP corrections, manual
//! `date -s`, suspend/resume across timezones) breaks "happened-before"
//! reasoning. We pair a monotonic logical counter with a wallclock hint:
//! the logical counter establishes ordering, the wallclock is for human
//! display only.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TimePoint {
    /// Monotonic per-session counter; established at event ingest. Earlier
    /// events have smaller logical values.
    pub logical: u64,
    /// Wallclock nanoseconds since the Unix epoch at ingest time. Display-only.
    pub wallclock_unix_nanos: u64,
}

impl TimePoint {
    pub const fn new(logical: u64, wallclock_unix_nanos: u64) -> Self {
        Self {
            logical,
            wallclock_unix_nanos,
        }
    }

    /// Smallest representable point; useful as a lower bound in queries.
    pub const fn min() -> Self {
        Self {
            logical: 0,
            wallclock_unix_nanos: 0,
        }
    }

    /// Largest representable point; useful as an upper bound in queries.
    pub const fn max() -> Self {
        Self {
            logical: u64::MAX,
            wallclock_unix_nanos: u64::MAX,
        }
    }
}

/// Half-open `[start, end)` range over `TimePoint`s, for store queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: TimePoint,
    pub end: TimePoint,
}

impl TimeRange {
    pub const fn new(start: TimePoint, end: TimePoint) -> Self {
        Self { start, end }
    }

    pub fn contains(&self, point: TimePoint) -> bool {
        point >= self.start && point < self.end
    }

    pub fn all() -> Self {
        Self::new(TimePoint::min(), TimePoint::max())
    }
}

/// Half-open range over command sequence numbers within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqRange {
    pub start: u64,
    pub end: u64,
}

impl SeqRange {
    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub fn contains(&self, seq: u64) -> bool {
        seq >= self.start && seq < self.end
    }

    pub fn single(seq: u64) -> Self {
        Self::new(seq, seq.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_ordering_uses_logical_first() {
        let a = TimePoint::new(1, 1_000_000_000);
        let b = TimePoint::new(2, 0); // wallclock earlier, logical later
        assert!(b > a);
    }

    #[test]
    fn time_range_contains_correctly() {
        let r = TimeRange::new(TimePoint::new(10, 0), TimePoint::new(20, 0));
        assert!(r.contains(TimePoint::new(10, 0)));
        assert!(r.contains(TimePoint::new(15, 0)));
        assert!(!r.contains(TimePoint::new(20, 0)));
        assert!(!r.contains(TimePoint::new(9, 0)));
    }

    #[test]
    fn seq_range_single() {
        let r = SeqRange::single(5);
        assert!(r.contains(5));
        assert!(!r.contains(4));
        assert!(!r.contains(6));
    }
}
