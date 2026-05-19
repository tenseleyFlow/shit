// SPDX-License-Identifier: AGPL-3.0-or-later

//! Perf-regression harness (S21.7).
//!
//! The four end-to-end workloads in `src/bin/` each measure wall-clock
//! latency of a synthetic command stream and emit a JSON
//! [`RunResult`]. CI (S21.9) compares the result against a baseline
//! pulled from the last 14 days of `trunk` runs on the same OS.
//!
//! This file is the **statistics core**:
//!
//! - [`collect`] runs a closure N times, gathers µs samples.
//! - [`reject_outliers_mad`] strips samples > 3·MAD from the median
//!   (median absolute deviation — robust against the long tail
//!   typical of latency distributions).
//! - [`percentile`] computes p50/p99/etc. via linear interpolation.
//! - [`detect_regression`] compares a current run against a baseline
//!   and against absolute project-budget thresholds.
//!
//! Every numeric routine has direct unit tests. The bins are thin
//! wrappers: they invoke the workload, time it, and serialise.
//!
//! ## Why MAD and not Tukey fences
//!
//! Tukey's `(Q1 - 1.5·IQR, Q3 + 1.5·IQR)` rule is fine for normal-ish
//! distributions but rejects too aggressively in the long upper tail
//! that latency naturally has. MAD is the modern robust-statistics
//! default and rejects only "really anomalous" points (think GC pauses
//! in unrelated processes, runner-host hiccups), keeping the legit
//! distribution intact.
//!
//! ## Why u64 microseconds throughout
//!
//! Wall-clock latencies on the hot path are 100–500 µs. `Duration`
//! and `f64` both work but invite drift; u64 µs is the same unit the
//! daemon's `MetricsSnapshot` uses, so a baseline file from the bench
//! is directly comparable to a snapshot from `shit metrics`.

use serde::{Deserialize, Serialize};

/// One latency sample. Microseconds because the budget unit (per
/// `shit_proto::MetricsSnapshot`) is microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sample {
    pub micros: u64,
}

/// Result of running a workload `n` times. Serialised to JSON in CI
/// artifacts and consumed by [`detect_regression`] on later runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub workload: String,
    pub host_os: String,
    pub host_arch: String,
    /// Iteration count *before* outlier rejection.
    pub n_total: usize,
    /// Iteration count *after* outlier rejection.
    pub n_kept: usize,
    pub outliers_rejected: usize,
    pub median_us: u64,
    pub p99_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
    /// Wall-clock seconds the bench took end-to-end. Useful for CI
    /// budget tracking: a 4 min bench growing to 6 min is itself a
    /// signal.
    pub wall_secs: u64,
}

/// Run `f` `n` times, collecting one [`Sample`] per call, then fold
/// down into a [`RunResult`]. The bench bins use this with a closure
/// that runs their workload and returns its measured µs.
///
/// `f` must be idempotent — the harness will call it `n` times and
/// the bench should produce a comparable sample each time. Anything
/// that drifts across iterations (warm cache effects, growing state)
/// makes the median dishonest.
pub fn collect(
    workload: &str,
    n: usize,
    host_os: &str,
    host_arch: &str,
    mut f: impl FnMut() -> u64,
) -> RunResult {
    let wall_start = std::time::Instant::now();
    let raw: Vec<u64> = (0..n).map(|_| f()).collect();
    let wall_secs = wall_start.elapsed().as_secs();
    summarize(workload, host_os, host_arch, &raw, wall_secs)
}

/// Pure-logic summariser. Split from [`collect`] so tests can drive
/// it with synthetic distributions and not depend on wall-clock.
pub fn summarize(
    workload: &str,
    host_os: &str,
    host_arch: &str,
    raw: &[u64],
    wall_secs: u64,
) -> RunResult {
    let n_total = raw.len();
    let (kept, rejected) = reject_outliers_mad(raw);
    let n_kept = kept.len();
    let median_us = percentile(&kept, 0.50);
    let p99_us = percentile(&kept, 0.99);
    let (min_us, max_us, mean_us) = min_max_mean(&kept);
    RunResult {
        workload: workload.to_string(),
        host_os: host_os.to_string(),
        host_arch: host_arch.to_string(),
        n_total,
        n_kept,
        outliers_rejected: rejected,
        median_us,
        p99_us,
        min_us,
        max_us,
        mean_us,
        wall_secs,
    }
}

/// Median absolute deviation outlier rejection.
///
/// Returns `(kept, n_rejected)`. A sample `s` is kept iff
/// `|s - median| <= 3 · MAD`. MAD is the median of `|sᵢ - median|`,
/// scaled by 1.4826 to be a consistent estimator of σ for normal
/// data. (We don't need the scale factor for the cutoff comparison —
/// the 3· stands in — but the constant is documented for readers who
/// want to compare with a textbook formula.)
///
/// Edge cases:
/// - Empty input → empty result, zero rejected.
/// - Single sample → kept, zero rejected.
/// - All-identical samples → MAD = 0, every sample within 0 of the
///   median, all kept. This is the right answer (zero variance means
///   nothing is anomalous) but trips a naive "reject if outside
///   `[median - 3·MAD, median + 3·MAD]`" implementation that uses
///   strict-less-than. Use `<=` to handle this.
pub fn reject_outliers_mad(samples: &[u64]) -> (Vec<u64>, usize) {
    if samples.is_empty() {
        return (Vec::new(), 0);
    }
    if samples.len() == 1 {
        return (samples.to_vec(), 0);
    }
    let med = percentile(samples, 0.50);
    // Absolute deviations from the median, then the median of those.
    let mut abs_devs: Vec<u64> = samples
        .iter()
        .map(|s| if *s >= med { s - med } else { med - s })
        .collect();
    abs_devs.sort_unstable();
    let mad = abs_devs[abs_devs.len() / 2];
    // Cutoff: 3·MAD. If MAD is zero, only exact-match samples survive
    // and the rest are rejected — that's pathological data (one mode
    // dominates and the rest are flagged anomalous). Cap the rejection
    // rate to avoid eating the whole sample set: if more than 25% of
    // points would be rejected we abandon the filter and keep all.
    let cutoff = mad.saturating_mul(3);
    let kept: Vec<u64> = samples
        .iter()
        .copied()
        .filter(|s| {
            let dev = if *s >= med { s - med } else { med - s };
            dev <= cutoff
        })
        .collect();
    let rejected = samples.len() - kept.len();
    if rejected * 4 > samples.len() {
        // Reject-rate too high → MAD is not a useful descriptor here.
        // Return everything; the regression detector will still see
        // the dispersion via the percentiles.
        return (samples.to_vec(), 0);
    }
    (kept, rejected)
}

/// Linear-interpolated percentile of `samples`. Mutates a sort-buffer
/// internally; takes `&[u64]` so callers can hand the same slice to
/// multiple percentile calls without re-sorting (we sort each time —
/// fine for `n ≤ ~10_000`).
///
/// `q` is in [0.0, 1.0]. q=0 returns the min, q=1 the max, q=0.5 the
/// median.
///
/// Empty input → 0 (sentinel that downstream code can spot via
/// `n_kept == 0`).
pub fn percentile(samples: &[u64], q: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let q = q.clamp(0.0, 1.0);
    if q <= 0.0 {
        return sorted[0];
    }
    if q >= 1.0 {
        return sorted[sorted.len() - 1];
    }
    let pos = q * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        return sorted[lo];
    }
    let frac = pos - lo as f64;
    let lo_v = sorted[lo] as f64;
    let hi_v = sorted[hi] as f64;
    (lo_v + (hi_v - lo_v) * frac).round() as u64
}

fn min_max_mean(samples: &[u64]) -> (u64, u64, u64) {
    if samples.is_empty() {
        return (0, 0, 0);
    }
    let mut min = u64::MAX;
    let mut max = u64::MIN;
    let mut sum: u128 = 0;
    for s in samples {
        if *s < min {
            min = *s;
        }
        if *s > max {
            max = *s;
        }
        sum += *s as u128;
    }
    let mean = (sum / samples.len() as u128) as u64;
    (min, max, mean)
}

/// Project-budget absolute thresholds. Source: the perf budget in
/// the project plan ("Shell hook: <500µs steady-state. Auth-event
/// handling: <100µs p50, <1ms p99. Postexec ack: <2ms p50.").
///
/// A workload pins which thresholds apply via [`BudgetGate`]. CI uses
/// these as hard floors that *can never* be crossed; the rolling
/// baseline catches softer drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetGate {
    pub median_us_max: u64,
    pub p99_us_max: u64,
}

impl BudgetGate {
    /// Tight-loop / hook latency budget: <500µs median, <2ms p99.
    pub const SHELL_HOOK: BudgetGate = BudgetGate {
        median_us_max: 500,
        p99_us_max: 2_000,
    };
    /// Auth-event handling budget (helper-side, per-event).
    pub const AUTH_EVENT: BudgetGate = BudgetGate {
        median_us_max: 100,
        p99_us_max: 1_000,
    };
    /// Postexec ack RTT budget.
    pub const POSTEXEC_ACK: BudgetGate = BudgetGate {
        median_us_max: 2_000,
        p99_us_max: 5_000,
    };

    /// Linux fanotify-perm capture-to-ALLOW budget. The fanotify-perm
    /// kernel buffer holds events behind a slow userspace responder;
    /// if we take >~50ms the kernel starts marking events FAN_NOFD
    /// (overflow) and the syscalls fail with EPERM. 10ms p99 leaves
    /// a comfortable 5x margin to that cliff. See L01 design notes.
    pub const CAPTURE_TO_ALLOW: BudgetGate = BudgetGate {
        median_us_max: 5_000,
        p99_us_max: 10_000,
    };

    /// Hard upper bound from the fanotify-perm kernel buffer behaviour.
    /// Crossing this is a correctness failure, not a perf regression —
    /// once the kernel overflows, events are silently dropped and
    /// capture is unsound. Reserved as a panic-grade gate for any
    /// future capture-stress harness that wants to assert "we never
    /// approach the deadlock cliff."
    pub const CAPTURE_KERNEL_DEADLINE: BudgetGate = BudgetGate {
        median_us_max: 25_000,
        p99_us_max: 50_000,
    };
}

/// Per-comparison verdict. Carries the numbers that made the call
/// so CI can render a useful failure message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RegressionVerdict {
    Pass,
    /// Median latency exceeded the absolute project budget.
    BudgetExceededMedian {
        current: u64,
        budget: u64,
    },
    /// p99 latency exceeded the absolute project budget.
    BudgetExceededP99 {
        current: u64,
        budget: u64,
    },
    /// Median regressed > `pct_threshold` against baseline.
    MedianRegressed {
        baseline: u64,
        current: u64,
        pct_change: f64,
    },
    /// p99 regressed > `pct_threshold` against baseline.
    P99Regressed {
        baseline: u64,
        current: u64,
        pct_change: f64,
    },
}

/// Default relative-regression thresholds (S21 design notes).
pub const DEFAULT_MEDIAN_PCT: f64 = 10.0;
pub const DEFAULT_P99_PCT: f64 = 20.0;

/// Compare `current` against `baseline` and `gate`, return the first
/// failure. Absolute-budget checks come first — a run that's
/// 5% slower than baseline but inside budget is a `Pass`; a run
/// inside the 10% threshold but blowing the absolute budget is a
/// failure.
pub fn detect_regression(
    current: &RunResult,
    baseline: Option<&RunResult>,
    gate: BudgetGate,
    median_pct_threshold: f64,
    p99_pct_threshold: f64,
) -> RegressionVerdict {
    if current.median_us > gate.median_us_max {
        return RegressionVerdict::BudgetExceededMedian {
            current: current.median_us,
            budget: gate.median_us_max,
        };
    }
    if current.p99_us > gate.p99_us_max {
        return RegressionVerdict::BudgetExceededP99 {
            current: current.p99_us,
            budget: gate.p99_us_max,
        };
    }
    if let Some(b) = baseline {
        if let Some(pct) = pct_change(b.median_us, current.median_us)
            && pct > median_pct_threshold
        {
            return RegressionVerdict::MedianRegressed {
                baseline: b.median_us,
                current: current.median_us,
                pct_change: pct,
            };
        }
        if let Some(pct) = pct_change(b.p99_us, current.p99_us)
            && pct > p99_pct_threshold
        {
            return RegressionVerdict::P99Regressed {
                baseline: b.p99_us,
                current: current.p99_us,
                pct_change: pct,
            };
        }
    }
    RegressionVerdict::Pass
}

/// Percentage change from `baseline` to `current`. Positive == got
/// slower. `None` if baseline is zero (avoid div-by-zero; CI treats
/// zero baseline as "no comparison available").
pub fn pct_change(baseline: u64, current: u64) -> Option<f64> {
    if baseline == 0 {
        return None;
    }
    let delta = current as f64 - baseline as f64;
    Some(delta / baseline as f64 * 100.0)
}

/// Serialise a result to a pretty JSON string. Used by the bench
/// bins; tests assert roundtrip.
pub fn to_json(r: &RunResult) -> String {
    serde_json::to_string_pretty(r).expect("RunResult is always serialisable")
}

/// Inverse of [`to_json`]. CI reads baseline files this way.
pub fn from_json(s: &str) -> anyhow::Result<RunResult> {
    Ok(serde_json::from_str(s)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_basic_distribution() {
        let samples = (1..=100u64).collect::<Vec<_>>();
        // Linear interpolation: q=0.5 over [1..=100] hits index 49.5
        // → mid-point of 50 and 51 = 50.5, rounds to 51. This is the
        // standard "type 7" percentile (numpy, R default). Documented
        // explicitly so a reader doesn't expect the Excel default
        // which uses a different interpolation.
        assert_eq!(percentile(&samples, 0.50), 51);
        assert_eq!(percentile(&samples, 0.99), 99);
        assert_eq!(percentile(&samples, 0.00), 1);
        assert_eq!(percentile(&samples, 1.00), 100);
    }

    #[test]
    fn percentile_empty_returns_zero() {
        let empty: [u64; 0] = [];
        assert_eq!(percentile(&empty, 0.50), 0);
        assert_eq!(percentile(&empty, 0.99), 0);
    }

    #[test]
    fn percentile_single_sample() {
        assert_eq!(percentile(&[42], 0.50), 42);
        assert_eq!(percentile(&[42], 0.99), 42);
        assert_eq!(percentile(&[42], 0.0), 42);
    }

    #[test]
    fn percentile_interpolation_between_samples() {
        // For [10, 20], q=0.5 should be the midpoint = 15.
        let s = [10u64, 20];
        assert_eq!(percentile(&s, 0.5), 15);
    }

    #[test]
    fn percentile_q_out_of_range_clamps() {
        let s = [10, 20, 30];
        assert_eq!(percentile(&s, -0.5), 10);
        assert_eq!(percentile(&s, 2.0), 30);
    }

    #[test]
    fn percentile_unsorted_input_handled() {
        // The bench harness may hand samples in arrival order, not
        // sorted. Percentile must sort internally.
        let s = [5, 1, 4, 2, 3];
        assert_eq!(percentile(&s, 0.50), 3);
    }

    #[test]
    fn mad_rejects_clear_outlier() {
        // 100 samples around 100µs, one 100ms outlier.
        let mut samples: Vec<u64> = (90..190).collect();
        samples.push(100_000);
        let (kept, rejected) = reject_outliers_mad(&samples);
        assert_eq!(rejected, 1, "exactly the one outlier rejected");
        assert!(!kept.contains(&100_000));
    }

    #[test]
    fn mad_empty_input_is_safe() {
        let (kept, rejected) = reject_outliers_mad(&[]);
        assert!(kept.is_empty());
        assert_eq!(rejected, 0);
    }

    #[test]
    fn mad_single_sample_kept() {
        let (kept, rejected) = reject_outliers_mad(&[42]);
        assert_eq!(kept, vec![42]);
        assert_eq!(rejected, 0);
    }

    #[test]
    fn mad_all_identical_samples_all_kept() {
        // Pathological: zero variance. We use `<=` not `<` in the
        // cutoff so this case isn't ablated.
        let s = vec![100u64; 50];
        let (kept, rejected) = reject_outliers_mad(&s);
        assert_eq!(kept.len(), 50);
        assert_eq!(rejected, 0);
    }

    #[test]
    fn mad_abandons_filter_when_reject_rate_too_high() {
        // Bimodal distribution where MAD-3 would reject ~half. The
        // safety valve: rather than eat the dataset, return
        // everything and let percentile dispersion speak.
        let mut s: Vec<u64> = (0..50).map(|_| 100u64).collect();
        s.extend((0..50).map(|_| 1000u64));
        let (kept, rejected) = reject_outliers_mad(&s);
        // No rejection — the filter bailed.
        assert_eq!(kept.len(), 100);
        assert_eq!(rejected, 0);
    }

    #[test]
    fn summarize_round_trip_preserves_shape() {
        let s = (1..=100u64).collect::<Vec<_>>();
        let r = summarize("test", "linux", "x86_64", &s, 5);
        assert_eq!(r.workload, "test");
        assert_eq!(r.host_os, "linux");
        assert_eq!(r.host_arch, "x86_64");
        assert_eq!(r.n_total, 100);
        assert_eq!(r.median_us, 51); // see percentile_basic_distribution for the rounding rule
        assert_eq!(r.p99_us, 99);
        assert_eq!(r.min_us, 1);
        assert_eq!(r.max_us, 100);
        assert_eq!(r.wall_secs, 5);
    }

    #[test]
    fn detect_regression_pass_when_inside_budget_and_baseline() {
        let baseline = synth(100, 500);
        let current = synth(105, 520); // 5% slower median, 4% p99
        let v = detect_regression(
            &current,
            Some(&baseline),
            BudgetGate::SHELL_HOOK,
            DEFAULT_MEDIAN_PCT,
            DEFAULT_P99_PCT,
        );
        assert_eq!(v, RegressionVerdict::Pass);
    }

    #[test]
    fn detect_regression_fails_on_absolute_budget_exceeded() {
        // Median sneaks past 500µs even with no baseline regression.
        let current = synth(600, 1_500);
        let v = detect_regression(
            &current,
            None,
            BudgetGate::SHELL_HOOK,
            DEFAULT_MEDIAN_PCT,
            DEFAULT_P99_PCT,
        );
        assert_eq!(
            v,
            RegressionVerdict::BudgetExceededMedian {
                current: 600,
                budget: 500
            }
        );
    }

    #[test]
    fn detect_regression_fails_on_p99_budget_exceeded() {
        let current = synth(400, 2_500); // p99 over 2000
        let v = detect_regression(
            &current,
            None,
            BudgetGate::SHELL_HOOK,
            DEFAULT_MEDIAN_PCT,
            DEFAULT_P99_PCT,
        );
        assert_eq!(
            v,
            RegressionVerdict::BudgetExceededP99 {
                current: 2_500,
                budget: 2_000
            }
        );
    }

    #[test]
    fn detect_regression_fails_on_median_relative_threshold() {
        let baseline = synth(100, 500);
        // 25% median regression, still under absolute budget
        let current = synth(125, 520);
        let v = detect_regression(
            &current,
            Some(&baseline),
            BudgetGate::SHELL_HOOK,
            DEFAULT_MEDIAN_PCT,
            DEFAULT_P99_PCT,
        );
        match v {
            RegressionVerdict::MedianRegressed {
                baseline: b,
                current: c,
                pct_change: pct,
            } => {
                assert_eq!(b, 100);
                assert_eq!(c, 125);
                assert!((pct - 25.0).abs() < 0.01);
            }
            other => panic!("expected MedianRegressed, got {other:?}"),
        }
    }

    #[test]
    fn detect_regression_fails_on_p99_relative_threshold() {
        let baseline = synth(100, 500);
        // 5% median (pass) but 30% p99 (fail relative)
        let current = synth(105, 650);
        let v = detect_regression(
            &current,
            Some(&baseline),
            BudgetGate::SHELL_HOOK,
            DEFAULT_MEDIAN_PCT,
            DEFAULT_P99_PCT,
        );
        assert!(matches!(v, RegressionVerdict::P99Regressed { .. }));
    }

    #[test]
    fn detect_regression_improvement_is_pass() {
        let baseline = synth(200, 800);
        let current = synth(100, 400); // 50% faster
        let v = detect_regression(
            &current,
            Some(&baseline),
            BudgetGate::SHELL_HOOK,
            DEFAULT_MEDIAN_PCT,
            DEFAULT_P99_PCT,
        );
        assert_eq!(v, RegressionVerdict::Pass);
    }

    #[test]
    fn detect_regression_zero_baseline_skips_relative_check() {
        let baseline = synth(0, 0);
        let current = synth(100, 500); // can't compare against zero
        let v = detect_regression(
            &current,
            Some(&baseline),
            BudgetGate::SHELL_HOOK,
            DEFAULT_MEDIAN_PCT,
            DEFAULT_P99_PCT,
        );
        assert_eq!(v, RegressionVerdict::Pass);
    }

    #[test]
    fn pct_change_handles_zero_baseline() {
        assert_eq!(pct_change(0, 100), None);
        assert_eq!(pct_change(100, 100), Some(0.0));
        assert_eq!(pct_change(100, 150), Some(50.0));
        assert_eq!(pct_change(100, 50), Some(-50.0));
    }

    #[test]
    fn budget_gates_match_project_plan() {
        // Catch a future drift between the project plan's perf
        // budget and the constants we gate on. If a budget moves,
        // both the plan AND this test must be updated together.
        assert_eq!(BudgetGate::SHELL_HOOK.median_us_max, 500);
        assert_eq!(BudgetGate::SHELL_HOOK.p99_us_max, 2_000);
        assert_eq!(BudgetGate::AUTH_EVENT.median_us_max, 100);
        assert_eq!(BudgetGate::AUTH_EVENT.p99_us_max, 1_000);
        assert_eq!(BudgetGate::POSTEXEC_ACK.median_us_max, 2_000);
        assert_eq!(BudgetGate::CAPTURE_TO_ALLOW.median_us_max, 5_000);
        assert_eq!(BudgetGate::CAPTURE_TO_ALLOW.p99_us_max, 10_000);
        assert_eq!(BudgetGate::CAPTURE_KERNEL_DEADLINE.median_us_max, 25_000);
        assert_eq!(BudgetGate::CAPTURE_KERNEL_DEADLINE.p99_us_max, 50_000);
    }

    #[test]
    fn capture_budget_is_below_kernel_deadline() {
        // The 10ms target must stay strictly under the 50ms cliff so
        // a passing CAPTURE_TO_ALLOW run never approaches the kernel
        // overflow behaviour. Five-times margin is the design intent.
        assert!(BudgetGate::CAPTURE_TO_ALLOW.p99_us_max * 5 <= BudgetGate::CAPTURE_KERNEL_DEADLINE.p99_us_max);
        assert!(BudgetGate::CAPTURE_TO_ALLOW.median_us_max * 5 <= BudgetGate::CAPTURE_KERNEL_DEADLINE.median_us_max);
    }

    #[test]
    fn json_roundtrip_preserves_all_fields() {
        let r = synth(123, 456);
        let s = to_json(&r);
        let back = from_json(&s).unwrap();
        assert_eq!(back.median_us, r.median_us);
        assert_eq!(back.p99_us, r.p99_us);
        assert_eq!(back.workload, r.workload);
        assert_eq!(back.host_os, r.host_os);
        assert_eq!(back.n_total, r.n_total);
    }

    #[test]
    fn from_json_rejects_malformed_input() {
        assert!(from_json("not json").is_err());
        assert!(from_json("{}").is_err()); // missing required fields
    }

    #[test]
    fn collect_runs_closure_n_times() {
        let mut counter = 0u64;
        let r = collect("counting", 10, "test", "test", || {
            counter += 1;
            counter * 10
        });
        assert_eq!(counter, 10);
        assert_eq!(r.n_total, 10);
        // samples are 10, 20, ..., 100 → median = 55 (interpolated)
        assert_eq!(r.median_us, 55);
    }

    /// Build a [`RunResult`] with a chosen median/p99 for test inputs.
    fn synth(median: u64, p99: u64) -> RunResult {
        RunResult {
            workload: "test".to_string(),
            host_os: "test".to_string(),
            host_arch: "test".to_string(),
            n_total: 100,
            n_kept: 100,
            outliers_rejected: 0,
            median_us: median,
            p99_us: p99,
            min_us: median.saturating_sub(50),
            max_us: p99,
            mean_us: median,
            wall_secs: 1,
        }
    }
}
