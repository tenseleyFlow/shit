// SPDX-License-Identifier: AGPL-3.0-or-later

//! `compare` — the CI gate. Loads a current bench result and (if
//! present) a baseline, applies the configured [`BudgetGate`], emits
//! a human-readable verdict, and exits 0 (pass) or 1 (fail).
//!
//! Designed to be the single command CI invokes after each bench run:
//!
//! ```bash
//! cargo run --release -p shit-regression-bench --bin compare -- \
//!     --current target/bench/tight-loop.json \
//!     --baseline benches/regression/baselines/ubuntu-24.04-x64.json \
//!     --gate shell-hook
//! ```
//!
//! Baseline-absent is a soft pass with a warning — the workflow keeps
//! moving on the first run on a new OS, and absolute-budget thresholds
//! still apply.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use shit_regression_bench::{
    BudgetGate, DEFAULT_MEDIAN_PCT, DEFAULT_P99_PCT, RegressionVerdict, detect_regression,
    from_json,
};

#[derive(Parser)]
#[command(name = "compare", about = "shit perf bench: regression gate")]
struct Args {
    /// Path to the current run's JSON result.
    #[arg(long)]
    current: std::path::PathBuf,
    /// Path to a baseline JSON. Soft-absent: if not present, only
    /// absolute-budget checks run.
    #[arg(long)]
    baseline: Option<std::path::PathBuf>,
    /// Which budget gate the workload is held to.
    #[arg(long)]
    gate: GateChoice,
    /// Skip the absolute-budget check. Use for unhooked floor
    /// measurements where the SHELL_HOOK budget doesn't apply
    /// (raw spawn cost dominates). Relative regression vs baseline
    /// is still enforced.
    #[arg(long)]
    no_budget: bool,
    /// Relative regression threshold for median (% slower than baseline).
    #[arg(long, default_value_t = DEFAULT_MEDIAN_PCT)]
    median_pct: f64,
    /// Relative regression threshold for p99.
    #[arg(long, default_value_t = DEFAULT_P99_PCT)]
    p99_pct: f64,
}

#[derive(Copy, Clone, ValueEnum)]
enum GateChoice {
    ShellHook,
    AuthEvent,
    PostexecAck,
    /// L01 fanotify-perm capture-to-ALLOW hot path.
    Capture,
    /// Kernel-overflow deadline (panic-grade; reserved for stress harnesses).
    CaptureKernelDeadline,
}

impl GateChoice {
    fn to_budget(self) -> BudgetGate {
        match self {
            GateChoice::ShellHook => BudgetGate::SHELL_HOOK,
            GateChoice::AuthEvent => BudgetGate::AUTH_EVENT,
            GateChoice::PostexecAck => BudgetGate::POSTEXEC_ACK,
            GateChoice::Capture => BudgetGate::CAPTURE_TO_ALLOW,
            GateChoice::CaptureKernelDeadline => BudgetGate::CAPTURE_KERNEL_DEADLINE,
        }
    }
}

fn main() -> Result<std::process::ExitCode> {
    let args = Args::parse();
    let current_raw = std::fs::read_to_string(&args.current)
        .with_context(|| format!("read {:?}", args.current))?;
    let current = from_json(&current_raw)?;
    let baseline = match args.baseline.as_deref() {
        Some(p) if p.exists() => {
            let raw = std::fs::read_to_string(p)?;
            Some(from_json(&raw)?)
        }
        Some(p) => {
            eprintln!("warning: baseline {p:?} not present; falling back to absolute-budget only");
            None
        }
        None => None,
    };
    // When --no-budget is set, swap in a "permissive" gate
    // (u64::MAX bounds) so detect_regression's absolute-budget
    // branches never fire; relative checks still apply.
    let gate = if args.no_budget {
        BudgetGate {
            median_us_max: u64::MAX,
            p99_us_max: u64::MAX,
        }
    } else {
        args.gate.to_budget()
    };
    let verdict = detect_regression(
        &current,
        baseline.as_ref(),
        gate,
        args.median_pct,
        args.p99_pct,
    );
    print_verdict(&current.workload, &verdict, &current);
    Ok(match verdict {
        RegressionVerdict::Pass => std::process::ExitCode::SUCCESS,
        _ => std::process::ExitCode::FAILURE,
    })
}

fn print_verdict(
    workload: &str,
    v: &RegressionVerdict,
    current: &shit_regression_bench::RunResult,
) {
    println!("workload: {workload}");
    println!(
        "samples: {} (kept after MAD: {})",
        current.n_total, current.n_kept
    );
    println!(
        "current: median={}µs p99={}µs mean={}µs min={}µs max={}µs",
        current.median_us, current.p99_us, current.mean_us, current.min_us, current.max_us
    );
    match v {
        RegressionVerdict::Pass => println!("verdict: PASS"),
        RegressionVerdict::BudgetExceededMedian { current, budget } => {
            println!("verdict: FAIL — median {current}µs > absolute budget {budget}µs");
        }
        RegressionVerdict::BudgetExceededP99 { current, budget } => {
            println!("verdict: FAIL — p99 {current}µs > absolute budget {budget}µs");
        }
        RegressionVerdict::MedianRegressed {
            baseline,
            current,
            pct_change,
        } => {
            println!(
                "verdict: FAIL — median regressed {pct_change:.1}% \
                 (baseline {baseline}µs, current {current}µs)"
            );
        }
        RegressionVerdict::P99Regressed {
            baseline,
            current,
            pct_change,
        } => {
            println!(
                "verdict: FAIL — p99 regressed {pct_change:.1}% \
                 (baseline {baseline}µs, current {current}µs)"
            );
        }
    }
}
