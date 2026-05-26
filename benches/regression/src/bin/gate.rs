// SPDX-License-Identifier: AGPL-3.0-or-later

//! B07 — perf budget gate. Reads a bench JSON (RunResult) and
//! compares its p50/p99 against `tools/perf/budgets.toml`.
//! Exits 0 within budget, 1 on breach, 2 on missing/unknown gate
//! (so CI surfaces config drift loud).
//!
//! Usage: `gate --gate <name> --input <result.json>
//!              [--budgets <path>] [--skip-on-missing-gate]`
//!
//! `--skip-on-missing-gate` lets the workflow keep running while
//! new bins are being added; without it, an unknown `<name>` fails
//! with exit 2.
//!
//! Handles the cross-platform "skipped" placeholder some bins emit
//! on the wrong OS (e.g. kqueue-drain on Linux): if the JSON
//! contains `"skipped": "..."`, the gate prints + exits 0.

use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "gate", about = "B07 perf budget gate")]
struct Args {
    /// Gate name to enforce (e.g. "doctor", "shell-hook").
    #[arg(long)]
    gate: String,
    /// Path to the bench JSON to evaluate.
    #[arg(long)]
    input: PathBuf,
    /// Path to budgets.toml. Defaults to tools/perf/budgets.toml.
    #[arg(long, default_value = "tools/perf/budgets.toml")]
    budgets: PathBuf,
    /// If the gate name isn't in budgets.toml, exit 0 instead of
    /// the default exit 2. Useful when iterating bin additions.
    #[arg(long)]
    skip_on_missing_gate: bool,
}

#[derive(Debug, Deserialize)]
struct BudgetsFile {
    #[serde(default)]
    gate: Vec<GateEntry>,
}

#[derive(Debug, Deserialize)]
struct GateEntry {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default = "default_kind")]
    kind: String,
    p50_us: u64,
    p99_us: u64,
    fail_at_p99_us: u64,
}

fn default_kind() -> String {
    "latency".into()
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BenchJson {
    Result {
        workload: String,
        host_os: String,
        host_arch: String,
        median_us: u64,
        p99_us: u64,
        n_kept: usize,
    },
    Skipped {
        workload: String,
        skipped: String,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    let raw = std::fs::read_to_string(&args.input)
        .with_context(|| format!("read {}", args.input.display()))?;
    let parsed: BenchJson =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", args.input.display()))?;

    let (workload, median_us, p99_us, host_os, host_arch, n_kept) = match parsed {
        BenchJson::Skipped { workload, skipped } => {
            println!("{}: SKIP ({skipped})", workload);
            return Ok(());
        }
        BenchJson::Result {
            workload,
            host_os,
            host_arch,
            median_us,
            p99_us,
            n_kept,
        } => (workload, median_us, p99_us, host_os, host_arch, n_kept),
    };

    let budgets_raw = std::fs::read_to_string(&args.budgets)
        .with_context(|| format!("read budgets {}", args.budgets.display()))?;
    let budgets: BudgetsFile = toml::from_str(&budgets_raw)
        .with_context(|| format!("parse budgets {}", args.budgets.display()))?;

    let Some(gate) = budgets.gate.iter().find(|g| g.name == args.gate) else {
        if args.skip_on_missing_gate {
            println!(
                "{}: SKIP (no '{}' gate in {})",
                workload,
                args.gate,
                args.budgets.display()
            );
            return Ok(());
        }
        eprintln!(
            "{}: gate '{}' not found in {} (use --skip-on-missing-gate to ignore)",
            workload,
            args.gate,
            args.budgets.display()
        );
        std::process::exit(2);
    };

    let desc = gate.description.as_deref().unwrap_or("");
    let kind_label = match gate.kind.as_str() {
        "throughput" => "throughput",
        _ => "latency",
    };
    println!(
        "[{kind_label}] {workload} on {host_os}/{host_arch} (n_kept={n_kept}): \
         p50={median_us}µs p99={p99_us}µs vs budget p50≤{}µs p99≤{}µs fail≤{}µs",
        gate.p50_us, gate.p99_us, gate.fail_at_p99_us,
    );
    if !desc.is_empty() {
        println!("  {desc}");
    }

    let p50_breach = median_us > gate.p50_us;
    let p99_breach = p99_us > gate.p99_us;
    let p99_hard = p99_us > gate.fail_at_p99_us;

    if p99_hard {
        eprintln!(
            "{workload}: FAIL — p99 {p99_us}µs > 2x-ceiling {}µs",
            gate.fail_at_p99_us
        );
        std::process::exit(1);
    }
    if p50_breach || p99_breach {
        // Within the 2x ceiling but above p50/p99 budgets. Warn
        // loudly but still exit 0: this is the "approaching the
        // edge" zone, not "broken". Operator looks at the trend.
        eprintln!(
            "{workload}: WARN — within 2x ceiling but over budget \
             (p50_breach={p50_breach} p99_breach={p99_breach})"
        );
    } else {
        println!("{workload}: PASS");
    }
    Ok(())
}
