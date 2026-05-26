// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit undo` — the entry point users actually care about.
//!
//! ## The bare-`shit`-is-undo rule
//!
//! Typing `shit` with no args runs `shit undo` with default args.
//! That's the single sentence that explains the project's name. The
//! rule has a sharp edge in the CLI: bare `shit` does **not** accept
//! the args/flags that `shit undo` does. `shit --dry-run` is an
//! error; `shit undo --dry-run` is the dry-run.
//!
//! The enforcement happens at the parser layer (see `main.rs`):
//! the top-level `Cli.cmd` is an `Option<Cmd>` — when None, we
//! dispatch here with `UndoArgs::default()`, never parsing any
//! further argv tokens at the top level.
//!
//! ## Stage 1 scope
//!
//! Stage 1 of S11 ships the executor + orchestrator + exec log
//! against synthetic plans. The daemon ↔ planner ↔ CLI plumbing
//! that hands a real `UndoPlan` to this command lives partly in S12
//! (CLI surface) and partly in the deferred runtime-capture sprints
//! (DR-* in `DEFERRED-RUNTIME.md`). Stage 1 prints a clear
//! message describing what would happen and returns 0 — no
//! mutation, no failure.

use std::path::PathBuf;

use clap::{ArgAction, Args, ValueEnum};
use shit_planner::ConflictPolicy;

/// Args for `shit undo`. Default values land when the user types
/// bare `shit`.
#[derive(Debug, Clone, Args)]
pub struct UndoArgs {
    /// How many commands back to undo. `1` (the default) means "undo
    /// the most recent command." `N` means "undo N commands in
    /// LIFO order."
    #[arg(default_value_t = 1)]
    pub steps: u32,

    /// Show what would happen without mutating anything.
    #[arg(long, action = ArgAction::SetTrue)]
    pub dry_run: bool,

    /// How to handle conflicts (live state differs from captured state).
    /// `abort` halts at the first blocking conflict (default), `skip`
    /// records conflicts and keeps going, `force` applies over them
    /// (requires `--yes`).
    #[arg(long, value_enum, default_value_t = ConflictPolicyArg::Abort)]
    pub on_conflict: ConflictPolicyArg,

    /// Acknowledge the risk of `--on-conflict=force`. Required when
    /// `--on-conflict=force` is set.
    #[arg(long, action = ArgAction::SetTrue)]
    pub yes: bool,

    /// Bypass smart-render heuristics (e.g. the `.git/` summary) and
    /// show the raw inverse-op list. Useful for debugging.
    #[arg(long, action = ArgAction::SetTrue)]
    pub raw: bool,

    /// Restrict the undo to paths matching one of these glob patterns.
    /// May be passed multiple times: `--paths '/etc/**' --paths '/var/log/**'`.
    /// Ops with no path (env, package, etc.) are not affected by this
    /// filter — they always pass.
    #[arg(long = "paths", action = ArgAction::Append)]
    pub paths: Vec<String>,

    /// Override the daemon ctl socket. Diagnostic; not for normal use.
    #[arg(long)]
    pub ctl_sock: Option<PathBuf>,

    /// C06.8: when a `ShellStateRestore` op is in the plan, queue the
    /// per-shell undo snippet through the bash / zsh precmd
    /// mechanism so it applies before your next prompt. Fish refuses
    /// (no safe precmd-queue equivalent). OFF BY DEFAULT — surprise-
    /// mutating the interactive shell is worse UX than missing one
    /// undo step; opt in explicitly per invocation.
    #[arg(long = "apply-shell-state", action = ArgAction::SetTrue)]
    pub apply_shell_state: bool,
}

impl Default for UndoArgs {
    fn default() -> Self {
        Self {
            steps: 1,
            dry_run: false,
            on_conflict: ConflictPolicyArg::Abort,
            yes: false,
            raw: false,
            paths: Vec::new(),
            ctl_sock: None,
            apply_shell_state: false,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ConflictPolicyArg {
    Abort,
    Skip,
    Force,
}

impl From<ConflictPolicyArg> for ConflictPolicy {
    fn from(c: ConflictPolicyArg) -> Self {
        match c {
            ConflictPolicyArg::Abort => Self::Abort,
            ConflictPolicyArg::Skip => Self::Skip,
            ConflictPolicyArg::Force => Self::Force,
        }
    }
}

/// Entry point for the `shit undo` subcommand AND the bare-`shit`
/// invocation.
pub fn run(args: UndoArgs) -> anyhow::Result<()> {
    // Force requires explicit consent.
    if matches!(args.on_conflict, ConflictPolicyArg::Force) && !args.yes {
        eprintln!(
            "refusing `--on-conflict=force` without `--yes`. \
             Force-applying overwrites the user's changes after capture; \
             you must opt in explicitly."
        );
        return Err(anyhow::anyhow!("force without --yes"));
    }

    // Compile --paths filters here so a malformed pattern fails before
    // we round-trip the daemon. The compiled set is then ignored — the
    // daemon recompiles from the raw strings itself. We do this client
    // side first because the error message is friendlier.
    if let Err(e) = shit_planner::compile_paths_filter(&args.paths) {
        eprintln!("{e}");
        return Err(anyhow::anyhow!("invalid --paths pattern"));
    }

    let policy_wire = match args.on_conflict {
        ConflictPolicyArg::Abort => shit_proto::ConflictPolicyWire::Abort,
        ConflictPolicyArg::Skip => shit_proto::ConflictPolicyWire::Skip,
        ConflictPolicyArg::Force => shit_proto::ConflictPolicyWire::Force,
    };
    let req = shit_proto::CtlRequest::Undo(shit_proto::UndoRequest {
        steps: args.steps,
        dry_run: args.dry_run,
        on_conflict: policy_wire,
        paths: args.paths.clone(),
    });

    let ctl_path = args
        .ctl_sock
        .clone()
        .unwrap_or_else(crate::paths::default_ctl_socket_path);
    let resp = crate::cmd::ctl_client::call(&ctl_path, &req)
        .map_err(|e| anyhow::anyhow!("daemon call failed: {e:?}"))?;

    match resp {
        shit_proto::CtlResponse::UndoReport(report) => {
            println!("{}", report.summary);
            if !report.detail_lines.is_empty() {
                println!();
                for line in &report.detail_lines {
                    println!("  {line}");
                }
            }
            // AR07.2: render the refuse-list short-circuits in their
            // own block. Refusals aren't conflicts or failures —
            // they're honest "we can't do this, and here's why" — so
            // they get their own header to keep the user's eye from
            // confusing them with actionable problems.
            if !report.refusal_lines.is_empty() {
                println!();
                println!("Refused (out of scope for shit undo):");
                for line in &report.refusal_lines {
                    println!("  {line}");
                }
            }
            // Exit non-zero when anything failed/conflicted so scripts
            // and the smoke matrix get an actionable status.
            if report.ops_failed > 0 || report.ops_conflicted > 0 {
                return Err(anyhow::anyhow!(
                    "undo: {} failed, {} conflicted",
                    report.ops_failed,
                    report.ops_conflicted,
                ));
            }
            // AR07.2: a plan whose ONLY content was refusals isn't
            // a success — the user typed `shit undo` expecting
            // something to happen. Exit non-zero so scripts can
            // see this state, but with a different message than
            // failed/conflicted (no remediation, no "fix this").
            if report.ops_applied == 0
                && report.ops_refused > 0
                && report.ops_failed == 0
                && report.ops_conflicted == 0
            {
                return Err(anyhow::anyhow!(
                    "undo: nothing applicable — {} refused class(es) only",
                    report.ops_refused,
                ));
            }
            Ok(())
        }
        shit_proto::CtlResponse::Error(msg) => Err(anyhow::anyhow!("daemon error: {msg}")),
        other => Err(anyhow::anyhow!("unexpected ctl response: {other:?}")),
    }
}
