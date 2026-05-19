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

    // DR-17: compile --paths filters here so a malformed pattern
    // fails the command before any daemon round-trip. The compiled
    // GlobSet is what the orchestrator's `with_paths_filter`
    // consumes once the daemon-fetch path lights up.
    let paths_filter = match shit_planner::compile_paths_filter(&args.paths) {
        Ok(set) => set,
        Err(e) => {
            eprintln!("{e}");
            return Err(anyhow::anyhow!("invalid --paths pattern"));
        }
    };

    // Stage 1: print a clear status message describing what would happen.
    // Real plumbing (daemon → plan fetch → orchestrator.run) lands once
    // the runtime capture pipeline is wired (DR-* items in
    // .docs/sprints/DEFERRED-RUNTIME.md).
    let policy: ConflictPolicy = args.on_conflict.into();
    println!("shit undo — stage 1 (executor + orchestrator landed; daemon plumbing pending)");
    println!("  steps:       {}", args.steps);
    println!("  dry-run:     {}", args.dry_run);
    println!("  on-conflict: {policy:?}");
    println!("  raw:         {}", args.raw);
    println!(
        "  paths:       {:?}{}",
        args.paths,
        if paths_filter.is_some() {
            " (compiled)"
        } else {
            ""
        }
    );
    println!();
    println!(
        "The S11 executor pipeline is in place: \
         FileExecutor + Orchestrator + ExecLog all work against an UndoPlan."
    );
    println!(
        "The daemon-side plan-fetch endpoint that supplies the plan to this \
         command is on the S12 / runtime-capture path; see \
         .docs/sprints/DEFERRED-RUNTIME.md for tracking."
    );
    Ok(())
}
