// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit redo` — re-apply the most recently-undone command.
//!
//! Per S11's design (DR-16): the executor records each undo in its
//! exec log, tagged `kind = SystemUndo`. `shit redo` invokes the same
//! orchestrator with the *forward* op derived from the original event
//! sequence — not a stored "redo journal." This keeps redo idempotent
//! and avoids a parallel storage path.
//!
//! Stage 1: CLI shape. Real wiring needs:
//! 1. Daemon endpoint to look up "the most recent SystemUndo".
//! 2. `shit-planner` `forward_plan(events)` constructor — currently
//!    only `plan()` (the inverse) exists. Adding it is small.
//! 3. The orchestrator handles forward and inverse identically since
//!    it executes whatever `InverseOp`s land in the plan.

use clap::Args;

use crate::cmd::undo::ConflictPolicyArg;
use crate::exitcode::CliError;

#[derive(Debug, Clone, Args)]
pub struct RedoArgs {
    /// Show the forward plan without executing.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
    /// Conflict policy (live state may have diverged since the undo).
    #[arg(long, value_enum, default_value_t = ConflictPolicyArg::Abort)]
    pub on_conflict: ConflictPolicyArg,
    /// Required with `--on-conflict=force`.
    #[arg(long, default_value_t = false)]
    pub yes: bool,
}

pub fn run(args: RedoArgs) -> Result<(), CliError> {
    println!("shit redo — stage 1 (DR-16; forward-plan builder in planner not yet implemented)");
    println!(
        "  dry_run={}, on_conflict={:?}, yes={}",
        args.dry_run, args.on_conflict, args.yes
    );
    Ok(())
}
