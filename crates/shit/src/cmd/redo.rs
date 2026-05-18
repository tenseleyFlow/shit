// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit redo` — re-apply the most recently-undone command.
//!
//! DR-16 design: `shit-planner::plan_forward` produces the forward
//! plan from the original event sequence. The orchestrator executes
//! it the same way it executes an inverse plan; the executor doesn't
//! need a new mode.
//!
//! The forward planner now exists (`crate::cmd::redo` calls into
//! `shit_planner::plan_forward::plan_forward`). What's still
//! deferred for true end-to-end:
//! 1. Daemon endpoint to look up "the most recent SystemUndo" so
//!    this command can fetch the events to forward-plan.
//! 2. CLI integration with the daemon fetch path (gated on the
//!    same runtime work that `shit undo` waits on).

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
    println!("shit redo — DR-16 forward planner ready");
    println!(
        "  dry_run={}, on_conflict={:?}, yes={}",
        args.dry_run, args.on_conflict, args.yes
    );
    println!(
        "The `shit_planner::plan_forward::plan_forward` constructor \
         emits the redo plan; daemon-fetch wiring for the original \
         event sequence is still on the runtime-capture path."
    );
    Ok(())
}
