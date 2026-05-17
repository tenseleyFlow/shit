// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit forget <id>` — drop a captured command's savepoint.
//!
//! Stage 1: CLI shape. Forgetting requires the daemon to (a) remove
//! the journal row, (b) decref-and-maybe-GC referenced blobs. The
//! blob GC half lives in S13.

use clap::Args;

use crate::exitcode::CliError;

#[derive(Debug, Clone, Args)]
pub struct ForgetArgs {
    /// Command id to forget. Format `<session>:<seq>`.
    pub id: String,
    /// Don't prompt before forgetting. Required when stdin isn't a TTY.
    #[arg(long, default_value_t = false)]
    pub yes: bool,
}

pub fn run(args: ForgetArgs) -> Result<(), CliError> {
    println!(
        "shit forget {} (yes={}) — stage 1 (daemon retention API lands in S13)",
        args.id, args.yes
    );
    Ok(())
}
