// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit pin <id>` — protect a captured command's savepoint from GC.
//!
//! Stage 1: CLI shape only. Pinning writes a row to the daemon's
//! retention table — that table doesn't exist yet (S13).

use clap::Args;

use crate::exitcode::CliError;

#[derive(Debug, Clone, Args)]
pub struct PinArgs {
    /// Command id to pin. Format `<session>:<seq>`.
    pub id: String,
    /// Optional human-friendly name to remember it by. Surfaces in
    /// `shit list --pinned` (S13).
    #[arg(long)]
    pub name: Option<String>,
}

pub fn run(args: PinArgs) -> Result<(), CliError> {
    println!(
        "shit pin {} (name={:?}) — stage 1 (retention table lands in S13)",
        args.id, args.name
    );
    Ok(())
}
