// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit gc` — manual blob-store garbage collection trigger.
//!
//! Stage 1: CLI shape only. The actual sweep policy + executor lives
//! in S13 (retention-gc sprint). This command is the user-facing
//! handle the daemon and S13 share.

use clap::Args;

use crate::exitcode::CliError;

#[derive(Debug, Clone, Args)]
pub struct GcArgs {
    /// Show what would be reclaimed without actually deleting.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
    /// Run the policy harder than the default (shorter TTL window,
    /// smaller per-session caps). Useful when disk pressure is acute.
    #[arg(long, default_value_t = false)]
    pub aggressive: bool,
    /// Cap total blob-store size at this many bytes; reclaim down to
    /// the cap. Accepts suffixes via the user's shell — pass raw bytes.
    #[arg(long)]
    pub size_cap: Option<u64>,
    /// Drop blobs older than this duration (e.g. `7d`, `12h`).
    #[arg(long)]
    pub age_cap: Option<String>,
}

pub fn run(args: GcArgs) -> Result<(), CliError> {
    println!("shit gc — stage 1 (sweep policy lands in S13)");
    println!(
        "  dry_run={}, aggressive={}, size_cap={:?}, age_cap={:?}",
        args.dry_run, args.aggressive, args.size_cap, args.age_cap
    );
    Ok(())
}
