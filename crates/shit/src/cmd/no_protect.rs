// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit --no-protect <command...>` escape hatch.
//!
//! Runs the user's command **without** capture protection — bypasses
//! the hard-fail when the daemon would refuse the command. Recorded
//! in the journal as a `Bypassed` entry so the user can see what
//! they opted out of (and not undo it later).
//!
//! Stage 1: spawns the user's command directly (no daemon notify yet).
//! The journal-write side lands when the daemon ctl endpoint exposes
//! a `Bypassed` event variant.

use clap::Args;

use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct NoProtectArgs {
    /// Command argv, including the binary. Example:
    /// `shit no-protect -- rm -rf ~/scratch`.
    ///
    /// The leading `--` is recommended to separate this from `shit`'s
    /// own flag parsing.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
    pub command: Vec<String>,
}

pub fn run(args: NoProtectArgs) -> Result<(), CliError> {
    let Some((bin, rest)) = args.command.split_first() else {
        return Err(CliError::fail(
            GENERIC_FAILURE,
            "no-protect: no command given",
        ));
    };
    // Stage 1: just exec the command. Daemon-notify (record as
    // Bypassed) lands when the daemon endpoint exists.
    let status = std::process::Command::new(bin).args(rest).status()?;
    if !status.success() {
        return Err(CliError::fail(
            status.code().map(|c| c as u8).unwrap_or(GENERIC_FAILURE),
            format!("`{bin}` exited with {status}"),
        ));
    }
    Ok(())
}
