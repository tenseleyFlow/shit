// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit disable` / `shit enable` — temporarily turn capture off.
//!
//! Three shapes:
//!
//! - `shit disable` — toggle session-wide capture off until manually
//!   re-enabled or the shell exits.
//! - `shit disable --duration 1h` — auto re-enable after the duration.
//! - `shit disable --this-shell` — disable for the current shell only
//!   (env-var-scoped); other shells in the same session keep capturing.
//!
//! Stage 1: CLI shape; the daemon-side toggle endpoint lands in S02
//! follow-up. The `--this-shell` form is purely client-side (writes
//! an env var into the hook output) and could land sooner if needed.

use clap::Args;

use crate::exitcode::CliError;

#[derive(Debug, Clone, Args)]
pub struct DisableArgs {
    /// How long to stay disabled. Format `<N><unit>` (`5m`, `2h`, `1d`).
    /// Without this flag, capture stays off until `shit enable` or
    /// shell exit (with `--this-shell`).
    #[arg(long)]
    pub duration: Option<String>,
    /// Scope the disable to the current shell. Otherwise affects the
    /// whole session for this user.
    #[arg(long, default_value_t = false)]
    pub this_shell: bool,
}

pub fn run(args: DisableArgs) -> Result<(), CliError> {
    println!(
        "shit disable — stage 1 (daemon toggle endpoint pending; duration={:?}, this_shell={})",
        args.duration, args.this_shell
    );
    Ok(())
}

#[derive(Debug, Clone, Args)]
pub struct EnableArgs;

pub fn enable(_: EnableArgs) -> Result<(), CliError> {
    println!("shit enable — stage 1 (daemon toggle endpoint pending)");
    Ok(())
}
