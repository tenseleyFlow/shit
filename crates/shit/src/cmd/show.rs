// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit show <id>` — full detail surface for one captured command.
//!
//! Stage 1: CLI shape + JSON skeleton. The detail body is fetched
//! from the daemon's plan-and-events endpoint (not yet exposed).

use clap::Args;

use crate::exitcode::CliError;
use crate::render::write_json;

#[derive(Debug, Clone, Args)]
pub struct ShowArgs {
    /// Command id from `shit list`. Format is `<session-uuid>:<seq>`.
    pub id: String,
    /// Show post-execution records from the exec log instead of (or
    /// alongside) the capture journal.
    #[arg(long, default_value_t = false)]
    pub exec: bool,
    /// Emit a JSON envelope instead of human-readable output.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(serde::Serialize)]
struct ShowBody {
    id: String,
    found: bool,
    note: &'static str,
}

pub fn run(args: ShowArgs) -> Result<(), CliError> {
    let body = ShowBody {
        id: args.id.clone(),
        found: false,
        note: "stage 1: daemon detail endpoint not yet wired",
    };
    if args.json {
        write_json(&mut std::io::stdout(), &body)
            .map_err(|e| CliError::fail(1, format!("json: {e}")))?;
        return Ok(());
    }
    println!("shit show {} — stage 1", args.id);
    if args.exec {
        println!(
            "(exec log replay is implemented as `shit_planner::exec_log::read_all`; \
             the CLI wiring lands once `shit show --exec` knows where to look — \
             needs the daemon to surface the per-undo log paths)"
        );
    } else {
        println!("(no captured detail; daemon command-detail endpoint not yet wired)");
    }
    Ok(())
}
