// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit list` — captured commands in this session (and across).
//!
//! Stage 1: CLI shape + JSON envelope. The actual journal-fetch goes
//! through the daemon ctl IPC, which doesn't yet expose this endpoint
//! — added in S02 follow-up. The DEFERRED-RUNTIME doc tracks the
//! capture-pipeline prerequisite.

use clap::Args;

use crate::exitcode::CliError;
use crate::render::write_json;

#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// Restrict to one session uuid. Default: current shell's session.
    #[arg(long)]
    pub session: Option<String>,
    /// Maximum number of rows. Open-question default is 20.
    #[arg(long, default_value_t = 20)]
    pub limit: u32,
    /// Restrict to commands within a duration of now (e.g. `5m`, `1h`).
    #[arg(long)]
    pub since: Option<String>,
    /// Include `SystemUndo`-tagged entries (the executor's own writes).
    #[arg(long, default_value_t = false)]
    pub include_system: bool,
    /// Emit a JSON envelope instead of a table.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(serde::Serialize)]
struct ListBody {
    commands: Vec<CommandRow>,
    truncated: bool,
}

#[derive(serde::Serialize)]
struct CommandRow {
    id: String,
    time_iso: String,
    cwd: String,
    cmd: String,
    files_touched: u32,
    status: &'static str,
    pinned: bool,
}

pub fn run(args: ListArgs) -> Result<(), CliError> {
    // Stage-1 body: empty list with a clear status note.
    let body = ListBody {
        commands: Vec::new(),
        truncated: false,
    };
    if args.json {
        write_json(&mut std::io::stdout(), &body)
            .map_err(|e| CliError::fail(1, format!("json: {e}")))?;
        return Ok(());
    }
    println!("shit list — stage 1 (daemon command-journal endpoint not yet wired)");
    println!(
        "  filters: session={:?}, limit={}, since={:?}, include_system={}",
        args.session, args.limit, args.since, args.include_system
    );
    println!();
    println!("(no captured commands; capture-runtime pipeline is in DEFERRED-RUNTIME.md)");
    Ok(())
}
