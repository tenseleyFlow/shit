// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit show <id>` — full detail surface for one captured command.
//!
//! AU30 replaced the stage-1 stub with a real ctl round-trip:
//! `CtlRequest::CmdDetail` → `CmdDetailBody` → human or JSON render.
//! The command body shows top-line metadata, the plan summary, and
//! every captured event. Per-event detail dispatches by
//! `kind_label` through [`crate::render::cmd_detail`]; new event
//! kinds round-trip via a generic JSON fallback so they're visible
//! even before a dedicated renderer lands.

use clap::Args;
use shit_proto::{CtlRequest, CtlResponse};

use crate::cmd::ctl_client;
use crate::exitcode::{CliError, GENERIC_FAILURE};
use crate::render::write_json;

#[derive(Debug, Clone, Args)]
pub struct ShowArgs {
    /// Command id from `shit list`. Format is `<session-uuid>:<seq>`,
    /// or a bookmark note (resolved daemon-side).
    pub id: String,
    /// Show post-execution records from the exec log instead of (or
    /// alongside) the capture journal.
    ///
    /// Stage-1 stub — the exec-log endpoint isn't wired through ctl
    /// yet. Daemon needs to surface per-undo log paths first; until
    /// then this flag prints a short deferral note.
    #[arg(long, default_value_t = false)]
    pub exec: bool,
    /// Include the shell-state diff section in the output when the
    /// command's undo plan contains a `ShellStateRestore` op.
    ///
    /// Stage-1 — needs DR-CR-50 (precmd-queue mechanism) for the
    /// `--apply-shell-state` dispatch path. The plan summary still
    /// reports `ShellState` tier counts; this flag controls a
    /// future detailed-diff section.
    #[arg(long = "shell-state", default_value_t = false)]
    pub shell_state: bool,
    /// Cap the events list at this many entries (default 200). The
    /// body's `events_total` always reports the full count; the
    /// renderer notes "(N more truncated — use --json for the full
    /// envelope)" when the cap fires.
    #[arg(long = "events-limit", default_value_t = 200)]
    pub events_limit: usize,
    /// Emit a JSON envelope of the full `CmdDetailBody` instead of
    /// the human-readable rendering.
    #[arg(long, default_value_t = false)]
    pub json: bool,
    /// Override the ctl socket path (test harnesses).
    #[arg(long, hide = true)]
    pub ctl_sock: Option<std::path::PathBuf>,
}

pub fn run(args: ShowArgs) -> Result<(), CliError> {
    let ctl_path = args
        .ctl_sock
        .clone()
        .unwrap_or_else(crate::paths::default_ctl_socket_path);

    let req = CtlRequest::CmdDetail {
        id: args.id.clone(),
        events_limit: Some(args.events_limit),
    };
    let resp = ctl_client::call(&ctl_path, &req)?;

    let body = match resp {
        CtlResponse::CmdDetail(body) => body,
        CtlResponse::CmdNotFound { id } => {
            return Err(CliError::fail(
                GENERIC_FAILURE,
                format!("no captured command for id `{id}`"),
            ));
        }
        CtlResponse::Error(e) => {
            return Err(CliError::fail(GENERIC_FAILURE, format!("daemon: {e}")));
        }
        other => {
            return Err(CliError::fail(
                GENERIC_FAILURE,
                format!("unexpected response: {other:?}"),
            ));
        }
    };

    if args.json {
        write_json(&mut std::io::stdout(), &body)
            .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("json: {e}")))?;
        return Ok(());
    }

    let mut out = std::io::stdout();
    crate::render::cmd_detail::render(&mut out, &body, args.exec, args.shell_state)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("render: {e}")))?;
    Ok(())
}
