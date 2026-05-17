// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit pin <id>` — protect a captured command's savepoint from GC
//! (real implementation, S13.8).
//!
//! Also supports `shit pin --list` per the S13 open-question default.

use clap::{ArgAction, Args};
use shit_proto::{CtlRequest, CtlResponse, PinRequest};

use crate::cmd::ctl_client;
use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct PinArgs {
    /// Command id to pin. Format `<session>:<seq>`. Required unless
    /// `--list` is passed.
    pub id: Option<String>,
    /// Optional human-friendly name to remember it by. Surfaces in
    /// `shit pin --list`.
    #[arg(long)]
    pub name: Option<String>,
    /// TTL for the pin (e.g. `7d`, `12h`). Default: no expiry.
    /// **Stage 1:** the daemon does not yet parse the duration string;
    /// it stores None either way. The flag is accepted so user-visible
    /// behavior matches the eventual semantics.
    #[arg(long)]
    pub expire: Option<String>,
    /// List currently pinned commands. Skips `id` and `--name`.
    #[arg(long, action = ArgAction::SetTrue)]
    pub list: bool,
    /// JSON output (`--list` only).
    #[arg(long, default_value_t = false)]
    pub json: bool,
    /// Override the daemon ctl socket path.
    #[arg(long)]
    pub ctl_sock: Option<std::path::PathBuf>,
}

pub fn run(args: PinArgs) -> Result<(), CliError> {
    let ctl_path = args
        .ctl_sock
        .clone()
        .unwrap_or_else(crate::paths::default_ctl_socket_path);
    if args.list {
        let resp = ctl_client::call(&ctl_path, &CtlRequest::PinList)?;
        return render_list(resp, args.json);
    }
    let id = args
        .id
        .ok_or_else(|| CliError::fail(GENERIC_FAILURE, "pin: missing <id> (or pass --list)"))?;
    let resp = ctl_client::call(
        &ctl_path,
        &CtlRequest::Pin(PinRequest {
            id: id.clone(),
            name: args.name.clone(),
            expire: args.expire.clone(),
        }),
    )?;
    match resp {
        CtlResponse::PinAck => {
            println!("pinned: {id}");
            Ok(())
        }
        CtlResponse::Error(e) => Err(CliError::fail(GENERIC_FAILURE, format!("daemon: {e}"))),
        other => Err(CliError::fail(
            GENERIC_FAILURE,
            format!("unexpected response: {other:?}"),
        )),
    }
}

fn render_list(resp: CtlResponse, json: bool) -> Result<(), CliError> {
    match resp {
        CtlResponse::Pins(pins) => {
            if json {
                crate::render::write_json(&mut std::io::stdout(), &pins)
                    .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("json: {e}")))?;
                return Ok(());
            }
            if pins.is_empty() {
                println!("(no pinned commands)");
            } else {
                println!(
                    "{:<24}  {:<20}  pinned@  expires",
                    "command-id-prefix", "name"
                );
                for p in &pins {
                    let short_id = p.id.chars().take(24).collect::<String>();
                    let name = p.name.as_deref().unwrap_or("");
                    let exp = p
                        .expires_logical
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "-".into());
                    println!(
                        "{:<24}  {:<20}  {}       {}",
                        short_id, name, p.pinned_logical, exp
                    );
                }
            }
            Ok(())
        }
        CtlResponse::Error(e) => Err(CliError::fail(GENERIC_FAILURE, format!("daemon: {e}"))),
        other => Err(CliError::fail(
            GENERIC_FAILURE,
            format!("unexpected response: {other:?}"),
        )),
    }
}
