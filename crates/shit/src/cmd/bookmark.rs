// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit bookmark <id>` — create a metadata-only durable reference to a
//! captured command. Unlike `pin`, a bookmark survives blob-tier GC AND
//! the eventual reaping of the underlying command row (C01.7).
//!
//! - `shit bookmark <id> [--note ...]` — create.
//! - `shit bookmark --list` — enumerate.
//! - `shit bookmark --remove <id>` — drop.

use clap::{ArgAction, Args};
use shit_proto::{BookmarkRequest, CtlRequest, CtlResponse};

use crate::cmd::ctl_client;
use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct BookmarkArgs {
    /// Command id to bookmark. Format `<session>:<seq>`. Required unless
    /// `--list` or `--remove` is passed.
    pub id: Option<String>,
    /// Optional human-readable note. Surfaces in `--list`.
    #[arg(long)]
    pub note: Option<String>,
    /// List existing bookmarks.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "remove")]
    pub list: bool,
    /// Remove the bookmark for the given id.
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "list")]
    pub remove: bool,
    /// Don't prompt before removing. Required when stdin isn't a TTY.
    #[arg(long, default_value_t = false)]
    pub yes: bool,
    /// JSON output (`--list` only).
    #[arg(long, default_value_t = false)]
    pub json: bool,
    /// Override the daemon ctl socket path.
    #[arg(long)]
    pub ctl_sock: Option<std::path::PathBuf>,
}

pub fn run(args: BookmarkArgs) -> Result<(), CliError> {
    let ctl_path = args
        .ctl_sock
        .clone()
        .unwrap_or_else(crate::paths::default_ctl_socket_path);

    if args.list {
        let resp = ctl_client::call(&ctl_path, &CtlRequest::BookmarkList)?;
        return render_list(resp, args.json);
    }

    let id = args.id.ok_or_else(|| {
        CliError::fail(GENERIC_FAILURE, "bookmark: missing <id> (or pass --list)")
    })?;

    if args.remove {
        let resp = ctl_client::call(
            &ctl_path,
            &CtlRequest::BookmarkRemove {
                id: id.clone(),
                yes: args.yes,
            },
        )?;
        return match resp {
            CtlResponse::BookmarkAck => {
                println!("removed bookmark: {id}");
                Ok(())
            }
            CtlResponse::Error(e) => Err(CliError::fail(GENERIC_FAILURE, format!("daemon: {e}"))),
            other => Err(CliError::fail(
                GENERIC_FAILURE,
                format!("unexpected response: {other:?}"),
            )),
        };
    }

    let resp = ctl_client::call(
        &ctl_path,
        &CtlRequest::Bookmark(BookmarkRequest {
            id: id.clone(),
            note: args.note.clone(),
        }),
    )?;
    match resp {
        CtlResponse::BookmarkAck => {
            println!("bookmarked: {id}");
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
        CtlResponse::Bookmarks(rows) => {
            if json {
                crate::render::write_json(&mut std::io::stdout(), &rows)
                    .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("json: {e}")))?;
                return Ok(());
            }
            if rows.is_empty() {
                println!("(no bookmarks)");
            } else {
                println!("{:<40}  {:<8}  note", "id", "created");
                for b in &rows {
                    let short = b.id.chars().take(40).collect::<String>();
                    let note = b.note.as_deref().unwrap_or("");
                    println!("{:<40}  {:<8}  {}", short, b.created_logical, note);
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
