// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit gc` — manual blob-store garbage collection trigger (S13.8).
//!
//! Dispatches to the daemon's ctl `Gc(GcRequest)` endpoint (S13.7).

use clap::Args;
use shit_proto::{CtlRequest, CtlResponse, GcRequest};

use crate::cmd::ctl_client;
use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct GcArgs {
    /// Show what would be reclaimed without actually deleting.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
    /// Run the policy harder than the default (shorter TTL window,
    /// smaller per-session caps). Useful when disk pressure is acute.
    #[arg(long, default_value_t = false)]
    pub aggressive: bool,
    /// Cap total blob-store size at this many bytes for this run only.
    #[arg(long)]
    pub size_cap: Option<u64>,
    /// Override the age cap in logical units for this run. Diagnostic;
    /// `--age-cap-secs` is the user-friendly form (lands when the
    /// daemon's wall→logical clock converter is wired).
    #[arg(long)]
    pub age_cap_logical: Option<u64>,
    /// Override the daemon ctl socket path.
    #[arg(long)]
    pub ctl_sock: Option<std::path::PathBuf>,
    /// JSON output instead of the human-readable summary.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub fn run(args: GcArgs) -> Result<(), CliError> {
    let ctl_path = args
        .ctl_sock
        .clone()
        .unwrap_or_else(crate::paths::default_ctl_socket_path);
    let req = CtlRequest::Gc(GcRequest {
        dry_run: args.dry_run,
        aggressive: args.aggressive,
        size_cap_bytes: args.size_cap,
        age_cap_logical: args.age_cap_logical,
    });
    let resp = ctl_client::call(&ctl_path, &req)?;
    match resp {
        CtlResponse::GcReport(r) => {
            if args.json {
                crate::render::write_json(&mut std::io::stdout(), &r)
                    .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("json: {e}")))?;
                return Ok(());
            }
            let mode = if r.aggressive_mode_used {
                "aggressive"
            } else {
                "default"
            };
            let action = if r.dry_run { "would " } else { "" };
            println!(
                "shit gc ({mode}{}):",
                if r.dry_run { ", dry-run" } else { "" }
            );
            println!(
                "  {action}drop  : {} commands ({} events)",
                r.commands_dropped, r.events_dropped
            );
            println!(
                "  {action}sweep : {} blobs ({} bytes)",
                r.blobs_swept, r.bytes_reclaimed
            );
            println!("  {action}compact paths: {}", r.paths_compacted);
            println!("  vacuumed       : {}", r.vacuumed);
            println!("  pass took      : {} ms", r.duration_ms);
            Ok(())
        }
        CtlResponse::Error(e) => Err(CliError::fail(GENERIC_FAILURE, format!("daemon: {e}"))),
        other => Err(CliError::fail(
            GENERIC_FAILURE,
            format!("unexpected response: {other:?}"),
        )),
    }
}
