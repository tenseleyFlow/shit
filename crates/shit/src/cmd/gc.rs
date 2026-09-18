// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit gc` — manual blob-store garbage collection trigger (S13.8).
//!
//! Dispatches to the daemon's ctl `Gc(GcRequest)` endpoint (S13.7).

use clap::Args;
use shit_proto::{CtlRequest, CtlResponse, GcRequest, GcWallRequest};

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
    /// Override the age cap in wall-clock seconds for this run.
    #[arg(long)]
    pub age_cap_secs: Option<u64>,
    /// Removed: logical counters do not measure elapsed time. Use
    /// `--age-cap-secs`; this flag is accepted only to emit a clear error.
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
    if args.age_cap_logical.is_some() {
        return Err(CliError::fail(
            GENERIC_FAILURE,
            "--age-cap-logical is no longer supported; use --age-cap-secs",
        ));
    }
    let ctl_path = args
        .ctl_sock
        .clone()
        .unwrap_or_else(crate::paths::default_ctl_socket_path);
    let req = if let Some(age_cap_secs) = args.age_cap_secs {
        CtlRequest::GcWall(GcWallRequest {
            dry_run: args.dry_run,
            aggressive: args.aggressive,
            size_cap_bytes: args.size_cap,
            age_cap_secs: Some(age_cap_secs),
        })
    } else {
        // Preserve ordinary GC interoperability with older daemons. Only the
        // new seconds override needs the append-only GcWall protocol seam.
        CtlRequest::Gc(GcRequest {
            dry_run: args.dry_run,
            aggressive: args.aggressive,
            size_cap_bytes: args.size_cap,
            age_cap_logical: None,
        })
    };
    let resp = ctl_client::call(&ctl_path, &req)?;
    match resp {
        CtlResponse::GcReport(r) => {
            if args.json {
                crate::render::write_json(&mut std::io::stdout(), &r)
                    .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("json: {e}")))?;
                return Ok(());
            }
            print_report(
                r.dry_run,
                r.aggressive_mode_used,
                None,
                r.commands_dropped,
                r.events_dropped,
                r.blobs_swept,
                r.bytes_reclaimed,
                r.paths_compacted,
                r.vacuumed,
                r.duration_ms,
            );
            Ok(())
        }
        CtlResponse::GcWallReport(r) => {
            if args.json {
                crate::render::write_json(&mut std::io::stdout(), &r)
                    .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("json: {e}")))?;
                return Ok(());
            }
            print_report(
                r.dry_run,
                r.aggressive_mode_used,
                Some(r.age_expiry_suppressed),
                r.commands_dropped,
                r.events_dropped,
                r.blobs_swept,
                r.bytes_reclaimed,
                r.paths_compacted,
                r.vacuumed,
                r.duration_ms,
            );
            Ok(())
        }
        CtlResponse::Error(e) => Err(CliError::fail(GENERIC_FAILURE, format!("daemon: {e}"))),
        other => Err(CliError::fail(
            GENERIC_FAILURE,
            format!("unexpected response: {other:?}"),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn print_report(
    dry_run: bool,
    aggressive_mode_used: bool,
    age_expiry_suppressed: Option<bool>,
    commands_dropped: u64,
    events_dropped: u64,
    blobs_swept: u64,
    bytes_reclaimed: u64,
    paths_compacted: u64,
    vacuumed: bool,
    duration_ms: u64,
) {
    let mode = if aggressive_mode_used {
        "aggressive"
    } else {
        "default"
    };
    let action = if dry_run { "would " } else { "" };
    println!(
        "shit gc ({mode}{}):",
        if dry_run { ", dry-run" } else { "" }
    );
    println!("  {action}drop  : {commands_dropped} commands ({events_dropped} events)");
    println!("  {action}sweep : {blobs_swept} blobs ({bytes_reclaimed} bytes)");
    println!("  {action}compact paths: {paths_compacted}");
    println!("  vacuumed       : {vacuumed}");
    if let Some(suppressed) = age_expiry_suppressed {
        println!(
            "  age expiry     : {}",
            if suppressed {
                "suppressed (wall-clock quarantine)"
            } else {
                "enabled"
            }
        );
    }
    println!("  pass took      : {duration_ms} ms");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_logical_age_flag_errors_before_contacting_daemon() {
        let error = run(GcArgs {
            dry_run: false,
            aggressive: false,
            size_cap: None,
            age_cap_secs: None,
            age_cap_logical: Some(7),
            ctl_sock: Some(std::path::PathBuf::from("/definitely/not/a/socket")),
            json: false,
        })
        .unwrap_err();
        assert!(error.to_string().contains("--age-cap-logical"));
        assert!(error.to_string().contains("--age-cap-secs"));
    }
}
