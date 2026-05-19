// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit container-stashes {list,prune}` — manage the C04 image /
//! volume tarball stash store. Image stashes are LARGE and short-lived
//! by design (1-day default retention); this CLI exists so users can
//! audit what's taking up disk and force a prune before the next GC
//! pass runs.

use clap::{Args, Subcommand};
use shit_proto::{CtlRequest, CtlResponse};

use crate::cmd::ctl_client;
use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct ContainerStashesArgs {
    #[command(subcommand)]
    pub action: ContainerStashesAction,
    /// Override the daemon ctl socket path.
    #[arg(long, global = true)]
    pub ctl_sock: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ContainerStashesAction {
    /// Enumerate active container stashes.
    List {
        /// JSON output.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Prune stashes older than `--before <duration>`.
    Prune {
        /// Drop stashes older than this duration. Accepts `s`/`m`/`h`/`d`
        /// suffixes (`90m`, `2h`, `7d`). Default `24h` matches
        /// `container_stash_retention_days = 1`.
        #[arg(long, default_value = "24h")]
        before: String,
        /// Don't prompt before pruning. Required when stdin isn't a TTY.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

pub fn run(args: ContainerStashesArgs) -> Result<(), CliError> {
    let ctl_path = args
        .ctl_sock
        .clone()
        .unwrap_or_else(crate::paths::default_ctl_socket_path);
    match args.action {
        ContainerStashesAction::List { json } => list(&ctl_path, json),
        ContainerStashesAction::Prune { before, yes } => prune(&ctl_path, &before, yes),
    }
}

fn list(ctl_path: &std::path::Path, json: bool) -> Result<(), CliError> {
    let resp = ctl_client::call(ctl_path, &CtlRequest::ContainerStashesList)?;
    match resp {
        CtlResponse::ContainerStashes(rows) => {
            if json {
                crate::render::write_json(&mut std::io::stdout(), &rows)
                    .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("json: {e}")))?;
                return Ok(());
            }
            if rows.is_empty() {
                println!("(no container stashes)");
                return Ok(());
            }
            println!(
                "{:<14}  {:<8}  {:<10}  {:<32}  {:>12}  age",
                "kind", "runtime", "hash[..8]", "name", "size",
            );
            let total: u64 = rows.iter().map(|r| r.size_bytes).sum();
            for r in &rows {
                let short_hash = r.blob_hash.chars().take(8).collect::<String>();
                let name = r.name.chars().take(32).collect::<String>();
                let age = render_age(r.created_unix_secs);
                println!(
                    "{:<14}  {:<8}  {:<10}  {:<32}  {:>12}  {}",
                    r.kind,
                    r.runtime,
                    short_hash,
                    name,
                    render_size(r.size_bytes),
                    age,
                );
            }
            println!();
            println!(
                "{} stash{} • total {}",
                rows.len(),
                if rows.len() == 1 { "" } else { "es" },
                render_size(total),
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

fn prune(ctl_path: &std::path::Path, before: &str, yes: bool) -> Result<(), CliError> {
    let older_than_secs = parse_duration_secs(before)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("--before: {e}")))?;
    if !yes && atty_stdin() {
        println!(
            "About to prune container stashes older than {}.",
            render_duration(older_than_secs)
        );
        println!("Re-run with --yes to confirm.");
        return Ok(());
    }
    let resp = ctl_client::call(
        ctl_path,
        &CtlRequest::ContainerStashesPrune { older_than_secs },
    )?;
    match resp {
        CtlResponse::ContainerStashPruneReport {
            pruned_count,
            bytes_freed,
        } => {
            println!(
                "pruned {pruned_count} stash{} • freed {}",
                if pruned_count == 1 { "" } else { "es" },
                render_size(bytes_freed),
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

/// Parse a duration like `30s`, `15m`, `2h`, `7d` into seconds.
/// Pure-numeric input is interpreted as seconds.
pub fn parse_duration_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num, mul): (&str, u64) = if let Some(rest) = s.strip_suffix('d') {
        (rest, 86_400)
    } else if let Some(rest) = s.strip_suffix('h') {
        (rest, 3_600)
    } else if let Some(rest) = s.strip_suffix('m') {
        (rest, 60)
    } else if let Some(rest) = s.strip_suffix('s') {
        (rest, 1)
    } else {
        (s, 1)
    };
    let n: u64 = num
        .parse()
        .map_err(|e| format!("bad number `{num}`: {e}"))?;
    n.checked_mul(mul).ok_or_else(|| "overflow".into())
}

fn render_size(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if b >= GB {
        format!("{:.1} GiB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.1} MiB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.1} KiB", b as f64 / KB as f64)
    } else {
        format!("{b} B")
    }
}

fn render_age(created_unix_secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let dt = now.saturating_sub(created_unix_secs);
    render_duration(dt)
}

fn render_duration(secs: u64) -> String {
    if secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs >= 3_600 {
        format!("{}h", secs / 3_600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

fn atty_stdin() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_secs_accepts_all_units() {
        assert_eq!(parse_duration_secs("45s").unwrap(), 45);
        assert_eq!(parse_duration_secs("15m").unwrap(), 15 * 60);
        assert_eq!(parse_duration_secs("2h").unwrap(), 2 * 3_600);
        assert_eq!(parse_duration_secs("7d").unwrap(), 7 * 86_400);
    }

    #[test]
    fn parse_duration_secs_no_suffix_is_seconds() {
        assert_eq!(parse_duration_secs("90").unwrap(), 90);
    }

    #[test]
    fn parse_duration_secs_rejects_garbage() {
        assert!(parse_duration_secs("").is_err());
        assert!(parse_duration_secs("forever").is_err());
        assert!(parse_duration_secs("3x").is_err());
    }

    #[test]
    fn render_size_renders_human_units() {
        assert_eq!(render_size(0), "0 B");
        assert_eq!(render_size(500), "500 B");
        assert_eq!(render_size(2 * 1024), "2.0 KiB");
        assert_eq!(render_size(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(render_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn render_duration_picks_appropriate_unit() {
        assert_eq!(render_duration(30), "30s");
        assert_eq!(render_duration(90), "1m");
        assert_eq!(render_duration(2 * 3_600), "2h");
        assert_eq!(render_duration(2 * 86_400), "2d");
    }
}
