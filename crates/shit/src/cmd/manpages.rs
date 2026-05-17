// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit manpages <DIR>` — write roff-format man pages for the binary
//! and each subcommand. The packaging sprint (S22) calls this during
//! install; users typically don't.
//!
//! Hidden from the top-level `shit --help` output because it's a
//! packaging concern, not a user one.

use clap::{Args, CommandFactory};

use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct ManpagesArgs {
    /// Output directory. Created if missing.
    pub out_dir: std::path::PathBuf,
}

pub fn run(args: ManpagesArgs) -> Result<(), CliError> {
    let cmd = crate::Cli::command();
    std::fs::create_dir_all(&args.out_dir)?;
    render_recursive(&cmd, &args.out_dir, None)?;
    Ok(())
}

fn render_recursive(
    cmd: &clap::Command,
    dir: &std::path::Path,
    parent: Option<&str>,
) -> Result<(), CliError> {
    let name = cmd.get_name();
    let full = match parent {
        Some(p) => format!("{p}-{name}"),
        None => name.to_string(),
    };
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buf: Vec<u8> = Vec::new();
    man.render(&mut buf)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("render {full}: {e}")))?;
    let path = dir.join(format!("{full}.1"));
    std::fs::write(&path, &buf)?;
    for sub in cmd.get_subcommands() {
        // Skip clap-generated `help` subcommand to avoid `shit-help.1`.
        if sub.get_name() == "help" {
            continue;
        }
        render_recursive(sub, dir, Some(&full))?;
    }
    Ok(())
}
