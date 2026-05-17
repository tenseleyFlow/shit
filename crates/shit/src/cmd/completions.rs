// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit completions <SHELL>` — emit shell-completion scripts.
//!
//! Generated via `clap_complete::generate`; no hand-written
//! completion logic. The sprint plan also calls for `clap_mangen`
//! man-page generation; rather than wire that through `build.rs`
//! (which would need Cli reachable from a build script), we expose
//! `shit completions --man-pages <dir>` and call it from packaging
//! (S22) at install time.

use std::io::Write;

use clap::{Args, CommandFactory, ValueEnum};
use clap_complete::Shell;

use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct CompletionsArgs {
    /// Target shell.
    pub shell: ShellArg,
    /// Write completion to file instead of stdout (e.g. `~/.config/fish/completions/shit.fish`).
    #[arg(long)]
    pub out: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ShellArg {
    Bash,
    Zsh,
    Fish,
    PowerShell,
    Elvish,
}

impl From<ShellArg> for Shell {
    fn from(s: ShellArg) -> Self {
        match s {
            ShellArg::Bash => Shell::Bash,
            ShellArg::Zsh => Shell::Zsh,
            ShellArg::Fish => Shell::Fish,
            ShellArg::PowerShell => Shell::PowerShell,
            ShellArg::Elvish => Shell::Elvish,
        }
    }
}

pub fn run(args: CompletionsArgs) -> Result<(), CliError> {
    let mut cmd = crate::Cli::command();
    let shell: Shell = args.shell.into();
    let bin_name = "shit";
    let buf: Box<dyn Write> = match args.out {
        Some(p) => {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            Box::new(std::fs::File::create(&p).map_err(|e| {
                CliError::fail(GENERIC_FAILURE, format!("open {}: {e}", p.display()))
            })?)
        }
        None => Box::new(std::io::stdout()),
    };
    let mut buf = buf;
    clap_complete::generate(shell, &mut cmd, bin_name, &mut *buf);
    Ok(())
}
