// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit proc-hooks {install,uninstall,status}` — wire up the
//! process-tool wrappers that ship in `packaging/proc-hooks/`
//! (S18.9).
//!
//! Same shape as `net-hooks` / `svc-hooks`: detect tools on PATH,
//! install wrappers into `$XDG_CONFIG_HOME/shit/bin/` under the
//! literal tool name. The shell hook's PATH-prepend puts our
//! wrapper ahead of the real binary.
//!
//! ## Why a CLI subcommand for what could be `cp` of three files
//!
//! Detection. Not every box has all three tools (e.g., minimal
//! containers ship `kill` but not `pkill`/`killall`). The CLI does
//! PATH discovery so installing on a box without the tool doesn't
//! create a dead wrapper.
//!
//! ## kill is usually a shell builtin
//!
//! Both bash and zsh shadow `/bin/kill` with a builtin. The wrapper
//! is reached only when the user types `command kill`, `\kill`, or
//! scripts invoke kill through PATH. The shell builtin path is
//! observed via the preexec hook's `SHIT_JOB_TABLE` publication
//! (see [`shit_helper::proc::kill_targets`]). We install the
//! wrapper anyway; coverage is "best-effort" by design.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::{config_home, home_dir};

const KILL_WRAPPER: &str = include_str!("../../../../packaging/proc-hooks/kill-wrapper");
const PKILL_WRAPPER: &str = include_str!("../../../../packaging/proc-hooks/pkill-wrapper");
const KILLALL_WRAPPER: &str = include_str!("../../../../packaging/proc-hooks/killall-wrapper");

#[derive(Debug, Clone, Args)]
pub struct ProcHooksArgs {
    #[command(subcommand)]
    pub action: ProcHooksAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ProcHooksAction {
    Install,
    Uninstall,
    Status,
}

pub fn run(args: ProcHooksArgs) -> Result<()> {
    match args.action {
        ProcHooksAction::Install => install(),
        ProcHooksAction::Uninstall => uninstall(),
        ProcHooksAction::Status => status(),
    }
}

const TOOLS: &[(&str, &str)] = &[
    ("kill", KILL_WRAPPER),
    ("pkill", PKILL_WRAPPER),
    ("killall", KILLALL_WRAPPER),
];

fn shit_bin_dir() -> Result<PathBuf> {
    let dir = config_home()?.join("shit").join("bin");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn wrapper_path(name: &str) -> Result<PathBuf> {
    Ok(shit_bin_dir()?.join(name))
}

fn which(cmd: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let bin_dir = home_dir().ok()?.join(".config").join("shit").join("bin");
    for dir in std::env::split_paths(&path) {
        if dir == bin_dir {
            continue;
        }
        let cand = dir.join(cmd);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn install() -> Result<()> {
    let mut any = false;
    for (name, body) in TOOLS {
        if which(name).is_some() {
            write_wrapper(name, body)?;
            any = true;
        }
    }
    if !any {
        println!("no supported process tools detected on PATH");
        return Ok(());
    }
    println!();
    println!(
        "PATH-prepend: ensure ${{XDG_CONFIG_HOME:-$HOME/.config}}/shit/bin is on PATH (the shell hook does this when installed)."
    );
    println!(
        "Note: `kill` is usually a shell builtin; the wrapper is only reached for `command kill`, `\\kill`, or scripts. The shell preexec hook covers the builtin path via SHIT_JOB_TABLE."
    );
    Ok(())
}

fn write_wrapper(name: &str, body: &str) -> Result<()> {
    let path = wrapper_path(name)?;
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    println!("  installed: {}", path.display());
    Ok(())
}

fn uninstall() -> Result<()> {
    for (name, _) in TOOLS {
        let path = wrapper_path(name)?;
        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("removed: {}", path.display());
        }
    }
    Ok(())
}

fn status() -> Result<()> {
    println!("Detected process tools:");
    let mut any = false;
    for (name, _) in TOOLS {
        if let Some(p) = which(name) {
            println!("  - {} ({})", name, p.display());
            any = true;
        }
    }
    if !any {
        println!("  (none)");
    }
    println!();
    println!("Wrapper installation state:");
    for (name, _) in TOOLS {
        let path = wrapper_path(name)?;
        println!(
            "  {} at {}: {}",
            name,
            path.display(),
            if path.exists() { "present" } else { "absent" }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrappers_are_non_empty_and_start_with_shebang() {
        for (name, body) in TOOLS {
            assert!(
                body.starts_with("#!/usr/bin/env bash"),
                "{name} wrapper missing bash shebang"
            );
            assert!(body.contains("SPDX-License-Identifier"), "{name} missing SPDX");
            assert!(body.contains("proc-event"), "{name} doesn't call proc-event");
            assert!(body.contains("target-argv"), "{name} doesn't pass target-argv");
        }
    }

    #[test]
    fn wrappers_carry_loop_guard() {
        for (name, body) in TOOLS {
            assert!(
                body.contains("SHIT_WRAPPER_DEPTH"),
                "{name} missing loop guard"
            );
            assert!(
                body.contains("SHIT_DURING_UNDO"),
                "{name} missing during-undo short-circuit"
            );
        }
    }

    #[test]
    fn tools_list_matches_proc_tool_wire_variants() {
        // S18 wire types support exactly kill|pkill|killall;
        // wrappers must mirror that set so the helper accepts the
        // tool string verbatim.
        let names: Vec<&str> = TOOLS.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["kill", "pkill", "killall"]);
    }
}
