// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit container-hooks {install,uninstall,status}` — wire up the
//! container-tool wrappers that ship in `packaging/container-hooks/`
//! (C04.8).
//!
//! Same shape as `pkg-hooks`, `svc-hooks`, `net-hooks`, and
//! `cloud-hooks`: detect tools on PATH, install wrappers into
//! `$XDG_CONFIG_HOME/shit/bin/` under the literal tool name
//! (`docker`, `podman`, `docker-compose`). The shell hook
//! PATH-prepend puts our bin dir ahead of the real tool.
//!
//! Destructive operations use an atomic prepare/runtime/finalize
//! protocol. The currently admitted positive path is explicit image
//! removal with `rmi --no-prune`; unsupported destructive families
//! fail closed before the runtime executes (exit 125).

use anyhow::Result;
use clap::{Args, Subcommand};
use shit_shell::container_wrappers::{
    CONTAINER_WRAPPERS, WrapperState, install_wrapper_at, wrapper_state,
};
use std::path::PathBuf;

use crate::config_home;

#[derive(Debug, Clone, Args)]
#[command(
    after_help = "Safety policy: only one named-tag target in Docker `rmi --no-prune` against the local `default` context is eligible for capture. Every other destructive container command fails closed before runtime execution (exit 125)."
)]
pub struct ContainerHooksArgs {
    #[command(subcommand)]
    pub action: ContainerHooksAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ContainerHooksAction {
    Install,
    Uninstall,
    Status,
}

pub fn run(args: ContainerHooksArgs) -> Result<()> {
    match args.action {
        ContainerHooksAction::Install => install(),
        ContainerHooksAction::Uninstall => uninstall(),
        ContainerHooksAction::Status => status(),
    }
}

fn print_safety_policy() {
    println!(
        "Safety policy: only one named-tag target in Docker `rmi --no-prune` against the local `default` context is eligible for capture."
    );
    println!(
        "Podman, Compose, multiple targets, digests, image IDs, and every other destructive container command fail closed before runtime execution (exit 125)."
    );
}

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
    let bin_dir = config_home().ok()?.join("shit").join("bin");
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
    for (name, body) in CONTAINER_WRAPPERS {
        if which(name).is_some() {
            write_wrapper(name, body)?;
            any = true;
        }
    }
    if !any {
        println!("no supported container tools detected on PATH");
        return Ok(());
    }
    println!();
    println!(
        "PATH-prepend: ensure ${{XDG_CONFIG_HOME:-$HOME/.config}}/shit/bin is on PATH (the shell hook does this when installed)."
    );
    print_safety_policy();
    Ok(())
}

fn write_wrapper(name: &str, body: &str) -> Result<()> {
    let path = wrapper_path(name)?;
    let previous = wrapper_state(&path, body)?;
    if previous == WrapperState::Current {
        println!("  current:   {}", path.display());
        return Ok(());
    }

    install_wrapper_at(&path, body)?;
    let verb = match previous {
        WrapperState::Absent => "installed",
        WrapperState::Stale => "refreshed",
        WrapperState::Current => unreachable!("current wrappers return before installation"),
    };
    println!("  {verb}: {}", path.display());
    Ok(())
}

fn state_label(state: WrapperState) -> &'static str {
    match state {
        WrapperState::Absent => "absent",
        WrapperState::Current => "current",
        WrapperState::Stale => "stale (automatically refreshed by the CLI or daemon)",
    }
}

fn uninstall() -> Result<()> {
    for (name, _) in CONTAINER_WRAPPERS {
        let path = wrapper_path(name)?;
        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("removed: {}", path.display());
        }
    }
    Ok(())
}

fn status() -> Result<()> {
    println!("Detected container tools:");
    let mut any = false;
    for (name, _) in CONTAINER_WRAPPERS {
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
    for (name, body) in CONTAINER_WRAPPERS {
        let path = wrapper_path(name)?;
        println!(
            "  {} at {}: {}",
            name,
            path.display(),
            state_label(wrapper_state(&path, body)?)
        );
    }
    println!();
    print_safety_policy();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_wrappers_are_executable_shell_scripts() {
        for (name, body) in CONTAINER_WRAPPERS {
            assert!(
                body.starts_with("#!/bin/sh"),
                "{name} wrapper missing POSIX shell shebang"
            );
            assert!(
                body.contains("SHIT_DURING_UNDO"),
                "{name} missing undo guard"
            );
        }
    }
}
