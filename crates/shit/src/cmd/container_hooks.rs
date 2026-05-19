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
//! Stage 1 wrappers just exec the real tool with the SHIT_DURING_UNDO
//! recursion guard. The pre/post capture path through `shit-helper
//! container-event` is gated on DR-CR-21/26 (daemon-side capture
//! pipeline + helper subcommand).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::{config_home, home_dir};

const DOCKER_WRAPPER: &str = include_str!("../../../../packaging/container-hooks/docker-wrapper");
const PODMAN_WRAPPER: &str = include_str!("../../../../packaging/container-hooks/podman-wrapper");
const DOCKER_COMPOSE_WRAPPER: &str =
    include_str!("../../../../packaging/container-hooks/docker-compose-wrapper");

#[derive(Debug, Clone, Args)]
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

const TOOLS: &[(&str, &str)] = &[
    ("docker", DOCKER_WRAPPER),
    ("podman", PODMAN_WRAPPER),
    ("docker-compose", DOCKER_COMPOSE_WRAPPER),
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
        println!("no supported container tools detected on PATH");
        return Ok(());
    }
    println!();
    println!(
        "PATH-prepend: ensure ${{XDG_CONFIG_HOME:-$HOME/.config}}/shit/bin is on PATH (the shell hook does this when installed)."
    );
    println!(
        "Note: container-tool capture is informational in stage 1 — pre/post hooks via `shit-helper container-event` activate once DR-CR-21/26 lands."
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
    println!("Detected container tools:");
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
