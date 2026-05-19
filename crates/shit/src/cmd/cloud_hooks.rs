// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit cloud-hooks {install,uninstall,status}` — wire up the
//! cloud-tool wrappers that ship in `packaging/cloud-hooks/` (C03.7).
//!
//! Same shape as `pkg-hooks`, `svc-hooks`, and `net-hooks`: detect
//! tools on PATH, install wrappers into `$XDG_CONFIG_HOME/shit/bin/`
//! under the literal tool name (`kubectl`, `gh`, `aws`, `terraform`).
//! The shell hook PATH-prepend puts our bin dir ahead of the real
//! tool.
//!
//! Stage 1 wrappers just exec the real tool with the SHIT_DURING_UNDO
//! recursion guard. The pre/post capture path through
//! `shit-helper cloud-event` is gated on DR-CR-06 (daemon-side
//! capture pipeline).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::{config_home, home_dir};

const KUBECTL_WRAPPER: &str = include_str!("../../../../packaging/cloud-hooks/kubectl-wrapper");
const GH_WRAPPER: &str = include_str!("../../../../packaging/cloud-hooks/gh-wrapper");
const AWS_WRAPPER: &str = include_str!("../../../../packaging/cloud-hooks/aws-wrapper");
const TERRAFORM_WRAPPER: &str = include_str!("../../../../packaging/cloud-hooks/terraform-wrapper");

#[derive(Debug, Clone, Args)]
pub struct CloudHooksArgs {
    #[command(subcommand)]
    pub action: CloudHooksAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum CloudHooksAction {
    Install,
    Uninstall,
    Status,
}

pub fn run(args: CloudHooksArgs) -> Result<()> {
    match args.action {
        CloudHooksAction::Install => install(),
        CloudHooksAction::Uninstall => uninstall(),
        CloudHooksAction::Status => status(),
    }
}

const TOOLS: &[(&str, &str)] = &[
    ("kubectl", KUBECTL_WRAPPER),
    ("gh", GH_WRAPPER),
    ("aws", AWS_WRAPPER),
    ("terraform", TERRAFORM_WRAPPER),
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
        println!("no supported cloud tools detected on PATH");
        return Ok(());
    }
    println!();
    println!(
        "PATH-prepend: ensure ${{XDG_CONFIG_HOME:-$HOME/.config}}/shit/bin is on PATH (the shell hook does this when installed)."
    );
    println!(
        "Note: cloud-tool capture is informational in stage 1 — pre/post hooks via `shit-helper cloud-event` activate once DR-CR-06 lands."
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
    println!("Detected cloud tools:");
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
