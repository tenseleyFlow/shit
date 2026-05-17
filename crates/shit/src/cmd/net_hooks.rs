// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit net-hooks {install,uninstall,status}` — wire up the
//! network-tool wrappers that ship in `packaging/net-hooks/`
//! (S17.11).
//!
//! Same shape as `pkg-hooks` and `svc-hooks`: detect tools on PATH,
//! install wrappers into `$XDG_CONFIG_HOME/shit/bin/` under the
//! literal tool name (`iptables`, `nft`, `ufw`, `pfctl`, `ip`).
//! The shell hook PATH-prepend puts our bin dir ahead of the real
//! tool.
//!
//! Same sudo-PATH caveat as `svc-hooks` applies: `sudo iptables`
//! drops PATH, so system-scope writes need
//! `sudo --preserve-env=PATH` or a system-wide install path
//! (deferred to DR-43).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::{config_home, home_dir};

const IPTABLES_WRAPPER: &str = include_str!("../../../../packaging/net-hooks/iptables-wrapper");
const NFT_WRAPPER: &str = include_str!("../../../../packaging/net-hooks/nft-wrapper");
const UFW_WRAPPER: &str = include_str!("../../../../packaging/net-hooks/ufw-wrapper");
const PFCTL_WRAPPER: &str = include_str!("../../../../packaging/net-hooks/pfctl-wrapper");
const IP_WRAPPER: &str = include_str!("../../../../packaging/net-hooks/ip-wrapper");

#[derive(Debug, Clone, Args)]
pub struct NetHooksArgs {
    #[command(subcommand)]
    pub action: NetHooksAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum NetHooksAction {
    Install,
    Uninstall,
    Status,
}

pub fn run(args: NetHooksArgs) -> Result<()> {
    match args.action {
        NetHooksAction::Install => install(),
        NetHooksAction::Uninstall => uninstall(),
        NetHooksAction::Status => status(),
    }
}

const TOOLS: &[(&str, &str)] = &[
    ("iptables", IPTABLES_WRAPPER),
    ("ip6tables", IPTABLES_WRAPPER),
    ("nft", NFT_WRAPPER),
    ("ufw", UFW_WRAPPER),
    ("pfctl", PFCTL_WRAPPER),
    ("ip", IP_WRAPPER),
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
        println!("no supported network tools detected on PATH");
        return Ok(());
    }
    println!();
    println!(
        "PATH-prepend: ensure ${{XDG_CONFIG_HOME:-$HOME/.config}}/shit/bin is on PATH (the shell hook does this when installed)."
    );
    println!(
        "Note: `sudo iptables ...` does NOT use your PATH by default. Use `sudo --preserve-env=PATH iptables ...` or install the wrapper system-wide (DR-43)."
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
    println!("Detected network tools:");
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
