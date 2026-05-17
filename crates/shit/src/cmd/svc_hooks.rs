// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit svc-hooks {install,uninstall,status}` — wire up the
//! systemctl/launchctl wrappers that ship in `packaging/svc-hooks/`
//! (S16.9).
//!
//! Stage-1 scope:
//!
//! - Both wrappers are user-scope. They install into
//!   `$XDG_CONFIG_HOME/shit/bin/` as the literal binary names
//!   `systemctl` / `launchctl`, so the shell-hook PATH-prepend puts
//!   them ahead of the real binaries.
//! - The wrappers themselves know how to find the real binary; no
//!   sudo is required to install or use them in user-scope.
//! - **System-scope usage (sudo systemctl ...) is a known gap**:
//!   sudo's default `env_reset` policy drops our PATH, so the
//!   wrapper isn't invoked. The status command warns about this.
//!   DR-37 tracks an auto-`sudo --preserve-env=PATH` recipe.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::{config_home, home_dir};

const SYSTEMCTL_WRAPPER: &str = include_str!("../../../../packaging/svc-hooks/systemctl-wrapper");
const LAUNCHCTL_WRAPPER: &str = include_str!("../../../../packaging/svc-hooks/launchctl-wrapper");

#[derive(Debug, Clone, Args)]
pub struct SvcHooksArgs {
    #[command(subcommand)]
    pub action: SvcHooksAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum SvcHooksAction {
    /// Install the systemctl/launchctl wrappers under
    /// `$XDG_CONFIG_HOME/shit/bin/` (ahead of the real binary in
    /// PATH).
    Install,
    /// Remove the wrappers.
    Uninstall,
    /// Report which tools were detected and whether the wrappers
    /// are present.
    Status,
}

pub fn run(args: SvcHooksArgs) -> Result<()> {
    match args.action {
        SvcHooksAction::Install => install(),
        SvcHooksAction::Uninstall => uninstall(),
        SvcHooksAction::Status => status(),
    }
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
    let bin_dir = home_dir().ok()?.join(".config").join("shit").join("bin");
    for dir in std::env::split_paths(&path) {
        // Skip our own bin dir — we're looking for the *real* tool.
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
    let mut installed = 0;
    if which("systemctl").is_some() {
        write_wrapper("systemctl", SYSTEMCTL_WRAPPER)?;
        installed += 1;
    }
    if which("launchctl").is_some() {
        write_wrapper("launchctl", LAUNCHCTL_WRAPPER)?;
        installed += 1;
    }
    if installed == 0 {
        println!("no supported service managers detected (systemctl/launchctl)");
        return Ok(());
    }
    println!();
    println!(
        "PATH-prepend: ensure ${{XDG_CONFIG_HOME:-$HOME/.config}}/shit/bin is on PATH (the shell hook does this when installed)."
    );
    println!(
        "Note: `sudo systemctl ...` does NOT use your PATH by default. Use `sudo --preserve-env=PATH systemctl ...` or install the wrapper system-wide (DR-37)."
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
    for name in ["systemctl", "launchctl"] {
        let path = wrapper_path(name)?;
        if path.exists() {
            std::fs::remove_file(&path)?;
            println!("removed: {}", path.display());
        }
    }
    Ok(())
}

fn status() -> Result<()> {
    println!("Detected service managers:");
    let systemctl = which("systemctl");
    let launchctl = which("launchctl");
    match (&systemctl, &launchctl) {
        (None, None) => println!("  (none)"),
        _ => {
            if let Some(p) = &systemctl {
                println!("  - systemctl ({})", p.display());
            }
            if let Some(p) = &launchctl {
                println!("  - launchctl ({})", p.display());
            }
        }
    }
    println!();
    println!("Wrapper installation state:");
    for name in ["systemctl", "launchctl"] {
        let path = wrapper_path(name)?;
        println!(
            "  {} at {}: {}",
            name,
            path.display(),
            if path.exists() { "present" } else { "absent" }
        );
    }
    if systemctl.is_some() {
        println!();
        println!(
            "Note: `sudo systemctl ...` will NOT invoke the wrapper unless PATH is preserved."
        );
    }
    Ok(())
}
