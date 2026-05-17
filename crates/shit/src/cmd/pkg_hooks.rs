// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit pkg-hooks {install,uninstall,status}` — wire up the package
//! manager hooks that ship in `packaging/pkg-hooks/` (S14.12).
//!
//! Scope of this stage-1 implementation:
//!
//! - **brew** (macOS + linuxbrew): user-scope. We install a wrapper
//!   into `$XDG_CONFIG_HOME/shit/bin/brew` and rely on the shell-hook
//!   PATH-prepend to put it ahead of the real brew. No sudo.
//! - **apt / pacman / dnf / FreeBSD pkg**: system-scope. Writing the
//!   actual hook configs requires root. Rather than silently invoke
//!   sudo (which would surprise users), we *stage* the files under
//!   `$XDG_STATE_HOME/shit/pkg-hooks-staging/` and print the exact
//!   `sudo cp` invocations the user should run. The real auto-sudo
//!   path is deferred (DR-29).
//!
//! Uninstall mirrors install: brew wrapper is removed; staging dir is
//! removed; per-system files are listed with a "remove these as root"
//! hint (we never try to delete root-owned files).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::process::Command;

use crate::{config_home, home_dir};

const APT_HOOK_BODY: &str = include_str!("../../../../packaging/pkg-hooks/apt-99shit");
const PACMAN_HOOK_BODY: &str = include_str!("../../../../packaging/pkg-hooks/pacman-zz-shit.hook");
const DNF_PLUGIN_BODY: &str =
    include_str!("../../../../packaging/pkg-hooks/dnf-plugin/shit_record.py");
const BREW_WRAPPER_BODY: &str = include_str!("../../../../packaging/pkg-hooks/brew-wrapper");
const PKG_EVENT_CONF: &str = include_str!("../../../../packaging/pkg-hooks/pkg-event.conf");
const PKG_EVENT_PIPE_SH: &str = include_str!("../../../../packaging/pkg-hooks/pkg-event-pipe.sh");

#[derive(Debug, Clone, Args)]
pub struct PkgHooksArgs {
    #[command(subcommand)]
    pub action: PkgHooksAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum PkgHooksAction {
    /// Detect supported package managers and install/stage hooks for
    /// each present manager.
    Install,
    /// Remove user-scope hooks; print teardown commands for the
    /// system-scope hooks (which require root to remove).
    Uninstall,
    /// Report which managers were detected and whether their hook
    /// configs are present.
    Status,
}

pub fn run(args: PkgHooksArgs) -> Result<()> {
    match args.action {
        PkgHooksAction::Install => install(),
        PkgHooksAction::Uninstall => uninstall(),
        PkgHooksAction::Status => status(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Manager {
    Apt,
    Pacman,
    Dnf,
    Brew,
    FreeBSDPkg,
}

impl Manager {
    fn label(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Pacman => "pacman",
            Self::Dnf => "dnf",
            Self::Brew => "brew",
            Self::FreeBSDPkg => "pkg",
        }
    }
}

/// Probe `$PATH` for each manager's CLI. Faster than reading
/// platform tables; works fine on cross-installs (e.g. linuxbrew on
/// Ubuntu coexisting with apt).
fn detect_managers() -> Vec<Manager> {
    let mut out = Vec::new();
    for (m, cmd) in [
        (Manager::Apt, "apt-get"),
        (Manager::Pacman, "pacman"),
        (Manager::Dnf, "dnf"),
        (Manager::Brew, "brew"),
        (Manager::FreeBSDPkg, "pkg"),
    ] {
        // `pkg` exists on Linux as a different tool (musl pkg, etc.).
        // Restrict the FreeBSD pkg detection to actual FreeBSD.
        if m == Manager::FreeBSDPkg && !cfg!(target_os = "freebsd") {
            continue;
        }
        if which(cmd).is_some() {
            out.push(m);
        }
    }
    out
}

fn which(cmd: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(cmd);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn staging_dir() -> Result<PathBuf> {
    let dir = if let Some(s) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(s).join("shit").join("pkg-hooks-staging")
    } else {
        home_dir()?
            .join(".local")
            .join("state")
            .join("shit")
            .join("pkg-hooks-staging")
    };
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn brew_wrapper_path() -> Result<PathBuf> {
    let dir = config_home()?.join("shit").join("bin");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("brew"))
}

fn install() -> Result<()> {
    let managers = detect_managers();
    if managers.is_empty() {
        println!("no supported package managers detected");
        return Ok(());
    }
    let staging = staging_dir()?;
    println!(
        "Detected: {}",
        managers
            .iter()
            .map(|m| m.label())
            .collect::<Vec<_>>()
            .join(", ")
    );
    for m in managers {
        match m {
            Manager::Apt => stage(&staging, "apt-99shit", APT_HOOK_BODY, false)?,
            Manager::Pacman => {
                stage(&staging, "pacman-zz-shit.hook", PACMAN_HOOK_BODY, false)?;
            }
            Manager::Dnf => stage(&staging, "shit_record.py", DNF_PLUGIN_BODY, false)?,
            Manager::Brew => install_brew_wrapper()?,
            Manager::FreeBSDPkg => {
                stage(&staging, "pkg-event.conf", PKG_EVENT_CONF, false)?;
                stage(&staging, "pkg-event-pipe.sh", PKG_EVENT_PIPE_SH, true)?;
            }
        }
    }
    Ok(())
}

fn stage(dir: &std::path::Path, name: &str, body: &str, executable: bool) -> Result<()> {
    let path = dir.join(name);
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    if executable {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    }
    println!("  staged: {}", path.display());
    print_sudo_instructions(name, &path);
    Ok(())
}

fn print_sudo_instructions(name: &str, staged: &std::path::Path) {
    let p = staged.display();
    match name {
        "apt-99shit" => {
            println!("    install: sudo install -m 0644 {p} /etc/apt/apt.conf.d/99shit");
        }
        "pacman-zz-shit.hook" => {
            println!("    install: sudo install -m 0644 {p} /usr/share/libalpm/hooks/zz-shit.hook");
        }
        "shit_record.py" => {
            println!(
                "    install: sudo install -m 0644 {p} \\\n             $(python3 -c 'import dnf,os; print(os.path.dirname(dnf.__file__))')/dnf-plugins/shit_record.py"
            );
        }
        "pkg-event.conf" => {
            println!("    install: cat {p} | sudo tee -a /usr/local/etc/pkg.conf");
        }
        "pkg-event-pipe.sh" => {
            println!(
                "    install: sudo install -m 0755 {p} /usr/local/libexec/shit/pkg-event-pipe.sh"
            );
        }
        _ => {}
    }
}

fn install_brew_wrapper() -> Result<()> {
    let dest = brew_wrapper_path()?;
    std::fs::write(&dest, BREW_WRAPPER_BODY)
        .with_context(|| format!("write {}", dest.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    println!("  installed: {}", dest.display());
    println!(
        "    PATH-prepend: ensure ${{XDG_CONFIG_HOME:-$HOME/.config}}/shit/bin is on PATH (the shell hook does this when installed)"
    );
    Ok(())
}

fn uninstall() -> Result<()> {
    let brew_path = brew_wrapper_path()?;
    if brew_path.exists() {
        std::fs::remove_file(&brew_path)?;
        println!("removed: {}", brew_path.display());
    }
    let staging = staging_dir()?;
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
        println!("removed staging dir: {}", staging.display());
    }
    println!();
    println!("System-scope hook configs (require root to remove):");
    for (name, path) in [
        ("apt", "/etc/apt/apt.conf.d/99shit"),
        ("pacman", "/usr/share/libalpm/hooks/zz-shit.hook"),
        ("pkg.conf EVENT_PIPE line", "/usr/local/etc/pkg.conf"),
        (
            "FreeBSD pkg-event pipe",
            "/usr/local/libexec/shit/pkg-event-pipe.sh",
        ),
        (
            "dnf plugin",
            "/usr/lib/python3/site-packages/dnf-plugins/shit_record.py",
        ),
    ] {
        println!("  {name}: sudo rm -f {path}  (if it exists)");
    }
    Ok(())
}

fn status() -> Result<()> {
    let managers = detect_managers();
    println!("Detected package managers:");
    if managers.is_empty() {
        println!("  (none)");
        return Ok(());
    }
    for m in managers {
        println!("  - {}", m.label());
    }
    println!();
    println!("Hook installation state:");
    let brew_path = brew_wrapper_path()?;
    println!(
        "  brew wrapper at {}: {}",
        brew_path.display(),
        if brew_path.exists() {
            "present"
        } else {
            "absent"
        }
    );
    for (name, path) in [
        ("apt 99shit", "/etc/apt/apt.conf.d/99shit"),
        (
            "pacman zz-shit.hook",
            "/usr/share/libalpm/hooks/zz-shit.hook",
        ),
    ] {
        let exists = std::path::Path::new(path).exists();
        println!("  {name}: {}", if exists { "present" } else { "absent" });
    }
    Ok(())
}

// Hush the `Command` warning on platforms that don't end up calling
// any of the system tools. The current implementation doesn't shell
// out at all (we only `which` via $PATH), but keep the import gated
// to future-proof.
#[allow(dead_code)]
fn _quiet_unused_command() {
    let _ = Command::new("true");
}
