// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result, bail};
use shit_proto::ShellKind;
use shit_shell::{
    InstallParams, MARKER_BEGIN, plan_install, remove_marker_block, render_template,
    upsert_marker_block,
};
use std::path::Path;

use crate::{config_home, home_dir, paths};

pub fn install(shell: Option<ShellKind>) -> Result<()> {
    let shell = shell.context("could not detect shell; pass --shell explicitly")?;
    let home = home_dir()?;
    let cfg = config_home()?;
    let plan = plan_install(shell, &home, &cfg).context("plan install")?;
    let shit_bin = std::env::current_exe().context("current_exe")?;
    let params = InstallParams {
        shit_bin,
        socket_path: paths::default_socket_path(),
    };
    let body = render_template(shell, &params).context("render template")?;

    if let Some(parent) = plan.hook_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create_dir_all {}", parent.display()))?;
    }
    std::fs::write(&plan.hook_file, body)
        .with_context(|| format!("write {}", plan.hook_file.display()))?;

    if matches!(shell, ShellKind::Fish) {
        // Fish autoloads everything in conf.d/, so we don't touch config.fish.
        println!("installed fish hook at {}", plan.hook_file.display());
        println!("fish autoloads conf.d/ — no further action required");
        println!(
            "source the file in any existing fish sessions: source {}",
            plan.hook_file.display()
        );
        return Ok(());
    }

    let rc_path = plan.rc_file;
    let existing = std::fs::read_to_string(&rc_path).unwrap_or_default();
    let updated = upsert_marker_block(&existing, &plan.source_line);
    write_atomic(&rc_path, &updated).with_context(|| format!("write {}", rc_path.display()))?;

    println!("installed {} hook", shell.as_str());
    println!("  hook script: {}", plan.hook_file.display());
    println!("  rc file:     {}", rc_path.display());
    println!(
        "open a new shell (or `source {}`) to activate",
        rc_path.display()
    );
    Ok(())
}

pub fn uninstall(shell: Option<ShellKind>) -> Result<()> {
    let shell = shell.context("could not detect shell; pass --shell explicitly")?;
    let home = home_dir()?;
    let cfg = config_home()?;
    let plan = plan_install(shell, &home, &cfg).context("plan uninstall")?;

    if matches!(shell, ShellKind::Fish) {
        if plan.hook_file.exists() {
            std::fs::remove_file(&plan.hook_file)
                .with_context(|| format!("remove {}", plan.hook_file.display()))?;
            println!("removed fish hook at {}", plan.hook_file.display());
        } else {
            println!("no fish hook installed");
        }
        return Ok(());
    }

    let rc_path = plan.rc_file;
    let existing = match std::fs::read_to_string(&rc_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "rc file {} does not exist; nothing to uninstall",
                rc_path.display()
            );
            return Ok(());
        }
        Err(e) => bail!("read {}: {e}", rc_path.display()),
    };
    if !existing.contains(MARKER_BEGIN) {
        println!("no shit marker block found in {}", rc_path.display());
        return Ok(());
    }
    let updated = remove_marker_block(&existing);
    write_atomic(&rc_path, &updated).with_context(|| format!("write {}", rc_path.display()))?;
    println!("removed shit marker block from {}", rc_path.display());
    if plan.hook_file.exists() {
        println!("hook script left in place at {}", plan.hook_file.display());
        println!(
            "remove it manually if desired: rm {}",
            plan.hook_file.display()
        );
    }
    Ok(())
}

pub fn status() -> Result<()> {
    let home = home_dir()?;
    let cfg = config_home()?;
    for shell in [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish] {
        let plan = match plan_install(shell, &home, &cfg) {
            Ok(p) => p,
            Err(e) => {
                println!("{}: error: {e}", shell.as_str());
                continue;
            }
        };
        let hook_present = plan.hook_file.exists();
        let rc_marker = matches!(shell, ShellKind::Fish) || rc_has_marker(&plan.rc_file);
        let state = match (hook_present, rc_marker) {
            (true, true) => "installed",
            (true, false) => "hook present, rc not sourced",
            (false, true) => "rc references missing hook",
            (false, false) => "not installed",
        };
        println!(
            "{:<5} {:<35} hook={} rc-marker={} state={}",
            shell.as_str(),
            plan.hook_file.display().to_string(),
            hook_present,
            rc_marker,
            state
        );
    }
    Ok(())
}

fn rc_has_marker(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|s| s.contains(MARKER_BEGIN))
        .unwrap_or(false)
}

fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    // Write to a sibling tmp file, rename. Avoids torn writes if the user is
    // editing rc files concurrently (unlikely but cheap insurance).
    let parent = path.parent().unwrap_or(Path::new("."));
    let mut tmp = parent.to_path_buf();
    let pid = std::process::id();
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("rcfile");
    tmp.push(format!(".{stem}.shit-{pid}.tmp"));
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
