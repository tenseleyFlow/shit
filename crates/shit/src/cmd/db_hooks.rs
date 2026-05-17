// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit db-hooks {install,uninstall,status}` — wire up the DB CLI
//! wrappers that ship in `packaging/db-hooks/` (S19.9).
//!
//! Same shape as `net-hooks` / `svc-hooks` / `proc-hooks`. DB shims
//! are **opt-in** (stretch sprint UX rule): the user has to call
//! `shit db-hooks install` explicitly — we don't ship them as part
//! of the default install path. The status subcommand reports
//! detection + wrapper presence for the three supported engines.
//!
//! ## Naming
//!
//! Spec S19 called for `shit shim install --db <engine>`; we use
//! `db-hooks` here for consistency with the other tier-installer
//! subcommands. The spec-aligned `shim` verb is parked for a
//! future revision if the user surface grows beyond DBs (DR-59).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::{config_home, home_dir};

const PSQL_WRAPPER: &str = include_str!("../../../../packaging/db-hooks/psql-wrapper");
const MYSQL_WRAPPER: &str = include_str!("../../../../packaging/db-hooks/mysql-wrapper");
const SQLITE3_WRAPPER: &str = include_str!("../../../../packaging/db-hooks/sqlite3-wrapper");

#[derive(Debug, Clone, Args)]
pub struct DbHooksArgs {
    #[command(subcommand)]
    pub action: DbHooksAction,
}

#[derive(Debug, Clone, Subcommand)]
pub enum DbHooksAction {
    Install,
    Uninstall,
    Status,
}

pub fn run(args: DbHooksArgs) -> Result<()> {
    match args.action {
        DbHooksAction::Install => install(),
        DbHooksAction::Uninstall => uninstall(),
        DbHooksAction::Status => status(),
    }
}

const TOOLS: &[(&str, &str)] = &[
    ("psql", PSQL_WRAPPER),
    ("mysql", MYSQL_WRAPPER),
    ("sqlite3", SQLITE3_WRAPPER),
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
        println!("no supported DB tools detected on PATH");
        return Ok(());
    }
    println!();
    println!(
        "PATH-prepend: ensure ${{XDG_CONFIG_HOME:-$HOME/.config}}/shit/bin is on PATH (the shell hook does this when installed)."
    );
    println!(
        "Note: DB shims are stretch-sprint UX. Interactive psql/mysql sessions are NOT captured; only -c / -e / -f invocations are journaled. See `shit show` for any captured statements."
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
    println!("Detected DB tools:");
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
            assert!(
                body.contains("SPDX-License-Identifier"),
                "{name} missing SPDX"
            );
            assert!(body.contains("db-event"), "{name} doesn't call db-event");
            assert!(
                body.contains("statement-blob"),
                "{name} doesn't pass statement-blob"
            );
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
    fn tools_list_matches_db_engine_wire_variants() {
        // S19 wire types accept exactly psql|mysql|sqlite3 as
        // canonical engine names; wrappers mirror that set verbatim.
        let names: Vec<&str> = TOOLS.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["psql", "mysql", "sqlite3"]);
    }

    #[test]
    fn psql_wrapper_handles_dash_c_and_dash_f() {
        let (_, body) = TOOLS[0];
        assert!(body.contains("-c|--command"));
        assert!(body.contains("-f|--file"));
    }

    #[test]
    fn mysql_wrapper_handles_dash_e_glued_and_split() {
        let (_, body) = TOOLS[1];
        assert!(body.contains("-e|--execute"));
        assert!(body.contains("-e*"), "mysql wrapper missing glued -e support");
    }

    #[test]
    fn sqlite3_wrapper_recognizes_cmd_flag_and_value_skips() {
        let (_, body) = TOOLS[2];
        assert!(body.contains("-cmd"));
        assert!(body.contains("-lookaside"));
        assert!(body.contains("-pagecache"));
    }
}
