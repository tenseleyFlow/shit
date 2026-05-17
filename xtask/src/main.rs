// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use walkdir::WalkDir;

const SPDX_HEADER: &str = "// SPDX-License-Identifier: AGPL-3.0-or-later";

#[derive(Parser)]
#[command(name = "xtask", about = "internal repo task runner")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify every .rs file in the workspace begins with the SPDX header.
    LicenseCheck,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::LicenseCheck => license_check(),
    }
}

fn license_check() -> Result<()> {
    let mut missing: Vec<PathBuf> = Vec::new();
    for entry in WalkDir::new(".")
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        if path.components().any(|c| {
            matches!(
                c.as_os_str().to_str(),
                Some("target")
                    | Some("vendor")
                    | Some(".git")
                    | Some(".docs")
                    | Some(".refs")
                    | Some(".fackr")
            )
        }) {
            continue;
        }
        let content = fs::read_to_string(path)?;
        if !content.starts_with(SPDX_HEADER) {
            missing.push(path.to_path_buf());
        }
    }
    if !missing.is_empty() {
        eprintln!("files missing SPDX header:");
        for p in &missing {
            eprintln!("  {}", p.display());
        }
        bail!("{} file(s) missing SPDX header", missing.len());
    }
    println!("all rust files have SPDX header");
    Ok(())
}
