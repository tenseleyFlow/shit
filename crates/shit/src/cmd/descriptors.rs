// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit descriptors {list, validate, test}` — administer reverse-API
//! descriptor packs (C02.9).
//!
//! - `list` enumerates the loaded packs at the standard search roots
//!   (system + user). Runs entirely offline against the filesystem;
//!   does not consult the daemon.
//! - `validate <path>` parses + lints a single TOML file and prints
//!   the error (if any) with location.
//! - `test <path> -- <argv...>` parses + matches the pack against the
//!   given argv, printing the match score and the interpolated reverse
//!   argv from a synthetic captured-state map (every extract.<key> →
//!   `<TEST:key>`). Lets users sanity-check their packs before deploy.

use clap::{Args, Subcommand};
use shit_desc::{Descriptor, DescriptorAuthority, Loader, MatchOutcome, match_descriptor};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct DescriptorsArgs {
    #[command(subcommand)]
    pub sub: DescriptorsSub,
}

#[derive(Debug, Clone, Subcommand)]
pub enum DescriptorsSub {
    /// List loaded descriptor packs from the standard search roots.
    List(ListArgs),
    /// Parse and lint a single descriptor file.
    Validate(ValidateArgs),
    /// Match a pack against a sample argv and print the rendered reverse.
    Test(TestArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ListArgs {
    /// Additional system root to search (overrides the default
    /// `/usr/share/shit/descriptors/`).
    #[arg(long)]
    pub system_root: Option<PathBuf>,
    /// Additional user root to search (overrides the default
    /// `$XDG_CONFIG_HOME/shit/descriptors/`).
    #[arg(long)]
    pub user_root: Option<PathBuf>,
    /// Emit JSON instead of the table view.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ValidateArgs {
    /// Path to a `.toml` descriptor file.
    pub path: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct TestArgs {
    /// Path to a `.toml` descriptor file.
    pub path: PathBuf,
    /// Sample argv to match against. Use `--` to separate from `shit`'s
    /// own flags: `shit descriptors test pack.toml -- hostname foo`.
    pub argv: Vec<String>,
}

pub fn run(args: DescriptorsArgs) -> Result<(), CliError> {
    match args.sub {
        DescriptorsSub::List(a) => run_list(a),
        DescriptorsSub::Validate(a) => run_validate(a),
        DescriptorsSub::Test(a) => run_test(a),
    }
}

fn run_list(args: ListArgs) -> Result<(), CliError> {
    let system = args.system_root.unwrap_or_else(default_system_root);
    let user = args.user_root.unwrap_or_else(default_user_root);
    let loader = Loader::from_roots(&[
        (DescriptorAuthority::Builtin, system.as_path()),
        (DescriptorAuthority::User, user.as_path()),
    ])
    .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("descriptors list: {e}")))?;

    if args.json {
        let rows: Vec<serde_json::Value> = loader
            .iter()
            .map(|(auth, ld)| {
                serde_json::json!({
                    "authority": auth,
                    "name": ld.descriptor.descriptor.name,
                    "description": ld.descriptor.descriptor.description,
                    "source": ld.source,
                })
            })
            .collect();
        let out = serde_json::to_string_pretty(&rows)
            .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("json: {e}")))?;
        println!("{out}");
        return Ok(());
    }

    if loader.is_empty() {
        println!(
            "(no descriptors loaded; searched {} and {})",
            system.display(),
            user.display()
        );
        return Ok(());
    }
    println!("{:<10}  {:<24}  description", "authority", "name");
    for (auth, ld) in loader.iter() {
        let name: &str = &ld.descriptor.descriptor.name;
        let desc: &str = &ld.descriptor.descriptor.description;
        let short = if desc.len() > 60 { &desc[..60] } else { desc };
        println!("{auth:<10}  {name:<24}  {short}");
    }
    Ok(())
}

fn run_validate(args: ValidateArgs) -> Result<(), CliError> {
    let text = std::fs::read_to_string(&args.path)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("read {:?}: {e}", args.path)))?;
    match Descriptor::from_toml(&text) {
        Ok(d) => {
            println!(
                "ok: {} (version {}, authority {})",
                d.descriptor.name, d.descriptor.version, d.descriptor.authority
            );
            Ok(())
        }
        Err(e) => Err(CliError::fail(
            GENERIC_FAILURE,
            format!("validate {:?}: {e}", args.path),
        )),
    }
}

fn run_test(args: TestArgs) -> Result<(), CliError> {
    let text = std::fs::read_to_string(&args.path)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("read {:?}: {e}", args.path)))?;
    let d = Descriptor::from_toml(&text)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("parse {:?}: {e}", args.path)))?;

    let outcome: MatchOutcome = match_descriptor(&d.match_, &args.argv);
    if !outcome.matched {
        println!("NO MATCH against argv {:?}", args.argv);
        return Ok(());
    }
    println!(
        "MATCH score={:.3} against argv {:?}",
        outcome.score, args.argv
    );

    // Build a synthetic captured-state map: every extract key maps to
    // a labelled placeholder so the user sees which value goes where.
    let mut state: BTreeMap<String, String> = BTreeMap::new();
    for key in d.snapshot.pre.extract.keys() {
        state.insert(key.clone(), format!("<TEST:{key}>"));
    }
    if let Some(post) = &d.snapshot.post {
        for key in post.extract.keys() {
            state.insert(key.clone(), format!("<TEST:{key}>"));
        }
    }

    let rendered = shit_desc::interpolate_argv(&d.reverse.command, &state)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("interpolate: {e}")))?;
    println!("reverse argv (synthetic state): {rendered:?}");
    println!(
        "  privileged={} requires_confirmation={}",
        d.reverse.privileged, d.reverse.requires_confirmation
    );
    if let Some(g) = &d.reverse.guard {
        let g_substr = shit_desc::interpolate_token(&g.expected_substring, &state)
            .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("guard interpolate: {e}")))?;
        println!("  guard: {:?} expects substring `{g_substr}`", g.command);
    }
    Ok(())
}

fn default_system_root() -> PathBuf {
    PathBuf::from("/usr/share/shit/descriptors/builtin")
}

fn default_user_root() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        Path::new(&xdg).join("shit/descriptors")
    } else if let Some(home) = std::env::var_os("HOME") {
        Path::new(&home).join(".config/shit/descriptors")
    } else {
        PathBuf::from(".config/shit/descriptors")
    }
}
