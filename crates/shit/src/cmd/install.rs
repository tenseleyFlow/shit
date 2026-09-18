// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit install <cmd>` — explicit-opt-in install wrapper (C05.6).
//!
//! Sets up the env vars the shim needs (LD_PRELOAD on Linux/BSD,
//! DYLD_INSERT_LIBRARIES on macOS; `SHIT_PRELOAD_ACTIVE=1`;
//! `SHIT_DAEMON_SOCK=<resolved>`) and `exec`s the user's command. The
//! shim then captures pre-state for every install-prefix-touching
//! syscall the wrapped command issues; the daemon writes the captures
//! into the journal under the current shell session.
//!
//! ## Why this exists alongside shell auto-injection
//!
//! The shell hook auto-injects for a recognized set of commands
//! (`make install`, `cargo install --path …`, `pip install --user …`).
//! `shit install <cmd>` is the escape hatch for everything else: a
//! one-off `./install.sh`, a vendored `setup.sh`, a `dotfiles
//! bootstrap`, etc.
//!
//! ## Lib-path resolution
//!
//! The wrapper looks for `libshit_preload_shim.{so,dylib}` in (in order):
//!
//! 1. `--lib <path>` argument (explicit override),
//! 2. `$XDG_DATA_HOME/shit/lib/libshit_preload_shim.{so,dylib}` (user-scope),
//! 3. `/usr/local/lib/shit/libshit_preload_shim.{so,dylib}` (system-scope),
//! 4. `$CARGO_TARGET_DIR/<profile>/libshit_preload_shim.{so,dylib}` (dev,
//!    detected via `OUT_DIR` of the current build),
//! 5. The compile-time `CARGO_MANIFEST_DIR`-relative `target/debug/`
//!    and `target/release/` paths.
//!
//! If none exists, the wrapper refuses cleanly with a build / install
//! hint rather than silently running the user's command unhooked.

use anyhow::{Context, Result, bail};
use clap::Args;
use shit_preload_shim::dispatch::SHIT_INSTALL_PREFIXES_ENV;
use shit_preload_shim::install_config;
use shit_preload_shim::runtime::{
    DYLD_INSERT_LIBRARIES_ENV, LD_PRELOAD_ENV, SHIT_DAEMON_SOCK_ENV, SHIT_PRELOAD_ACTIVE_ENV,
};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Args)]
pub struct InstallArgs {
    /// Explicit path to `libshit_preload_shim.{so,dylib}`. Overrides the
    /// default search.
    #[arg(long, value_name = "PATH")]
    pub lib: Option<PathBuf>,
    /// Override the daemon UDS path. Defaults to the resolved
    /// `SHIT_DAEMON_SOCK` env, then the daemon's ctl socket path.
    #[arg(long, value_name = "PATH")]
    pub sock: Option<PathBuf>,
    /// Print the resolved env vars and exit without exec-ing the
    /// user's command. Useful for debugging the wrapper's setup
    /// without actually running the install.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
    /// User's command and its argv. Use `--` to separate from
    /// `shit install`'s own options.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub cmd: Vec<String>,
}

pub fn run(args: InstallArgs) -> Result<()> {
    if args.cmd.is_empty() {
        bail!("shit install: missing command (try `shit install -- <cmd> <args...>`)");
    }
    let lib_path = resolve_lib_path(args.lib.as_deref())
        .context("could not locate libshit_preload_shim.{so,dylib}; pass `--lib <path>` or install the daemon package")?;
    let sock_path = resolve_sock_path(args.sock.as_deref())?;
    let install_prefixes = resolve_install_prefixes()?;
    let install_prefixes_env = encode_install_prefixes(&install_prefixes)?;

    let preload_env = if cfg!(target_os = "macos") {
        DYLD_INSERT_LIBRARIES_ENV
    } else {
        LD_PRELOAD_ENV
    };

    if args.dry_run {
        println!("shit install: would run:");
        println!("  argv      = {:?}", args.cmd);
        println!("  {preload_env} = {}", lib_path.display());
        println!("  {SHIT_PRELOAD_ACTIVE_ENV} = 1");
        println!("  {SHIT_DAEMON_SOCK_ENV} = {}", sock_path.display());
        println!("  {SHIT_INSTALL_PREFIXES_ENV} = {install_prefixes_env}");
        return Ok(());
    }

    let (cmd, rest) = args.cmd.split_first().unwrap();
    let mut child = Command::new(cmd);
    child.args(rest);
    child.env(preload_env, &lib_path);
    child.env(SHIT_PRELOAD_ACTIVE_ENV, "1");
    child.env(SHIT_DAEMON_SOCK_ENV, &sock_path);
    child.env(SHIT_INSTALL_PREFIXES_ENV, &install_prefixes_env);

    let status = child.status().with_context(|| format!("exec {cmd}"))?;
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    // Killed by signal — exit non-zero so the parent shell sees a
    // failure rather than silently succeeding.
    std::process::exit(128);
}

/// Resolve the configured install roots before loading the shim. The cdylib
/// deliberately does not parse TOML or consult HOME on its syscall hot path;
/// callers pass this stable, fully expanded set through the environment.
pub(super) fn resolve_install_prefixes() -> Result<Vec<String>> {
    let config_path = crate::config_home()?.join("shit/install-prefixes.toml");
    let home = crate::home_dir()?;
    resolve_install_prefixes_from(&config_path, &home)
}

fn resolve_install_prefixes_from(config_path: &Path, home: &Path) -> Result<Vec<String>> {
    let config = install_config::load_file(config_path)
        .with_context(|| format!("load install prefixes from {}", config_path.display()))?;
    let prefixes = install_config::resolve_with_fs(&config, home)
        .with_context(|| format!("resolve install prefixes from {}", config_path.display()))?;
    prefixes
        .into_iter()
        .map(|prefix| {
            let canonical = std::fs::canonicalize(&prefix)
                .with_context(|| format!("canonicalize install prefix {prefix}"))?;
            canonical.into_os_string().into_string().map_err(|_| {
                anyhow::anyhow!("install prefix is not representable as UTF-8: {prefix}")
            })
        })
        .collect()
}

/// Encode the prefix set in the shim's documented colon-separated wire form.
/// Refuse an unrepresentable path rather than silently broadening or splitting
/// the capture scope at the wrong boundary.
pub(super) fn encode_install_prefixes(prefixes: &[String]) -> Result<String> {
    if let Some(path) = prefixes.iter().find(|path| path.contains(':')) {
        bail!("install prefix contains ':' and cannot be encoded safely: {path}");
    }
    Ok(prefixes.join(":"))
}

/// Find `libshit_preload_shim.{so,dylib}` in the documented search order.
fn resolve_lib_path(override_path: Option<&Path>) -> Result<PathBuf> {
    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    if let Some(p) = override_path {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        bail!("--lib path does not exist: {}", p.display());
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        let mut p = PathBuf::from(xdg);
        p.push("shit/lib");
        p.push(format!("libshit_preload_shim.{ext}"));
        candidates.push(p);
    }
    if let Ok(home) = crate::home_dir() {
        let mut p = home;
        p.push(".local/share/shit/lib");
        p.push(format!("libshit_preload_shim.{ext}"));
        candidates.push(p);
    }
    candidates.push(PathBuf::from(format!(
        "/usr/local/lib/shit/libshit_preload_shim.{ext}"
    )));
    // Dev-mode fallbacks under the workspace target dir. The cdylib
    // crate-type emits `libshit_preload_shim.{so,dylib}` (underscored) so
    // we check both forms.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir)
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf);
    if let Some(root) = workspace_root {
        for profile in ["release", "debug"] {
            let mut p = root.clone();
            p.push("target");
            p.push(profile);
            p.push(format!("libshit_preload_shim.{ext}"));
            candidates.push(p);
        }
    }
    for c in &candidates {
        if c.exists() {
            return Ok(c.clone());
        }
    }
    bail!(
        "no libshit_preload_shim.{ext} found; searched: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Choose the daemon UDS path the shim will connect to.
fn resolve_sock_path(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    if let Some(env) = std::env::var_os(SHIT_DAEMON_SOCK_ENV) {
        return Ok(PathBuf::from(env));
    }
    Ok(crate::paths::default_ctl_socket_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolution helper returns an explicit path if it exists.
    #[test]
    fn resolve_lib_path_honors_existing_override() {
        // The cargo manifest is guaranteed to exist; use it as a
        // stand-in for the lib path. We only care that the function
        // returns the override when it exists, not that it's a real
        // .so / .dylib.
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let got = resolve_lib_path(Some(&p)).unwrap();
        assert_eq!(got, p);
    }

    #[test]
    fn resolve_lib_path_rejects_nonexistent_override() {
        let p = PathBuf::from("/nonexistent/path/libshit_preload_shim.so");
        let err = resolve_lib_path(Some(&p)).unwrap_err();
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn resolve_sock_path_uses_override_first() {
        let p = PathBuf::from("/tmp/test-shit.sock");
        let got = resolve_sock_path(Some(&p)).unwrap();
        assert_eq!(got, p);
    }

    #[test]
    fn install_prefix_env_is_colon_separated() {
        let encoded = encode_install_prefixes(&[
            "/usr/local".to_string(),
            "/Users/u/Library/Python".to_string(),
        ])
        .unwrap();
        assert_eq!(encoded, "/usr/local:/Users/u/Library/Python");
    }

    #[test]
    fn install_prefix_env_rejects_unrepresentable_colon() {
        let err = encode_install_prefixes(&["/tmp/prefix:other".to_string()]).unwrap_err();
        assert!(err.to_string().contains("cannot be encoded safely"));
    }

    #[test]
    fn configured_install_prefixes_are_canonicalized_before_handoff() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let real_prefix = temp.path().join("real-prefix");
        let configured_prefix = temp.path().join("configured-prefix");
        let config_path = temp.path().join("install-prefixes.toml");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&real_prefix).unwrap();
        std::os::unix::fs::symlink(&real_prefix, &configured_prefix).unwrap();
        std::fs::write(
            &config_path,
            format!(
                "replace = true\n[[prefix]]\npath = {:?}\n",
                configured_prefix.to_string_lossy()
            ),
        )
        .unwrap();

        let prefixes = resolve_install_prefixes_from(&config_path, &home).unwrap();
        assert_eq!(
            prefixes,
            vec![
                std::fs::canonicalize(&real_prefix)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            ]
        );
    }
}
