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
//! The wrapper looks for `libshit-preload.{so,dylib}` in (in order):
//!
//! 1. `--lib <path>` argument (explicit override),
//! 2. `$XDG_DATA_HOME/shit/lib/libshit-preload.{so,dylib}` (user-scope),
//! 3. `/usr/local/lib/shit/libshit-preload.{so,dylib}` (system-scope),
//! 4. `$CARGO_TARGET_DIR/<profile>/libshit_preload.{so,dylib}` (dev,
//!    detected via `OUT_DIR` of the current build),
//! 5. The compile-time `CARGO_MANIFEST_DIR`-relative `target/debug/`
//!    and `target/release/` paths.
//!
//! If none exists, the wrapper refuses cleanly with a build / install
//! hint rather than silently running the user's command unhooked.

use anyhow::{Context, Result, bail};
use clap::Args;
use shit_preload_shim::runtime::{
    DYLD_INSERT_LIBRARIES_ENV, LD_PRELOAD_ENV, SHIT_DAEMON_SOCK_ENV, SHIT_PRELOAD_ACTIVE_ENV,
};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Args)]
pub struct InstallArgs {
    /// Explicit path to `libshit-preload.{so,dylib}`. Overrides the
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
        .context("could not locate libshit-preload.{so,dylib}; pass `--lib <path>` or install the daemon package")?;
    let sock_path = resolve_sock_path(args.sock.as_deref())?;

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
        return Ok(());
    }

    let (cmd, rest) = args.cmd.split_first().unwrap();
    let mut child = Command::new(cmd);
    child.args(rest);
    child.env(preload_env, &lib_path);
    child.env(SHIT_PRELOAD_ACTIVE_ENV, "1");
    child.env(SHIT_DAEMON_SOCK_ENV, &sock_path);

    let status = child.status().with_context(|| format!("exec {cmd}"))?;
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    // Killed by signal — exit non-zero so the parent shell sees a
    // failure rather than silently succeeding.
    std::process::exit(128);
}

/// Find `libshit-preload.{so,dylib}` in the documented search order.
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
        p.push(format!("libshit-preload.{ext}"));
        candidates.push(p);
    }
    if let Ok(home) = crate::home_dir() {
        let mut p = home;
        p.push(".local/share/shit/lib");
        p.push(format!("libshit-preload.{ext}"));
        candidates.push(p);
    }
    candidates.push(PathBuf::from(format!(
        "/usr/local/lib/shit/libshit-preload.{ext}"
    )));
    // Dev-mode fallbacks under the workspace target dir. The cdylib
    // crate-type emits `libshit_preload.{so,dylib}` (underscored) so
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
            p.push(format!("libshit_preload.{ext}"));
            candidates.push(p);
        }
    }
    for c in &candidates {
        if c.exists() {
            return Ok(c.clone());
        }
    }
    bail!(
        "no libshit-preload.{ext} found; searched: {}",
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
        let p = PathBuf::from("/nonexistent/path/libshit-preload.so");
        let err = resolve_lib_path(Some(&p)).unwrap_err();
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn resolve_sock_path_uses_override_first() {
        let p = PathBuf::from("/tmp/test-shit.sock");
        let got = resolve_sock_path(Some(&p)).unwrap();
        assert_eq!(got, p);
    }
}
