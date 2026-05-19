// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit auto-inject-install-env <argv...>` — shell hook helper that
//! decides whether an about-to-run command matches an install
//! pattern, and if so, prints the env-var assignments the shell
//! should prepend to the command (C05.7).
//!
//! The shell preexec hook calls this once per command. The helper
//! exits 0 with empty stdout when the command doesn't match (the
//! hook then runs the command unwrapped); when it does match, the
//! helper prints assignment-per-line output the hook prepends to the
//! user's command line.
//!
//! ## Output forms
//!
//! - `--shell posix` (default): assignment-per-line, single-quoted,
//!   suitable for `eval`-prepending in bash / zsh:
//!
//!   ```text
//!   LD_PRELOAD='/usr/local/lib/shit/libshit-preload.so'
//!   SHIT_PRELOAD_ACTIVE='1'
//!   SHIT_DAEMON_SOCK='/var/run/shit/daemon.sock'
//!   ```
//!
//! - `--shell fish`: fish-syntax env assignments. The hook wraps the
//!   user command with `env` invocations or `--no-shadowing` set
//!   commands.
//!
//! - `--json`: structured output for non-shell consumers (the daemon's
//!   own command-runner harness for tests).

use clap::{Args, ValueEnum};
use shit_preload_shim::install_pattern::{InstallPattern, classify_install_argv};
use shit_preload_shim::runtime::{
    DYLD_INSERT_LIBRARIES_ENV, LD_PRELOAD_ENV, SHIT_DAEMON_SOCK_ENV, SHIT_PRELOAD_ACTIVE_ENV,
};

use crate::exitcode::CliError;

#[derive(Debug, Clone, ValueEnum, Default)]
pub enum ShellSyntax {
    /// `KEY='value'` — works for bash, zsh, sh, dash, mksh, ksh.
    #[default]
    Posix,
    /// `set -x KEY value` — fish's standard form.
    Fish,
}

#[derive(Debug, Clone, Args)]
pub struct AutoInjectArgs {
    /// Output syntax. `--shell posix` (default) emits
    /// `KEY='value'`-per-line; `--shell fish` emits `set -x KEY value`.
    #[arg(long, value_enum, default_value_t = ShellSyntax::Posix)]
    pub shell: ShellSyntax,
    /// JSON output. Mutually exclusive with `--shell`.
    #[arg(long, default_value_t = false, conflicts_with = "shell")]
    pub json: bool,
    /// Explicit path to `libshit-preload.{so,dylib}`. The hook
    /// resolves this at install time and bakes it in; this flag
    /// exists for test harnesses.
    #[arg(long, value_name = "PATH")]
    pub lib: Option<String>,
    /// Explicit daemon socket path. The hook bakes the resolved path
    /// at install time; this flag is for tests.
    #[arg(long, value_name = "PATH")]
    pub sock: Option<String>,
    /// The argv being inspected. Use `--` to separate from
    /// `shit auto-inject-install-env`'s own options.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub argv: Vec<String>,
}

pub fn run(args: AutoInjectArgs) -> Result<(), CliError> {
    let matched = classify_install_argv(&args.argv);
    let Some(pattern) = matched else {
        // No match: exit 0 with empty stdout. Shell hook treats
        // empty output as "run unhooked".
        return Ok(());
    };
    let lib = args.lib.clone().unwrap_or_else(default_lib_path_for_render);
    let sock = args
        .sock
        .clone()
        .unwrap_or_else(default_sock_path_for_render);
    let assignments = build_assignments(&lib, &sock);
    if args.json {
        render_json(pattern, &assignments)?;
    } else {
        match args.shell {
            ShellSyntax::Posix => render_posix(&assignments),
            ShellSyntax::Fish => render_fish(&assignments),
        }
    }
    Ok(())
}

/// Path placeholder used in the rendered output when the caller
/// hasn't passed `--lib`. Production `shit install` resolves a real
/// path, but the auto-inject helper hands the bake-time placeholder
/// to the shell hook so the hook can substitute it once at install
/// time.
fn default_lib_path_for_render() -> String {
    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    format!("/usr/local/lib/shit/libshit-preload.{ext}")
}

fn default_sock_path_for_render() -> String {
    crate::paths::default_ctl_socket_path()
        .display()
        .to_string()
}

fn build_assignments(lib: &str, sock: &str) -> Vec<(&'static str, String)> {
    let preload_env = if cfg!(target_os = "macos") {
        DYLD_INSERT_LIBRARIES_ENV
    } else {
        LD_PRELOAD_ENV
    };
    vec![
        (preload_env, lib.to_string()),
        (SHIT_PRELOAD_ACTIVE_ENV, "1".to_string()),
        (SHIT_DAEMON_SOCK_ENV, sock.to_string()),
    ]
}

fn render_posix(assignments: &[(&'static str, String)]) {
    for (k, v) in assignments {
        println!("{k}='{}'", posix_single_quote(v));
    }
}

fn render_fish(assignments: &[(&'static str, String)]) {
    for (k, v) in assignments {
        println!("set -x {k} '{}'", posix_single_quote(v));
    }
}

fn render_json(
    pattern: InstallPattern,
    assignments: &[(&'static str, String)],
) -> Result<(), CliError> {
    let json_assignments: Vec<serde_json::Value> = assignments
        .iter()
        .map(|(k, v)| serde_json::json!({"name": k, "value": v}))
        .collect();
    let payload = serde_json::json!({
        "pattern": pattern.as_str(),
        "env": json_assignments,
    });
    println!("{}", serde_json::to_string(&payload).unwrap_or_default());
    Ok(())
}

/// POSIX shell single-quote escape: the only thing that needs
/// escaping inside `'...'` is a single quote itself, which is done by
/// closing the string, emitting `\'`, and reopening — i.e. `'\''`.
fn posix_single_quote(s: &str) -> String {
    s.replace('\'', "'\\''")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_for(argv: &[&str]) -> AutoInjectArgs {
        AutoInjectArgs {
            shell: ShellSyntax::Posix,
            json: false,
            lib: Some("/lib/preload.so".into()),
            sock: Some("/run/shit.sock".into()),
            argv: argv.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn non_install_argv_produces_no_output() {
        // We can't capture stdout from a clap-driven `run()` easily
        // here, so we exercise the classifier path that gates the
        // output.
        let argv: Vec<String> = ["cd", "/tmp"].iter().map(|s| s.to_string()).collect();
        assert!(classify_install_argv(&argv).is_none());
    }

    #[test]
    fn build_assignments_contains_all_three_vars() {
        let a = build_assignments("/lib.so", "/sock");
        assert_eq!(a.len(), 3);
        let names: Vec<&str> = a.iter().map(|(k, _)| *k).collect();
        if cfg!(target_os = "macos") {
            assert!(names.contains(&DYLD_INSERT_LIBRARIES_ENV));
        } else {
            assert!(names.contains(&LD_PRELOAD_ENV));
        }
        assert!(names.contains(&SHIT_PRELOAD_ACTIVE_ENV));
        assert!(names.contains(&SHIT_DAEMON_SOCK_ENV));
    }

    #[test]
    fn posix_single_quote_escapes_inner_quotes() {
        assert_eq!(posix_single_quote("/a/b"), "/a/b");
        assert_eq!(posix_single_quote("a'b"), "a'\\''b");
        assert_eq!(posix_single_quote("'"), "'\\''");
    }

    #[test]
    fn classify_install_argv_returns_pattern_for_recognised_argvs() {
        // Sanity: the install-pattern matcher is reachable from
        // here. (Full coverage lives in install_pattern's own tests.)
        let argv: Vec<String> = ["make", "install"].iter().map(|s| s.to_string()).collect();
        assert_eq!(classify_install_argv(&argv), Some(InstallPattern::Make));
    }

    #[test]
    fn shell_syntax_default_is_posix() {
        assert!(matches!(ShellSyntax::default(), ShellSyntax::Posix));
    }

    #[test]
    fn dummy_args_run_returns_ok_for_no_match() {
        // The matcher returning None ⇒ run() prints nothing and exits
        // 0. We can't intercept stdout here, but we can confirm the
        // happy path returns Ok.
        let args = args_for(&["cd", "/tmp"]);
        let out = run(args);
        assert!(out.is_ok());
    }
}
