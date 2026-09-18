// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shell hook templates and installer logic for `shit`.
//!
//! Each supported shell has an embedded template file (see `shell/` at repo
//! root). The installer renders a template by substituting `@@SHIT_BIN@@` and
//! `@@SHIT_SOCK@@` placeholders, writes the result to a stable per-user
//! location, and idempotently inserts a marker-delimited source line into the
//! user's rc file.

use shit_proto::ShellKind;
use std::path::{Path, PathBuf};

pub mod container_wrappers;
pub mod redirect;
pub mod snippet;
pub mod state;

pub const MARKER_BEGIN: &str = "# >>> shit hooks >>>";
pub const MARKER_END: &str = "# <<< shit hooks <<<";

const BASH_TEMPLATE: &str = include_str!("../../../shell/bash.sh");
const ZSH_TEMPLATE: &str = include_str!("../../../shell/zsh.sh");
const FISH_TEMPLATE: &str = include_str!("../../../shell/fish.fish");

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("home directory not found")]
    NoHome,
    #[error("unsupported shell: {0:?}")]
    UnsupportedShell(ShellKind),
    #[error("path is not utf-8: {0:?}")]
    NonUtf8Path(PathBuf),
}

#[derive(Debug, Clone)]
pub struct InstallParams {
    pub shit_bin: PathBuf,
    pub socket_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct InstallPlan {
    pub shell: ShellKind,
    pub rc_file: PathBuf,
    pub hook_file: PathBuf,
    pub source_line: String,
}

/// Render the embedded template for `shell` with placeholders substituted.
pub fn render_template(shell: ShellKind, params: &InstallParams) -> Result<String, InstallError> {
    let template = match shell {
        ShellKind::Bash => BASH_TEMPLATE,
        ShellKind::Zsh => ZSH_TEMPLATE,
        ShellKind::Fish => FISH_TEMPLATE,
        ShellKind::Unknown => return Err(InstallError::UnsupportedShell(shell)),
    };
    let bin = path_to_str(&params.shit_bin)?;
    let sock = path_to_str(&params.socket_path)?;
    Ok(template
        .replace("@@SHIT_BIN@@", bin)
        .replace("@@SHIT_SOCK@@", sock))
}

/// Compute the install plan (paths, source line, ...) for `shell` and the
/// given home directory. Does not touch the filesystem.
pub fn plan_install(
    shell: ShellKind,
    home: &Path,
    config_home: &Path,
) -> Result<InstallPlan, InstallError> {
    let (rc_file, hook_file, source_line) = match shell {
        ShellKind::Bash => {
            let rc = home.join(".bashrc");
            let hook = config_home.join("shit").join("hook.bash");
            let line = format!("source {}", path_to_str(&hook)?);
            (rc, hook, line)
        }
        ShellKind::Zsh => {
            let rc = home.join(".zshrc");
            let hook = config_home.join("shit").join("hook.zsh");
            let line = format!("source {}", path_to_str(&hook)?);
            (rc, hook, line)
        }
        ShellKind::Fish => {
            // fish's autoload directory is the conventional place; sourcing
            // from there is more idiomatic than appending to config.fish.
            let rc = config_home.join("fish").join("config.fish");
            let hook = config_home.join("fish").join("conf.d").join("shit.fish");
            let line = format!("# shit hook lives at {}", path_to_str(&hook)?);
            (rc, hook, line)
        }
        ShellKind::Unknown => return Err(InstallError::UnsupportedShell(shell)),
    };
    Ok(InstallPlan {
        shell,
        rc_file,
        hook_file,
        source_line,
    })
}

/// Insert (or replace) the `# >>> shit hooks >>>` marker block in `rc_content`.
/// Idempotent: re-running with the same `inner_line` yields identical output.
pub fn upsert_marker_block(rc_content: &str, inner_line: &str) -> String {
    let block = format!("{MARKER_BEGIN}\n{inner_line}\n{MARKER_END}\n");
    if let Some((before, rest)) = rc_content.split_once(MARKER_BEGIN)
        && let Some((_, after)) = rest.split_once(MARKER_END)
    {
        // Strip the existing block (and the trailing newline if present).
        let after = after.strip_prefix('\n').unwrap_or(after);
        let mut out = String::with_capacity(rc_content.len() + block.len());
        out.push_str(before);
        out.push_str(&block);
        out.push_str(after);
        return out;
    }
    // No existing block; append.
    let mut out = String::with_capacity(rc_content.len() + block.len() + 1);
    out.push_str(rc_content);
    if !rc_content.ends_with('\n') && !rc_content.is_empty() {
        out.push('\n');
    }
    out.push_str(&block);
    out
}

/// Remove the `# >>> shit hooks >>>` marker block from `rc_content`. Returns
/// the content unchanged if no block is present.
pub fn remove_marker_block(rc_content: &str) -> String {
    if let Some((before, rest)) = rc_content.split_once(MARKER_BEGIN)
        && let Some((_, after)) = rest.split_once(MARKER_END)
    {
        let after = after.strip_prefix('\n').unwrap_or(after);
        let mut out = String::with_capacity(before.len() + after.len());
        out.push_str(before.trim_end_matches('\n'));
        if !before.is_empty() && !after.is_empty() {
            out.push('\n');
        }
        out.push_str(after);
        return out;
    }
    rc_content.to_string()
}

fn path_to_str(p: &Path) -> Result<&str, InstallError> {
    p.to_str()
        .ok_or_else(|| InstallError::NonUtf8Path(p.to_path_buf()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_rendered_with_substitutions() {
        let params = InstallParams {
            shit_bin: PathBuf::from("/usr/local/bin/shit"),
            socket_path: PathBuf::from("/tmp/shit-1000.sock"),
        };
        let body = render_template(ShellKind::Bash, &params).unwrap();
        assert!(body.contains("/usr/local/bin/shit"));
        assert!(body.contains("/tmp/shit-1000.sock"));
        assert!(!body.contains("@@SHIT_BIN@@"));
        assert!(!body.contains("@@SHIT_SOCK@@"));
    }

    #[test]
    fn post_capture_messages_precede_command_close_in_every_template() {
        let params = InstallParams {
            shit_bin: PathBuf::from("/usr/local/bin/shit"),
            socket_path: PathBuf::from("/tmp/shit.sock"),
        };
        for shell in [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish] {
            let body = render_template(shell, &params).unwrap();
            let post_shell = body
                .find("hook-send post-exec-shell-state")
                .expect("post shell-state capture");
            let post_env = body
                .find("hook-send post-exec-env")
                .expect("post env capture");
            let close = body
                .find("hook-send post-exec \\")
                .expect("PostExec close message");
            assert!(
                post_shell < close,
                "{shell:?}: shell state must precede close"
            );
            assert!(post_env < close, "{shell:?}: env must precede close");
            assert!(
                body.contains("_SHIT_PREPARED_SEQ"),
                "{shell:?}: hook failures must gate close"
            );
            assert!(
                body.contains("_SHIT_PREPARED_SEQ=-1") || body.contains("_SHIT_PREPARED_SEQ -1"),
                "{shell:?}: startup prompt must not close synthetic sequence zero"
            );
        }
    }

    #[test]
    fn redirect_prestash_is_ordered_and_uses_the_live_command_in_every_template() {
        let params = InstallParams {
            shit_bin: PathBuf::from("/usr/local/bin/shit"),
            socket_path: PathBuf::from("/tmp/shit.sock"),
        };
        for shell in [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish] {
            let body = render_template(shell, &params).unwrap();
            let pre_exec = body
                .find("hook-send pre-exec \\")
                .expect("PreExec command open");
            let shell_state = body
                .find("hook-send pre-exec-shell-state")
                .expect("pre-command shell state");
            let redirects = body
                .find("hook-send pre-exec-redirects")
                .expect("synchronous redirect pre-stash");
            let prepared = match shell {
                ShellKind::Bash | ShellKind::Zsh => body
                    .find("_SHIT_PREPARED_SEQ=$_SHIT_SEQ")
                    .expect("prepared close marker"),
                ShellKind::Fish => body
                    .find("set _SHIT_PREPARED_SEQ $_SHIT_SEQ")
                    .expect("prepared close marker"),
                ShellKind::Unknown => unreachable!(),
            };
            assert!(
                pre_exec < shell_state && shell_state < redirects && redirects < prepared,
                "{shell:?}: redirect pre-stash must run after command open and before execution is marked prepared"
            );

            let redirect_call = &body[redirects..body.len().min(redirects + 400)];
            let (seq, cmdline) = match shell {
                ShellKind::Bash => ("--seq \"$_SHIT_SEQ\"", "--cmdline \"$BASH_COMMAND\""),
                ShellKind::Zsh => ("--seq \"$_SHIT_SEQ\"", "--cmdline \"${1:-}\""),
                ShellKind::Fish => ("--seq $_SHIT_SEQ", "--cmdline \"$_shit_cmdline\""),
                ShellKind::Unknown => unreachable!(),
            };
            assert!(
                redirect_call.contains(seq),
                "{shell:?}: redirect request must use the current command sequence"
            );
            assert!(
                redirect_call.contains(cmdline),
                "{shell:?}: redirect request must preserve the shell's live command text"
            );
        }
    }

    #[test]
    fn companion_failure_is_recovered_before_any_later_sequence() {
        let params = InstallParams {
            shit_bin: PathBuf::from("/definitely/missing/shit"),
            socket_path: PathBuf::from("/tmp/shit.sock"),
        };
        for shell in [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish] {
            let body = render_template(shell, &params).unwrap();
            let redirect = body
                .find("hook-send pre-exec-redirects")
                .expect("redirect pre-stash call");
            let prepared = match shell {
                ShellKind::Bash | ShellKind::Zsh => body
                    .find("_SHIT_PREPARED_SEQ=$_SHIT_SEQ")
                    .expect("prepared close marker"),
                ShellKind::Fish => body
                    .find("set _SHIT_PREPARED_SEQ $_SHIT_SEQ")
                    .expect("prepared close marker"),
                ShellKind::Unknown => unreachable!(),
            };
            let failure_path = &body[redirect..prepared];
            match shell {
                ShellKind::Bash | ShellKind::Zsh => {
                    assert!(failure_path.contains("__shit_mark_failed"));
                    assert!(failure_path.contains("return 0"));
                    assert!(!failure_path.contains("|| true"));
                }
                ShellKind::Fish => {
                    assert!(failure_path.contains("__shit_mark_failed"));
                    assert!(failure_path.contains("return 0"));
                    assert!(!failure_path.contains("or true"));
                }
                ShellKind::Unknown => unreachable!(),
            }

            assert!(
                body.contains("hook-send refuse-and-close"),
                "{shell:?}: failures need a synchronous durable close path"
            );
            assert!(
                body.contains("_SHIT_FAILED_SEQ"),
                "{shell:?}: a failed sequence must survive across prompt cycles"
            );

            let recovery_call = body
                .find("__shit_refuse_and_close_failed")
                .expect("recovery helper definition");
            let pre_increment = match shell {
                ShellKind::Bash | ShellKind::Zsh => {
                    body.find("_SHIT_SEQ=$((").expect("sequence increment")
                }
                ShellKind::Fish => body
                    .find("set _SHIT_SEQ (math")
                    .expect("sequence increment"),
                ShellKind::Unknown => unreachable!(),
            };
            assert!(
                recovery_call < pre_increment,
                "{shell:?}: recovery must be available before a new sequence opens"
            );
        }
    }

    #[test]
    fn session_and_sequence_are_exported_to_mutating_descendants() {
        let params = InstallParams {
            shit_bin: PathBuf::from("/usr/local/bin/shit"),
            socket_path: PathBuf::from("/tmp/shit.sock"),
        };
        let bash = render_template(ShellKind::Bash, &params).unwrap();
        assert!(bash.contains("export _SHIT_SESSION"));
        assert!(bash.contains("export _SHIT_SEQ=0"));

        let zsh = render_template(ShellKind::Zsh, &params).unwrap();
        assert!(zsh.contains("export _SHIT_SESSION"));
        assert!(zsh.contains("export _SHIT_SEQ"));

        let fish = render_template(ShellKind::Fish, &params).unwrap();
        assert!(fish.contains("set -gx _SHIT_SESSION"));
        assert!(fish.contains("set -gx _SHIT_SEQ"));
    }

    #[test]
    fn every_template_activates_the_wrapper_directory_on_path() {
        let params = InstallParams {
            shit_bin: PathBuf::from("/usr/local/bin/shit"),
            socket_path: PathBuf::from("/tmp/shit.sock"),
        };
        for shell in [ShellKind::Bash, ShellKind::Zsh, ShellKind::Fish] {
            let body = render_template(shell, &params).unwrap();
            assert!(
                body.contains("_SHIT_HOOK_BIN_DIR"),
                "{shell:?}: wrapper directory variable missing"
            );
            assert!(
                body.contains("shit/bin"),
                "{shell:?}: wrapper directory is not constructed"
            );
            assert!(
                body.contains("PATH"),
                "{shell:?}: wrapper directory is not activated"
            );
        }
    }

    #[test]
    fn upsert_into_empty_appends_block() {
        let out = upsert_marker_block("", "source /tmp/h.sh");
        assert!(out.contains(MARKER_BEGIN));
        assert!(out.contains("source /tmp/h.sh"));
        assert!(out.contains(MARKER_END));
    }

    #[test]
    fn upsert_is_idempotent() {
        let line = "source /tmp/h.sh";
        let once = upsert_marker_block("existing rc content\n", line);
        let twice = upsert_marker_block(&once, line);
        assert_eq!(once, twice);
    }

    #[test]
    fn upsert_replaces_old_block() {
        let mut s = String::from("preamble\n");
        s.push_str(MARKER_BEGIN);
        s.push_str("\nold-line\n");
        s.push_str(MARKER_END);
        s.push_str("\ntail\n");

        let out = upsert_marker_block(&s, "new-line");
        assert!(out.contains("new-line"));
        assert!(!out.contains("old-line"));
        assert!(out.contains("preamble"));
        assert!(out.contains("tail"));
    }

    #[test]
    fn remove_strips_block() {
        let mut s = String::from("before\n");
        s.push_str(MARKER_BEGIN);
        s.push_str("\nthe line\n");
        s.push_str(MARKER_END);
        s.push_str("\nafter\n");

        let out = remove_marker_block(&s);
        assert!(!out.contains(MARKER_BEGIN));
        assert!(!out.contains("the line"));
        assert!(out.contains("before"));
        assert!(out.contains("after"));
    }

    #[test]
    fn remove_no_block_is_noop() {
        let s = "rc with no block\n";
        assert_eq!(s, remove_marker_block(s));
    }

    #[test]
    fn plan_install_bash() {
        let plan = plan_install(
            ShellKind::Bash,
            Path::new("/home/u"),
            Path::new("/home/u/.config"),
        )
        .unwrap();
        assert_eq!(plan.rc_file, PathBuf::from("/home/u/.bashrc"));
        assert_eq!(
            plan.hook_file,
            PathBuf::from("/home/u/.config/shit/hook.bash")
        );
    }
}
