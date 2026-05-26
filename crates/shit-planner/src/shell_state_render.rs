// SPDX-License-Identifier: AGPL-3.0-or-later

//! AR06.1/.2/.3 — snippet rendering for shell-state diffs.
//!
//! Mirrors `shit_shell::snippet::render_bash` / `render_zsh`. We
//! re-implement here rather than pulling shit-shell into shit-
//! planner's dep graph because the diff shape lives natively in
//! the planner's `inverse::{OptDiff, AliasDiff, FuncDiff}` types
//! and the renderer is ~40 lines per shell.
//!
//! ## Quoting
//!
//! POSIX single-quote escape: `'` -> `'\''`. The closing quote
//! ends the literal, then `\'` inserts a literal quote, then `'`
//! re-opens. This works in both bash and zsh.

use crate::inverse::{AliasDiff, FuncDiff, OptDiff};
use std::path::Path;

/// POSIX single-quote-escape a string. Result is safe to wrap in
/// outer single-quotes: `'<escaped>'`.
fn sh_quote(s: &str) -> String {
    let inner = s.replace('\'', "'\\''");
    format!("'{inner}'")
}

/// fish single-quote-escape. fish single-quoted strings honor
/// only `\\` (literal backslash) and `\'` (literal single-quote)
/// as escapes — the bash `'...'\''...'` dance is invalid here.
fn fish_quote(s: &str) -> String {
    let inner = s.replace('\\', "\\\\").replace('\'', "\\'");
    format!("'{inner}'")
}

/// Render a bash snippet that reverses the captured diff. The
/// snippet ends with a trailing newline so the precmd-queue
/// drain (source + truncate) handles multiple queued entries
/// cleanly.
pub fn render_bash(
    pwd_before: Option<&Path>,
    opts: &[OptDiff],
    aliases: &[AliasDiff],
    funcs: &[FuncDiff],
) -> String {
    let mut out = String::new();
    if let Some(p) = pwd_before {
        out.push_str(&format!("cd {}\n", sh_quote(&p.to_string_lossy())));
    }
    for opt in opts {
        if opt.pre == "on" && opt.post != "on" {
            out.push_str(&format!("set -o {}\n", opt.name));
        } else if opt.pre == "off" && opt.post != "off" {
            out.push_str(&format!("set +o {}\n", opt.name));
        } else {
            // Stringly-typed option — bash can't set/unset
            // generically; surface as a comment for the user.
            out.push_str(&format!(
                "# manual: option `{}` was `{}`, now `{}`\n",
                opt.name, opt.pre, opt.post
            ));
        }
    }
    for a in aliases {
        match &a.pre {
            Some(expansion) => {
                out.push_str(&format!("alias {}={}\n", a.name, sh_quote(expansion)));
            }
            None => {
                // Alias didn't exist before — undo it.
                out.push_str(&format!("unalias {} 2>/dev/null || true\n", a.name));
            }
        }
    }
    for f in funcs {
        match &f.pre {
            Some(body) => {
                // Preserve the function body verbatim. `declare -f`
                // emits `name () { ...body... }` which is valid bash
                // that re-defines the function on source.
                out.push_str(body);
                if !body.ends_with('\n') {
                    out.push('\n');
                }
            }
            None => {
                out.push_str(&format!("unset -f {} 2>/dev/null || true\n", f.name));
            }
        }
    }
    out
}

/// Render a zsh snippet. Differs from bash only on the option
/// path: zsh uses `setopt` / `unsetopt`, not `set ±o`.
pub fn render_zsh(
    pwd_before: Option<&Path>,
    opts: &[OptDiff],
    aliases: &[AliasDiff],
    funcs: &[FuncDiff],
) -> String {
    let mut out = String::new();
    if let Some(p) = pwd_before {
        out.push_str(&format!("cd {}\n", sh_quote(&p.to_string_lossy())));
    }
    for opt in opts {
        if opt.pre == "on" && opt.post != "on" {
            out.push_str(&format!("setopt {}\n", opt.name));
        } else if opt.pre == "off" && opt.post != "off" {
            out.push_str(&format!("unsetopt {}\n", opt.name));
        } else {
            out.push_str(&format!(
                "# manual: option `{}` was `{}`, now `{}`\n",
                opt.name, opt.pre, opt.post
            ));
        }
    }
    for a in aliases {
        match &a.pre {
            Some(expansion) => {
                out.push_str(&format!("alias {}={}\n", a.name, sh_quote(expansion)));
            }
            None => {
                out.push_str(&format!("unalias {} 2>/dev/null || true\n", a.name));
            }
        }
    }
    for f in funcs {
        match &f.pre {
            Some(body) => {
                out.push_str(body);
                if !body.ends_with('\n') {
                    out.push('\n');
                }
            }
            None => {
                out.push_str(&format!("unset -f {} 2>/dev/null || true\n", f.name));
            }
        }
    }
    out
}

/// Render a fish snippet. Differs from bash/zsh:
///
/// - Quoting follows fish single-quote rules (`\\` and `\'`); the
///   POSIX `'...'\''...'` dance is invalid in fish.
/// - fish has no `set -o` equivalent (no shell-wide errexit /
///   nounset / etc.), so opt diffs surface as comments only.
/// - aliases in fish are functions; removal is `functions --erase`
///   not `unalias`.
///
/// Informational only on the apply path — `ShellStateExecutor`
/// refuses fish via DR-30. This rendering is for `shit show` and
/// the user copy-pasting manually.
pub fn render_fish(
    pwd_before: Option<&Path>,
    opts: &[OptDiff],
    aliases: &[AliasDiff],
    funcs: &[FuncDiff],
) -> String {
    let mut out = String::new();
    if let Some(p) = pwd_before {
        out.push_str(&format!("cd {}\n", fish_quote(&p.to_string_lossy())));
    }
    for opt in opts {
        out.push_str(&format!(
            "# manual: option `{}` was `{}`, now `{}` (fish has no `set -o` equivalent)\n",
            opt.name, opt.pre, opt.post
        ));
    }
    for a in aliases {
        match &a.pre {
            Some(expansion) => {
                out.push_str(&format!("alias {}={}\n", a.name, fish_quote(expansion)));
            }
            None => {
                out.push_str(&format!(
                    "functions --erase {} 2>/dev/null; or true\n",
                    a.name
                ));
            }
        }
    }
    for f in funcs {
        match &f.pre {
            Some(body) => {
                out.push_str(body);
                if !body.ends_with('\n') {
                    out.push('\n');
                }
            }
            None => {
                out.push_str(&format!(
                    "functions --erase {} 2>/dev/null; or true\n",
                    f.name
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn pwd_only_renders_cd_with_quoting() {
        let pwd = PathBuf::from("/home/u/it's a project");
        let snip = render_bash(Some(&pwd), &[], &[], &[]);
        // POSIX single-quote escape: ' becomes '\''
        assert!(snip.contains("'/home/u/it'\\''s a project'"));
    }

    #[test]
    fn errexit_off_to_on_renders_set_plus_o() {
        let opt = OptDiff {
            name: "errexit".into(),
            pre: "off".into(),
            post: "on".into(),
        };
        let snip = render_bash(None, &[opt], &[], &[]);
        assert!(snip.contains("set +o errexit\n"));
    }

    #[test]
    fn errexit_on_to_off_renders_set_dash_o() {
        let opt = OptDiff {
            name: "errexit".into(),
            pre: "on".into(),
            post: "off".into(),
        };
        let snip = render_bash(None, &[opt], &[], &[]);
        assert!(snip.contains("set -o errexit\n"));
    }

    #[test]
    fn newly_set_alias_unaliased_on_undo() {
        let a = AliasDiff {
            name: "g".into(),
            pre: None,
            post: Some("git".into()),
        };
        let snip = render_bash(None, &[], &[a], &[]);
        assert!(snip.contains("unalias g 2>/dev/null || true"));
    }

    #[test]
    fn modified_alias_restores_to_pre_value() {
        let a = AliasDiff {
            name: "ll".into(),
            pre: Some("ls -la".into()),
            post: Some("ls -laFh".into()),
        };
        let snip = render_bash(None, &[], &[a], &[]);
        assert!(snip.contains("alias ll='ls -la'\n"));
    }

    #[test]
    fn zsh_uses_setopt_not_set_dash_o() {
        let opt = OptDiff {
            name: "errexit".into(),
            pre: "off".into(),
            post: "on".into(),
        };
        let snip = render_zsh(None, &[opt], &[], &[]);
        assert!(snip.contains("unsetopt errexit\n"));
        assert!(!snip.contains("set "));
    }

    #[test]
    fn stringly_typed_opt_surfaces_as_comment() {
        let opt = OptDiff {
            name: "history-size".into(),
            pre: "1000".into(),
            post: "10000".into(),
        };
        let snip = render_bash(None, &[opt], &[], &[]);
        assert!(snip.contains("# manual:"));
        assert!(snip.contains("`1000`"));
    }

    #[test]
    fn fish_pwd_uses_fish_quoting() {
        // fish escapes ' as \' inside single quotes, not '\'' like bash.
        let pwd = PathBuf::from("/home/u/it's a project");
        let snip = render_fish(Some(&pwd), &[], &[], &[]);
        assert!(snip.contains("'/home/u/it\\'s a project'"));
    }

    #[test]
    fn fish_opts_always_comment_only() {
        let opt = OptDiff {
            name: "errexit".into(),
            pre: "off".into(),
            post: "on".into(),
        };
        let snip = render_fish(None, &[opt], &[], &[]);
        assert!(snip.contains("# manual:"));
        assert!(snip.contains("no `set -o`"));
        // Critical: no `set -o` / `setopt` ever leaks through.
        assert!(!snip.contains("\nset -o "));
        assert!(!snip.contains("\nsetopt "));
    }

    #[test]
    fn fish_new_alias_erases_via_functions_erase() {
        let a = AliasDiff {
            name: "g".into(),
            pre: None,
            post: Some("git".into()),
        };
        let snip = render_fish(None, &[], &[a], &[]);
        assert!(snip.contains("functions --erase g"));
        // Must NOT emit POSIX unalias.
        assert!(!snip.contains("unalias "));
    }

    #[test]
    fn fish_modified_alias_restores_with_alias_keyword() {
        let a = AliasDiff {
            name: "ll".into(),
            pre: Some("ls -la".into()),
            post: Some("ls -laFh".into()),
        };
        let snip = render_fish(None, &[], &[a], &[]);
        assert!(snip.contains("alias ll='ls -la'\n"));
    }
}
