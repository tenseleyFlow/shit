// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-shell undo-snippet renderer (C06.4).
//!
//! Takes a `state::Diff` and emits a shell-script snippet the user
//! can source (or, with `shit undo --apply-shell-state`, the bash /
//! zsh precmd queue runs automatically) to restore the pre-state.
//!
//! Three target shells — bash, zsh, fish — with slightly different
//! syntaxes for option manipulation, alias management, and function
//! deletion. Fish handles aliases as functions, so its snippet
//! always renders aliases as `function … end` blocks.
//!
//! The renderer is pure: a `Diff` in, a `String` out. Both are
//! exercised end-to-end in C06.9's integration tests.

use crate::state::Diff;

/// Render an undo snippet targeting `bash`.
pub fn render_bash(diff: &Diff) -> String {
    let mut out = String::new();
    out.push_str("# C06: restore shell state. Re-source to apply.\n");
    if let Some((from, _to)) = &diff.pwd_changed {
        out.push_str(&format!("cd {}\n", sh_quote(&from.to_string_lossy())));
    }
    for (name, pre, post) in &diff.opts {
        // bash's set -o NAME enables; set +o NAME disables.
        if pre == "on" && post != "on" {
            out.push_str(&format!("set -o {name}\n"));
        } else if pre == "off" && post != "off" {
            out.push_str(&format!("set +o {name}\n"));
        } else {
            // Numeric / stringly-typed options bash can't restore via
            // set ±o. Surface as a comment so the user knows what to
            // tweak manually.
            out.push_str(&format!(
                "# manual: option `{name}` was `{pre}`, now `{post}`\n"
            ));
        }
    }
    for (name, pre, _post) in &diff.aliases {
        match pre {
            Some(expansion) => {
                out.push_str(&format!("alias {name}={}\n", sh_quote(expansion)));
            }
            None => {
                // The alias didn't exist before — unalias it.
                out.push_str(&format!("unalias {name} 2>/dev/null || true\n"));
            }
        }
    }
    for (name, pre, _post) in &diff.funcs {
        match pre {
            Some(body) => {
                // Preserve the function body verbatim. The body
                // already includes the `name() { ... }` shape (the
                // capture-side renderer normalises it).
                out.push_str(body);
                if !body.ends_with('\n') {
                    out.push('\n');
                }
            }
            None => {
                out.push_str(&format!("unset -f {name} 2>/dev/null || true\n"));
            }
        }
    }
    out
}

/// Render an undo snippet targeting `zsh`.
pub fn render_zsh(diff: &Diff) -> String {
    let mut out = String::new();
    out.push_str("# C06: restore shell state. Re-source to apply.\n");
    if let Some((from, _to)) = &diff.pwd_changed {
        out.push_str(&format!("cd {}\n", sh_quote(&from.to_string_lossy())));
    }
    for (name, pre, post) in &diff.opts {
        // zsh uses setopt / unsetopt, not set ±o.
        if pre == "on" && post != "on" {
            out.push_str(&format!("setopt {name}\n"));
        } else if pre == "off" && post != "off" {
            out.push_str(&format!("unsetopt {name}\n"));
        } else {
            out.push_str(&format!(
                "# manual: option `{name}` was `{pre}`, now `{post}`\n"
            ));
        }
    }
    for (name, pre, _post) in &diff.aliases {
        match pre {
            Some(expansion) => {
                out.push_str(&format!("alias {name}={}\n", sh_quote(expansion)));
            }
            None => {
                out.push_str(&format!("unalias {name} 2>/dev/null || true\n"));
            }
        }
    }
    for (name, pre, _post) in &diff.funcs {
        match pre {
            Some(body) => {
                out.push_str(body);
                if !body.ends_with('\n') {
                    out.push('\n');
                }
            }
            None => {
                out.push_str(&format!("unset -f {name} 2>/dev/null || true\n"));
            }
        }
    }
    out
}

/// Render an undo snippet targeting `fish`. Fish doesn't have
/// `set -o` / `setopt`; options surface as fish variables (out of
/// scope for v1 — env tracking handles those). Fish "aliases" are
/// just functions, so the aliases diff is rendered as function
/// bodies; in practice the bash/zsh capture-side keeps aliases
/// separate and the fish-side snapshot leaves the aliases map empty.
pub fn render_fish(diff: &Diff) -> String {
    let mut out = String::new();
    out.push_str("# C06: restore shell state. Re-source to apply.\n");
    if let Some((from, _to)) = &diff.pwd_changed {
        out.push_str(&format!("cd {}\n", sh_quote(&from.to_string_lossy())));
    }
    for (name, pre, post) in &diff.opts {
        out.push_str(&format!(
            "# manual: option `{name}` was `{pre}`, now `{post}`\n"
        ));
    }
    // fish's `alias` is sugar for `function … end`; we render the
    // function form for clarity.
    for (name, pre, _post) in &diff.aliases {
        match pre {
            Some(expansion) => {
                out.push_str(&format!("function {name}; {expansion} $argv; end\n",));
            }
            None => {
                out.push_str(&format!("functions -e {name} 2>/dev/null; or true\n"));
            }
        }
    }
    for (name, pre, _post) in &diff.funcs {
        match pre {
            Some(body) => {
                out.push_str(body);
                if !body.ends_with('\n') {
                    out.push('\n');
                }
            }
            None => {
                out.push_str(&format!("functions -e {name} 2>/dev/null; or true\n",));
            }
        }
    }
    out
}

/// Single-quote a string for safe POSIX shell embedding. The only
/// thing that needs escaping inside `'...'` is `'` itself, which is
/// done by closing the string, emitting `\'`, and reopening.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Snapshot;
    use crate::state::compute_diff;
    use std::path::PathBuf;

    fn snap_with(pwd: &str) -> Snapshot {
        Snapshot {
            pwd: PathBuf::from(pwd),
            ..Default::default()
        }
    }

    // ----- pwd restore -----

    #[test]
    fn bash_pwd_restore_renders_cd_to_pre_value() {
        let pre = snap_with("/home/u/project");
        let post = snap_with("/tmp");
        let d = compute_diff(&pre, &post);
        let out = render_bash(&d);
        assert!(out.contains("cd '/home/u/project'"));
    }

    #[test]
    fn pwd_with_special_chars_is_quoted() {
        let pre = snap_with("/home/u/with 'quotes' and spaces");
        let post = snap_with("/tmp");
        let d = compute_diff(&pre, &post);
        let bash = render_bash(&d);
        // Single-quote-escape: `'\''`.
        assert!(bash.contains("'/home/u/with '\\''quotes'\\'' and spaces'"));
    }

    // ----- option restore -----

    #[test]
    fn bash_set_o_for_pre_on_post_off() {
        let mut pre = snap_with("/h");
        let mut post = pre.clone();
        pre.set_opts.insert("errexit".into(), "on".into());
        post.set_opts.insert("errexit".into(), "off".into());
        let d = compute_diff(&pre, &post);
        let out = render_bash(&d);
        assert!(out.contains("set -o errexit"));
    }

    #[test]
    fn bash_set_plus_o_for_pre_off_post_on() {
        let mut pre = snap_with("/h");
        let mut post = pre.clone();
        pre.set_opts.insert("nounset".into(), "off".into());
        post.set_opts.insert("nounset".into(), "on".into());
        let d = compute_diff(&pre, &post);
        let out = render_bash(&d);
        assert!(out.contains("set +o nounset"));
    }

    #[test]
    fn zsh_uses_setopt_unsetopt_not_set_dash_o() {
        let mut pre = snap_with("/h");
        let mut post = pre.clone();
        pre.set_opts.insert("errexit".into(), "on".into());
        post.set_opts.insert("errexit".into(), "off".into());
        let out = render_zsh(&compute_diff(&pre, &post));
        assert!(out.contains("setopt errexit"));
        assert!(!out.contains("set -o errexit"));
    }

    #[test]
    fn non_boolean_option_becomes_manual_comment() {
        let mut pre = snap_with("/h");
        let mut post = pre.clone();
        pre.set_opts.insert("histsize".into(), "500".into());
        post.set_opts.insert("histsize".into(), "10000".into());
        let out = render_bash(&compute_diff(&pre, &post));
        assert!(out.contains("# manual:"));
        assert!(out.contains("`histsize`"));
        assert!(out.contains("`500`"));
        assert!(out.contains("`10000`"));
    }

    // ----- alias restore -----

    #[test]
    fn bash_alias_restored_to_pre_value() {
        let mut pre = snap_with("/h");
        let mut post = pre.clone();
        pre.aliases.insert("ll".into(), "ls -la".into());
        post.aliases.insert("ll".into(), "ls -laG".into());
        let out = render_bash(&compute_diff(&pre, &post));
        assert!(out.contains("alias ll='ls -la'"));
    }

    #[test]
    fn bash_alias_added_post_is_unaliased_on_undo() {
        let pre = snap_with("/h");
        let mut post = pre.clone();
        post.aliases.insert("g".into(), "git".into());
        let out = render_bash(&compute_diff(&pre, &post));
        assert!(out.contains("unalias g 2>/dev/null || true"));
    }

    #[test]
    fn fish_alias_renders_as_function_block() {
        let mut pre = snap_with("/h");
        let mut post = pre.clone();
        pre.aliases.insert("ll".into(), "ls -la".into());
        post.aliases.clear();
        let out = render_fish(&compute_diff(&pre, &post));
        assert!(out.contains("function ll; ls -la $argv; end"));
    }

    // ----- function restore -----

    #[test]
    fn function_added_post_is_unset_on_undo() {
        let pre = snap_with("/h");
        let mut post = pre.clone();
        post.functions
            .insert("greet".into(), "greet() { echo hi; }".into());
        let out = render_bash(&compute_diff(&pre, &post));
        assert!(out.contains("unset -f greet 2>/dev/null || true"));
    }

    #[test]
    fn function_removed_post_is_restored_from_pre_body() {
        let mut pre = snap_with("/h");
        let body = "greet() { echo hello; }";
        pre.functions.insert("greet".into(), body.into());
        let post = snap_with("/h");
        let out = render_bash(&compute_diff(&pre, &post));
        assert!(out.contains(body));
    }

    #[test]
    fn function_body_change_restores_pre_body() {
        let mut pre = snap_with("/h");
        let mut post = pre.clone();
        pre.functions.insert("foo".into(), "foo() { :; }".into());
        post.functions
            .insert("foo".into(), "foo() { echo changed; }".into());
        let out = render_zsh(&compute_diff(&pre, &post));
        assert!(out.contains("foo() { :; }"));
    }

    // ----- empty diff -----

    #[test]
    fn empty_diff_yields_header_only() {
        let s = snap_with("/h");
        let d = compute_diff(&s, &s);
        for out in [render_bash(&d), render_zsh(&d), render_fish(&d)] {
            assert!(out.starts_with("# C06: restore shell state"));
            // Header + nothing else.
            assert_eq!(out.lines().count(), 1);
        }
    }

    // ----- end-to-end shape -----

    #[test]
    fn pwd_opt_alias_func_combined_in_bash_snippet() {
        let mut pre = snap_with("/home/u");
        let mut post = snap_with("/tmp");
        pre.set_opts.insert("errexit".into(), "on".into());
        post.set_opts.insert("errexit".into(), "off".into());
        pre.aliases.insert("g".into(), "git".into());
        post.functions
            .insert("greet".into(), "greet() { echo hi; }".into());
        let out = render_bash(&compute_diff(&pre, &post));
        assert!(out.contains("cd '/home/u'"));
        assert!(out.contains("set -o errexit"));
        assert!(out.contains("alias g='git'"));
        assert!(out.contains("unset -f greet"));
    }
}
