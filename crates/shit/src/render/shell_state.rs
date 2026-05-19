// SPDX-License-Identifier: AGPL-3.0-or-later

//! Render a `Shell state diff:` section for `shit show` (C06.7).
//!
//! Takes a [`shit_planner::InverseOp::ShellStateRestore`] (the
//! planner-side encoded diff + pre-rendered snippets) and produces a
//! human-readable block of:
//!
//! ```text
//! Shell state diff:
//!   pwd:       /home/u/project -> /tmp
//!   options:   set -o errexit          (was: off → on)
//!              set -o nounset          (was: off → on)
//!   aliases:   + ll  =  'ls -la'
//!              - g
//!   functions: + greet
//!              - oldfn
//!
//! Restore snippet (bash):
//!     # C06: restore shell state. Re-source to apply.
//!     cd '/home/u/project'
//!     set +o errexit
//!     ...
//!
//! Apply via: shit undo <id> --apply-shell-state
//! ```
//!
//! Pure-text rendering — no I/O; the caller writes the result to
//! stdout / a pager / a json envelope.

use shit_planner::{AliasDiff, FuncDiff, InverseOp, OptDiff};

/// Render the section for one `ShellStateRestore` op. Returns `None`
/// if the diff is structurally empty (no pwd change, no opts, no
/// aliases, no functions) — the caller can decide to skip emitting
/// the section header in that case.
pub fn render(op: &InverseOp) -> Option<String> {
    let InverseOp::ShellStateRestore {
        pwd_before,
        opts_diff,
        aliases_diff,
        funcs_diff,
        snippet_bash,
        snippet_zsh,
        snippet_fish,
    } = op
    else {
        return None;
    };
    if pwd_before.is_none()
        && opts_diff.is_empty()
        && aliases_diff.is_empty()
        && funcs_diff.is_empty()
    {
        return None;
    }
    let mut out = String::new();
    out.push_str("Shell state diff:\n");
    if let Some(p) = pwd_before {
        out.push_str(&format!(
            "  pwd:       {} -> (post-exec value)\n",
            p.display()
        ));
    }
    if !opts_diff.is_empty() {
        out.push_str("  options:\n");
        for OptDiff { name, pre, post } in opts_diff {
            out.push_str(&format!("    - {name:<20} (was: {pre} → now: {post})\n",));
        }
    }
    if !aliases_diff.is_empty() {
        out.push_str("  aliases:\n");
        for AliasDiff { name, pre, post } in aliases_diff {
            match (pre.as_deref(), post.as_deref()) {
                (None, Some(_)) => out.push_str(&format!("    + {name}\n")),
                (Some(_), None) => out.push_str(&format!("    - {name}\n")),
                (Some(p), Some(_)) => {
                    out.push_str(&format!("    ~ {name:<20} (was: '{p}')\n"));
                }
                (None, None) => {}
            }
        }
    }
    if !funcs_diff.is_empty() {
        out.push_str("  functions:\n");
        for FuncDiff { name, pre, post } in funcs_diff {
            match (pre.is_some(), post.is_some()) {
                (false, true) => out.push_str(&format!("    + {name}\n")),
                (true, false) => out.push_str(&format!("    - {name}\n")),
                (true, true) => out.push_str(&format!("    ~ {name} (body changed)\n")),
                (false, false) => {}
            }
        }
    }
    out.push('\n');
    if let Some(body) = snippet_bash {
        out.push_str("Restore snippet (bash):\n");
        indent_into(&mut out, body, "    ");
        out.push('\n');
    }
    if let Some(body) = snippet_zsh {
        out.push_str("Restore snippet (zsh):\n");
        indent_into(&mut out, body, "    ");
        out.push('\n');
    }
    if let Some(body) = snippet_fish {
        out.push_str("Restore snippet (fish):\n");
        indent_into(&mut out, body, "    ");
        out.push('\n');
    }
    out.push_str(
        "Apply: re-run `shit undo <id> --apply-shell-state` (bash/zsh only; fish is \
         informational — copy-paste).\n",
    );
    Some(out)
}

fn indent_into(buf: &mut String, body: &str, prefix: &str) {
    for line in body.lines() {
        buf.push_str(prefix);
        buf.push_str(line);
        buf.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn full_op() -> InverseOp {
        InverseOp::ShellStateRestore {
            pwd_before: Some(PathBuf::from("/home/u")),
            opts_diff: vec![OptDiff {
                name: "errexit".into(),
                pre: "off".into(),
                post: "on".into(),
            }],
            aliases_diff: vec![
                AliasDiff {
                    name: "ll".into(),
                    pre: Some("ls -la".into()),
                    post: Some("ls -laG".into()),
                },
                AliasDiff {
                    name: "g".into(),
                    pre: None,
                    post: Some("git".into()),
                },
                AliasDiff {
                    name: "x".into(),
                    pre: Some("xargs".into()),
                    post: None,
                },
            ],
            funcs_diff: vec![FuncDiff {
                name: "greet".into(),
                pre: None,
                post: Some("greet() { echo hi; }".into()),
            }],
            snippet_bash: Some("cd '/home/u'\nset +o errexit\n".into()),
            snippet_zsh: None,
            snippet_fish: None,
        }
    }

    #[test]
    fn empty_diff_yields_none() {
        let op = InverseOp::ShellStateRestore {
            pwd_before: None,
            opts_diff: vec![],
            aliases_diff: vec![],
            funcs_diff: vec![],
            snippet_bash: None,
            snippet_zsh: None,
            snippet_fish: None,
        };
        assert!(render(&op).is_none());
    }

    #[test]
    fn non_shell_state_variant_yields_none() {
        let op = InverseOp::SetEnv {
            name: "X".into(),
            value: "Y".into(),
        };
        assert!(render(&op).is_none());
    }

    #[test]
    fn section_header_present() {
        let out = render(&full_op()).unwrap();
        assert!(out.starts_with("Shell state diff:\n"));
    }

    #[test]
    fn pwd_line_rendered_when_present() {
        let out = render(&full_op()).unwrap();
        assert!(out.contains("pwd:       /home/u"));
    }

    #[test]
    fn alias_diff_uses_plus_minus_tilde_markers() {
        let out = render(&full_op()).unwrap();
        assert!(out.contains("    + g"));
        assert!(out.contains("    - x"));
        assert!(out.contains("    ~ ll"));
    }

    #[test]
    fn function_diff_uses_plus_minus_tilde_markers() {
        let out = render(&full_op()).unwrap();
        assert!(out.contains("    + greet"));
    }

    #[test]
    fn option_diff_shows_old_arrow_new() {
        let out = render(&full_op()).unwrap();
        assert!(out.contains("errexit"));
        assert!(out.contains("was: off"));
        assert!(out.contains("now: on"));
    }

    #[test]
    fn snippet_section_is_indented_under_label() {
        let out = render(&full_op()).unwrap();
        assert!(out.contains("Restore snippet (bash):"));
        // Each snippet line is prefixed with 4 spaces.
        assert!(out.contains("    cd '/home/u'"));
        assert!(out.contains("    set +o errexit"));
    }

    #[test]
    fn apply_hint_present_at_end() {
        let out = render(&full_op()).unwrap();
        assert!(out.contains("--apply-shell-state"));
    }

    #[test]
    fn pwd_only_diff_still_renders() {
        let op = InverseOp::ShellStateRestore {
            pwd_before: Some(PathBuf::from("/h")),
            opts_diff: vec![],
            aliases_diff: vec![],
            funcs_diff: vec![],
            snippet_bash: Some("cd '/h'\n".into()),
            snippet_zsh: None,
            snippet_fish: None,
        };
        let out = render(&op).unwrap();
        assert!(out.contains("pwd:       /h"));
        assert!(out.contains("Restore snippet (bash):"));
    }
}
