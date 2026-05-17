// SPDX-License-Identifier: AGPL-3.0-or-later

//! Render the "Processes affected" section for `shit show` / `shit undo`
//! (S18.8).
//!
//! Pure stringifier — same contract as [`crate::render::env_diff`]: no
//! terminal probing, no I/O. Takes a slice of
//! [`RestartSuggestion`](shit_planner::executors::process::RestartSuggestion)
//! produced by the [`ProcessExecutor`] (or by direct synthesis from
//! captured notes) and emits text.
//!
//! ## Redaction
//!
//! Env values matching the `<redacted:...>` shape (see
//! [`crate::render::env_diff`]) are masked. The redaction sigil is
//! the same — anything from the env capture pipeline is uniformly
//! treated.
//!
//! ## Shape
//!
//! ```text
//! Processes affected:
//!   killed: sleep 1000
//!     cwd: /tmp
//!     restart: sleep 1000
//!   killed: nginx -g 'daemon off;'
//!     cwd: /
//!     restart: systemctl restart nginx.service
//!     note: killed by user (signal=TERM)
//! ```

use std::fmt::Write;

use shit_planner::executors::process::{
    RestartHint, RestartSuggestion, render_snippet as render_process_snippet,
};

use crate::render::env_diff::RedactionDisplay;

const REDACTED_PREFIX: &str = "<redacted:";
const REDACTED_LABEL: &str = "<redacted>";

/// Render `Processes affected:` for a list of suggestions. Returns
/// an empty string when `suggestions` is empty so callers can
/// concatenate cheaply.
pub fn render(suggestions: &[RestartSuggestion], display: RedactionDisplay) -> String {
    if suggestions.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str("Processes affected:\n");
    for s in suggestions {
        render_one(&mut out, s, display);
    }
    out
}

fn render_one(out: &mut String, s: &RestartSuggestion, display: RedactionDisplay) {
    let _ = writeln!(out, "  killed: {}", join_argv(&s.original_argv));
    let _ = writeln!(out, "    cwd: {}", s.cwd.display());
    if !s.env_summary.is_empty() {
        let env_line = render_env_summary(s, display);
        if !env_line.is_empty() {
            let _ = writeln!(out, "    env: {env_line}");
        }
    }
    let _ = writeln!(out, "    restart: {}", render_process_snippet(s));
    if !s.message.trim().is_empty() {
        let _ = writeln!(out, "    note: {}", s.message.trim());
    }
    if matches!(s.hint, RestartHint::RawArgv) {
        // Honest note: we couldn't cross-reference a service manager.
        let _ = writeln!(out, "    (no service manager match; raw argv)");
    }
}

fn render_env_summary(s: &RestartSuggestion, display: RedactionDisplay) -> String {
    let mut parts = Vec::with_capacity(s.env_summary.len());
    for (k, v) in &s.env_summary {
        let redacted = v.starts_with(REDACTED_PREFIX);
        if redacted && matches!(display, RedactionDisplay::HideEntirely) {
            continue;
        }
        let display_value = if redacted { REDACTED_LABEL } else { v.as_str() };
        parts.push(format!("{k}={display_value}"));
    }
    parts.join(" ")
}

fn join_argv(argv: &[String]) -> String {
    let mut out = String::new();
    let mut first = true;
    for tok in argv {
        if !first {
            out.push(' ');
        }
        first = false;
        if needs_quote(tok) {
            out.push('\'');
            for c in tok.chars() {
                if c == '\'' {
                    out.push_str("'\\''");
                } else {
                    out.push(c);
                }
            }
            out.push('\'');
        } else {
            out.push_str(tok);
        }
    }
    out
}

fn needs_quote(tok: &str) -> bool {
    if tok.is_empty() {
        return true;
    }
    tok.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '\'' | '"' | '\\' | '$' | '`' | ';' | '&' | '|' | '<' | '>' | '*' | '?' | '(' | ')'
            )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::events::SystemdScope;
    use shit_planner::executors::process::{RestartHint, RestartSuggestion};
    use std::path::PathBuf;

    fn sug(argv: &[&str], cwd: &str, env: &[(&str, &str)], hint: RestartHint) -> RestartSuggestion {
        RestartSuggestion {
            original_argv: argv.iter().map(|s| (*s).to_string()).collect(),
            cwd: PathBuf::from(cwd),
            env_summary: env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            message: String::new(),
            hint,
        }
    }

    #[test]
    fn empty_input_yields_empty_string() {
        let out = render(&[], RedactionDisplay::default());
        assert!(out.is_empty());
    }

    #[test]
    fn raw_argv_section_lists_argv_cwd_and_restart() {
        let s = sug(&["sleep", "1000"], "/tmp", &[], RestartHint::RawArgv);
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.starts_with("Processes affected:\n"));
        assert!(out.contains("killed: sleep 1000"));
        assert!(out.contains("cwd: /tmp"));
        assert!(out.contains("restart: cd '/tmp' && 'sleep' '1000'"));
        assert!(out.contains("(no service manager match"));
    }

    #[test]
    fn systemd_unit_hint_is_one_liner() {
        let s = sug(
            &["/usr/sbin/nginx"],
            "/",
            &[],
            RestartHint::SystemdUnit {
                scope: SystemdScope::System,
                unit: "nginx.service".into(),
            },
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("restart: systemctl restart nginx.service"));
        assert!(!out.contains("no service manager match"));
    }

    #[test]
    fn user_scope_systemd_uses_user_flag() {
        let s = sug(
            &["foo"],
            "/",
            &[],
            RestartHint::SystemdUnit {
                scope: SystemdScope::User,
                unit: "foo.service".into(),
            },
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("restart: systemctl --user restart foo.service"));
    }

    #[test]
    fn launchd_unit_hint_renders_kickstart() {
        let s = sug(
            &["com.example.foo"],
            "/",
            &[],
            RestartHint::LaunchdUnit {
                scope: SystemdScope::LaunchdSystem,
                unit: "com.example.foo".into(),
            },
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("restart: launchctl kickstart -k system/com.example.foo"));
    }

    #[test]
    fn env_summary_rendered_in_default_display() {
        let s = sug(
            &["python3", "app.py"],
            "/srv",
            &[("APP_ENV", "production"), ("WORKERS", "4")],
            RestartHint::RawArgv,
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("env: APP_ENV=production WORKERS=4"));
    }

    #[test]
    fn env_summary_redacts_secret_marker() {
        let s = sug(
            &["app"],
            "/",
            &[("GITHUB_TOKEN", "<redacted:deadbeef>")],
            RestartHint::RawArgv,
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("GITHUB_TOKEN=<redacted>"));
        assert!(!out.contains("deadbeef"));
    }

    #[test]
    fn env_summary_hide_entirely_drops_redacted_var() {
        let s = sug(
            &["app"],
            "/",
            &[("GITHUB_TOKEN", "<redacted:deadbeef>"), ("WORKERS", "4")],
            RestartHint::RawArgv,
        );
        let out = render(&[s], RedactionDisplay::HideEntirely);
        assert!(!out.contains("GITHUB_TOKEN"));
        assert!(!out.contains("deadbeef"));
        assert!(out.contains("WORKERS=4"));
    }

    #[test]
    fn argv_quoting_is_minimal_but_safe() {
        // Bare identifier: no quotes.
        let s = sug(&["sleep", "1000"], "/", &[], RestartHint::RawArgv);
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("killed: sleep 1000"));

        // Embedded space: quotes.
        let s = sug(
            &["nginx", "-g", "daemon off;"],
            "/",
            &[],
            RestartHint::RawArgv,
        );
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("killed: nginx -g 'daemon off;'"));
    }

    #[test]
    fn message_appears_as_note_line() {
        let mut s = sug(&["sleep"], "/", &[], RestartHint::RawArgv);
        s.message = "killed by user (signal=TERM)".into();
        let out = render(&[s], RedactionDisplay::default());
        assert!(out.contains("note: killed by user (signal=TERM)"));
    }

    #[test]
    fn multiple_suggestions_each_get_a_section_entry() {
        let a = sug(&["sleep", "1"], "/tmp", &[], RestartHint::RawArgv);
        let b = sug(
            &["nginx"],
            "/",
            &[],
            RestartHint::SystemdUnit {
                scope: SystemdScope::System,
                unit: "nginx.service".into(),
            },
        );
        let out = render(&[a, b], RedactionDisplay::default());
        let killed_lines = out.lines().filter(|l| l.contains("killed:")).count();
        assert_eq!(killed_lines, 2);
    }

    #[test]
    fn empty_env_summary_does_not_render_env_line() {
        let s = sug(&["sleep"], "/", &[], RestartHint::RawArgv);
        let out = render(&[s], RedactionDisplay::default());
        assert!(!out.contains("env:"));
    }

    #[test]
    fn hide_entirely_drops_env_line_when_only_redacted_keys() {
        let s = sug(
            &["app"],
            "/",
            &[("SECRET", "<redacted:cafe>")],
            RestartHint::RawArgv,
        );
        let out = render(&[s], RedactionDisplay::HideEntirely);
        assert!(!out.contains("env:"));
    }

    #[test]
    fn argv_quoting_handles_embedded_single_quote() {
        let s = sug(&["echo", "it's"], "/", &[], RestartHint::RawArgv);
        let out = render(&[s], RedactionDisplay::default());
        // Verify shell-safe escape, not the visually-prettier form.
        assert!(out.contains(r"killed: echo 'it'\''s'"));
    }
}
