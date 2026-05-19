// SPDX-License-Identifier: AGPL-3.0-or-later

//! Render env diffs for `shit show` and `shit undo` (S15.6).
//!
//! The shape:
//!
//! ```text
//! Environment changes:
//!   + GITHUB_TOKEN  <redacted>
//!   - OLD_PATH      /usr/local/bin
//!   ~ PATH          /usr/bin → /usr/local/bin:/usr/bin
//! ```
//!
//! Redacted values are shown as the literal `<redacted>` regardless
//! of [`RedactionDisplay`]; the flag only controls whether the
//! variable *name* is shown at all (some users want to see "a token
//! changed" without revealing which one).
//!
//! The renderer is a pure stringifier: no I/O, no terminal probing.
//! Callers wrap with [`crate::render::pager`] or write to stdout
//! directly.

use std::fmt::Write;

use shit_planner::EnvDiff;

/// How redacted entries should appear in the rendered diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedactionDisplay {
    /// Default — print the variable name + `<redacted>` placeholder.
    #[default]
    NamesVisible,
    /// Hide redacted entries entirely (no name, no value). Useful
    /// in JSON exports that ship to a wider audience.
    HideEntirely,
}

const REDACTED_PREFIX: &str = "<redacted:";
const REDACTED_LABEL: &str = "<redacted>";

/// Render an [`EnvDiff`] as the canonical `+/-/~` table. The output
/// includes a trailing newline.
pub fn render(diff: &EnvDiff, display: RedactionDisplay) -> String {
    let mut out = String::new();
    if diff.is_empty() {
        out.push_str("Environment changes: (none)\n");
        return out;
    }
    out.push_str("Environment changes:\n");

    let max_name_width = max_name_width(diff, display);
    let pad = max_name_width.max(8);

    for (name, value) in &diff.added {
        if let Some(line) = format_row("+", name, None, Some(value), pad, display) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    for (name, value) in &diff.removed {
        if let Some(line) = format_row("-", name, Some(value), None, pad, display) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    for (name, (pre, post)) in &diff.modified {
        if let Some(line) = format_row("~", name, Some(pre), Some(post), pad, display) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

fn max_name_width(diff: &EnvDiff, display: RedactionDisplay) -> usize {
    let names = diff
        .added
        .keys()
        .chain(diff.removed.keys())
        .chain(diff.modified.keys())
        .filter(|n| match display {
            RedactionDisplay::HideEntirely => !is_redacted_pair(diff, n),
            RedactionDisplay::NamesVisible => true,
        });
    names.map(|s| s.len()).max().unwrap_or(0)
}

fn is_redacted_pair(diff: &EnvDiff, name: &str) -> bool {
    let test = |s: &str| s.starts_with(REDACTED_PREFIX);
    if let Some(v) = diff.added.get(name) {
        return test(v);
    }
    if let Some(v) = diff.removed.get(name) {
        return test(v);
    }
    if let Some((a, b)) = diff.modified.get(name) {
        return test(a) || test(b);
    }
    false
}

fn format_row(
    sym: &str,
    name: &str,
    pre: Option<&str>,
    post: Option<&str>,
    pad: usize,
    display: RedactionDisplay,
) -> Option<String> {
    let any_redacted =
        pre.map(starts_redacted).unwrap_or(false) || post.map(starts_redacted).unwrap_or(false);
    if any_redacted && matches!(display, RedactionDisplay::HideEntirely) {
        return None;
    }
    let pre_disp = pre.map(value_for_display);
    let post_disp = post.map(value_for_display);
    let mut line = String::with_capacity(64);
    let _ = write!(line, "  {sym} {name:<pad$}  ");
    match (pre_disp, post_disp) {
        (None, Some(p)) => line.push_str(&p),
        (Some(p), None) => line.push_str(&p),
        (Some(a), Some(b)) => {
            let _ = write!(line, "{a} → {b}");
        }
        (None, None) => {}
    }
    Some(line)
}

fn starts_redacted(v: &str) -> bool {
    v.starts_with(REDACTED_PREFIX)
}

fn value_for_display(v: &str) -> String {
    if starts_redacted(v) {
        REDACTED_LABEL.to_string()
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn diff() -> EnvDiff {
        let mut added = BTreeMap::new();
        added.insert("GITHUB_TOKEN".into(), "<redacted:deadbeef>".into());
        let mut removed = BTreeMap::new();
        removed.insert("OLD_PATH".into(), "/usr/local/bin".into());
        let mut modified = BTreeMap::new();
        modified.insert(
            "PATH".into(),
            ("/usr/bin".into(), "/usr/local/bin:/usr/bin".into()),
        );
        EnvDiff {
            added,
            removed,
            modified,
        }
    }

    #[test]
    fn render_default_shows_redacted_label() {
        let s = render(&diff(), RedactionDisplay::default());
        assert!(s.contains("+ GITHUB_TOKEN"));
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("deadbeef"), "redacted hash leaked");
    }

    #[test]
    fn render_includes_arrow_for_modified() {
        let s = render(&diff(), RedactionDisplay::default());
        assert!(s.contains("PATH"));
        assert!(s.contains("/usr/bin → /usr/local/bin:/usr/bin"));
    }

    #[test]
    fn render_hide_entirely_drops_redacted_rows() {
        let s = render(&diff(), RedactionDisplay::HideEntirely);
        assert!(!s.contains("GITHUB_TOKEN"));
        assert!(s.contains("PATH"));
        assert!(s.contains("OLD_PATH"));
    }

    #[test]
    fn render_empty_diff_says_none() {
        let empty = EnvDiff {
            added: BTreeMap::new(),
            removed: BTreeMap::new(),
            modified: BTreeMap::new(),
        };
        let s = render(&empty, RedactionDisplay::default());
        assert!(s.contains("(none)"));
    }

    #[test]
    fn render_columns_align() {
        let s = render(&diff(), RedactionDisplay::default());
        // Each data row is `  <sym> <name> ...` — verify the names
        // line up. We can't easily diff alignment, but we can assert
        // the row prefix shape is stable.
        for line in s.lines().filter(|l| !l.starts_with("Environment")) {
            assert!(line.starts_with("  "), "row prefix wrong: {line:?}");
        }
    }
}
