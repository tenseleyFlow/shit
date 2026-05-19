// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shell-state snapshots + diff math (C06.3).
//!
//! Captures four pieces of per-shell state at PreBlock and PostBlock,
//! computes the diff, and returns a structured result the planner can
//! turn into an `InverseOp::ShellStateRestore`.
//!
//! ## What's captured
//!
//! - **pwd** — `getcwd(3)` equivalent. Changes when the user `cd`s.
//! - **set_opts** — `set -o` (bash) / `setopt` (zsh) / a normalized
//!   fish option snapshot. Each entry maps option name → value (for
//!   booleans, `"on"` / `"off"`; for numeric / string options, the
//!   raw value).
//! - **aliases** — alias name → expansion. Fish doesn't have aliases
//!   as a separate concept (they're functions), so fish snapshots
//!   leave this empty.
//! - **functions** — function name → body. Bodies are size-bounded
//!   (see [`FUNC_BODY_MAX_BYTES`]); anything larger is captured as
//!   `<oversized: N bytes>` so the diff renderer can flag it.
//!
//! ## Pure logic
//!
//! This module does NO shell I/O. The per-shell `state.sh` /
//! `state.fish` companion scripts populate the snapshots by shelling
//! out from the hook (bash `compgen` / zsh `functions` / fish
//! `functions`); they hand the resulting `BTreeMap`s to
//! `compute_diff`. That separation keeps this module testable without
//! a real shell.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Maximum bytes per function body kept verbatim. A function over
/// this cap is recorded as the placeholder string so the diff doesn't
/// dominate the snapshot wire size. 100 KiB is the documented v1 cap
/// (`.docs/sprints/C06`).
pub const FUNC_BODY_MAX_BYTES: usize = 100 * 1024;

/// Snapshot of relevant shell state at one point in time (PreBlock or
/// PostBlock).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub pwd: PathBuf,
    /// Option name → value. `"errexit" → "on"`, `"pipefail" → "off"`,
    /// `"history-size" → "1000"`.
    pub set_opts: BTreeMap<String, String>,
    /// Alias name → expansion. Empty for fish.
    pub aliases: BTreeMap<String, String>,
    /// Function name → body (or `<oversized:N bytes>` placeholder).
    pub functions: BTreeMap<String, String>,
}

impl Snapshot {
    /// Apply [`FUNC_BODY_MAX_BYTES`] to a function body before
    /// storing. Returns the placeholder marker for oversized bodies;
    /// returns the body unchanged otherwise.
    pub fn bound_body(body: &str) -> String {
        if body.len() > FUNC_BODY_MAX_BYTES {
            format!("<oversized:{} bytes>", body.len())
        } else {
            body.to_string()
        }
    }
}

/// Diff between two snapshots. Drives the planner's
/// `InverseOp::ShellStateRestore`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    /// `Some((from, to))` when pwd changed across the command.
    pub pwd_changed: Option<(PathBuf, PathBuf)>,
    /// Options that changed: `(name, pre_value, post_value)`. Both
    /// values are always present — an option doesn't "appear" or
    /// "disappear" in normal shell usage.
    pub opts: Vec<(String, String, String)>,
    /// Aliases that changed: `(name, pre, post)`. `None` indicates the
    /// alias didn't exist on that side.
    pub aliases: Vec<(String, Option<String>, Option<String>)>,
    /// Functions that changed. Same `(name, pre, post)` shape.
    pub funcs: Vec<(String, Option<String>, Option<String>)>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.pwd_changed.is_none()
            && self.opts.is_empty()
            && self.aliases.is_empty()
            && self.funcs.is_empty()
    }
}

/// Compute the diff between two snapshots. Stable / deterministic —
/// `BTreeMap`'s ordered iteration drives the output, so the same
/// inputs always produce the same diff (important for postcard wire
/// reproducibility and for golden-test stability).
pub fn compute_diff(pre: &Snapshot, post: &Snapshot) -> Diff {
    let pwd_changed = if pre.pwd != post.pwd {
        Some((pre.pwd.clone(), post.pwd.clone()))
    } else {
        None
    };

    // Option diff: for boolean options the value moves between "on"
    // and "off"; for stringly-typed options any change registers.
    let mut opts = Vec::new();
    let all_opt_names: std::collections::BTreeSet<&String> =
        pre.set_opts.keys().chain(post.set_opts.keys()).collect();
    for name in all_opt_names {
        let before = pre.set_opts.get(name).cloned().unwrap_or_default();
        let after = post.set_opts.get(name).cloned().unwrap_or_default();
        if before != after {
            opts.push((name.clone(), before, after));
        }
    }

    // Aliases: symmetric difference + value mismatch.
    let mut aliases = Vec::new();
    let all_alias_names: std::collections::BTreeSet<&String> =
        pre.aliases.keys().chain(post.aliases.keys()).collect();
    for name in all_alias_names {
        let before = pre.aliases.get(name).cloned();
        let after = post.aliases.get(name).cloned();
        if before != after {
            aliases.push((name.clone(), before, after));
        }
    }

    // Functions: same shape.
    let mut funcs = Vec::new();
    let all_func_names: std::collections::BTreeSet<&String> =
        pre.functions.keys().chain(post.functions.keys()).collect();
    for name in all_func_names {
        let before = pre.functions.get(name).cloned();
        let after = post.functions.get(name).cloned();
        if before != after {
            funcs.push((name.clone(), before, after));
        }
    }

    Diff {
        pwd_changed,
        opts,
        aliases,
        funcs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(pwd: &str) -> Snapshot {
        Snapshot {
            pwd: PathBuf::from(pwd),
            ..Default::default()
        }
    }

    #[test]
    fn identical_snapshots_diff_to_nothing() {
        let s = snap("/home/u");
        let d = compute_diff(&s, &s);
        assert!(d.is_empty());
    }

    #[test]
    fn pwd_change_detected() {
        let pre = snap("/home/u");
        let post = snap("/tmp");
        let d = compute_diff(&pre, &post);
        assert_eq!(
            d.pwd_changed,
            Some((PathBuf::from("/home/u"), PathBuf::from("/tmp")))
        );
        assert!(d.opts.is_empty());
    }

    #[test]
    fn option_added_yields_empty_pre() {
        let mut pre = snap("/home/u");
        let mut post = pre.clone();
        post.set_opts.insert("errexit".into(), "on".into());
        let d = compute_diff(&pre, &post);
        assert_eq!(d.opts.len(), 1);
        assert_eq!(d.opts[0].0, "errexit");
        assert_eq!(d.opts[0].1, ""); // pre value: absent ⇒ empty string
        assert_eq!(d.opts[0].2, "on");
        // No accidental aliasing changes.
        pre.set_opts.insert("nounset".into(), "off".into());
        let _ = compute_diff(&pre, &post); // no panic
    }

    #[test]
    fn option_removed_yields_empty_post() {
        let mut pre = snap("/home/u");
        pre.set_opts.insert("noclobber".into(), "on".into());
        let post = snap("/home/u");
        let d = compute_diff(&pre, &post);
        assert_eq!(d.opts.len(), 1);
        assert_eq!(d.opts[0], ("noclobber".into(), "on".into(), "".into()));
    }

    #[test]
    fn option_value_change_detected() {
        let mut pre = snap("/home/u");
        let mut post = pre.clone();
        pre.set_opts.insert("histsize".into(), "500".into());
        post.set_opts.insert("histsize".into(), "10000".into());
        let d = compute_diff(&pre, &post);
        assert_eq!(d.opts.len(), 1);
        assert_eq!(d.opts[0].1, "500");
        assert_eq!(d.opts[0].2, "10000");
    }

    #[test]
    fn alias_added_detected() {
        let pre = snap("/h");
        let mut post = pre.clone();
        post.aliases.insert("ll".into(), "ls -la".into());
        let d = compute_diff(&pre, &post);
        assert_eq!(d.aliases.len(), 1);
        assert_eq!(d.aliases[0].0, "ll");
        assert_eq!(d.aliases[0].1, None);
        assert_eq!(d.aliases[0].2, Some("ls -la".into()));
    }

    #[test]
    fn alias_removed_detected() {
        let mut pre = snap("/h");
        pre.aliases.insert("g".into(), "git".into());
        let post = snap("/h");
        let d = compute_diff(&pre, &post);
        assert_eq!(d.aliases.len(), 1);
        assert_eq!(d.aliases[0].1, Some("git".into()));
        assert_eq!(d.aliases[0].2, None);
    }

    #[test]
    fn alias_value_change_detected() {
        let mut pre = snap("/h");
        let mut post = pre.clone();
        pre.aliases.insert("ll".into(), "ls -la".into());
        post.aliases.insert("ll".into(), "ls -laG".into());
        let d = compute_diff(&pre, &post);
        assert_eq!(d.aliases.len(), 1);
        assert_eq!(d.aliases[0].1, Some("ls -la".into()));
        assert_eq!(d.aliases[0].2, Some("ls -laG".into()));
    }

    #[test]
    fn function_added_detected() {
        let pre = snap("/h");
        let mut post = pre.clone();
        post.functions
            .insert("greet".into(), "greet() { echo hi; }".into());
        let d = compute_diff(&pre, &post);
        assert_eq!(d.funcs.len(), 1);
        assert_eq!(d.funcs[0].0, "greet");
        assert_eq!(d.funcs[0].1, None);
    }

    #[test]
    fn function_body_change_detected() {
        let mut pre = snap("/h");
        let mut post = pre.clone();
        pre.functions.insert("foo".into(), "foo() { :; }".into());
        post.functions
            .insert("foo".into(), "foo() { echo hi; }".into());
        let d = compute_diff(&pre, &post);
        assert_eq!(d.funcs.len(), 1);
    }

    #[test]
    fn diff_is_deterministic_across_runs() {
        let mut pre = snap("/h");
        let mut post = pre.clone();
        pre.aliases.insert("a".into(), "1".into());
        pre.aliases.insert("b".into(), "2".into());
        post.aliases.insert("a".into(), "9".into());
        post.aliases.insert("c".into(), "3".into());
        let d1 = compute_diff(&pre, &post);
        let d2 = compute_diff(&pre, &post);
        assert_eq!(d1, d2);
        // BTreeMap-driven, so the diff is sorted by name.
        let names: Vec<&str> = d1.aliases.iter().map(|t| t.0.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn bound_body_preserves_small_input() {
        let body = "foo() { echo hi; }";
        assert_eq!(Snapshot::bound_body(body), body);
    }

    #[test]
    fn bound_body_replaces_oversized_input() {
        let big = "x".repeat(FUNC_BODY_MAX_BYTES + 1);
        let bounded = Snapshot::bound_body(&big);
        assert!(bounded.starts_with("<oversized:"), "got {bounded:?}");
        assert!(bounded.contains(&format!("{}", FUNC_BODY_MAX_BYTES + 1)));
    }

    #[test]
    fn unchanged_options_do_not_appear_in_diff() {
        let mut pre = snap("/h");
        let mut post = pre.clone();
        pre.set_opts.insert("errexit".into(), "on".into());
        post.set_opts.insert("errexit".into(), "on".into());
        let d = compute_diff(&pre, &post);
        assert!(d.is_empty());
    }
}
