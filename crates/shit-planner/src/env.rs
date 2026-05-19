// SPDX-License-Identifier: AGPL-3.0-or-later

//! Env-tracking primitives (S15).
//!
//! Pure-rust helpers that the shell hook, the daemon, and the
//! renderer all consume. Nothing here does I/O.
//!
//! ## Wire format
//!
//! An "env block" on the wire is a `&[u8]` of `KEY=VALUE` pairs
//! sorted by key (byte-wise) and joined by NUL. The trailing byte
//! may or may not be NUL — both forms parse identically.
//!
//! ## Hashing
//!
//! [`hash_env_block`] returns the blake3 hash of the canonicalized
//! block. Hashing happens *after* canonicalization so the result is
//! stable regardless of how the producing shell ordered its
//! enumeration.
//!
//! ## Redaction
//!
//! Variable names matching a redaction glob (defaults:
//! `*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`) have their value
//! replaced with `<redacted:<short-hash>>` *before* the diff is
//! computed. The short hash is the first 8 hex chars of the blake3
//! of the value, so two redacted vars with the same value still
//! compare equal (no false "changed" detections), but the value
//! itself is unrecoverable.
//!
//! ## Ignore filter
//!
//! Variables matching the ignore set are dropped entirely before
//! diffing — they never surface in `CaptureEvent::EnvDiff`. The
//! defaults cover universally-noisy vars (`_`, `OLDPWD`, `SHLVL`,
//! `RANDOM`, `LINENO`, `PROMPT_COMMAND`, `STARSHIP_SESSION_KEY`,
//! and the `STARSHIP_*` prefix).

use std::collections::BTreeMap;

/// Default set of variable names to ignore entirely. Matched exactly
/// against the variable name; the `STARSHIP_` prefix is checked
/// separately by [`is_ignored`].
pub const DEFAULT_IGNORE: &[&str] = &[
    "_",
    "OLDPWD",
    "SHLVL",
    "RANDOM",
    "LINENO",
    "PROMPT_COMMAND",
    "STARSHIP_SESSION_KEY",
    "STARSHIP_SHELL",
    "STARSHIP_START_TIME",
    "PWD",
    "SECONDS",
];

/// Variable-name prefixes whose entire family is ignored. Cheap
/// glob alternative for prompt-related noise.
pub const DEFAULT_IGNORE_PREFIXES: &[&str] = &["STARSHIP_"];

/// Default substrings that mark a variable's *value* for redaction.
/// Matched case-insensitively against the variable name.
pub const DEFAULT_REDACT_SUBSTRINGS: &[&str] =
    &["TOKEN", "SECRET", "PASSWORD", "API_KEY", "APIKEY"];

/// Configuration for env diffing. All fields have safe defaults so
/// callers can construct via `EnvFilter::default()`.
#[derive(Debug, Clone)]
pub struct EnvFilter {
    pub ignore: Vec<String>,
    pub ignore_prefixes: Vec<String>,
    pub redact_substrings: Vec<String>,
    /// When true, ignore lists are bypassed (the user opted into
    /// tracking every var). Redaction is still honored — turning
    /// off redaction is a *separate* toggle the user must own
    /// explicitly per-variable.
    pub track_all: bool,
}

impl Default for EnvFilter {
    fn default() -> Self {
        Self {
            ignore: DEFAULT_IGNORE.iter().map(|s| s.to_string()).collect(),
            ignore_prefixes: DEFAULT_IGNORE_PREFIXES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            redact_substrings: DEFAULT_REDACT_SUBSTRINGS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            track_all: false,
        }
    }
}

impl EnvFilter {
    pub fn is_ignored(&self, name: &str) -> bool {
        if self.track_all {
            return false;
        }
        if self.ignore.iter().any(|n| n == name) {
            return true;
        }
        if self
            .ignore_prefixes
            .iter()
            .any(|p| name.starts_with(p.as_str()))
        {
            return true;
        }
        false
    }

    pub fn is_redacted(&self, name: &str) -> bool {
        let upper = name.to_ascii_uppercase();
        self.redact_substrings.iter().any(|s| upper.contains(s))
    }
}

/// Canonicalize a `key → value` map into the wire-format byte string
/// (sorted by key, joined by NUL). Used by both the producer (shell
/// hook side, via the planner's helpers) and the consumer (daemon).
pub fn canonicalize(env: &BTreeMap<String, String>) -> Vec<u8> {
    let mut out = Vec::with_capacity(env.len() * 32);
    for (i, (k, v)) in env.iter().enumerate() {
        if i > 0 {
            out.push(0);
        }
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
    }
    out
}

/// Parse a wire-format block back into a map. Tolerates trailing NUL
/// and trailing whitespace. Variables without `=` are dropped (an
/// invalid env entry).
pub fn parse_block(block: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for chunk in block.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let pos = match chunk.iter().position(|&b| b == b'=') {
            Some(p) => p,
            None => continue,
        };
        let (k, rest) = chunk.split_at(pos);
        let v = &rest[1..]; // skip the '='
        // Lossy UTF-8: env vars with non-UTF-8 bytes are vanishingly
        // rare on modern systems; preserve fidelity where we can and
        // accept ? substitution otherwise. The redaction path makes
        // exact-value preservation moot anyway for the high-risk vars.
        let k = String::from_utf8_lossy(k).into_owned();
        let v = String::from_utf8_lossy(v).into_owned();
        out.insert(k, v);
    }
    out
}

/// blake3 hash of an already-canonicalized env block. Returned as the
/// raw 32-byte digest so the wire types (which use `[u8; 32]`) carry
/// it without reformatting.
pub fn hash_env_block(block: &[u8]) -> [u8; 32] {
    *blake3::hash(block).as_bytes()
}

/// Convenience: canonicalize + hash. Cheaper than re-running both
/// when the caller already has a map.
pub fn hash_env(env: &BTreeMap<String, String>) -> [u8; 32] {
    hash_env_block(&canonicalize(env))
}

/// Redact a value via blake3 of the bytes, taking the first 8 hex
/// chars. Stable across calls — equal values produce equal redactions
/// so the diff doesn't spuriously flag a "modified" var that hasn't
/// changed.
pub fn redact_value(value: &str) -> String {
    let h = blake3::hash(value.as_bytes());
    let hex: String = h
        .as_bytes()
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("<redacted:{hex}>")
}

/// One diff outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvDiff {
    /// Vars present in `post` but not in `pre`.
    pub added: BTreeMap<String, String>,
    /// Vars present in `pre` but not in `post`.
    pub removed: BTreeMap<String, String>,
    /// Vars whose value changed: `name -> (pre, post)`.
    pub modified: BTreeMap<String, (String, String)>,
}

impl EnvDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

/// Diff two env blocks (parsed from the wire). Applies the filter's
/// ignore + redact rules along the way: ignored vars are skipped
/// entirely, redact-marked vars have their values replaced.
pub fn diff_env_blocks(pre: &[u8], post: &[u8], filter: &EnvFilter) -> EnvDiff {
    let pre = parse_block(pre);
    let post = parse_block(post);
    diff_env_maps(&pre, &post, filter)
}

/// Diff two already-parsed env maps.
pub fn diff_env_maps(
    pre: &BTreeMap<String, String>,
    post: &BTreeMap<String, String>,
    filter: &EnvFilter,
) -> EnvDiff {
    let project = |name: &str, value: &str| -> String {
        if filter.is_redacted(name) {
            redact_value(value)
        } else {
            value.to_string()
        }
    };

    let mut added = BTreeMap::new();
    let mut removed = BTreeMap::new();
    let mut modified = BTreeMap::new();

    for (name, value) in post {
        if filter.is_ignored(name) {
            continue;
        }
        match pre.get(name) {
            None => {
                added.insert(name.clone(), project(name, value));
            }
            Some(prev) if prev != value => {
                modified.insert(name.clone(), (project(name, prev), project(name, value)));
            }
            _ => {}
        }
    }
    for (name, value) in pre {
        if filter.is_ignored(name) {
            continue;
        }
        if !post.contains_key(name) {
            removed.insert(name.clone(), project(name, value));
        }
    }
    EnvDiff {
        added,
        removed,
        modified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn canonicalize_is_sorted_and_nul_joined() {
        let m = env(&[("ZZ", "z"), ("AA", "a")]);
        let bytes = canonicalize(&m);
        assert_eq!(bytes, b"AA=a\0ZZ=z");
    }

    #[test]
    fn canonicalize_empty_map_is_empty() {
        assert!(canonicalize(&env(&[])).is_empty());
    }

    #[test]
    fn parse_block_round_trips_canonicalize() {
        let m = env(&[("FOO", "bar"), ("BAZ", "qux")]);
        let bytes = canonicalize(&m);
        let back = parse_block(&bytes);
        assert_eq!(back, m);
    }

    #[test]
    fn parse_block_drops_entries_without_equals() {
        let bad = b"FOO=bar\0BROKEN\0BAZ=qux".as_slice();
        let parsed = parse_block(bad);
        assert_eq!(parsed.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(parsed.get("BAZ").map(String::as_str), Some("qux"));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_block_handles_trailing_nul() {
        let bytes = b"A=1\0B=2\0".as_slice();
        let parsed = parse_block(bytes);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn hash_stable_for_same_content() {
        let a = env(&[("X", "1"), ("Y", "2")]);
        let b = env(&[("Y", "2"), ("X", "1")]); // different insertion order
        assert_eq!(hash_env(&a), hash_env(&b));
    }

    #[test]
    fn hash_changes_when_value_changes() {
        let a = env(&[("X", "1")]);
        let b = env(&[("X", "2")]);
        assert_ne!(hash_env(&a), hash_env(&b));
    }

    #[test]
    fn redact_value_format_is_stable() {
        let r = redact_value("ghp_supersecrettoken");
        assert!(r.starts_with("<redacted:"));
        assert!(r.ends_with('>'));
        // Same input → same output.
        assert_eq!(r, redact_value("ghp_supersecrettoken"));
    }

    #[test]
    fn diff_ignores_default_noise() {
        let pre = env(&[("PATH", "/usr/bin"), ("OLDPWD", "/tmp")]);
        let post = env(&[("PATH", "/usr/bin"), ("OLDPWD", "/home")]);
        let d = diff_env_maps(&pre, &post, &EnvFilter::default());
        // OLDPWD must NOT appear in modified.
        assert!(d.modified.is_empty(), "{d:?}");
    }

    #[test]
    fn diff_redacts_token_values() {
        let pre = env(&[]);
        let post = env(&[("GITHUB_TOKEN", "ghp_xyz")]);
        let d = diff_env_maps(&pre, &post, &EnvFilter::default());
        let v = d.added.get("GITHUB_TOKEN").expect("var present");
        assert!(v.starts_with("<redacted:"), "value leaked: {v}");
    }

    #[test]
    fn diff_redacts_password_values_case_insensitive() {
        let pre = env(&[("MY_password", "letmein")]);
        let post = env(&[]);
        let d = diff_env_maps(&pre, &post, &EnvFilter::default());
        let v = d.removed.get("MY_password").expect("present");
        assert!(v.starts_with("<redacted:"), "leaked: {v}");
    }

    #[test]
    fn diff_track_all_overrides_ignore_but_not_redact() {
        let pre = env(&[("OLDPWD", "/tmp"), ("API_KEY", "x")]);
        let post = env(&[("OLDPWD", "/home"), ("API_KEY", "y")]);
        let f = EnvFilter {
            track_all: true,
            ..EnvFilter::default()
        };
        let d = diff_env_maps(&pre, &post, &f);
        assert!(d.modified.contains_key("OLDPWD"));
        let (pre_v, post_v) = d.modified.get("API_KEY").unwrap();
        assert!(pre_v.starts_with("<redacted:"));
        assert!(post_v.starts_with("<redacted:"));
    }

    #[test]
    fn diff_added_removed_modified_separation() {
        let pre = env(&[("KEEP", "1"), ("MODME", "old"), ("RMME", "x")]);
        let post = env(&[("KEEP", "1"), ("MODME", "new"), ("NEWNEW", "y")]);
        let d = diff_env_maps(&pre, &post, &EnvFilter::default());
        assert!(d.added.contains_key("NEWNEW"));
        assert!(d.removed.contains_key("RMME"));
        assert_eq!(
            d.modified
                .get("MODME")
                .map(|(a, b)| (a.as_str(), b.as_str())),
            Some(("old", "new"))
        );
    }

    #[test]
    fn starship_prefix_ignored_by_default() {
        let pre = env(&[("STARSHIP_RANDOM_KEY", "1")]);
        let post = env(&[("STARSHIP_RANDOM_KEY", "2")]);
        let d = diff_env_maps(&pre, &post, &EnvFilter::default());
        assert!(d.is_empty());
    }
}
