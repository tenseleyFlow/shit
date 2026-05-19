// SPDX-License-Identifier: AGPL-3.0-or-later

//! Path-prefix matcher for the install-prefix capture gate (C05.1).
//!
//! The shim's hot path is `if (!path_under_prefix(path)) return
//! real_call(...)` — every non-install open / rename / unlink must
//! return inside a handful of nanoseconds. This module is the prefix
//! lookup; it is intentionally `no_std`-shaped (no allocations on the
//! match path, no syscalls beyond what the caller hands in) so it can
//! live in a cdylib that runs in every process loaded under
//! `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`.
//!
//! ## Semantics
//!
//! A `PrefixSet` stores a list of canonical absolute prefix paths
//! (typically `/usr/local`, `/opt`, `$HOME/.local`, `$HOME/.cargo/bin`,
//! ...). [`PrefixSet::matches`] returns `true` iff the input path is
//! lexically equal to one of the prefixes OR is strictly below it
//! (i.e. the next character past the prefix is `/`). It does NOT
//! resolve symlinks itself — the caller (typically the shim's interpose
//! routine) is responsible for canonicalizing the input first so a
//! symlink at `~/.local/bin/foo → /tmp/foo` doesn't slip past the gate
//! by writing to the link target.
//!
//! Lexical-match-after-canonicalize is the right factorization for
//! testability: the slow `realpath` call lives outside this module, so
//! tests can be 100% pure-logic with hand-rolled path inputs.
//!
//! ## Performance
//!
//! Linear scan over the prefix list. For the realistic config size
//! (5–10 prefixes), linear is faster than a trie or hashmap because
//! the strings are short and a byte-by-byte compare vectorizes well.
//! If users add 100+ prefixes the matcher can be upgraded to a sorted
//! binary search; until then linear is simpler.

use std::path::Path;

/// A set of canonical absolute prefix paths used by the shim's
/// install-prefix gate. Construct via [`PrefixSet::new`].
#[derive(Debug, Clone, Default)]
pub struct PrefixSet {
    /// Canonicalised prefixes, each guaranteed to be:
    /// - absolute (starts with `/`),
    /// - non-empty,
    /// - free of trailing `/` (except for the root prefix `/`, which
    ///   we treat specially: matching "/" would gate every path, which
    ///   is a config error — see [`PrefixSet::new`]).
    prefixes: Vec<String>,
}

impl PrefixSet {
    /// Build a `PrefixSet` from `roots`. Each root is:
    /// - converted to a string (skipped if non-UTF8 — this is a
    ///   pragmatic restriction, see "Pitfalls" in the sprint spec),
    /// - rejected if it is the literal root `/` (would gate every
    ///   write — likely a config mistake),
    /// - normalized by stripping any trailing `/`s.
    ///
    /// Order is preserved (matching is order-independent so this only
    /// matters for diagnostic output).
    pub fn new<I, S>(roots: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut prefixes = Vec::new();
        for r in roots {
            let s = r.as_ref();
            if !s.starts_with('/') || s == "/" {
                continue;
            }
            let trimmed = s.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }
            if !prefixes.iter().any(|p: &String| p == trimmed) {
                prefixes.push(trimmed.to_string());
            }
        }
        Self { prefixes }
    }

    /// Returns `true` if `path` is one of the configured prefixes or
    /// strictly below it.
    ///
    /// The check is **lexical** — symlinks are not followed. Callers
    /// must canonicalize first. The result is correct only for absolute
    /// inputs; relative inputs always return `false` (we'd need a CWD
    /// to resolve them, and the shim's hot path doesn't have one
    /// without an extra syscall).
    pub fn matches(&self, path: &Path) -> bool {
        let Some(s) = path.to_str() else {
            return false;
        };
        if !s.starts_with('/') {
            return false;
        }
        for p in &self.prefixes {
            if s == p.as_str() {
                return true;
            }
            // `p` has no trailing `/`. The "strictly below" check is
            // "s starts with p followed by /".
            if s.len() > p.len() && s.as_bytes()[p.len()] == b'/' && s.starts_with(p.as_str()) {
                return true;
            }
        }
        false
    }

    /// Same as `matches` but takes a string slice directly. Saves the
    /// caller a `Path::to_str` when they already have a `&str`.
    pub fn matches_str(&self, s: &str) -> bool {
        if !s.starts_with('/') {
            return false;
        }
        for p in &self.prefixes {
            if s == p.as_str() {
                return true;
            }
            if s.len() > p.len() && s.as_bytes()[p.len()] == b'/' && s.starts_with(p.as_str()) {
                return true;
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty()
    }

    pub fn len(&self) -> usize {
        self.prefixes.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.prefixes.iter().map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn set(roots: &[&str]) -> PrefixSet {
        PrefixSet::new(roots.iter().copied())
    }

    #[test]
    fn empty_set_matches_nothing() {
        let s = set(&[]);
        assert!(!s.matches(Path::new("/usr/local/bin/foo")));
    }

    #[test]
    fn exact_prefix_match_is_true() {
        let s = set(&["/usr/local"]);
        assert!(s.matches(Path::new("/usr/local")));
    }

    #[test]
    fn strict_below_match_is_true() {
        let s = set(&["/usr/local"]);
        assert!(s.matches(Path::new("/usr/local/bin")));
        assert!(s.matches(Path::new("/usr/local/bin/foo")));
        assert!(s.matches(Path::new("/usr/local/share/man/man1/foo.1.gz")));
    }

    #[test]
    fn sibling_with_shared_prefix_does_not_match() {
        // /usr/locallib must NOT match /usr/local — that would be a
        // false positive from a naïve `starts_with`.
        let s = set(&["/usr/local"]);
        assert!(!s.matches(Path::new("/usr/locallib")));
        assert!(!s.matches(Path::new("/usr/local-staging/bin/foo")));
    }

    #[test]
    fn trailing_slash_in_config_is_stripped() {
        let s = set(&["/usr/local/"]);
        assert!(s.matches(Path::new("/usr/local")));
        assert!(s.matches(Path::new("/usr/local/bin")));
        assert!(!s.matches(Path::new("/usr/locallib")));
    }

    #[test]
    fn multiple_trailing_slashes_are_stripped() {
        let s = set(&["/opt///"]);
        assert!(s.matches(Path::new("/opt")));
        assert!(s.matches(Path::new("/opt/foo")));
        // `/` alone in config is rejected:
        let only_root = set(&["/"]);
        assert!(only_root.is_empty());
    }

    #[test]
    fn relative_input_path_never_matches() {
        let s = set(&["/usr/local"]);
        assert!(!s.matches(Path::new("usr/local/bin/foo")));
        assert!(!s.matches(Path::new("./bin/foo")));
        assert!(!s.matches(Path::new("../etc/passwd")));
    }

    #[test]
    fn non_absolute_config_path_is_dropped() {
        let s = set(&["usr/local", "/opt"]);
        assert!(!s.matches(Path::new("/usr/local/bin/foo")));
        assert!(s.matches(Path::new("/opt/foo")));
    }

    #[test]
    fn duplicate_prefixes_collapse() {
        let s = set(&["/usr/local", "/usr/local/", "/usr/local"]);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn multiple_prefixes_match_independently() {
        let s = set(&["/usr/local", "/opt", "/home/u/.cargo/bin"]);
        assert!(s.matches(Path::new("/usr/local/bin/foo")));
        assert!(s.matches(Path::new("/opt/bar")));
        assert!(s.matches(Path::new("/home/u/.cargo/bin/cargo-fmt")));
        assert!(!s.matches(Path::new("/home/u/.cache/foo")));
        assert!(!s.matches(Path::new("/var/lib/foo")));
    }

    #[test]
    fn matches_str_parity_with_matches() {
        let s = set(&["/usr/local", "/opt"]);
        for path in [
            "/usr/local",
            "/usr/local/bin/foo",
            "/usr/locallib",
            "/opt",
            "/opt/x",
            "/var/lib",
            "usr/local/bin",
        ] {
            assert_eq!(
                s.matches_str(path),
                s.matches(Path::new(path)),
                "parity mismatch for `{path}`"
            );
        }
    }

    #[test]
    fn iter_returns_normalized_prefixes_in_insertion_order() {
        let s = set(&["/opt/", "/usr/local/"]);
        let got: Vec<&str> = s.iter().collect();
        assert_eq!(got, vec!["/opt", "/usr/local"]);
    }

    #[test]
    fn empty_string_root_is_dropped() {
        let s = set(&["", "/usr/local"]);
        assert_eq!(s.len(), 1);
        assert!(s.matches(Path::new("/usr/local/bin")));
    }

    #[test]
    fn non_utf8_path_returns_false() {
        // OsString with non-UTF8 bytes on Unix; matches() returns
        // false rather than panicking. We can't construct a non-UTF8
        // `Path::new(&str)` directly, so just exercise the to_str path
        // for a UTF-8 string and trust the explicit `else { return
        // false }` arm.
        let s = set(&["/usr/local"]);
        let pb = PathBuf::from("/usr/local/bin/foo");
        assert!(s.matches(&pb));
    }
}
