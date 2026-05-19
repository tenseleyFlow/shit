// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hot-path decision helper (C05.5).
//!
//! The interpose layer (the dlsym(RTLD_NEXT) machinery that lives on
//! trunk under S24.D) calls [`should_capture`] at the top of every
//! wrapped syscall. The check is short-circuit-cheap on the cold path
//! — three env reads and a prefix string compare — so the per-call
//! overhead for non-install-prefix paths stays in single-digit
//! nanoseconds.
//!
//! Three things must all be true for the shim to capture:
//!
//! 1. `SHIT_PRELOAD_ACTIVE=1` (set by the `shit install` wrapper or
//!    the shell auto-injector; never set globally).
//! 2. `SHIT_PRELOAD_DEPTH=0` (no enclosing wrapped invocation; defends
//!    against double-capture when a wrapped process forks `cp` and
//!    `cp` is also wrapped).
//! 3. The resolved-canonical destination path is at-or-below one of
//!    the configured install prefixes.
//!
//! The first two are env reads from [`crate::runtime`]; the third is
//! a lexical match against [`crate::prefix_match::PrefixSet`]. The
//! caller is responsible for canonicalising the path BEFORE calling
//! `should_capture` — see the module-level doc on `prefix_match` for
//! why.

use crate::prefix_match::PrefixSet;
use crate::runtime;
use std::path::Path;

/// `SHIT_INSTALL_PREFIXES` — colon-separated list of resolved install
/// prefixes. The daemon resolves the user's `install-prefixes.toml`
/// at startup and ships the result via this env var (and via the
/// `shit install` wrapper). The shim reads it once at cdylib load
/// time and caches the [`PrefixSet`].
pub const SHIT_INSTALL_PREFIXES_ENV: &str = "SHIT_INSTALL_PREFIXES";

/// Build a [`PrefixSet`] from the `SHIT_INSTALL_PREFIXES` env var.
/// Returns an empty set if the env var is unset — that's a fail-safe:
/// no prefixes ⇒ no captures ⇒ no shim overhead.
pub fn prefix_set_from_env() -> PrefixSet {
    match std::env::var(SHIT_INSTALL_PREFIXES_ENV) {
        Ok(s) => PrefixSet::new(s.split(':').filter(|s| !s.is_empty())),
        Err(_) => PrefixSet::new(std::iter::empty::<&str>()),
    }
}

/// Should the shim capture pre-state for an operation against `path`?
///
/// `path` MUST already be a canonical absolute path. Callers that
/// have a raw `*const c_char` from libc must `realpath()` it (or do
/// an equivalent kernel-side resolution) before invoking this.
pub fn should_capture(path: &Path, prefix_set: &PrefixSet) -> bool {
    runtime::is_active() && runtime::at_top_level() && prefix_set.matches(path)
}

/// Convenience for callers that have a string path. Same semantics as
/// [`should_capture`].
pub fn should_capture_str(path: &str, prefix_set: &PrefixSet) -> bool {
    runtime::is_active() && runtime::at_top_level() && prefix_set.matches_str(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{SHIT_PRELOAD_ACTIVE_ENV, SHIT_PRELOAD_DEPTH_ENV, TEST_ENV_LOCK};

    /// Shared with runtime::tests — `std::env` is process-wide.
    static ENV_LOCK: &std::sync::Mutex<()> = &TEST_ENV_LOCK;

    fn restore_env(active: Option<&str>, depth: Option<&str>, prefixes: Option<&str>) {
        unsafe {
            match active {
                Some(v) => std::env::set_var(SHIT_PRELOAD_ACTIVE_ENV, v),
                None => std::env::remove_var(SHIT_PRELOAD_ACTIVE_ENV),
            }
            match depth {
                Some(v) => std::env::set_var(SHIT_PRELOAD_DEPTH_ENV, v),
                None => std::env::remove_var(SHIT_PRELOAD_DEPTH_ENV),
            }
            match prefixes {
                Some(v) => std::env::set_var(SHIT_INSTALL_PREFIXES_ENV, v),
                None => std::env::remove_var(SHIT_INSTALL_PREFIXES_ENV),
            }
        }
    }

    // ----- prefix_set_from_env -----

    #[test]
    fn prefix_set_from_env_unset_is_empty() {
        let _g = ENV_LOCK.lock().unwrap();
        restore_env(None, None, None);
        let s = prefix_set_from_env();
        assert!(s.is_empty());
    }

    #[test]
    fn prefix_set_from_env_parses_colon_separated() {
        let _g = ENV_LOCK.lock().unwrap();
        restore_env(None, None, Some("/usr/local:/opt:/home/u/.local"));
        let s = prefix_set_from_env();
        assert_eq!(s.len(), 3);
        assert!(s.matches(Path::new("/usr/local/bin/foo")));
        assert!(s.matches(Path::new("/opt/bar")));
        assert!(s.matches(Path::new("/home/u/.local/lib/x")));
        restore_env(None, None, None);
    }

    #[test]
    fn prefix_set_from_env_skips_empty_segments() {
        let _g = ENV_LOCK.lock().unwrap();
        restore_env(None, None, Some(":/usr/local::/opt:"));
        let s = prefix_set_from_env();
        assert_eq!(s.len(), 2);
        restore_env(None, None, None);
    }

    // ----- should_capture -----

    #[test]
    fn should_capture_false_when_active_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        restore_env(None, None, None);
        let s = PrefixSet::new(["/usr/local"]);
        assert!(!should_capture(Path::new("/usr/local/bin/foo"), &s));
    }

    #[test]
    fn should_capture_false_when_active_set_but_not_one() {
        let _g = ENV_LOCK.lock().unwrap();
        restore_env(Some("yes"), None, None);
        let s = PrefixSet::new(["/usr/local"]);
        assert!(!should_capture(Path::new("/usr/local/bin/foo"), &s));
        restore_env(None, None, None);
    }

    #[test]
    fn should_capture_true_when_active_top_level_and_path_under_prefix() {
        let _g = ENV_LOCK.lock().unwrap();
        restore_env(Some("1"), None, None);
        let s = PrefixSet::new(["/usr/local"]);
        assert!(should_capture(Path::new("/usr/local/bin/foo"), &s));
        restore_env(None, None, None);
    }

    #[test]
    fn should_capture_false_when_at_depth_one() {
        let _g = ENV_LOCK.lock().unwrap();
        restore_env(Some("1"), Some("1"), None);
        let s = PrefixSet::new(["/usr/local"]);
        assert!(
            !should_capture(Path::new("/usr/local/bin/foo"), &s),
            "depth ≥ 1 must short-circuit to prevent re-entrant capture"
        );
        restore_env(None, None, None);
    }

    #[test]
    fn should_capture_false_when_path_outside_prefix() {
        let _g = ENV_LOCK.lock().unwrap();
        restore_env(Some("1"), None, None);
        let s = PrefixSet::new(["/usr/local"]);
        assert!(!should_capture(Path::new("/etc/passwd"), &s));
        assert!(!should_capture(Path::new("/tmp/build/intermediate.o"), &s));
        restore_env(None, None, None);
    }

    #[test]
    fn should_capture_str_parity_with_should_capture() {
        let _g = ENV_LOCK.lock().unwrap();
        restore_env(Some("1"), None, None);
        let s = PrefixSet::new(["/usr/local"]);
        for path in [
            "/usr/local",
            "/usr/local/bin/foo",
            "/usr/locallib",
            "/etc/passwd",
            "relative/path",
        ] {
            assert_eq!(
                should_capture_str(path, &s),
                should_capture(Path::new(path), &s),
                "parity mismatch for `{path}`"
            );
        }
        restore_env(None, None, None);
    }
}
