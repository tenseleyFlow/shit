// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime env-var gates for the shim (C05.4).
//!
//! Three knobs drive the shim's hot-path behavior. All three are
//! string-valued env vars so they can be set / unset without IPC and
//! survive `exec`:
//!
//! - [`SHIT_PRELOAD_ACTIVE_ENV`] (`SHIT_PRELOAD_ACTIVE`): opt-in
//!   gate. The shim short-circuits immediately if this is unset (or
//!   set to anything other than `"1"`). Without this, accidentally
//!   leaving `LD_PRELOAD` set globally (because some other tool put
//!   it there) doesn't make every open everywhere go through the
//!   capture pipeline.
//! - [`SHIT_PRELOAD_DEPTH_ENV`] (`SHIT_PRELOAD_DEPTH`): recursion
//!   guard. Incremented by the shim when entering a wrapped syscall
//!   to detect re-entrant shim invocations (a wrapped process forks
//!   `cp` which is also wrapped → second-level entry). At depth ≥ 1
//!   the inner shim falls through without capture so we don't emit
//!   duplicate events.
//! - [`SHIT_DAEMON_SOCK_ENV`] (`SHIT_DAEMON_SOCK`): UDS path the shim
//!   sends `PreInstall` events to. Set by the `shit install` wrapper
//!   (and by the shell auto-injector); the shim falls through without
//!   capture if this is unset (no point capturing if the daemon can't
//!   be reached).
//!
//! ## Spawner contract
//!
//! `shitd` and `shit-helper` MUST strip `LD_PRELOAD` /
//! `DYLD_INSERT_LIBRARIES` / `SHIT_PRELOAD_ACTIVE` from every child
//! environment they construct. See [`strip_for_child_env`]. This
//! defends against the fatal-loop case where the daemon's helper
//! inherits the shim and captures its own writes.

use std::ffi::{OsStr, OsString};

/// `SHIT_PRELOAD_ACTIVE` — the opt-in gate. Must equal `"1"` for the
/// shim to do anything beyond fall-through.
pub const SHIT_PRELOAD_ACTIVE_ENV: &str = "SHIT_PRELOAD_ACTIVE";
/// `SHIT_PRELOAD_DEPTH` — re-entry counter incremented per wrap.
pub const SHIT_PRELOAD_DEPTH_ENV: &str = "SHIT_PRELOAD_DEPTH";
/// `SHIT_DAEMON_SOCK` — UDS path for the daemon's preload listener.
pub const SHIT_DAEMON_SOCK_ENV: &str = "SHIT_DAEMON_SOCK";
/// Linux dynamic-loader env var. Stripped from helper / daemon child
/// envs to prevent the shim from re-entering privileged code.
pub const LD_PRELOAD_ENV: &str = "LD_PRELOAD";
/// macOS DYLD interpose env var. Stripped from child envs alongside
/// `LD_PRELOAD`. (SIP-protected binaries strip it themselves; we still
/// strip it on the way in to keep behaviour consistent for non-SIP
/// children.)
pub const DYLD_INSERT_LIBRARIES_ENV: &str = "DYLD_INSERT_LIBRARIES";

/// Returns `true` iff the env claims the shim is active. The cdylib
/// calls this at every interposed syscall entry; the rlib consumers
/// call it during pure-logic decisions (tests, mocks).
pub fn is_active() -> bool {
    std::env::var(SHIT_PRELOAD_ACTIVE_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Returns the current recursion depth — the value of
/// `SHIT_PRELOAD_DEPTH` as a `u32`, defaulting to `0`. Non-numeric
/// values are treated as `0` (a malformed depth shouldn't make us
/// fall through forever).
pub fn current_depth() -> u32 {
    std::env::var(SHIT_PRELOAD_DEPTH_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Returns `true` iff we are at depth 0 (top-level wrapped command).
/// At depth ≥ 1 the shim short-circuits to avoid duplicate captures.
pub fn at_top_level() -> bool {
    current_depth() == 0
}

/// Strip the shim-related env vars from a child environment. Returns
/// a new `Vec` with the offending entries removed. Used by the daemon
/// and helper spawners so children never inherit the shim.
pub fn strip_for_child_env<I, K, V>(parent: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<OsString>,
    V: Into<OsString>,
{
    let stripped = stripped_env_names();
    parent
        .into_iter()
        .filter_map(|(k, v)| {
            let k: OsString = k.into();
            if stripped.iter().any(|s| OsStr::new(s) == k.as_os_str()) {
                None
            } else {
                Some((k, v.into()))
            }
        })
        .collect()
}

/// Names of env vars that [`strip_for_child_env`] removes.
pub fn stripped_env_names() -> &'static [&'static str] {
    &[
        SHIT_PRELOAD_ACTIVE_ENV,
        SHIT_PRELOAD_DEPTH_ENV,
        LD_PRELOAD_ENV,
        DYLD_INSERT_LIBRARIES_ENV,
    ]
}

/// Produce the env-var assignments that the `shit install` wrapper
/// (and the shell auto-injector) prepends to the user's command.
/// `lib_path` is the absolute path to `libshit_preload_shim.{so,dylib}`;
/// `sock_path` is the daemon UDS. The caller is responsible for
/// joining each `(k, v)` into the child's environment using whatever
/// spawn API they're driving.
pub fn injection_env(lib_path: &str, sock_path: &str) -> Vec<(&'static str, String)> {
    let preload_env = if cfg!(target_os = "macos") {
        DYLD_INSERT_LIBRARIES_ENV
    } else {
        LD_PRELOAD_ENV
    };
    vec![
        (preload_env, lib_path.to_string()),
        (SHIT_PRELOAD_ACTIVE_ENV, "1".to_string()),
        (SHIT_DAEMON_SOCK_ENV, sock_path.to_string()),
    ]
}

/// `std::env` reads/writes process-wide globals; tests that touch them
/// must serialise to avoid cross-test poisoning. The lock is exported
/// `pub(crate)` so sibling test modules (currently `dispatch::tests`)
/// share a single critical section with `runtime::tests`.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    /// Local alias to keep the test bodies readable.
    static ENV_LOCK: &std::sync::Mutex<()> = &TEST_ENV_LOCK;

    #[test]
    fn is_active_returns_true_only_when_env_equals_one() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(SHIT_PRELOAD_ACTIVE_ENV) };
        assert!(!is_active());
        unsafe { std::env::set_var(SHIT_PRELOAD_ACTIVE_ENV, "1") };
        assert!(is_active());
        unsafe { std::env::set_var(SHIT_PRELOAD_ACTIVE_ENV, "0") };
        assert!(!is_active());
        unsafe { std::env::set_var(SHIT_PRELOAD_ACTIVE_ENV, "yes") };
        assert!(!is_active(), "only `1` should activate");
        unsafe { std::env::set_var(SHIT_PRELOAD_ACTIVE_ENV, "") };
        assert!(!is_active());
        unsafe { std::env::remove_var(SHIT_PRELOAD_ACTIVE_ENV) };
    }

    #[test]
    fn current_depth_defaults_to_zero() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(SHIT_PRELOAD_DEPTH_ENV) };
        assert_eq!(current_depth(), 0);
    }

    #[test]
    fn current_depth_parses_numeric() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var(SHIT_PRELOAD_DEPTH_ENV, "3") };
        assert_eq!(current_depth(), 3);
        unsafe { std::env::set_var(SHIT_PRELOAD_DEPTH_ENV, "garbage") };
        assert_eq!(current_depth(), 0, "non-numeric falls back to 0");
        unsafe { std::env::remove_var(SHIT_PRELOAD_DEPTH_ENV) };
    }

    #[test]
    fn at_top_level_inverts_current_depth() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var(SHIT_PRELOAD_DEPTH_ENV) };
        assert!(at_top_level());
        unsafe { std::env::set_var(SHIT_PRELOAD_DEPTH_ENV, "1") };
        assert!(!at_top_level());
        unsafe { std::env::remove_var(SHIT_PRELOAD_DEPTH_ENV) };
    }

    #[test]
    fn strip_for_child_env_removes_all_known_keys() {
        let parent: Vec<(OsString, OsString)> = [
            ("PATH", "/usr/bin"),
            ("HOME", "/home/u"),
            (LD_PRELOAD_ENV, "/usr/lib/libshit.so"),
            (SHIT_PRELOAD_ACTIVE_ENV, "1"),
            (SHIT_PRELOAD_DEPTH_ENV, "1"),
            (DYLD_INSERT_LIBRARIES_ENV, "/usr/lib/libshit.dylib"),
            ("CARGO_HOME", "/home/u/.cargo"),
        ]
        .iter()
        .map(|(k, v)| (OsString::from(*k), OsString::from(*v)))
        .collect();
        let cleaned = strip_for_child_env(parent);
        let keys: Vec<String> = cleaned
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert!(keys.contains(&"PATH".to_string()));
        assert!(keys.contains(&"HOME".to_string()));
        assert!(keys.contains(&"CARGO_HOME".to_string()));
        assert!(!keys.iter().any(|k| k == LD_PRELOAD_ENV));
        assert!(!keys.iter().any(|k| k == SHIT_PRELOAD_ACTIVE_ENV));
        assert!(!keys.iter().any(|k| k == SHIT_PRELOAD_DEPTH_ENV));
        assert!(!keys.iter().any(|k| k == DYLD_INSERT_LIBRARIES_ENV));
    }

    #[test]
    fn strip_for_child_env_is_idempotent() {
        // Stripping an env that has no shim vars to begin with is a no-op.
        let parent: Vec<(OsString, OsString)> = vec![
            (OsString::from("PATH"), OsString::from("/bin")),
            (OsString::from("FOO"), OsString::from("bar")),
        ];
        let cleaned = strip_for_child_env(parent.clone());
        assert_eq!(cleaned.len(), parent.len());
    }

    #[test]
    fn injection_env_picks_correct_loader_var() {
        let env = injection_env("/usr/lib/libshit.so", "/var/run/shit.sock");
        let keys: Vec<&str> = env.iter().map(|(k, _)| *k).collect();
        if cfg!(target_os = "macos") {
            assert!(keys.contains(&DYLD_INSERT_LIBRARIES_ENV));
            assert!(!keys.contains(&LD_PRELOAD_ENV));
        } else {
            assert!(keys.contains(&LD_PRELOAD_ENV));
            assert!(!keys.contains(&DYLD_INSERT_LIBRARIES_ENV));
        }
        assert!(keys.contains(&SHIT_PRELOAD_ACTIVE_ENV));
        assert!(keys.contains(&SHIT_DAEMON_SOCK_ENV));
    }

    #[test]
    fn stripped_env_names_includes_all_four() {
        let names = stripped_env_names();
        assert!(names.contains(&SHIT_PRELOAD_ACTIVE_ENV));
        assert!(names.contains(&SHIT_PRELOAD_DEPTH_ENV));
        assert!(names.contains(&LD_PRELOAD_ENV));
        assert!(names.contains(&DYLD_INSERT_LIBRARIES_ENV));
    }
}
