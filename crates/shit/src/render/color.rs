// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code)]

//! Color preference resolution.
//!
//! Three signals, in priority order:
//!
//! 1. **Explicit CLI flag** (`--color auto|never|always`).
//! 2. **`NO_COLOR` env var** (any non-empty value disables color —
//!    see <https://no-color.org/>).
//! 3. **TTY detection on stdout**.
//!
//! Plus `CLICOLOR=0` as a weaker no-color signal (the no-color.org
//! page documents it as an older convention).
//!
//! Subcommands read the resolved `bool` once at the start of output
//! and pass it to whatever renderer they're using.

use std::io::IsTerminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum ColorPref {
    #[default]
    Auto,
    Never,
    Always,
}

/// Resolve the color preference against the live environment +
/// stdout. The `is_tty` callback is dependency-injected for tests so
/// we don't have to mock `IsTerminal`.
pub fn resolve_color_with<F: FnOnce() -> bool>(pref: ColorPref, is_tty: F) -> bool {
    if pref == ColorPref::Always {
        return true;
    }
    if pref == ColorPref::Never {
        return false;
    }
    // Auto: respect NO_COLOR / CLICOLOR / TTY in that order.
    if std::env::var_os("NO_COLOR")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return false;
    }
    if let Some(v) = std::env::var_os("CLICOLOR")
        && v == "0"
    {
        return false;
    }
    is_tty()
}

/// Convenience: resolve against stdout.
pub fn resolve_color(pref: ColorPref) -> bool {
    resolve_color_with(pref, || std::io::stdout().is_terminal())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Process-global lock serializing env mutation across the
    /// parallel test runner. Without it the NO_COLOR/CLICOLOR tests
    /// race against each other — one thread sets `CLICOLOR=0` while
    /// another is in the middle of asserting it's unset.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper: run a closure with `NO_COLOR` and `CLICOLOR` cleared,
    /// then restore. Holds `ENV_LOCK` for the closure's duration so
    /// other tests can't observe our temporary state.
    fn with_clean_env<F: FnOnce() -> R, R>(f: F) -> R {
        let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let no_color = std::env::var_os("NO_COLOR");
        let clicolor = std::env::var_os("CLICOLOR");
        unsafe {
            std::env::remove_var("NO_COLOR");
            std::env::remove_var("CLICOLOR");
        }
        let r = f();
        unsafe {
            match no_color {
                Some(v) => std::env::set_var("NO_COLOR", v),
                None => std::env::remove_var("NO_COLOR"),
            }
            match clicolor {
                Some(v) => std::env::set_var("CLICOLOR", v),
                None => std::env::remove_var("CLICOLOR"),
            }
        }
        r
    }

    #[test]
    fn always_overrides_no_tty() {
        with_clean_env(|| {
            assert!(resolve_color_with(ColorPref::Always, || false));
        });
    }

    #[test]
    fn never_overrides_tty() {
        with_clean_env(|| {
            assert!(!resolve_color_with(ColorPref::Never, || true));
        });
    }

    #[test]
    fn auto_falls_back_to_tty_signal() {
        with_clean_env(|| {
            assert!(resolve_color_with(ColorPref::Auto, || true));
            assert!(!resolve_color_with(ColorPref::Auto, || false));
        });
    }

    #[test]
    fn no_color_env_disables_even_with_tty() {
        // SAFETY: tests run sequentially within this fn; with_clean_env
        // brackets restore order around the closure body.
        with_clean_env(|| {
            unsafe { std::env::set_var("NO_COLOR", "1") };
            assert!(!resolve_color_with(ColorPref::Auto, || true));
        });
    }

    #[test]
    fn clicolor_zero_disables_even_with_tty() {
        with_clean_env(|| {
            unsafe { std::env::set_var("CLICOLOR", "0") };
            assert!(!resolve_color_with(ColorPref::Auto, || true));
        });
    }

    #[test]
    fn always_beats_no_color_env() {
        // No-color.org spec is ambiguous on this; the CLI flag is
        // *explicit user intent*, so we honor it over the env signal.
        with_clean_env(|| {
            unsafe { std::env::set_var("NO_COLOR", "1") };
            assert!(resolve_color_with(ColorPref::Always, || false));
        });
    }
}
