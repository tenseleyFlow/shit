// SPDX-License-Identifier: AGPL-3.0-or-later

//! `install-prefixes.toml` configuration loader (C05.3).
//!
//! Built-in defaults always apply unless the user sets `replace =
//! true` at the top of their `~/.config/shit/install-prefixes.toml`.
//! The user's extra prefixes are appended; any with `optional = true`
//! that don't exist on disk are silently dropped, while non-optional
//! missing prefixes are a load-time error so a typo doesn't silently
//! disable capture for a path the user thinks is covered.
//!
//! This module is `rlib`-only (the cdylib hot path doesn't read TOML;
//! the daemon reads the config at startup and passes the resolved
//! prefix list to the shim out-of-band via env var / IPC).
//!
//! ## Config shape
//!
//! ```toml
//! # Optional; default `false`. When `true`, the built-in defaults
//! # are NOT included — the user takes full responsibility for the
//! # set of install prefixes.
//! replace = false
//!
//! [[prefix]]
//! path = "/opt/local"
//!
//! [[prefix]]
//! path = "~/.cabal/bin"
//! optional = true
//! ```
//!
//! `~/` at the start of a path is expanded to `$HOME`. Other `~`
//! forms (e.g. `~user/`) are NOT supported — keeping path resolution
//! syscall-free.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Hard-coded built-in install prefixes. Order matters only for
/// `shit show` diagnostic rendering — the matcher itself is
/// order-independent.
///
/// `~/` placeholders are expanded against the runtime `$HOME` by
/// [`resolve`].
pub const BUILTIN_PREFIXES: &[&str] = &[
    "/usr/local",
    "/opt",
    "~/.local",
    "~/.local/bin",
    "~/.local/lib",
    "~/.cargo/bin",
];

/// Raw parsed `install-prefixes.toml`. Use [`load_str`] / [`load_file`]
/// to build one; pass it to [`resolve`] to apply the
/// merge-with-defaults and the on-disk validation.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub replace: bool,
    #[serde(default, rename = "prefix")]
    pub prefixes: Vec<PrefixEntry>,
}

impl Config {
    pub fn empty() -> Self {
        Self {
            replace: false,
            prefixes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PrefixEntry {
    pub path: String,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error(
        "required install prefix `{0}` does not exist on disk; mark `optional = true` or fix the path"
    )]
    RequiredMissing(String),
}

/// Parse a `Config` from raw TOML bytes.
pub fn load_str(s: &str) -> Result<Config, ConfigError> {
    Ok(toml::from_str(s)?)
}

/// Parse a `Config` from a file on disk. A missing file is treated
/// as `Config::empty()` so users who haven't created one still get
/// the built-in defaults.
pub fn load_file(path: &Path) -> Result<Config, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(s) => load_str(&s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::empty()),
        Err(e) => Err(ConfigError::Io(e)),
    }
}

/// Apply the merge rules and produce the resolved prefix list:
///
/// - If `cfg.replace == false`, the built-in defaults are included.
/// - User entries are appended; duplicates are deduped (first wins).
/// - Each `~/...` is expanded against `home`.
/// - Each entry is `exists`-checked via `exists`; required entries
///   that fail return [`ConfigError::RequiredMissing`].
///
/// The `exists` closure is parameterised so tests can run without
/// touching the filesystem. Production calls pass
/// `std::path::Path::exists` (boxed via `|p| p.exists()`).
pub fn resolve<E>(cfg: &Config, home: &Path, mut exists: E) -> Result<Vec<String>, ConfigError>
where
    E: FnMut(&Path) -> bool,
{
    let mut entries: Vec<(String, bool)> = Vec::new();
    if !cfg.replace {
        // Built-ins are implicitly `optional = true`: a missing
        // `~/.cargo/bin` on a host without Rust isn't an error.
        // Required-validation only fires for entries the user wrote
        // themselves.
        for p in BUILTIN_PREFIXES {
            entries.push(((*p).to_string(), true));
        }
    }
    for e in &cfg.prefixes {
        entries.push((e.path.clone(), e.optional));
    }

    let mut out: Vec<String> = Vec::with_capacity(entries.len());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (raw, optional) in entries {
        let expanded = expand_tilde(&raw, home);
        if !seen.insert(expanded.clone()) {
            continue;
        }
        let pb = PathBuf::from(&expanded);
        if exists(&pb) {
            out.push(expanded);
        } else if !optional {
            return Err(ConfigError::RequiredMissing(expanded));
        }
        // Optional + missing: silently drop.
    }
    Ok(out)
}

/// Convenience wrapper for production callers that want real fs
/// existence checks.
pub fn resolve_with_fs(cfg: &Config, home: &Path) -> Result<Vec<String>, ConfigError> {
    resolve(cfg, home, |p| p.exists())
}

/// Expand a leading `~/` to `$HOME/`. Other `~` forms pass through
/// unchanged — we intentionally don't support `~user/` because it
/// requires a `getpwnam(3)` syscall and the install-prefix list is
/// resolved at daemon startup, not in the shim hot path. If a user
/// genuinely needs `~someone-else/`, they can spell out the absolute
/// path.
pub fn expand_tilde(raw: &str, home: &Path) -> String {
    if let Some(rest) = raw.strip_prefix("~/") {
        let home_str = home.to_string_lossy();
        format!(
            "{}/{}",
            home_str.trim_end_matches('/'),
            rest.trim_start_matches('/')
        )
    } else if raw == "~" {
        home.to_string_lossy().into_owned()
    } else {
        raw.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> PathBuf {
        PathBuf::from("/home/u")
    }

    // ----- expand_tilde -----

    #[test]
    fn tilde_slash_expands() {
        assert_eq!(expand_tilde("~/foo", &home()), "/home/u/foo");
        assert_eq!(expand_tilde("~/.local/bin", &home()), "/home/u/.local/bin");
    }

    #[test]
    fn bare_tilde_expands_to_home() {
        assert_eq!(expand_tilde("~", &home()), "/home/u");
    }

    #[test]
    fn no_leading_tilde_is_passthrough() {
        assert_eq!(expand_tilde("/usr/local", &home()), "/usr/local");
        assert_eq!(expand_tilde("opt", &home()), "opt");
    }

    #[test]
    fn tilde_user_form_is_passthrough_by_design() {
        // Documented: we don't getpwnam-resolve. The user can spell
        // it absolute if they need it.
        assert_eq!(expand_tilde("~bob/x", &home()), "~bob/x");
    }

    // ----- load_str / load_file -----

    #[test]
    fn empty_config_parses() {
        let c = load_str("").unwrap();
        assert!(!c.replace);
        assert!(c.prefixes.is_empty());
    }

    #[test]
    fn replace_flag_parses() {
        let c = load_str("replace = true\n").unwrap();
        assert!(c.replace);
    }

    #[test]
    fn prefix_array_parses_with_default_optional_false() {
        let c = load_str(
            r#"
[[prefix]]
path = "/opt/local"

[[prefix]]
path = "~/.cabal/bin"
optional = true
"#,
        )
        .unwrap();
        assert_eq!(c.prefixes.len(), 2);
        assert_eq!(c.prefixes[0].path, "/opt/local");
        assert!(!c.prefixes[0].optional);
        assert!(c.prefixes[1].optional);
    }

    #[test]
    fn load_file_missing_returns_empty() {
        let cfg = load_file(Path::new("/nonexistent/path/install-prefixes.toml")).unwrap();
        assert!(!cfg.replace);
        assert!(cfg.prefixes.is_empty());
    }

    // ----- resolve -----

    fn always_exists(_: &Path) -> bool {
        true
    }

    fn never_exists(_: &Path) -> bool {
        false
    }

    #[test]
    fn resolve_empty_config_returns_all_builtins() {
        let cfg = Config::empty();
        let out = resolve(&cfg, &home(), always_exists).unwrap();
        assert_eq!(out.len(), BUILTIN_PREFIXES.len());
        // First two are absolute, untouched.
        assert_eq!(out[0], "/usr/local");
        assert_eq!(out[1], "/opt");
        // Tilde-prefixed entries are expanded.
        assert!(out.iter().any(|p| p == "/home/u/.local"));
        assert!(out.iter().any(|p| p == "/home/u/.cargo/bin"));
    }

    #[test]
    fn resolve_replace_drops_builtins() {
        let cfg = Config {
            replace: true,
            prefixes: vec![PrefixEntry {
                path: "/opt/local".into(),
                optional: false,
            }],
        };
        let out = resolve(&cfg, &home(), always_exists).unwrap();
        assert_eq!(out, vec!["/opt/local"]);
    }

    #[test]
    fn resolve_user_entries_appended_to_builtins() {
        let cfg = Config {
            replace: false,
            prefixes: vec![PrefixEntry {
                path: "/opt/local".into(),
                optional: false,
            }],
        };
        let out = resolve(&cfg, &home(), always_exists).unwrap();
        assert_eq!(out.len(), BUILTIN_PREFIXES.len() + 1);
        assert_eq!(out.last().unwrap(), "/opt/local");
    }

    #[test]
    fn resolve_required_missing_errors() {
        let cfg = Config {
            replace: true,
            prefixes: vec![PrefixEntry {
                path: "/opt/does-not-exist".into(),
                optional: false,
            }],
        };
        let err = resolve(&cfg, &home(), never_exists).unwrap_err();
        match err {
            ConfigError::RequiredMissing(p) => assert_eq!(p, "/opt/does-not-exist"),
            other => panic!("expected RequiredMissing, got {other:?}"),
        }
    }

    #[test]
    fn resolve_optional_missing_is_dropped_silently() {
        let cfg = Config {
            replace: true,
            prefixes: vec![PrefixEntry {
                path: "/opt/maybe".into(),
                optional: true,
            }],
        };
        let out = resolve(&cfg, &home(), never_exists).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn resolve_builtins_silently_drop_when_missing() {
        // Built-ins are implicitly optional — a user without
        // `~/.cargo/bin` (no Rust installed) shouldn't see an error
        // load-time. Required-error only fires on explicit user
        // entries.
        let cfg = Config::empty();
        let out = resolve(&cfg, &home(), never_exists).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn resolve_dedupes_duplicate_entries() {
        let cfg = Config {
            replace: false,
            prefixes: vec![
                PrefixEntry {
                    path: "/usr/local".into(),
                    optional: false,
                },
                PrefixEntry {
                    path: "/opt".into(),
                    optional: false,
                },
            ],
        };
        let out = resolve(&cfg, &home(), always_exists).unwrap();
        // /usr/local and /opt are also in BUILTIN_PREFIXES; expect
        // each to appear exactly once.
        let n_usr_local = out.iter().filter(|p| *p == "/usr/local").count();
        let n_opt = out.iter().filter(|p| *p == "/opt").count();
        assert_eq!(n_usr_local, 1);
        assert_eq!(n_opt, 1);
    }

    #[test]
    fn resolve_mix_of_present_and_absent_optional_user_entries() {
        let cfg = Config {
            replace: true,
            prefixes: vec![
                PrefixEntry {
                    path: "/opt/here".into(),
                    optional: false,
                },
                PrefixEntry {
                    path: "/opt/maybe".into(),
                    optional: true,
                },
            ],
        };
        let out = resolve(&cfg, &home(), |p| {
            p.as_os_str() == std::ffi::OsStr::new("/opt/here")
        })
        .unwrap();
        assert_eq!(out, vec!["/opt/here"]);
    }

    #[test]
    fn malformed_toml_errors() {
        let err = load_str("[ this is not valid toml").unwrap_err();
        matches!(err, ConfigError::Parse(_));
    }
}
