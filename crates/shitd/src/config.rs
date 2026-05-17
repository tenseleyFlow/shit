// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const DEFAULT_IDLE_SECS: u64 = 1800;
const DEFAULT_LOG_LEVEL: &str = "info";

/// On-disk config schema. Every field is optional; defaults fill in via
/// [`Config::resolve`].
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub hook_socket_path: Option<PathBuf>,
    #[serde(default)]
    pub ctl_socket_path: Option<PathBuf>,
    #[serde(default)]
    pub lock_path: Option<PathBuf>,
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub disable: bool,
    /// S15: env tracking. The `[env]` table in `config.toml`.
    #[serde(default)]
    pub env: EnvConfig,
    /// S21.6: OTLP export. The `[telemetry]` table in `config.toml`.
    /// Inert unless the daemon is built with `--features otel`.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

/// S21.6 OTLP export config.
///
/// Off by default. When `otlp_endpoint` is set AND the daemon is
/// built with the `otel` feature, spans are exported to that
/// collector. Without the feature, the config field is parsed but
/// ignored — set strictly so a missing build feature surfaces as
/// a startup warning rather than a silent drop.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct TelemetryConfig {
    /// gRPC endpoint of an OTLP collector (e.g. `http://127.0.0.1:4317`).
    /// `None` disables the exporter entirely. No default — operator
    /// must opt in by setting the endpoint.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// `service.name` resource attribute on exported spans. Defaults
    /// to `"shitd"`.
    #[serde(default)]
    pub service_name: Option<String>,
}

/// S15 env-tracking knobs. Defaults match `shit_planner::env::EnvFilter::default()`.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct EnvConfig {
    /// Additional variable names to ignore on top of the built-in
    /// noise list. Merged with the defaults; user names extend, not
    /// replace.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Additional prefixes to ignore (e.g. `STARSHIP_` is already in
    /// the default list).
    #[serde(default)]
    pub ignore_prefixes: Vec<String>,
    /// Override the redaction substrings entirely. When `None`, the
    /// built-in default list is used. Set to `[]` to disable
    /// redaction (NOT recommended).
    #[serde(default)]
    pub redact_substrings: Option<Vec<String>>,
    /// When true, the ignore lists are bypassed. Redaction still
    /// applies — turning it off requires `redact_substrings = []`
    /// explicitly.
    #[serde(default)]
    pub track_all: bool,
}

impl EnvConfig {
    /// Materialise an `EnvFilter` that the daemon and renderer can
    /// consume. Folds user-provided lists into the defaults; user
    /// `ignore` / `ignore_prefixes` extend the built-ins,
    /// `redact_substrings` replaces them if set.
    pub fn filter(&self) -> shit_planner::EnvFilter {
        let mut f = shit_planner::EnvFilter::default();
        for n in &self.ignore {
            if !f.ignore.iter().any(|e| e == n) {
                f.ignore.push(n.clone());
            }
        }
        for p in &self.ignore_prefixes {
            if !f.ignore_prefixes.iter().any(|e| e == p) {
                f.ignore_prefixes.push(p.clone());
            }
        }
        if let Some(rs) = &self.redact_substrings {
            f.redact_substrings = rs.clone();
        }
        f.track_all = self.track_all;
        f
    }
}

/// Fully-resolved config — what the daemon actually runs on.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub idle_timeout_secs: u64,
    pub hook_socket_path: PathBuf,
    pub ctl_socket_path: PathBuf,
    pub lock_path: PathBuf,
    pub state_dir: PathBuf,
    pub log_level: String,
    pub disable: bool,
    pub env: EnvConfig,
    pub telemetry: ResolvedTelemetryConfig,
}

#[derive(Debug, Clone)]
pub struct ResolvedTelemetryConfig {
    pub otlp_endpoint: Option<String>,
    pub service_name: String,
}

impl Config {
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let path = match explicit {
            Some(p) => p.to_path_buf(),
            None => default_config_path()?,
        };
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                toml::from_str::<Self>(&s).with_context(|| format!("parse {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn resolve(self) -> Result<ResolvedConfig> {
        let state = self.state_dir.map(Ok).unwrap_or_else(default_state_dir)?;
        Ok(ResolvedConfig {
            idle_timeout_secs: self.idle_timeout_secs.unwrap_or(DEFAULT_IDLE_SECS),
            hook_socket_path: self
                .hook_socket_path
                .unwrap_or_else(default_hook_socket_path),
            ctl_socket_path: self.ctl_socket_path.unwrap_or_else(default_ctl_socket_path),
            lock_path: self.lock_path.unwrap_or_else(|| state.join("daemon.lock")),
            state_dir: state,
            log_level: self
                .log_level
                .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string()),
            disable: self.disable,
            env: self.env,
            telemetry: ResolvedTelemetryConfig {
                otlp_endpoint: self.telemetry.otlp_endpoint,
                service_name: self
                    .telemetry
                    .service_name
                    .unwrap_or_else(|| "shitd".to_string()),
            },
        })
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    Ok(config_home()?.join("shit").join("config.toml"))
}

pub fn config_home() -> Result<PathBuf> {
    if let Some(s) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(s));
    }
    Ok(home_dir()?.join(".config"))
}

pub fn state_home() -> Result<PathBuf> {
    if let Some(s) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(s));
    }
    Ok(home_dir()?.join(".local").join("state"))
}

pub fn default_state_dir() -> Result<PathBuf> {
    Ok(state_home()?.join("shit"))
}

pub fn runtime_dir() -> PathBuf {
    if let Some(s) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(s);
    }
    std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

pub fn default_hook_socket_path() -> PathBuf {
    let rt = runtime_dir();
    if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
        rt.join("shit.sock")
    } else {
        // SAFETY: getuid always succeeds.
        let uid = unsafe { libc::getuid() };
        rt.join(format!("shit-{uid}.sock"))
    }
}

pub fn default_ctl_socket_path() -> PathBuf {
    let rt = runtime_dir();
    if std::env::var_os("XDG_RUNTIME_DIR").is_some() {
        rt.join("shit-ctl.sock")
    } else {
        let uid = unsafe { libc::getuid() };
        rt.join(format!("shit-ctl-{uid}.sock"))
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("$HOME not set"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_resolves_with_finite_values() {
        let r = Config::default().resolve().unwrap();
        assert_eq!(r.idle_timeout_secs, DEFAULT_IDLE_SECS);
        assert_eq!(r.log_level, DEFAULT_LOG_LEVEL);
        assert!(r.hook_socket_path.is_absolute());
        assert!(r.ctl_socket_path.is_absolute());
        assert!(r.lock_path.is_absolute());
        assert!(r.state_dir.is_absolute());
    }

    #[test]
    fn explicit_fields_win() {
        let toml = r#"
            idle_timeout_secs = 30
            log_level = "debug"
            disable = true
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let r = cfg.resolve().unwrap();
        assert_eq!(r.idle_timeout_secs, 30);
        assert_eq!(r.log_level, "debug");
        assert!(r.disable);
    }

    #[test]
    fn lock_path_defaults_under_state_dir() {
        let r = Config::default().resolve().unwrap();
        assert!(r.lock_path.starts_with(&r.state_dir));
        assert_eq!(r.lock_path.file_name().unwrap(), "daemon.lock");
    }

    #[test]
    fn env_config_defaults_empty_extensions() {
        let r = Config::default().resolve().unwrap();
        assert!(r.env.ignore.is_empty());
        assert!(r.env.ignore_prefixes.is_empty());
        assert!(r.env.redact_substrings.is_none());
        assert!(!r.env.track_all);
    }

    #[test]
    fn env_config_extends_defaults() {
        let toml = r#"
            [env]
            ignore = ["MY_LOCAL_NOISE"]
            ignore_prefixes = ["VCPKG_"]
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let r = cfg.resolve().unwrap();
        let f = r.env.filter();
        assert!(f.ignore.iter().any(|n| n == "MY_LOCAL_NOISE"));
        assert!(f.ignore.iter().any(|n| n == "OLDPWD"), "default kept");
        assert!(f.ignore_prefixes.iter().any(|n| n == "VCPKG_"));
        assert!(
            f.ignore_prefixes.iter().any(|n| n == "STARSHIP_"),
            "default prefix kept"
        );
    }

    #[test]
    fn env_config_redact_replaces_defaults_when_set() {
        let toml = r#"
            [env]
            redact_substrings = ["CREDENTIAL"]
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let f = cfg.resolve().unwrap().env.filter();
        assert!(f.is_redacted("MY_CREDENTIAL"));
        // Default `TOKEN` no longer in the list because user replaced.
        assert!(!f.is_redacted("GITHUB_TOKEN"));
    }

    #[test]
    fn telemetry_defaults_to_disabled() {
        let r = Config::default().resolve().unwrap();
        assert!(r.telemetry.otlp_endpoint.is_none());
        assert_eq!(r.telemetry.service_name, "shitd");
    }

    #[test]
    fn telemetry_endpoint_and_service_name_roundtrip() {
        let toml = r#"
            [telemetry]
            otlp_endpoint = "http://127.0.0.1:4317"
            service_name = "shitd-staging"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let r = cfg.resolve().unwrap();
        assert_eq!(
            r.telemetry.otlp_endpoint.as_deref(),
            Some("http://127.0.0.1:4317")
        );
        assert_eq!(r.telemetry.service_name, "shitd-staging");
    }

    #[test]
    fn telemetry_service_name_defaults_when_endpoint_set_alone() {
        let toml = r#"
            [telemetry]
            otlp_endpoint = "http://collector.internal:4317"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let r = cfg.resolve().unwrap();
        assert!(r.telemetry.otlp_endpoint.is_some());
        assert_eq!(r.telemetry.service_name, "shitd");
    }

    #[test]
    fn env_config_track_all_propagates() {
        let toml = r#"
            [env]
            track_all = true
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let f = cfg.resolve().unwrap().env.filter();
        assert!(!f.is_ignored("OLDPWD"));
    }
}
