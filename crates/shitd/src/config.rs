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
}

/// Fully-resolved config — what the daemon actually runs on. Some fields are
/// only consumed by later S02 sub-steps; the `expect` annotations get removed
/// as each step lands.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    #[allow(dead_code, reason = "consumed by S02.3 idle-down timer")]
    pub idle_timeout_secs: u64,
    pub hook_socket_path: PathBuf,
    #[allow(dead_code, reason = "consumed by S02.4 ctl-socket listener")]
    pub ctl_socket_path: PathBuf,
    pub lock_path: PathBuf,
    pub state_dir: PathBuf,
    pub log_level: String,
    pub disable: bool,
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
}
