// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cooperative, cross-process serialization for container-engine mutations.
//!
//! The shell wrappers and daemon use the same private per-uid root and the
//! same atomic hard-link publication protocol. A claim is completely written
//! before `hard_link` publishes it as the canonical lock, so no observer can
//! mistake a half-published owner for a stale lock.
//!
//! A dead owner is deliberately *not* reaped automatically. If a wrapper or
//! daemon is killed with SIGKILL, its Docker child can survive the owner PID;
//! PID death therefore does not prove that mutation has stopped. Leaving the
//! canonical lock in place fails closed until an operator has established
//! engine quiescence and removes it manually.

use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

const ENGINE: &str = "docker-engine";
const MAX_TOKEN_BYTES: u64 = 512;

/// Marker trait for a runner-held engine lock. Dropping the value releases a
/// normally-owned canonical lock after all restore probes/mutations finish.
pub trait ContainerEngineLockGuard {}

/// No-op guard used by injected test runners. Production runners override the
/// trait hook with [`CooperativeContainerLockState::acquire_docker`].
#[derive(Debug)]
pub struct NoopContainerEngineLockGuard;

impl ContainerEngineLockGuard for NoopContainerEngineLockGuard {}

/// Per-runner state that carries the exact lock capability into child
/// wrappers. The local mutex prevents two threads sharing one runner from
/// racing through acquisition.
#[derive(Debug, Default)]
pub struct CooperativeContainerLockState {
    local: Mutex<()>,
    active_token: Mutex<Option<String>>,
    root_override: Option<PathBuf>,
}

impl CooperativeContainerLockState {
    pub fn acquire_docker(&self) -> Result<CooperativeContainerLockGuard<'_>, String> {
        let local = self
            .local
            .lock()
            .map_err(|_| "local container-engine lock is poisoned".to_string())?;
        let uid = effective_uid();
        let root = self
            .root_override
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("/tmp/shit-container-hooks-{uid}")));
        ensure_private_root(&root, uid)?;

        let pid = std::process::id();
        let nonce = format!("rs.{pid}.{}", uuid::Uuid::now_v7());
        let token = format!("{ENGINE}:{pid}:{nonce}");
        let claim = root.join(format!(".{ENGINE}.claim.{nonce}"));
        let canonical = root.join(format!("{ENGINE}.lock"));
        let legacy_reaper = root.join(format!("{ENGINE}.reap"));

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&claim)
            .map_err(|error| format!("create container lock claim {}: {error}", claim.display()))?;
        let publish_claim = (|| -> Result<(), String> {
            file.write_all(token.as_bytes())
                .and_then(|()| file.write_all(b"\n"))
                .map_err(|error| {
                    format!("write container lock claim {}: {error}", claim.display())
                })?;
            file.sync_all()
                .map_err(|error| format!("sync container lock claim {}: {error}", claim.display()))
        })();
        drop(file);
        if let Err(error) = publish_claim {
            let _ = std::fs::remove_file(&claim);
            return Err(error);
        }

        let guard = CooperativeContainerLockGuard {
            state: self,
            _local: local,
            token,
            claim,
            canonical,
            canonical_owned: false,
        };
        guard.acquire(&legacy_reaper)
    }

    pub fn active_token(&self) -> Result<Option<String>, String> {
        self.active_token
            .lock()
            .map(|token| token.clone())
            .map_err(|_| "container-engine lock token is poisoned".to_string())
    }

    #[cfg(test)]
    fn for_test_root(root: PathBuf) -> Self {
        Self {
            local: Mutex::new(()),
            active_token: Mutex::new(None),
            root_override: Some(root),
        }
    }
}

#[derive(Debug)]
pub struct CooperativeContainerLockGuard<'a> {
    state: &'a CooperativeContainerLockState,
    _local: MutexGuard<'a, ()>,
    token: String,
    claim: PathBuf,
    canonical: PathBuf,
    canonical_owned: bool,
}

impl ContainerEngineLockGuard for CooperativeContainerLockGuard<'_> {}

impl CooperativeContainerLockGuard<'_> {
    fn acquire(mut self, legacy_reaper: &Path) -> Result<Self, String> {
        loop {
            if std::fs::symlink_metadata(legacy_reaper).is_ok() {
                return Err(format!(
                    "container engine lock recovery gate {} exists; refusing until engine quiescence is verified and the stale gate is removed",
                    legacy_reaper.display()
                ));
            }

            match std::fs::hard_link(&self.claim, &self.canonical) {
                Ok(()) => {
                    self.canonical_owned = true;
                    *self
                        .state
                        .active_token
                        .lock()
                        .map_err(|_| "container-engine lock token is poisoned".to_string())? =
                        Some(self.token.clone());
                    return Ok(self);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "publish container engine lock {}: {error}",
                        self.canonical.display()
                    ));
                }
            }

            let observed = read_regular_token(&self.canonical)?;
            let owner_pid = parse_owner_pid(&observed).ok_or_else(|| {
                format!(
                    "container engine lock {} has a malformed owner; refusing automatic recovery",
                    self.canonical.display()
                )
            })?;
            if process_is_alive(owner_pid) {
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            return Err(format!(
                "container engine lock {} belongs to dead owner {owner_pid}; a child runtime may still be active, so verify engine quiescence and remove the stale lock manually",
                self.canonical.display()
            ));
        }
    }
}

impl Drop for CooperativeContainerLockGuard<'_> {
    fn drop(&mut self) {
        if self.canonical_owned
            && read_regular_token(&self.canonical).is_ok_and(|observed| observed == self.token)
        {
            let _ = std::fs::remove_file(&self.canonical);
        }
        let _ = std::fs::remove_file(&self.claim);
        if let Ok(mut active) = self.state.active_token.lock()
            && active.as_deref() == Some(self.token.as_str())
        {
            *active = None;
        }
    }
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no failure mode on supported POSIX targets.
    unsafe { libc::geteuid() }
}

fn ensure_private_root(root: &Path, uid: u32) -> Result<(), String> {
    match DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(format!(
                "create container lock root {}: {error}",
                root.display()
            ));
        }
    }
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|error| format!("inspect container lock root {}: {error}", root.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(format!(
            "container lock root {} is not a private 0700 directory owned by uid {uid}",
            root.display()
        ));
    }
    Ok(())
}

fn read_regular_token(path: &Path) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect container engine lock {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_TOKEN_BYTES
    {
        return Err(format!(
            "container engine lock {} is not a bounded regular file",
            path.display()
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("read container engine lock {}: {error}", path.display()))?;
    Ok(text.lines().next().unwrap_or_default().to_string())
}

fn parse_owner_pid(token: &str) -> Option<i32> {
    let mut fields = token.splitn(3, ':');
    if fields.next()? != ENGINE {
        return None;
    }
    let pid = fields.next()?.parse::<i32>().ok()?;
    if pid <= 0 {
        return None;
    }
    if fields.next().is_some_and(str::is_empty) {
        return None;
    }
    Some(pid)
}

fn process_is_alive(pid: i32) -> bool {
    // SAFETY: signal 0 performs only existence/permission checking.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquisition_publishes_complete_token_and_drop_cleans_up() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("locks");
        let state = CooperativeContainerLockState::for_test_root(root.clone());

        let guard = state.acquire_docker().unwrap();
        let token = state.active_token().unwrap().unwrap();
        assert_eq!(
            read_regular_token(&root.join("docker-engine.lock")).unwrap(),
            token
        );
        assert!(token.starts_with(&format!("docker-engine:{}:rs.", std::process::id())));

        drop(guard);
        assert_eq!(state.active_token().unwrap(), None);
        assert!(!root.join("docker-engine.lock").exists());
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
    }

    #[test]
    fn dead_owner_fails_closed_instead_of_reaping_possible_children() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("locks");
        ensure_private_root(&root, effective_uid()).unwrap();
        std::fs::write(
            root.join("docker-engine.lock"),
            "docker-engine:2147483647:dead\n",
        )
        .unwrap();
        let state = CooperativeContainerLockState::for_test_root(root);

        let error = state.acquire_docker().unwrap_err();
        assert!(
            error.contains("child runtime may still be active"),
            "{error}"
        );
    }

    #[test]
    fn malformed_or_symlink_lock_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("locks");
        ensure_private_root(&root, effective_uid()).unwrap();
        std::fs::write(root.join("docker-engine.lock"), "not-an-owner\n").unwrap();
        let state = CooperativeContainerLockState::for_test_root(root);

        let error = state.acquire_docker().unwrap_err();
        assert!(error.contains("malformed owner"), "{error}");
    }
}
