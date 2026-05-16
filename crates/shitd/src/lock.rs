// SPDX-License-Identifier: AGPL-3.0-or-later

//! Single-instance enforcement via an exclusive `flock(2)` on a lock file.
//!
//! The lock is non-blocking; a second daemon startup observes the lock as held
//! and returns [`LockError::AlreadyHeld`] which the caller translates into a
//! prompt exit with a clear message.
//!
//! The lock file path is in config. The file persists on disk; the lock
//! release is implicit when the daemon process exits (kernel drops the file
//! lock). We do not delete the file on exit — keeping it stable means
//! tooling can stat it without races.

use anyhow::{Context, Result};
use nix::fcntl::{Flock, FlockArg};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("another shitd instance holds {0:?}; refusing to start")]
    AlreadyHeld(std::path::PathBuf),
}

/// Acquired exclusive lock — drop to release.
pub struct DaemonLock {
    _flock: Flock<File>,
}

impl DaemonLock {
    pub fn acquire(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create_dir_all {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        // Owner-only — defense in depth against same-host other-user accidents.
        if let Ok(meta) = file.metadata() {
            let mut perms = meta.permissions();
            if perms.mode() & 0o777 != 0o600 {
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }
        let flock = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, e)| {
            if e == nix::errno::Errno::EWOULDBLOCK {
                anyhow::anyhow!(LockError::AlreadyHeld(path.to_path_buf()))
            } else {
                anyhow::anyhow!("flock {}: {e}", path.display())
            }
        })?;
        Ok(Self { _flock: flock })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_acquire_succeeds_second_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("d.lock");

        let held = DaemonLock::acquire(&path);
        assert!(held.is_ok(), "first acquire should succeed");

        // Second attempt while the first is held must fail with AlreadyHeld.
        let second = DaemonLock::acquire(&path);
        match second {
            Ok(_) => panic!("expected lock contention, got success"),
            Err(e) => {
                let msg = format!("{e}");
                assert!(msg.contains("another shitd instance"), "wrong error: {msg}");
            }
        }
    }

    #[test]
    fn drop_releases_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("d.lock");
        {
            let first = DaemonLock::acquire(&path);
            assert!(first.is_ok());
            // first drops here
        }
        let second = DaemonLock::acquire(&path);
        assert!(second.is_ok(), "should re-acquire after drop");
    }
}
