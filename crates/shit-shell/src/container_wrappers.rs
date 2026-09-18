// SPDX-License-Identifier: AGPL-3.0-or-later

//! Embedded container wrappers and atomic upgrade repair.
//!
//! Wrapper safety is part of the binary/wrapper protocol. A package upgrade
//! must therefore refresh an already-installed copy before an older,
//! fail-open script can shadow the newly installed runtime binaries.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::InstallError;

pub const DOCKER_WRAPPER: &str = include_str!("../../../packaging/container-hooks/docker-wrapper");
pub const PODMAN_WRAPPER: &str = include_str!("../../../packaging/container-hooks/podman-wrapper");
pub const DOCKER_COMPOSE_WRAPPER: &str =
    include_str!("../../../packaging/container-hooks/docker-compose-wrapper");

pub const CONTAINER_WRAPPERS: &[(&str, &str)] = &[
    ("docker", DOCKER_WRAPPER),
    ("podman", PODMAN_WRAPPER),
    ("docker-compose", DOCKER_COMPOSE_WRAPPER),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapperState {
    Absent,
    Current,
    Stale,
}

pub fn wrapper_state(path: &Path, body: &str) -> Result<WrapperState, InstallError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(WrapperState::Absent),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o755 {
        return Ok(WrapperState::Stale);
    }
    Ok(if std::fs::read(path)? == body.as_bytes() {
        WrapperState::Current
    } else {
        WrapperState::Stale
    })
}

static INSTALL_NONCE: AtomicU64 = AtomicU64::new(0);

/// Publish a fully written wrapper with a same-directory atomic rename.
pub fn install_wrapper_at(path: &Path, body: &str) -> Result<(), InstallError> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "wrapper path has no parent")
    })?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "wrapper path has no file name")
    })?;
    let mut claimed = None;
    for _ in 0..1024 {
        let nonce = INSTALL_NONCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.install-{}-{nonce}.tmp",
            name.to_string_lossy(),
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(temp) => {
                claimed = Some((temp, candidate));
                break;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (mut temp, temp_path) = claimed.ok_or_else(|| {
        std::io::Error::new(
            ErrorKind::AlreadyExists,
            "could not allocate a unique wrapper installation file",
        )
    })?;

    let publish = (|| -> Result<(), std::io::Error> {
        temp.write_all(body.as_bytes())?;
        temp.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        temp.sync_all()?;
        drop(temp);
        std::fs::rename(&temp_path, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if publish.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    publish.map_err(InstallError::from)
}

/// Atomically refresh only wrapper paths that already exist. Absence means the
/// user never opted into container hooks and is preserved. The CLI and daemon
/// both call this so normal binary/service upgrades repair stale copies before
/// an interactive command can reach them.
pub fn refresh_existing(config_home: &Path) -> Result<Vec<PathBuf>, InstallError> {
    let bin_dir = config_home.join("shit").join("bin");
    if !bin_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut refreshed = Vec::new();
    for (name, body) in CONTAINER_WRAPPERS {
        let path = bin_dir.join(name);
        if wrapper_state(&path, body)? == WrapperState::Stale {
            install_wrapper_at(&path, body)?;
            refreshed.push(path);
        }
    }
    Ok(refreshed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_repairs_existing_stale_wrapper_but_preserves_opt_in() {
        let directory = tempfile::tempdir().unwrap();
        let bin = directory.path().join("shit/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let docker = bin.join("docker");
        std::fs::write(&docker, "#!/bin/sh\n# old fail-open wrapper\n").unwrap();
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();

        let refreshed = refresh_existing(directory.path()).unwrap();
        assert_eq!(refreshed, vec![docker.clone()]);
        assert_eq!(
            wrapper_state(&docker, DOCKER_WRAPPER).unwrap(),
            WrapperState::Current
        );
        assert_eq!(
            wrapper_state(&bin.join("podman"), PODMAN_WRAPPER).unwrap(),
            WrapperState::Absent,
            "upgrade repair must not install wrappers the user never enabled"
        );
    }

    #[test]
    fn atomic_install_leaves_no_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("docker");
        install_wrapper_at(&path, DOCKER_WRAPPER).unwrap();
        assert_eq!(
            wrapper_state(&path, DOCKER_WRAPPER).unwrap(),
            WrapperState::Current
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn atomic_install_skips_a_stale_temporary_name() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("docker");
        let nonce = INSTALL_NONCE.load(Ordering::Relaxed);
        let stale = directory.path().join(format!(
            ".docker.install-{}-{nonce}.tmp",
            std::process::id()
        ));
        std::fs::write(&stale, "stale partial wrapper").unwrap();

        install_wrapper_at(&path, DOCKER_WRAPPER).unwrap();

        assert_eq!(
            wrapper_state(&path, DOCKER_WRAPPER).unwrap(),
            WrapperState::Current
        );
        assert_eq!(
            std::fs::read_to_string(stale).unwrap(),
            "stale partial wrapper"
        );
    }
}
