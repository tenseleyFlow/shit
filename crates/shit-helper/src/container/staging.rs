// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded staging for container-runtime content captures.
//!
//! Runtime archive commands (`docker save`, the volume tar sidecar,
//! and their Podman equivalents) write an attacker-controlled amount
//! of data to stdout.  This module drains that stdout through a fixed
//! 64 KiB buffer into a mode-0600 staging file which is unlinked before
//! the child is spawned.  The resulting descriptor is therefore the
//! only name for the bytes: a helper/daemon crash cannot leave a large
//! archive behind in the runtime directory.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const COPY_CHUNK: usize = 64 * 1024;
const STDERR_LIMIT: usize = 32 * 1024;
static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("prepare private container-stash staging: {0}")]
    Staging(std::io::Error),
    #[error("spawn `{program}`: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("read `{program}` stdout: {source}")]
    Read {
        program: String,
        source: std::io::Error,
    },
    #[error("write container-stash staging: {0}")]
    Write(std::io::Error),
    #[error("sync container-stash staging: {0}")]
    Sync(std::io::Error),
    #[error("wait for `{program}`: {source}")]
    Wait {
        program: String,
        source: std::io::Error,
    },
    #[error("`{program}` exited {status}: {stderr}")]
    Exit {
        program: String,
        status: std::process::ExitStatus,
        stderr: String,
    },
    #[error("`{program}` output exceeds the {cap}-byte capture cap")]
    TooLarge { program: String, cap: u64 },
    #[error("staged archive size changed: expected {expected}, observed {observed}")]
    SizeChanged { expected: u64, observed: u64 },
    #[error("staged archive hash changed while being verified")]
    HashChanged,
    #[error("read staged archive: {0}")]
    VerifyRead(std::io::Error),
}

/// An immutable-by-convention, already-unlinked archive descriptor.
///
/// Today the inline ctl path calls [`CapturedArchive::into_inline`].
/// The AR10.8 SCM_RIGHTS path can instead transfer `file` after adding
/// a narrow accessor, without changing capture or verification.
#[derive(Debug)]
pub struct CapturedArchive {
    file: File,
    hash: [u8; 32],
    size: u64,
}

impl CapturedArchive {
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Read a bounded archive back for the existing inline wire path.
    /// Size and hash are re-proved from the descriptor before return.
    pub fn into_inline(mut self, cap: u64) -> Result<Vec<u8>, CaptureError> {
        if self.size > cap {
            return Err(CaptureError::TooLarge {
                program: "container archive".into(),
                cap,
            });
        }
        let observed = self
            .file
            .metadata()
            .map_err(CaptureError::VerifyRead)?
            .len();
        if observed != self.size {
            return Err(CaptureError::SizeChanged {
                expected: self.size,
                observed,
            });
        }

        self.file
            .seek(SeekFrom::Start(0))
            .map_err(CaptureError::VerifyRead)?;
        let capacity = usize::try_from(self.size).map_err(|_| CaptureError::TooLarge {
            program: "container archive".into(),
            cap,
        })?;
        let mut bytes = Vec::with_capacity(capacity);
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; COPY_CHUNK];
        let mut remaining = self.size;
        while remaining != 0 {
            let want = remaining.min(COPY_CHUNK as u64) as usize;
            let n = self
                .file
                .read(&mut buf[..want])
                .map_err(CaptureError::VerifyRead)?;
            if n == 0 {
                return Err(CaptureError::SizeChanged {
                    expected: self.size,
                    observed: self.size - remaining,
                });
            }
            hasher.update(&buf[..n]);
            bytes.extend_from_slice(&buf[..n]);
            remaining -= n as u64;
        }
        let mut extra = [0u8; 1];
        if self
            .file
            .read(&mut extra)
            .map_err(CaptureError::VerifyRead)?
            != 0
        {
            return Err(CaptureError::SizeChanged {
                expected: self.size,
                observed: self.size.saturating_add(1),
            });
        }
        if hasher.finalize().as_bytes() != &self.hash {
            return Err(CaptureError::HashChanged);
        }
        Ok(bytes)
    }
}

pub fn capture_command(
    program: &str,
    args: &[String],
    cap: u64,
) -> Result<CapturedArchive, CaptureError> {
    capture_command_in(program, args, cap, &default_staging_dir())
}

fn default_staging_dir() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime)
            .join("shit")
            .join("container-stash-staging");
    }
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    // SAFETY: getuid has no failure mode.
    let uid = unsafe { libc::getuid() };
    base.join(format!("shit-container-stash-{uid}"))
}

fn capture_command_in(
    program: &str,
    args: &[String],
    cap: u64,
    staging_dir: &Path,
) -> Result<CapturedArchive, CaptureError> {
    let mut staging = create_unlinked_staging(staging_dir)?;
    let mut child = Command::new(program)
        .args(args)
        .env("SHIT_DURING_UNDO", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| CaptureError::Spawn {
            program: program.into(),
            source,
        })?;
    let mut stdout = child.stdout.take().expect("stdout configured as piped");
    let stderr = child.stderr.take().expect("stderr configured as piped");
    let stderr_thread = std::thread::spawn(move || drain_stderr(stderr));

    let mut hasher = blake3::Hasher::new();
    let mut copied = 0u64;
    let mut buf = [0u8; COPY_CHUNK];
    let stream_result = loop {
        // Once exactly `cap` bytes have arrived, read one proof byte.
        // This catches an oversized stream without ever writing more
        // than the configured cap to disk.
        let want = if copied == cap {
            1
        } else {
            (cap - copied).min(COPY_CHUNK as u64) as usize
        };
        let n = match stdout.read(&mut buf[..want]) {
            Ok(n) => n,
            Err(source) => {
                break Err(CaptureError::Read {
                    program: program.into(),
                    source,
                });
            }
        };
        if n == 0 {
            break Ok(());
        }
        if copied == cap || n as u64 > cap - copied {
            break Err(CaptureError::TooLarge {
                program: program.into(),
                cap,
            });
        }
        if let Err(error) = staging.write_all(&buf[..n]) {
            break Err(CaptureError::Write(error));
        }
        hasher.update(&buf[..n]);
        copied += n as u64;
    };
    drop(stdout);

    if stream_result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|source| CaptureError::Wait {
        program: program.into(),
        source,
    });
    let stderr = stderr_thread
        .join()
        .unwrap_or_else(|_| b"stderr drain thread panicked".to_vec());
    stream_result?;
    let status = status?;
    if !status.success() {
        return Err(CaptureError::Exit {
            program: program.into(),
            status,
            stderr: String::from_utf8_lossy(&stderr).trim().to_string(),
        });
    }

    staging.sync_all().map_err(CaptureError::Sync)?;
    let observed = staging.metadata().map_err(CaptureError::VerifyRead)?.len();
    if observed != copied {
        return Err(CaptureError::SizeChanged {
            expected: copied,
            observed,
        });
    }
    staging
        .seek(SeekFrom::Start(0))
        .map_err(CaptureError::VerifyRead)?;
    Ok(CapturedArchive {
        file: staging,
        hash: *hasher.finalize().as_bytes(),
        size: copied,
    })
}

fn drain_stderr(mut stderr: impl Read) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stderr.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = STDERR_LIMIT.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    kept
}

fn create_unlinked_staging(dir: &Path) -> Result<File, CaptureError> {
    ensure_private_dir(dir)?;
    let dir_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .map_err(CaptureError::Staging)?;

    for _ in 0..128 {
        let id = NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let name = format!("{}-{id}.capture", std::process::id());
        let c_name = CString::new(name).expect("generated name contains no NUL");
        // SAFETY: the directory fd and C string are live for the call.
        let raw = unsafe {
            libc::openat(
                dir_file.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if raw < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(CaptureError::Staging(error));
        }
        // SAFETY: openat returned a fresh descriptor owned by us.
        let file = unsafe { File::from_raw_fd(raw) };
        // Unlink through the same pinned directory descriptor so a
        // concurrent path rename cannot redirect cleanup.
        // SAFETY: arguments remain live and valid for unlinkat.
        if unsafe { libc::unlinkat(dir_file.as_raw_fd(), c_name.as_ptr(), 0) } != 0 {
            return Err(CaptureError::Staging(std::io::Error::last_os_error()));
        }
        let metadata = file.metadata().map_err(CaptureError::Staging)?;
        if !metadata.is_file() || metadata.nlink() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(CaptureError::Staging(std::io::Error::other(
                "staging descriptor failed regular/unlinked/private proof",
            )));
        }
        return Ok(file);
    }
    Err(CaptureError::Staging(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique staging name",
    )))
}

fn ensure_private_dir(path: &Path) -> Result<(), CaptureError> {
    fs::create_dir_all(path).map_err(CaptureError::Staging)?;
    let metadata = fs::symlink_metadata(path).map_err(CaptureError::Staging)?;
    // SAFETY: getuid has no failure mode.
    let uid = unsafe { libc::getuid() };
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != uid {
        return Err(CaptureError::Staging(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "staging path is not a caller-owned directory",
        )));
    }
    if metadata.mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(CaptureError::Staging)?;
        let tightened = fs::symlink_metadata(path).map_err(CaptureError::Staging)?;
        if tightened.mode() & 0o077 != 0 {
            return Err(CaptureError::Staging(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "staging directory is accessible by group or other users",
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("fake-runtime");
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn staging_is_unlinked_while_descriptor_remains_readable() {
        let temp = tempfile::tempdir().unwrap();
        let tool = script(temp.path(), "printf 'archive-bytes'");
        let stage = temp.path().join("stage");
        let captured = capture_command_in(tool.to_str().unwrap(), &[], 1024, &stage).unwrap();
        assert_eq!(fs::read_dir(&stage).unwrap().count(), 0);
        assert_eq!(captured.size(), 13);
        assert_eq!(captured.into_inline(1024).unwrap(), b"archive-bytes");
    }

    #[test]
    fn fake_runtime_over_100_mib_is_killed_at_cap() {
        let temp = tempfile::tempdir().unwrap();
        let tool = script(
            temp.path(),
            "dd if=/dev/zero bs=1048576 count=101 2>/dev/null",
        );
        let error = capture_command_in(
            tool.to_str().unwrap(),
            &[],
            1024 * 1024,
            &temp.path().join("stage"),
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::TooLarge { .. }));
    }

    #[test]
    fn nonzero_runtime_status_rejects_complete_stdout() {
        let temp = tempfile::tempdir().unwrap();
        let tool = script(temp.path(), "printf bytes; echo nope >&2; exit 9");
        let error = capture_command_in(
            tool.to_str().unwrap(),
            &[],
            1024,
            &temp.path().join("stage"),
        )
        .unwrap_err();
        assert!(matches!(error, CaptureError::Exit { .. }));
        assert!(error.to_string().contains("nope"));
    }

    #[test]
    fn staging_failure_happens_before_runtime_spawn() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("spawned");
        let tool = script(
            temp.path(),
            &format!("touch '{}'; printf bytes", marker.display()),
        );
        let not_a_dir = temp.path().join("not-a-dir");
        fs::write(&not_a_dir, b"x").unwrap();
        let error = capture_command_in(tool.to_str().unwrap(), &[], 1024, &not_a_dir).unwrap_err();
        assert!(matches!(error, CaptureError::Staging(_)));
        assert!(!marker.exists());
    }

    #[test]
    fn hash_mismatch_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let tool = script(temp.path(), "printf bytes");
        let mut captured = capture_command_in(
            tool.to_str().unwrap(),
            &[],
            1024,
            &temp.path().join("stage"),
        )
        .unwrap();
        captured.hash = [0x55; 32];
        assert!(matches!(
            captured.into_inline(1024),
            Err(CaptureError::HashChanged)
        ));
    }
}
