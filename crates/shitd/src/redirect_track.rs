// SPDX-License-Identifier: AGPL-3.0-or-later

//! AR06.5 — synchronous pre-stash handler for shell stream redirects.
//!
//! The shell hook parses `cmd > file` / `tee file` / `dd of=file` via
//! [`shit_shell::redirect::parse_redirects`] BEFORE the shell performs
//! `open(O_TRUNC)`, and ships each destination as a
//! [`shit_proto::RedirectTargetWire`] inside a
//! [`shit_proto::CtlRequest::PreStashRedirects`]. We hash + stash the
//! file's bytes here, journal one
//! [`CaptureEventKind::FilePreImage`] per target keyed to the open
//! command window, then ack so the shell unblocks and lets the redirect
//! through. The planner picks up the `FilePreImage` event on undo and
//! emits `InverseOp::RestoreContent`, restoring the bytes that the
//! shell's truncation was about to discard.
//!
//! ## Append vs Truncate
//!
//! Truncate-class operators (`>`, `>|`, `2>`, `&>`, `tee` without
//! `-a`, `dd of=`) journal a [`CaptureEventKind::FilePreImage`] with
//! the file's full pre-content blob; inverse is `RestoreContent` via
//! tmpfile-rename.
//!
//! Append-class operators (`>>`, `tee -a`, `&>>`) journal a
//! [`CaptureEventKind::FileAppendPreStash`] with only the file's
//! pre-size (no blob — the bytes that need restoring are still on
//! disk in `[0..pre_size]`); inverse is `FileExtend { truncate_to:
//! pre_size }` via `ftruncate(2)`. AU27 / DR-CR-55 closed this.

use crate::active_commands::ActiveCommands;
use shit_planner::CommandId;
use shit_planner::events::{CaptureEvent, CaptureEventKind, EventId};
use shit_planner::inode::InodeRef;
use shit_planner::metadata::FileMetadata;
use shit_proto::{
    CtlResponse, PreStashRedirectError, PreStashRedirectsResult, RedirectOpWire, RedirectTargetWire,
};
use shit_store::{BlobStore, Index};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use tracing::debug;
use uuid::Uuid;

/// Redirect capture runs synchronously in the shell's preexec path. Bound both
/// fan-out and bytes so one command cannot stall the prompt indefinitely or
/// construct an unbounded ACK/error frame.
const MAX_REDIRECT_TARGETS: usize = 16;
const MAX_REDIRECT_PATH_BYTES: usize = 4096;
const MAX_REDIRECT_BYTES_PER_TARGET: u64 = 16 * 1024 * 1024;
const MAX_REDIRECT_BYTES_TOTAL: u64 = 32 * 1024 * 1024;
const MAX_REDIRECT_ERROR_PATH_BYTES: usize = 512;
const MAX_REDIRECT_ERROR_REASON_BYTES: usize = 512;

/// Handle a `CtlRequest::PreStashRedirects`. Returns the wire response.
///
/// The handler is best-effort per target: a failure on one target is returned
/// in `errors` and the next target is still attempted, but only after a
/// command-scoped `CaptureRefused` makes the missed pre-image durable. That
/// refusal is required because post-hoc tiers (notably stock macOS FSEvents)
/// cannot recover bytes already destroyed by `O_TRUNC`. If even the refusal
/// cannot be journaled, a sticky finalization block is retained and the
/// request returns a top-level error rather than publishing false completeness.
pub fn handle(
    session: Uuid,
    command_seq: u64,
    targets: Vec<RedirectTargetWire>,
    active: &ActiveCommands,
    index: &Index,
    blob_store: &BlobStore,
    finalization_blocks: &crate::server::FinalizationBlocks,
) -> CtlResponse {
    let command = CommandId {
        session,
        seq: command_seq,
    };
    // We do NOT consult `active` for the lookup -- the shell hook
    // tells us the command directly. We DO use it as an attribution
    // sanity check (orphan PreStashRedirects with no matching active
    // command means the shell sent us this after PostExec; we
    // accept the journal but emit a debug breadcrumb).
    if active.tracked_shell_count() == 0 {
        debug!(
            session = %session,
            command_seq,
            "PreStashRedirects with no active commands; journaling anyway"
        );
    }

    let mut stashed: u32 = 0;
    let mut errors: Vec<PreStashRedirectError> = Vec::new();
    let mut aggregate_bytes = 0_u64;

    if targets.len() > MAX_REDIRECT_TARGETS {
        let target = &targets[MAX_REDIRECT_TARGETS];
        let reason = format!(
            "too many redirect targets ({} > {MAX_REDIRECT_TARGETS})",
            targets.len()
        );
        if let Err(refusal_error) =
            persist_refusal(command, &target.path, &reason, index, finalization_blocks)
        {
            return CtlResponse::Error(refusal_error);
        }
        errors.push(bounded_wire_error(&target.path, &reason));
        return CtlResponse::PreStashRedirectsAck(PreStashRedirectsResult { stashed, errors });
    }

    for target in targets {
        let result = if target.path.len() > MAX_REDIRECT_PATH_BYTES {
            Err(format!(
                "redirect path exceeds {MAX_REDIRECT_PATH_BYTES}-byte safety limit"
            ))
        } else {
            stash_one(&target, command, index, blob_store, &mut aggregate_bytes)
        };
        match result {
            Ok(StashOutcome::Stashed) => stashed += 1,
            Err(reason) => {
                errors.push(bounded_wire_error(&target.path, &reason));
                if let Err(refusal_error) =
                    persist_refusal(command, &target.path, &reason, index, finalization_blocks)
                {
                    return CtlResponse::Error(refusal_error);
                }
            }
        }
    }
    CtlResponse::PreStashRedirectsAck(PreStashRedirectsResult { stashed, errors })
}

enum StashOutcome {
    Stashed,
}

fn persist_refusal(
    command: CommandId,
    path: &str,
    reason: &str,
    index: &Index,
    finalization_blocks: &crate::server::FinalizationBlocks,
) -> Result<(), String> {
    let detail = format!(
        "redirect target {path} could not be pre-stashed before command execution: {reason}"
    );
    // Install the close gate before attempting the fallback write. Clear only
    // this producer's token after the refusal is durable; another producer may
    // independently be preventing finalization for the same command.
    let block_token = finalization_blocks.insert(command, detail.clone());
    let refusal = CaptureEvent {
        id: EventId(0),
        command,
        ts: crate::server::next_ts(),
        partial: false,
        kind: CaptureEventKind::CaptureRefused {
            class: "redirect-prestash-failed".to_string(),
            path: PathBuf::from(path),
            detail: detail.clone(),
        },
    };
    match index.put_event(&refusal) {
        Ok(_) => {
            finalization_blocks.clear_token(command, block_token);
            Ok(())
        }
        Err(error) => {
            tracing::error!(
                %command,
                path,
                error = %error,
                "redirect pre-stash refusal was not durable; command close remains blocked"
            );
            Err(format!(
                "{detail}; durable CaptureRefused also failed: {error}"
            ))
        }
    }
}

fn bounded_wire_error(path: &str, reason: &str) -> PreStashRedirectError {
    PreStashRedirectError {
        path: truncate_utf8(path, MAX_REDIRECT_ERROR_PATH_BYTES),
        reason: truncate_utf8(reason, MAX_REDIRECT_ERROR_REASON_BYTES),
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

fn stash_one(
    target: &RedirectTargetWire,
    command: CommandId,
    index: &Index,
    blob_store: &BlobStore,
    aggregate_bytes: &mut u64,
) -> Result<StashOutcome, String> {
    match target.op {
        RedirectOpWire::Truncate | RedirectOpWire::TeeTruncate | RedirectOpWire::DdOf => {
            stash_truncate(
                target.path.as_str(),
                command,
                index,
                blob_store,
                aggregate_bytes,
            )
        }
        RedirectOpWire::Append | RedirectOpWire::TeeAppend => {
            // AU27 — Append/TeeAppend capture journals only the
            // pre-size (no blob); inverse is FileExtend which
            // truncates the file back at undo time. The bytes that
            // need restoring are still on disk in [0..pre_size]; the
            // appended bytes [pre_size..] get discarded by the
            // truncate.
            stash_append(target.path.as_str(), command, index)
        }
    }
}

fn stash_append(path_str: &str, command: CommandId, index: &Index) -> Result<StashOutcome, String> {
    let path = Path::new(path_str);
    let (file, meta) = open_regular_nofollow(path)?;
    verify_unchanged(path, &file, &meta)?;
    let ts = crate::server::next_ts();
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::FileAppendPreStash {
            inode: InodeRef::new(meta.dev(), meta.ino()),
            path: PathBuf::from(path),
            pre_size: meta.size(),
        },
    };
    index
        .put_event(&event)
        .map_err(|e| format!("put_event: {e}"))?;
    debug!(
        path = %path.display(),
        pre_size = meta.size(),
        session = %command.session,
        seq = command.seq,
        "append pre-stashed"
    );
    Ok(StashOutcome::Stashed)
}

fn stash_truncate(
    path_str: &str,
    command: CommandId,
    index: &Index,
    blob_store: &BlobStore,
    aggregate_bytes: &mut u64,
) -> Result<StashOutcome, String> {
    let path = Path::new(path_str);
    let (mut file, meta) = open_regular_nofollow(path)?;
    let xattrs = read_redirect_xattrs(file.as_raw_fd())
        .map_err(|error| format!("capture descriptor xattrs: {error}"))?;
    let flags = metadata_flags(&meta);
    if meta.size() > MAX_REDIRECT_BYTES_PER_TARGET {
        return Err(format!(
            "target is {} bytes, above the {MAX_REDIRECT_BYTES_PER_TARGET}-byte per-target limit",
            meta.size()
        ));
    }
    let next_total = aggregate_bytes
        .checked_add(meta.size())
        .ok_or_else(|| "redirect aggregate byte count overflow".to_string())?;
    if next_total > MAX_REDIRECT_BYTES_TOTAL {
        return Err(format!(
            "redirect pre-stash would exceed the {MAX_REDIRECT_BYTES_TOTAL}-byte aggregate limit"
        ));
    }
    // Reserve before I/O: a failed/racing target must not let later targets
    // repeatedly consume more synchronous work than the aggregate budget.
    *aggregate_bytes = next_total;
    let publication = blob_store.shared_guard();
    let (blob_hash, stat) = publication
        .put_stream_exact(&mut file, meta.size(), MAX_REDIRECT_BYTES_PER_TARGET)
        .map_err(|e| format!("blob stream: {e}"))?;
    verify_unchanged(path, &file, &meta)?;
    let ts = crate::server::next_ts();
    index
        .put_blob_record(blob_hash, stat.stored_bytes, stat.compressed, ts)
        .map_err(|e| format!("put_blob_record: {e}"))?;
    let event = CaptureEvent {
        id: EventId(0),
        command,
        ts,
        partial: false,
        kind: CaptureEventKind::FilePreImage {
            inode: InodeRef::new(meta.dev(), meta.ino()),
            path: PathBuf::from(path),
            blob: blob_hash,
            meta: FileMetadata {
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                size: meta.size(),
                mtime_unix_nanos: mtime_unix_nanos(&meta),
                xattrs,
                acl: None,
                flags,
            },
            // post_content_hash is None — we run pre-syscall and don't
            // see what bytes the about-to-run command will write.
            // Matches the shim's pre-image journaling.
            post_content_hash: None,
            // AR06.5 shell pre-stash: bytes captured at PreExec time,
            // before the user's command ran. Same guarantee as
            // W02.B's LiveBaseline promote.
            source: shit_planner::FilePreImageSource::BaselineCachePromote,
        },
    };
    index
        .put_event(&event)
        .map_err(|e| format!("put_event: {e}"))?;
    drop(publication);
    debug!(
        path = %path.display(),
        size = meta.size(),
        session = %command.session,
        seq = command.seq,
        "redirect pre-stashed"
    );
    Ok(StashOutcome::Stashed)
}

fn open_regular_nofollow(path: &Path) -> Result<(File, std::fs::Metadata), String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "target is absent; redirect creation has no synchronously fenced inverse"
                    .to_string()
            } else {
                format!("open no-follow: {error}")
            }
        })?;
    let meta = file.metadata().map_err(|error| format!("fstat: {error}"))?;
    if !meta.file_type().is_file() {
        return Err(format!("not a regular file ({:?})", meta.file_type()));
    }
    Ok((file, meta))
}

fn verify_unchanged(path: &Path, file: &File, before: &std::fs::Metadata) -> Result<(), String> {
    let after = file
        .metadata()
        .map_err(|error| format!("post-read fstat: {error}"))?;
    if !same_snapshot(before, &after) {
        return Err("target changed while its redirect pre-image was being captured".to_string());
    }
    let bound =
        std::fs::symlink_metadata(path).map_err(|error| format!("post-read path stat: {error}"))?;
    if bound.file_type().is_symlink() || bound.dev() != before.dev() || bound.ino() != before.ino()
    {
        return Err(
            "target path was replaced while its redirect pre-image was captured".to_string(),
        );
    }
    Ok(())
}

fn same_snapshot(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.size() == right.size()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn mtime_unix_nanos(meta: &std::fs::Metadata) -> i128 {
    let secs = meta.mtime() as i128;
    let nanos = meta.mtime_nsec() as i128;
    secs * 1_000_000_000 + nanos
}

#[cfg(target_os = "macos")]
fn metadata_flags(meta: &std::fs::Metadata) -> u32 {
    std::os::macos::fs::MetadataExt::st_flags(meta)
}

#[cfg(target_os = "freebsd")]
fn metadata_flags(meta: &std::fs::Metadata) -> u32 {
    std::os::freebsd::fs::MetadataExt::st_flags(meta)
}

#[cfg(target_os = "netbsd")]
fn metadata_flags(meta: &std::fs::Metadata) -> u32 {
    std::os::netbsd::fs::MetadataExt::st_flags(meta)
}

#[cfg(target_os = "openbsd")]
fn metadata_flags(meta: &std::fs::Metadata) -> u32 {
    std::os::openbsd::fs::MetadataExt::st_flags(meta)
}

#[cfg(target_os = "dragonfly")]
fn metadata_flags(meta: &std::fs::Metadata) -> u32 {
    std::os::dragonfly::fs::MetadataExt::st_flags(meta)
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn metadata_flags(_meta: &std::fs::Metadata) -> u32 {
    0
}

const REDIRECT_XATTR_CAPTURE_CAP: usize = 8 * 1024 * 1024;

#[cfg(target_os = "freebsd")]
fn read_redirect_xattrs(fd: libc::c_int) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    let namespace = libc::EXTATTR_NAMESPACE_USER;
    // SAFETY: NULL/0 is the documented size-query form and `fd` is live.
    let list_size = unsafe { libc::extattr_list_fd(fd, namespace, std::ptr::null_mut(), 0) };
    let list_size = checked_xattr_size(list_size, "xattr name list")?;
    if list_size == 0 {
        return Ok(BTreeMap::new());
    }
    let mut names = vec![0_u8; list_size];
    // SAFETY: `names` owns `list_size` writable bytes and `fd` is live.
    let got =
        unsafe { libc::extattr_list_fd(fd, namespace, names.as_mut_ptr().cast(), names.len()) };
    require_xattr_size(got, list_size, "xattr name list")?;

    let mut result = BTreeMap::new();
    let mut total = list_size;
    let mut cursor = 0;
    while cursor < names.len() {
        let name_len = names[cursor] as usize;
        cursor += 1;
        let end = cursor.checked_add(name_len).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr name length overflow",
            )
        })?;
        if end > names.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed FreeBSD xattr name list",
            ));
        }
        let name = std::str::from_utf8(&names[cursor..end]).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "xattr name is not UTF-8")
        })?;
        cursor = end;
        let c_name = CString::new(name)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        // SAFETY: cname is NUL-terminated; NULL/0 queries the value size.
        let value_size = unsafe {
            libc::extattr_get_fd(fd, namespace, c_name.as_ptr(), std::ptr::null_mut(), 0)
        };
        let value_size = checked_xattr_size(value_size, "xattr value")?;
        total = checked_xattr_total(total, value_size)?;
        let mut value = vec![0_u8; value_size];
        // SAFETY: value owns `value_size` writable bytes.
        let read = unsafe {
            libc::extattr_get_fd(
                fd,
                namespace,
                c_name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        require_xattr_size(read, value_size, "xattr value")?;
        result.insert(name.to_string(), value);
    }
    Ok(result)
}

#[cfg(target_os = "macos")]
fn read_redirect_xattrs(fd: libc::c_int) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    unsafe extern "C" {
        fn flistxattr(
            fd: libc::c_int,
            namebuf: *mut libc::c_char,
            size: libc::size_t,
            options: libc::c_int,
        ) -> libc::ssize_t;
        fn fgetxattr(
            fd: libc::c_int,
            name: *const libc::c_char,
            value: *mut libc::c_void,
            size: libc::size_t,
            position: u32,
            options: libc::c_int,
        ) -> libc::ssize_t;
    }

    // SAFETY: NULL/0 is the documented size-query form and `fd` is live.
    let list_size = unsafe { flistxattr(fd, std::ptr::null_mut(), 0, 0) };
    let list_size = checked_xattr_size(list_size, "xattr name list")?;
    if list_size == 0 {
        return Ok(BTreeMap::new());
    }
    let mut names = vec![0_u8; list_size];
    // SAFETY: `names` owns `list_size` writable bytes.
    let got = unsafe { flistxattr(fd, names.as_mut_ptr().cast(), names.len(), 0) };
    require_xattr_size(got, list_size, "xattr name list")?;
    read_nul_xattrs(
        &names,
        |_| true,
        |c_name| {
            // SAFETY: cname is NUL-terminated; NULL/0 queries the value size.
            let value_size =
                unsafe { fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
            let value_size = checked_xattr_size(value_size, "xattr value")?;
            let mut value = vec![0_u8; value_size];
            // SAFETY: value owns `value_size` writable bytes.
            let read = unsafe {
                fgetxattr(
                    fd,
                    c_name.as_ptr(),
                    value.as_mut_ptr().cast(),
                    value.len(),
                    0,
                    0,
                )
            };
            require_xattr_size(read, value_size, "xattr value")?;
            Ok(value)
        },
    )
}

#[cfg(target_os = "linux")]
fn read_redirect_xattrs(fd: libc::c_int) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    // SAFETY: NULL/0 is the documented size-query form and `fd` is live.
    let list_size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
    let list_size = checked_xattr_size(list_size, "xattr name list")?;
    if list_size == 0 {
        return Ok(BTreeMap::new());
    }
    let mut names = vec![0_u8; list_size];
    // SAFETY: `names` owns `list_size` writable bytes.
    let got = unsafe { libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len()) };
    require_xattr_size(got, list_size, "xattr name list")?;
    let all = read_nul_xattrs(
        &names,
        |name| name.starts_with("user."),
        |c_name| {
            // SAFETY: cname is NUL-terminated; NULL/0 queries the value size.
            let value_size =
                unsafe { libc::fgetxattr(fd, c_name.as_ptr(), std::ptr::null_mut(), 0) };
            let value_size = checked_xattr_size(value_size, "xattr value")?;
            let mut value = vec![0_u8; value_size];
            // SAFETY: value owns `value_size` writable bytes.
            let read = unsafe {
                libc::fgetxattr(fd, c_name.as_ptr(), value.as_mut_ptr().cast(), value.len())
            };
            require_xattr_size(read, value_size, "xattr value")?;
            Ok(value)
        },
    )?;
    Ok(all
        .into_iter()
        .filter_map(|(name, value)| {
            name.strip_prefix("user.")
                .map(|name| (name.to_string(), value))
        })
        .collect())
}

#[cfg(not(any(target_os = "freebsd", target_os = "macos", target_os = "linux")))]
fn read_redirect_xattrs(_fd: libc::c_int) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "descriptor xattr capture is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_nul_xattrs(
    names: &[u8],
    mut include: impl FnMut(&str) -> bool,
    mut read_value: impl FnMut(&CString) -> std::io::Result<Vec<u8>>,
) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    let mut result = BTreeMap::new();
    let mut total = names.len();
    for raw_name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = std::str::from_utf8(raw_name).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "xattr name is not UTF-8")
        })?;
        // Linux may list privileged namespaces (security.*, system.*,
        // trusted.*) that an unprivileged process cannot read. Filter the
        // name before constructing a value query so an irrelevant EACCES
        // cannot turn an otherwise complete user.* snapshot into a refusal.
        if !include(name) {
            continue;
        }
        let c_name = CString::new(name)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let value = read_value(&c_name)?;
        total = checked_xattr_total(total, value.len())?;
        result.insert(name.to_string(), value);
    }
    Ok(result)
}

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "linux"))]
fn checked_xattr_size(size: libc::ssize_t, what: &str) -> std::io::Result<usize> {
    if size < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let size = usize::try_from(size).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} does not fit usize"),
        )
    })?;
    if size > REDIRECT_XATTR_CAPTURE_CAP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} exceeds the {REDIRECT_XATTR_CAPTURE_CAP}-byte cap"),
        ));
    }
    Ok(size)
}

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "linux"))]
fn require_xattr_size(actual: libc::ssize_t, expected: usize, what: &str) -> std::io::Result<()> {
    let actual = checked_xattr_size(actual, what)?;
    if actual != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} changed during capture (expected {expected}, read {actual})"),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "linux"))]
fn checked_xattr_total(current: usize, additional: usize) -> std::io::Result<usize> {
    let total = current.checked_add(additional).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "xattr capture length overflow",
        )
    })?;
    if total > REDIRECT_XATTR_CAPTURE_CAP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("xattr capture exceeds the {REDIRECT_XATTR_CAPTURE_CAP}-byte cap"),
        ));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_planner::events::{CaptureEventKind, CommandRecord};
    use shit_planner::store::PlannerStore;
    use shit_planner::time::TimePoint;
    use std::io::Write;
    use tempfile::TempDir;

    fn fresh_session() -> Uuid {
        // The workspace uuid feature-set is v7 + serde (no v4). v7 is
        // monotonic + unique enough for test isolation.
        let ts = uuid::Timestamp::now(uuid::NoContext);
        Uuid::new_v7(ts)
    }

    fn fresh() -> (TempDir, BlobStore, Index, ActiveCommands) {
        let dir = TempDir::new().unwrap();
        let blob_store = BlobStore::open(dir.path().join("blobs")).unwrap();
        let index = Index::open(dir.path().join("db.sqlite")).unwrap();
        (dir, blob_store, index, ActiveCommands::new())
    }

    /// Register the (session, command) so FK constraints on `events`
    /// are satisfied — the real daemon does this via the PreExec
    /// hook path before any pre-stash arrives.
    fn register_command(index: &Index, cmd: CommandId) {
        index
            .put_session(cmd.session, "bash", 0, None, TimePoint::new(0, 0))
            .expect("put_session");
        index
            .put_command(&CommandRecord {
                command: cmd,
                cmd_string: Some("test".into()),
                cwd: PathBuf::from("/tmp"),
                pid: 4242,
                shell_kind: shit_proto::ShellKind::Bash,
                started_at: TimePoint::new(0, 0),
                ended_at: None,
                exit_code: None,
                event_ids: vec![],
            })
            .expect("put_command");
    }

    fn write_file(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn xattr_name_filter_runs_before_value_lookup() {
        let names = b"user.keep\0security.unreadable\0system.hidden\0";
        let mut queried = Vec::new();
        let captured = read_nul_xattrs(
            names,
            |name| name.starts_with("user."),
            |name| {
                let name = name.to_str().unwrap().to_string();
                queried.push(name.clone());
                assert!(
                    name.starts_with("user."),
                    "excluded namespace reached value lookup: {name}"
                );
                Ok(b"value".to_vec())
            },
        )
        .unwrap();

        assert_eq!(queried, vec!["user.keep"]);
        assert_eq!(captured.get("user.keep"), Some(&b"value".to_vec()));
        assert_eq!(captured.len(), 1);
    }

    #[test]
    fn truncate_target_journaled_as_file_pre_image() {
        let (dir, blob_store, index, active) = fresh();
        let path = write_file(dir.path(), "probe.txt", b"original v1\n");
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let blocks = crate::server::FinalizationBlocks::default();
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: path.to_string_lossy().to_string(),
            }],
            &active,
            &index,
            &blob_store,
            &blocks,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 1, "expected 1 stashed, got {}", r.stashed);
                assert!(r.errors.is_empty(), "unexpected errors: {:?}", r.errors);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        // Verify the FilePreImage event landed in the index keyed to
        // our command.
        let evs = index.events_for_command(cmd);
        assert_eq!(evs.len(), 1, "expected 1 event, got {}", evs.len());
        match &evs[0].kind {
            CaptureEventKind::FilePreImage { path: p, .. } => {
                assert_eq!(p, &path);
            }
            other => panic!("expected FilePreImage, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn truncate_target_captures_xattrs_and_bsd_flags() {
        unsafe extern "C" {
            fn fsetxattr(
                fd: libc::c_int,
                name: *const libc::c_char,
                value: *const libc::c_void,
                size: libc::size_t,
                position: u32,
                options: libc::c_int,
            ) -> libc::c_int;
        }

        let (dir, blob_store, index, active) = fresh();
        let path = write_file(dir.path(), "metadata.txt", b"original metadata bytes\n");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let name = CString::new("user.shit.redirect-metadata").unwrap();
        let value = b"captured-before-truncate";
        // SAFETY: the descriptor, NUL-terminated name, and value buffer remain
        // live for the duration of each syscall.
        assert_eq!(
            unsafe {
                fsetxattr(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    value.as_ptr().cast(),
                    value.len(),
                    0,
                    0,
                )
            },
            0,
            "fsetxattr: {}",
            std::io::Error::last_os_error()
        );
        // UF_HIDDEN is user-settable and does not prevent TempDir cleanup.
        // SAFETY: `file` owns a live descriptor and UF_HIDDEN has libc's
        // platform-specific flag width.
        assert_eq!(
            unsafe { libc::fchflags(file.as_raw_fd(), libc::UF_HIDDEN) },
            0,
            "fchflags: {}",
            std::io::Error::last_os_error()
        );

        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let blocks = crate::server::FinalizationBlocks::default();
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: path.to_string_lossy().into_owned(),
            }],
            &active,
            &index,
            &blob_store,
            &blocks,
        );
        assert!(matches!(
            resp,
            CtlResponse::PreStashRedirectsAck(result)
                if result.stashed == 1 && result.errors.is_empty()
        ));

        let events = index.events_for_command(cmd);
        assert_eq!(events.len(), 1);
        let CaptureEventKind::FilePreImage { meta, .. } = &events[0].kind else {
            panic!("expected FilePreImage, got {:?}", events[0].kind);
        };
        assert_eq!(
            meta.xattrs.get("user.shit.redirect-metadata"),
            Some(&value.to_vec())
        );
        assert_ne!(meta.flags & libc::UF_HIDDEN, 0);
    }

    #[test]
    fn truncate_publication_holds_blob_guard_until_event_is_durable() {
        let dir = TempDir::new().unwrap();
        let path = write_file(dir.path(), "guarded.txt", b"original guarded bytes");
        let command = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        let index = std::sync::Arc::new(Index::open(dir.path().join("db.sqlite")).unwrap());
        register_command(&index, command);
        let blob_store = std::sync::Arc::new(BlobStore::open(dir.path().join("blobs")).unwrap());
        let expected_blob = shit_planner::hash_file(&path).unwrap();

        // Force the publisher to stop between the canonical install and its
        // Index writes. The lifecycle writer must remain blocked throughout
        // that interval or GC could unlink the just-installed zero-ref blob.
        let index_lock = index.conn_for_test().lock().unwrap();
        let worker_index = std::sync::Arc::clone(&index);
        let worker_store = std::sync::Arc::clone(&blob_store);
        let worker_path = path.to_string_lossy().into_owned();
        let publisher = std::thread::spawn(move || {
            stash_truncate(&worker_path, command, &worker_index, &worker_store, &mut 0)
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !blob_store.contains(&expected_blob) {
            assert!(
                std::time::Instant::now() < deadline,
                "publisher never installed the canonical blob"
            );
            std::thread::yield_now();
        }

        let exclusive_store = std::sync::Arc::clone(&blob_store);
        let (attempting_tx, attempting_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let exclusive = std::thread::spawn(move || {
            attempting_tx.send(()).unwrap();
            let _guard = exclusive_store.exclusive_guard();
            acquired_tx.send(()).unwrap();
        });
        attempting_rx.recv().unwrap();
        assert!(matches!(
            acquired_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        drop(index_lock);
        assert!(matches!(
            publisher.join().unwrap(),
            Ok(StashOutcome::Stashed)
        ));
        acquired_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("exclusive lifecycle access should follow publication");
        exclusive.join().unwrap();

        assert_eq!(index.events_for_command(command).len(), 1);
    }

    #[test]
    fn missing_target_is_durably_refused() {
        let (dir, blob_store, index, active) = fresh();
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let blocks = crate::server::FinalizationBlocks::default();
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: dir.path().join("nope.txt").to_string_lossy().to_string(),
            }],
            &active,
            &index,
            &blob_store,
            &blocks,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 0);
                assert_eq!(r.errors.len(), 1);
                assert!(r.errors[0].reason.contains("target is absent"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert!(matches!(
            index.events_for_command(cmd).as_slice(),
            [CaptureEvent {
                kind: CaptureEventKind::CaptureRefused { class, .. },
                ..
            }] if class == "redirect-prestash-failed"
        ));
    }

    #[test]
    fn target_failure_is_a_durable_refusal_without_clearing_another_block() {
        let (dir, blob_store, index, active) = fresh();
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let blocks = crate::server::FinalizationBlocks::default();
        let independent = blocks.insert(cmd, "independent producer failure".to_string());
        let target = dir.path().join("not-a-file");
        std::fs::create_dir(&target).unwrap();

        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: target.to_string_lossy().into_owned(),
            }],
            &active,
            &index,
            &blob_store,
            &blocks,
        );

        match resp {
            CtlResponse::PreStashRedirectsAck(result) => {
                assert_eq!(result.stashed, 0);
                assert_eq!(result.errors.len(), 1);
                assert_eq!(result.errors[0].path, target.to_string_lossy());
                assert!(result.errors[0].reason.contains("not a regular file"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert_eq!(
            blocks.get(cmd).as_deref(),
            Some("independent producer failure"),
            "redirect success must clear only its provisional block"
        );
        blocks.clear_token(cmd, independent);
        assert!(blocks.get(cmd).is_none());
        assert!(matches!(
            index.events_for_command(cmd).as_slice(),
            [CaptureEvent {
                kind: CaptureEventKind::CaptureRefused {
                    class,
                    path,
                    detail,
                },
                ..
            }] if class == "redirect-prestash-failed"
                && path == &target
                && detail.contains("not a regular file")
        ));
    }

    #[test]
    fn refusal_write_failure_returns_error_and_leaves_close_blocked() {
        let (dir, blob_store, index, active) = fresh();
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        index
            .conn_for_test()
            .lock()
            .unwrap()
            .execute_batch(
                "CREATE TEMP TRIGGER reject_redirect_refusal
                 BEFORE INSERT ON events
                 WHEN NEW.discriminant = 'CaptureRefused'
                 BEGIN SELECT RAISE(FAIL, 'injected redirect refusal failure'); END;",
            )
            .unwrap();
        let blocks = crate::server::FinalizationBlocks::default();
        let target = dir.path().join("not-a-file");
        std::fs::create_dir(&target).unwrap();

        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: target.to_string_lossy().into_owned(),
            }],
            &active,
            &index,
            &blob_store,
            &blocks,
        );

        assert!(matches!(
            resp,
            CtlResponse::Error(detail)
                if detail.contains("not a regular file")
                    && detail.contains("injected redirect refusal failure")
        ));
        assert!(blocks.get(cmd).is_some_and(|detail| {
            detail.contains(&target.to_string_lossy().into_owned())
                && detail.contains("not a regular file")
        }));
        assert!(index.events_for_command(cmd).is_empty());
        assert!(
            index
                .command_by_id(cmd)
                .is_some_and(|record| record.ended_at.is_none())
        );
    }

    /// AU27 — Append targets are no longer deferred. The
    /// stash_append path journals a FileAppendPreStash event
    /// with the file's pre_size; the planner emits
    /// `InverseOp::FileExtend` from that event.
    #[test]
    fn append_target_stashes_pre_size() {
        let (dir, blob_store, index, active) = fresh();
        let path = write_file(dir.path(), "log.txt", b"old\n");
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let blocks = crate::server::FinalizationBlocks::default();
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Append,
                path: path.to_string_lossy().to_string(),
            }],
            &active,
            &index,
            &blob_store,
            &blocks,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 1, "stashed: got {}", r.stashed);
                assert!(
                    r.errors.is_empty(),
                    "no errors expected, got {:?}",
                    r.errors
                );
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// Appending to a pre-existing empty target still needs an inverse: after
    /// the command writes bytes, undo must truncate it back to zero.
    #[test]
    fn append_to_empty_file_journals_zero_pre_size() {
        let (dir, blob_store, index, active) = fresh();
        let path = write_file(dir.path(), "empty.log", b"");
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let blocks = crate::server::FinalizationBlocks::default();
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Append,
                path: path.to_string_lossy().to_string(),
            }],
            &active,
            &index,
            &blob_store,
            &blocks,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 1);
                assert!(r.errors.is_empty(), "unexpected errors: {:?}", r.errors);
            }
            other => panic!("unexpected response: {other:?}"),
        }
        assert!(matches!(
            index.events_for_command(cmd).as_slice(),
            [CaptureEvent {
                kind: CaptureEventKind::FileAppendPreStash { pre_size: 0, .. },
                ..
            }]
        ));
    }

    #[test]
    fn multiple_targets_partial_success() {
        let (dir, blob_store, index, active) = fresh();
        let good = write_file(dir.path(), "good.txt", b"keep me\n");
        let missing = dir.path().join("absent.txt");
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        // The absent target is not safe: the shell will create it and this
        // path has no synchronously fenced create inverse.
        let blocks = crate::server::FinalizationBlocks::default();
        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![
                RedirectTargetWire {
                    op: RedirectOpWire::Truncate,
                    path: good.to_string_lossy().to_string(),
                },
                RedirectTargetWire {
                    op: RedirectOpWire::Truncate,
                    path: missing.to_string_lossy().to_string(),
                },
                RedirectTargetWire {
                    op: RedirectOpWire::Append,
                    path: good.to_string_lossy().to_string(),
                },
            ],
            &active,
            &index,
            &blob_store,
            &blocks,
        );
        match resp {
            CtlResponse::PreStashRedirectsAck(r) => {
                assert_eq!(r.stashed, 2, "stashed: got {}", r.stashed);
                assert_eq!(r.errors.len(), 1, "errors: got {:?}", r.errors);
                assert!(r.errors[0].reason.contains("target is absent"));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[test]
    fn symlink_target_is_refused_without_following_it() {
        use std::os::unix::fs::symlink;

        let (dir, blob_store, index, active) = fresh();
        let real = write_file(dir.path(), "real.txt", b"secret");
        let link = dir.path().join("link.txt");
        symlink(&real, &link).unwrap();
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let blocks = crate::server::FinalizationBlocks::default();

        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: link.to_string_lossy().into_owned(),
            }],
            &active,
            &index,
            &blob_store,
            &blocks,
        );

        assert!(matches!(
            resp,
            CtlResponse::PreStashRedirectsAck(result)
                if result.stashed == 0 && result.errors.len() == 1
        ));
        assert_eq!(std::fs::read(&real).unwrap(), b"secret");
        assert!(matches!(
            index.events_for_command(cmd).as_slice(),
            [CaptureEvent {
                kind: CaptureEventKind::CaptureRefused { .. },
                ..
            }]
        ));
    }

    #[test]
    fn oversized_target_refuses_before_reading() {
        let (dir, blob_store, index, active) = fresh();
        let path = dir.path().join("large.txt");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_REDIRECT_BYTES_PER_TARGET + 1).unwrap();
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let blocks = crate::server::FinalizationBlocks::default();

        let resp = handle(
            cmd.session,
            cmd.seq,
            vec![RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: path.to_string_lossy().into_owned(),
            }],
            &active,
            &index,
            &blob_store,
            &blocks,
        );

        assert!(matches!(
            resp,
            CtlResponse::PreStashRedirectsAck(result)
                if result.stashed == 0
                    && result.errors.len() == 1
                    && result.errors[0].reason.contains("per-target limit")
        ));
        assert!(matches!(
            index.events_for_command(cmd).as_slice(),
            [CaptureEvent {
                kind: CaptureEventKind::CaptureRefused { .. },
                ..
            }]
        ));
    }

    #[test]
    fn target_count_cap_bounds_response_and_refuses_before_stashing() {
        let (dir, blob_store, index, active) = fresh();
        let path = write_file(dir.path(), "target.txt", b"original");
        let cmd = CommandId {
            session: fresh_session(),
            seq: 1,
        };
        register_command(&index, cmd);
        let blocks = crate::server::FinalizationBlocks::default();
        let targets = (0..=MAX_REDIRECT_TARGETS)
            .map(|_| RedirectTargetWire {
                op: RedirectOpWire::Truncate,
                path: path.to_string_lossy().into_owned(),
            })
            .collect();

        let resp = handle(
            cmd.session,
            cmd.seq,
            targets,
            &active,
            &index,
            &blob_store,
            &blocks,
        );

        assert!(matches!(
            resp,
            CtlResponse::PreStashRedirectsAck(result)
                if result.stashed == 0
                    && result.errors.len() == 1
                    && result.errors[0].reason.contains("too many redirect targets")
        ));
        assert_eq!(index.events_for_command(cmd).len(), 1);
    }
}
