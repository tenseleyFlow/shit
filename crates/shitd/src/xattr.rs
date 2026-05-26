// SPDX-License-Identifier: AGPL-3.0-or-later

//! Daemon-side xattr capture (W09.21 capsicum fix).
//!
//! The helper runs under `cap_enter(2)` by default on FreeBSD (B05).
//! FreeBSD kernel rejects `extattr_*_fd(2)` in capability mode with
//! `ECAPMODE` regardless of `cap_rights_limit` — the syscall is
//! gated at the capability-mode level, not by per-fd rights (verified
//! empirically on shit-fbsd 14.4: `extattr_list_fd` returns -1
//! errno=94 "Not permitted in capability mode" after `cap_enter()`
//! even when no `cap_rights_limit` is applied).
//!
//! So xattr capture has to happen in a process that hasn't entered
//! capability mode. The daemon is the natural home: it owns the
//! `LiveBaseline` cache, has the absolute path on the wire, and is
//! never `cap_enter`'d.
//!
//! This module reads user-namespace xattrs by absolute path
//! (path-based open, not fd-passing — the helper's fd is no use to
//! us since we want the daemon to do the open itself in its
//! unrestricted address space).

use std::collections::BTreeMap;
use std::path::Path;

/// Best-effort xattr read at `path`. Returns empty when the platform
/// doesn't support xattrs, the FS doesn't carry any, or any
/// individual read fails — never panics, never errors.
///
/// Reads the `EXTATTR_NAMESPACE_USER` namespace only on FreeBSD;
/// other platforms return empty (Linux daemon never runs this path
/// because Linux uses fanotify/LSM rather than live-baseline).
pub fn read_user_xattrs_at_path(path: &Path) -> BTreeMap<String, Vec<u8>> {
    #[cfg(target_os = "freebsd")]
    {
        freebsd::read(path)
    }
    #[cfg(not(target_os = "freebsd"))]
    {
        let _ = path;
        BTreeMap::new()
    }
}

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    pub fn read(path: &Path) -> BTreeMap<String, Vec<u8>> {
        let file = match std::fs::OpenOptions::new().read(true).open(path) {
            Ok(f) => f,
            Err(_) => return BTreeMap::new(),
        };
        let fd = file.as_raw_fd();
        let ns = libc::EXTATTR_NAMESPACE_USER;
        let list_size = unsafe { libc::extattr_list_fd(fd, ns, std::ptr::null_mut(), 0) };
        if list_size <= 0 {
            return BTreeMap::new();
        }
        let mut buf = vec![0u8; list_size as usize];
        let n = unsafe { libc::extattr_list_fd(fd, ns, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return BTreeMap::new();
        }
        let mut out = BTreeMap::new();
        let mut i = 0usize;
        let end = n as usize;
        // FreeBSD extattr_list_fd encoding: <u8 namelen><name…> repeating,
        // no terminator. Parse one entry at a time.
        while i < end {
            let len = buf[i] as usize;
            i += 1;
            if i + len > end {
                break;
            }
            let name_bytes = &buf[i..i + len];
            i += len;
            let Ok(name) = std::str::from_utf8(name_bytes) else {
                continue;
            };
            let Ok(cname) = CString::new(name) else {
                continue;
            };
            let val_size =
                unsafe { libc::extattr_get_fd(fd, ns, cname.as_ptr(), std::ptr::null_mut(), 0) };
            if val_size < 0 {
                continue;
            }
            let mut val = vec![0u8; val_size as usize];
            let m = unsafe {
                libc::extattr_get_fd(fd, ns, cname.as_ptr(), val.as_mut_ptr().cast(), val.len())
            };
            if m < 0 {
                continue;
            }
            val.truncate(m as usize);
            out.insert(name.to_string(), val);
        }
        out
    }
}

/// PostExec sweep: for each cached file in the cwd's LiveBaseline,
/// re-read xattrs from disk and diff against the cached baseline
/// xattrs. Any path whose xattrs changed gets a synthetic
/// `MetadataChange` event journaled, so the planner can emit a
/// `RestoreMetadata` inverse that puts the xattrs back.
///
/// Why this exists: kqueue's `NOTE_ATTRIB` does fire when a user
/// runs `setextattr`, but the helper is `cap_enter`'d and so its
/// `fstat_meta` returns empty xattrs both before and after — the
/// helper's `handle_attrib` sees `before == after` and drops the
/// event. The daemon isn't capsicum'd and can read xattrs; the
/// PostExec sweep is when it does that final compare.
///
/// The sweep is best-effort: per-file errors are warn-logged and
/// skipped. Other StatMeta fields (mode/uid/gid/mtime/size) are
/// already covered by the helper's normal NOTE_ATTRIB path —
/// those work under capsicum because plain `fstat(2)` isn't
/// gated, only `extattr_*_fd(2)` is.
pub fn post_exec_sweep(
    cwd: &std::path::Path,
    command: shit_planner::events::CommandId,
    live_baseline: &crate::baseline::LiveBaseline,
    index: &shit_store::Index,
) {
    let Some(cache) = live_baseline.get_cwd(cwd) else {
        return;
    };
    let entries = cache.snapshot_entries();
    if entries.is_empty() {
        return;
    }
    let mut emitted = 0usize;
    for (path, entry) in entries {
        let current = read_user_xattrs_at_path(&path);
        if current == entry.xattrs {
            continue;
        }
        // Build a MetadataChange event. Only xattrs differ — other
        // FileMetadata fields are filled with the live values so
        // the planner's RestoreMetadata inverse doesn't touch them
        // (target equals current ⇒ executor sees mode/uid/gid/mtime
        // unchanged and skips them).
        let Some(live_stat) = std::fs::metadata(&path).ok() else {
            continue;
        };
        use std::os::unix::fs::MetadataExt;
        let live_mode = live_stat.mode();
        let live_uid = live_stat.uid();
        let live_gid = live_stat.gid();
        let live_size = live_stat.size();
        let live_mtime_nanos =
            (live_stat.mtime() as i128) * 1_000_000_000 + (live_stat.mtime_nsec() as i128);
        let inode_ref = shit_planner::InodeRef::new(live_stat.dev(), live_stat.ino());
        let before = shit_planner::metadata::FileMetadata {
            mode: live_mode,
            uid: live_uid,
            gid: live_gid,
            size: live_size,
            mtime_unix_nanos: live_mtime_nanos,
            xattrs: entry.xattrs.clone(),
            acl: None,
        };
        let after = shit_planner::metadata::FileMetadata {
            mode: live_mode,
            uid: live_uid,
            gid: live_gid,
            size: live_size,
            mtime_unix_nanos: live_mtime_nanos,
            xattrs: current,
            acl: None,
        };
        let ts = crate::server::next_ts();
        let event = shit_planner::events::CaptureEvent {
            id: shit_planner::events::EventId(0),
            command,
            ts,
            partial: false,
            kind: shit_planner::events::CaptureEventKind::MetadataChange {
                inode: inode_ref,
                path: path.clone(),
                before,
                after,
            },
        };
        if let Err(e) = index.put_event(&event) {
            tracing::warn!(
                err = %e,
                path = %path.display(),
                "post-exec xattr sweep: journal put_event failed"
            );
            continue;
        }
        emitted += 1;
    }
    if emitted > 0 {
        tracing::info!(
            cwd = %cwd.display(),
            ?command,
            emitted,
            "post-exec xattr sweep emitted MetadataChange events"
        );
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::*;

    #[test]
    fn empty_file_has_no_xattrs() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let got = read_user_xattrs_at_path(f.path());
        assert!(got.is_empty(), "unexpected xattrs: {got:?}");
    }

    #[test]
    fn missing_path_returns_empty() {
        let got = read_user_xattrs_at_path(Path::new("/no/such/path/shit-xattr-test"));
        assert!(got.is_empty());
    }
}
