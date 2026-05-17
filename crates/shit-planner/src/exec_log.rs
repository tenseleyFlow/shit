// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-run execution log (S11.10).
//!
//! Every applied / failed / skipped / conflicted op writes one
//! length-prefixed postcard-encoded [`ExecutionRecord`] to a file
//! under `$XDG_STATE_HOME/shit/exec-log/`. The file is named after
//! the `undo_id` the caller supplies (today: an opaque UUID; later
//! shell-friendly `<session>-<seq>` form per the `CommandId`).
//!
//! ## Why an append-only binary log, not sqlite
//!
//! Three reasons:
//!
//! 1. **Crash-safety is cheap.** `write(2)` + `fsync(2)` per record
//!    means a torn write loses at most one record. A sqlite WAL gives
//!    us the same guarantee with much more machinery.
//! 2. **Replay is trivial.** `shit show --exec <undo-id>` reads the
//!    file front-to-back, decodes each record, renders. No SQL.
//! 3. **GC is `rm`.** S13's retention sweep just unlinks old log
//!    files; no foreign-key cascades.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::executor::ExecutionRecord;

#[derive(Debug, thiserror::Error)]
pub enum ExecLogError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("postcard: {0}")]
    Postcard(String),
    #[error("truncated record at offset {at}")]
    Truncated { at: u64 },
}

impl From<postcard::Error> for ExecLogError {
    fn from(e: postcard::Error) -> Self {
        Self::Postcard(format!("{e:?}"))
    }
}

/// On-disk handle for one undo-run's records. Append-only.
///
/// The constructor creates the log file (and parent dirs) but doesn't
/// open it for reading. Use [`ExecLog::iter`] (a free function) to
/// replay.
#[derive(Debug)]
pub struct ExecLog {
    file: File,
    path: PathBuf,
    /// Records written so far. Useful for `len()` queries; doesn't
    /// account for records written by other processes (writes are
    /// exclusive — see `O_CREAT | O_EXCL` below).
    written: usize,
}

impl ExecLog {
    /// Open a new log file for an undo run. Fails if a log with the
    /// same id already exists — the caller is expected to allocate
    /// fresh ids.
    pub fn create(dir: &Path, undo_id: &str) -> Result<Self, ExecLogError> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(format!("{undo_id}.log"));
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        Ok(Self {
            file,
            path,
            written: 0,
        })
    }

    /// Append a single record. fsync after every write — durable on
    /// return. Caller should accept the latency cost; an undo with
    /// 100k ops is unusual.
    pub fn append(&mut self, rec: &ExecutionRecord) -> Result<(), ExecLogError> {
        let body = postcard::to_allocvec(rec)?;
        // Length prefix as u32 little-endian. u32 is enough for any
        // record we'd emit; postcard-encoded ExecutionRecords are at
        // most a few KB.
        let len: u32 = body
            .len()
            .try_into()
            .map_err(|_| ExecLogError::Postcard("record exceeds 4 GiB".into()))?;
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&body)?;
        self.file.sync_all()?;
        self.written += 1;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn written(&self) -> usize {
        self.written
    }
}

/// Replay a log file. Yields each record in append order. Errors on
/// truncated tail (interpreted as "process died mid-write — caller
/// decides whether to ignore or recover").
pub fn read_all(path: &Path) -> Result<Vec<ExecutionRecord>, ExecLogError> {
    let mut f = File::open(path)?;
    let mut out = Vec::new();
    let mut offset: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        match f.read(&mut len_buf)? {
            0 => break, // clean EOF on a record boundary
            n if n < 4 => return Err(ExecLogError::Truncated { at: offset }),
            _ => {}
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        f.read_exact(&mut body)
            .map_err(|_| ExecLogError::Truncated { at: offset })?;
        let rec: ExecutionRecord = postcard::from_bytes(&body)?;
        out.push(rec);
        offset += 4 + len as u64;
    }
    Ok(out)
}

/// Header recorded once per file. Lets `shit show --exec` show the
/// plan summary without scanning every record. Currently unused —
/// keeping the type defined so adding it later is a non-breaking
/// extension (length prefix means the reader can skip unknown
/// trailing fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogHeader {
    pub schema_version: u32,
    pub command_id: String,
    pub dry_run: bool,
}

/// Resolve the default exec-log directory: `$XDG_STATE_HOME/shit/exec-log/`,
/// falling back to `$HOME/.local/state/shit/exec-log/` per XDG spec.
pub fn default_dir() -> PathBuf {
    if let Some(state) = std::env::var_os("XDG_STATE_HOME") {
        let mut p = PathBuf::from(state);
        p.push("shit");
        p.push("exec-log");
        p
    } else if let Some(home) = std::env::var_os("HOME") {
        let mut p = PathBuf::from(home);
        p.push(".local/state/shit/exec-log");
        p
    } else {
        // Last-resort tmpdir; not durable across reboots but better
        // than panicking.
        let mut p = std::env::temp_dir();
        p.push("shit/exec-log");
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::OutcomeKind;
    use crate::inverse::{InverseOp, InverseTier};
    use std::path::PathBuf;

    fn sample_record() -> ExecutionRecord {
        ExecutionRecord {
            op_index: 0,
            op: InverseOp::Unlink {
                path: PathBuf::from("/tmp/x"),
            },
            tier: InverseTier::Files,
            outcome_kind: OutcomeKind::Applied,
            detail: None,
        }
    }

    #[test]
    fn append_and_read_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = ExecLog::create(tmp.path(), "test-1").unwrap();
        let rec1 = sample_record();
        let mut rec2 = sample_record();
        rec2.op_index = 1;
        rec2.outcome_kind = OutcomeKind::Skipped;
        rec2.detail = Some("test-skip".into());
        log.append(&rec1).unwrap();
        log.append(&rec2).unwrap();
        assert_eq!(log.written(), 2);

        let recs = read_all(log.path()).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0], rec1);
        assert_eq!(recs[1], rec2);
    }

    #[test]
    fn create_refuses_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        ExecLog::create(tmp.path(), "exists-1").unwrap();
        let err = ExecLog::create(tmp.path(), "exists-1").unwrap_err();
        // io error kind AlreadyExists; we let it bubble through Io.
        match err {
            ExecLogError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
            }
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
    }

    #[test]
    fn truncated_tail_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = ExecLog::create(tmp.path(), "trunc-1").unwrap();
        log.append(&sample_record()).unwrap();
        // Corrupt: truncate the file mid-record. Read length prefix of
        // record 2 but no body.
        let mut f = OpenOptions::new().append(true).open(log.path()).unwrap();
        f.write_all(&[99u8, 0, 0, 0]).unwrap(); // claims body of 99 bytes
        drop(f);
        match read_all(log.path()) {
            Err(ExecLogError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn default_dir_under_xdg_state_home() {
        // Save + restore env so we don't leak state.
        let prev = std::env::var("XDG_STATE_HOME").ok();
        // SAFETY: tests are not parallel within this fn; we restore in
        // the matching unsafe block below.
        unsafe { std::env::set_var("XDG_STATE_HOME", "/tmp/xdg-test") };
        let d = default_dir();
        assert_eq!(d, PathBuf::from("/tmp/xdg-test/shit/exec-log"));
        unsafe {
            match prev {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
        }
    }
}
