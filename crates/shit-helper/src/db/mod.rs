// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database CLI shim integration (S19).
//!
//! Mirrors [`crate::pkg`] / [`crate::svc`] / [`crate::net`] /
//! [`crate::proc`]: transient `shit-helper db-event ...` mode that:
//!
//! 1. Parses the user's argv via [`shit_planner::db::parse_psql_argv`]
//!    (or the mysql/sqlite3 equivalents) into a [`ConnInfo`] with the
//!    password already stripped.
//! 2. Splits and classifies the statement blob — read-only statements
//!    are dropped at this boundary so `SELECT *` never reaches the
//!    journal.
//! 3. Ships a [`DbEventReq`] to the daemon.
//!
//! The Post phase doesn't (yet) probe the engine for commit/binlog
//! deltas — that's DR-56/DR-57. Stage 1 forwards the captured
//! statements with `transaction_state = Unknown`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shit_planner::db::{
    ConnInfo, classify_statement, parse_mysql_argv, parse_psql_argv, parse_sqlite3_argv,
    split_statements,
};
use shit_proto::{
    CtlRequest, CtlResponse, DbEngineWire, DbEventReq, DbTxStateWire, PkgPhase, decode_frame,
    encode_frame,
};

pub async fn run_event(
    engine: &str,
    phase: &str,
    target_argv_joined: &str,
    statement_blob: &str,
    ctl_sock: Option<&Path>,
) -> anyhow::Result<()> {
    let engine: DbEngineWire = engine.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    let phase: PkgPhase = match phase {
        "pre" => PkgPhase::Pre,
        "post" => PkgPhase::Post,
        other => {
            return Err(anyhow::anyhow!(
                "unknown phase: {other:?} (expected 'pre' or 'post')"
            ));
        }
    };

    if std::env::var_os("SHIT_DURING_UNDO").is_some() {
        tracing::info!(
            engine = engine.as_str(),
            phase = ?phase,
            "db-event suppressed (SHIT_DURING_UNDO=1)"
        );
        return Ok(());
    }

    let target_argv: Vec<String> = if target_argv_joined.is_empty() {
        Vec::new()
    } else {
        target_argv_joined.lines().map(str::to_string).collect()
    };

    let info: ConnInfo = match engine {
        DbEngineWire::Postgres => parse_psql_argv(&target_argv),
        DbEngineWire::Mysql => parse_mysql_argv(&target_argv),
        DbEngineWire::Sqlite3 => parse_sqlite3_argv(&target_argv),
    }
    .map_err(|e| anyhow::anyhow!("parse argv: {e}"))?;

    // Split + filter statements. Read-only ones never cross the wire.
    let statements: Vec<String> = filter_statements(statement_blob);

    // No statements + no clear target → there's nothing useful to
    // journal. Don't waste a wire roundtrip on an empty event.
    if statements.is_empty() && info.target.is_empty() {
        tracing::debug!(
            engine = engine.as_str(),
            phase = ?phase,
            "db-event: no statements and no target; dropping"
        );
        return Ok(());
    }

    // SAFETY: getpid/getuid always succeed.
    let my_pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let req = DbEventReq {
        engine,
        phase,
        conn: info.to_wire(),
        statements,
        // Post-phase engine probe (xact_commit delta, binlog position)
        // is DR-56/DR-57; Stage 1 always ships Unknown.
        transaction_state: DbTxStateWire::Unknown,
        pid: my_pid,
        uid,
        extras: Default::default(),
    };

    let ctl = match ctl_sock {
        Some(p) => p.to_path_buf(),
        None => default_ctl_socket_path(),
    };
    if let Err(e) = send_event(&ctl, &req) {
        tracing::warn!(
            engine = engine.as_str(),
            phase = ?req.phase,
            ctl = %ctl.display(),
            err = %e,
            "db-event: failed to ship to daemon; continuing"
        );
    }
    Ok(())
}

/// Split a statement blob and drop read-only entries. Exposed for
/// tests and for future use by the daemon-cross-ref path.
pub fn filter_statements(blob: &str) -> Vec<String> {
    if blob.trim().is_empty() {
        return Vec::new();
    }
    split_statements(blob)
        .into_iter()
        .filter(|s| classify_statement(s).is_mutating())
        .collect()
}

fn default_ctl_socket_path() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("shit-ctl.sock");
    }
    let tmp = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let uid = unsafe { libc::getuid() };
    tmp.join(format!("shit-ctl-{uid}.sock"))
}

const CTL_TIMEOUT: Duration = Duration::from_secs(10);

fn send_event(path: &Path, req: &DbEventReq) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CTL_TIMEOUT))?;
    stream.set_write_timeout(Some(CTL_TIMEOUT))?;
    let frame = encode_frame(&CtlRequest::DbEvent(req.clone()))?;
    stream.write_all(&frame)?;
    let mut buf = vec![0u8; 256 * 1024];
    let n = stream.read(&mut buf)?;
    let resp: CtlResponse = decode_frame(&buf[..n])?;
    match resp {
        CtlResponse::DbEventAck => Ok(()),
        CtlResponse::Error(e) => Err(anyhow::anyhow!("daemon: {e}")),
        other => Err(anyhow::anyhow!("unexpected daemon response: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_drops_readonly_keeps_mutating() {
        let blob = "SELECT 1; INSERT INTO t VALUES (1); SHOW TABLES; UPDATE t SET x = 2";
        let kept = filter_statements(blob);
        assert_eq!(kept.len(), 2);
        assert!(kept[0].starts_with("INSERT"));
        assert!(kept[1].starts_with("UPDATE"));
    }

    #[test]
    fn filter_empty_blob_is_empty() {
        assert!(filter_statements("").is_empty());
        assert!(filter_statements("   \n  ").is_empty());
    }

    #[test]
    fn filter_keeps_unknown_conservatively() {
        // Pure comment + nothing else → Unknown → kept (better
        // over-record than miss).
        let kept = filter_statements("/* just a comment */");
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn filter_keeps_transaction_control() {
        let kept = filter_statements("BEGIN; INSERT INTO t VALUES (1); COMMIT");
        assert_eq!(kept.len(), 3);
    }

    #[test]
    fn filter_drops_select_into_distinction() {
        // SELECT FOR UPDATE is still read-only by our classifier; SELECT INTO is mutating.
        let kept = filter_statements(
            "SELECT * FROM t FOR UPDATE; SELECT * INTO new FROM old",
        );
        assert_eq!(kept.len(), 1);
        assert!(kept[0].contains("INTO new"));
    }
}
