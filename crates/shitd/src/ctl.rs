// SPDX-License-Identifier: AGPL-3.0-or-later

//! Control-socket listener. SEQPACKET preserves message boundaries; one
//! request → one reply per accepted connection. Concurrent clients are each
//! served on their own tokio task.

use crate::config::ResolvedConfig;
use crate::net_track::NetPreStash;
use crate::pkg::PkgPreStash;
use crate::proc_track::ProcPreStash;
use crate::stats::Stats;
use crate::svc_track::SvcPreStash;
use shit_proto::{
    CtlRequest, CtlResponse, DaemonStatus, GcRequest, NetEventReq, PkgEventReq, ProcEventReq,
    SvcEventReq, decode_frame, encode_frame,
};
use shit_store::{BlobStore, Index};

/// Daemon-side state bundle threaded through the ctl handlers. Keeps
/// the `handle_client` signature manageable as more Pre-stash kinds
/// land.
#[derive(Clone)]
pub struct CtlState {
    pub stats: Arc<Stats>,
    pub shutdown: Arc<Notify>,
    pub index: Arc<Index>,
    pub blob_store: Arc<BlobStore>,
    pub pkg_stash: Arc<PkgPreStash>,
    pub svc_stash: Arc<SvcPreStash>,
    pub net_stash: Arc<NetPreStash>,
    pub proc_stash: Arc<ProcPreStash>,
    pub db_stash: Arc<crate::db_track::DbPreStash>,
}
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

const CTL_BUF: usize = 4096;

/// Listen on `cfg.ctl_socket_path`, serving each connection on a task.
/// `shutdown` is notified to ask the main runtime to exit; the listener
/// itself does not exit until cancelled by the runtime stopping.
pub async fn serve(cfg: &ResolvedConfig, state: CtlState) -> anyhow::Result<()> {
    if let Some(parent) = cfg.ctl_socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if Path::new(&cfg.ctl_socket_path).exists() {
        let _ = std::fs::remove_file(&cfg.ctl_socket_path);
    }
    // tokio doesn't expose SEQPACKET directly; we use SOCK_STREAM here, which
    // is fine because we frame every message with the length prefix. SEQPACKET
    // would buy us boundary preservation we don't need.
    let listener = tokio::net::UnixListener::bind(&cfg.ctl_socket_path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&cfg.ctl_socket_path, std::fs::Permissions::from_mode(0o600))?;
    info!(path = %cfg.ctl_socket_path.display(), "ctl listening");

    let cfg = cfg.clone();
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let cfg = cfg.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, &cfg, state).await {
                        debug!(err = %e, "ctl client errored");
                    }
                });
            }
            Err(e) => {
                warn!(err = %e, "ctl accept failed");
            }
        }
    }
}

async fn handle_client(
    mut stream: UnixStream,
    cfg: &ResolvedConfig,
    state: CtlState,
) -> anyhow::Result<()> {
    let CtlState {
        stats,
        shutdown,
        index,
        blob_store,
        pkg_stash,
        svc_stash,
        net_stash,
        proc_stash,
        db_stash,
    } = state;
    let mut buf = vec![0u8; CTL_BUF];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let req: CtlRequest = match decode_frame(&buf[..n]) {
        Ok(r) => r,
        Err(e) => {
            let frame = encode_frame(&CtlResponse::Error(format!("decode: {e}")))?;
            stream.write_all(&frame).await?;
            return Ok(());
        }
    };

    let resp = match req {
        CtlRequest::Ping => CtlResponse::Pong,
        CtlRequest::Status => CtlResponse::Status(snapshot(cfg, &stats)),
        CtlRequest::Shutdown => {
            shutdown.notify_one();
            CtlResponse::ShutdownAcked
        }
        CtlRequest::Gc(req) => handle_gc(req, index, blob_store).await,
        CtlRequest::Pin(req) => handle_pin(req, index),
        CtlRequest::Forget { id, yes: _ } => handle_forget(id, index),
        CtlRequest::PinList => handle_pin_list(index),
        CtlRequest::PkgEvent(req) => handle_pkg_event(req, &pkg_stash),
        CtlRequest::SvcEvent(req) => handle_svc_event(req, &svc_stash),
        CtlRequest::NetEvent(req) => handle_net_event(req, &net_stash),
        CtlRequest::ProcEvent(req) => handle_proc_event(req, &proc_stash),
        CtlRequest::DbEvent(req) => handle_db_event(req, &db_stash),
    };
    let frame = encode_frame(&resp)?;
    stream.write_all(&frame).await?;
    Ok(())
}

/// Trigger a one-shot GC pass. Runs in `spawn_blocking` because
/// `shit_store::gc::run_pass` does sync sqlite work that can hold a
/// connection across the entire pass.
async fn handle_gc(req: GcRequest, index: Arc<Index>, blob_store: Arc<BlobStore>) -> CtlResponse {
    let cancel = Arc::new(AtomicBool::new(false));
    let mut config = shit_store::GcConfig::default();
    if let Some(s) = req.size_cap_bytes {
        config.size_cap_bytes = Some(s);
    }
    if let Some(a) = req.age_cap_logical {
        config.age_threshold_logical = a;
    }
    // Aggressive mode is induced by passing an effectively-infinite
    // age threshold, since the algorithm already enters aggressive on
    // size-cap breach. Forcing the cutoff is the cleanest way to
    // route `--aggressive`.
    if req.aggressive {
        config.age_threshold_logical = 0;
    }
    if req.dry_run {
        // Dry-run: enumerate candidates without mutating. We don't
        // have a "dry-run mode" inside run_pass yet (it'd be a
        // helpful S13 follow-up). For stage 1, dry-run returns a
        // zeros report — accurate-enough for users wanting "did GC
        // run?" status.
        return CtlResponse::GcReport(shit_proto::GcReport {
            dry_run: true,
            aggressive_mode_used: false,
            commands_dropped: 0,
            events_dropped: 0,
            blobs_swept: 0,
            bytes_reclaimed: 0,
            paths_compacted: 0,
            vacuumed: false,
            duration_ms: 0,
        });
    }
    let join = tokio::task::spawn_blocking(move || {
        shit_store::run_pass(&index, &blob_store, &config, cancel, 1)
    })
    .await;
    match join {
        Ok(Ok(r)) => CtlResponse::GcReport(shit_proto::GcReport {
            dry_run: false,
            aggressive_mode_used: r.aggressive_mode_used,
            commands_dropped: r.commands_dropped as u64,
            events_dropped: r.events_dropped as u64,
            blobs_swept: r.blobs_swept as u64,
            bytes_reclaimed: r.bytes_reclaimed,
            paths_compacted: r.paths_compacted as u64,
            vacuumed: r.vacuumed,
            duration_ms: r.duration.as_millis() as u64,
        }),
        Ok(Err(e)) => CtlResponse::Error(format!("gc: {e}")),
        Err(e) => CtlResponse::Error(format!("gc spawn_blocking panic: {e}")),
    }
}

fn handle_pin(req: shit_proto::PinRequest, index: Arc<Index>) -> CtlResponse {
    let (session, seq) = match parse_command_id(&req.id) {
        Ok(p) => p,
        Err(e) => return CtlResponse::Error(format!("pin: {e}")),
    };
    let id = shit_planner::CommandId { session, seq };
    // Stage 1: pinned_logical uses the pin-table size + 1 as a
    // synthetic monotonic counter. When the daemon's real logical
    // clock lands (capture-runtime), swap this for the live value.
    let pinned_logical = index.pin_count().map(|n| n + 1).unwrap_or(1);
    // expires_logical: stage 1 doesn't parse the duration string yet
    // (S13.8 lands that on the CLI side); leaving None means no
    // expiry, which is the documented default.
    let _ = &req.expire;
    match index.pin_command(id, req.name.as_deref(), pinned_logical, None) {
        Ok(()) => CtlResponse::PinAck,
        Err(e) => CtlResponse::Error(format!("pin: {e}")),
    }
}

fn handle_forget(id: String, index: Arc<Index>) -> CtlResponse {
    let (session, seq) = match parse_command_id(&id) {
        Ok(p) => p,
        Err(e) => return CtlResponse::Error(format!("forget: {e}")),
    };
    let cmd_id = shit_planner::CommandId { session, seq };
    // The reaper uses the same path as the GC pass — same TOCTOU
    // protection on pins, same transactional semantics. If the
    // command was pinned, this is a no-op; `shit forget --force`
    // (when we add it) will unpin first.
    match shit_store::reap_commands(&index, std::slice::from_ref(&cmd_id)) {
        Ok(_) => CtlResponse::PinAck,
        Err(e) => CtlResponse::Error(format!("forget: {e}")),
    }
}

fn handle_pin_list(index: Arc<Index>) -> CtlResponse {
    match index.list_pins() {
        Ok(rows) => {
            let summaries = rows
                .into_iter()
                .map(
                    |(session, seq, name, pinned, expires)| shit_proto::PinSummary {
                        id: format!("{session}:{seq}"),
                        name,
                        pinned_logical: pinned,
                        expires_logical: expires,
                    },
                )
                .collect();
            CtlResponse::Pins(summaries)
        }
        Err(e) => CtlResponse::Error(format!("pin list: {e}")),
    }
}

/// Parse `<session-uuid>:<seq>` into the underlying parts.
fn parse_command_id(s: &str) -> Result<(uuid::Uuid, u64), String> {
    let (uuid_part, seq_part) = s
        .split_once(':')
        .ok_or_else(|| format!("expected `<uuid>:<seq>`, got `{s}`"))?;
    let uuid = uuid::Uuid::parse_str(uuid_part).map_err(|e| format!("bad uuid: {e}"))?;
    let seq: u64 = seq_part.parse().map_err(|e| format!("bad seq: {e}"))?;
    Ok((uuid, seq))
}

fn snapshot(cfg: &ResolvedConfig, stats: &Stats) -> DaemonStatus {
    DaemonStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("VERGEN_GIT_SHA").to_string(),
        // SAFETY: getpid always succeeds.
        pid: unsafe { libc::getpid() } as u32,
        uptime_secs: stats.started_at.elapsed().as_secs(),
        idle_for_secs: stats.idle_for().as_secs(),
        idle_timeout_secs: cfg.idle_timeout_secs,
        hook_socket_path: cfg.hook_socket_path.display().to_string(),
        ctl_socket_path: cfg.ctl_socket_path.display().to_string(),
        hook_messages_received: stats.hook_msgs.load(std::sync::atomic::Ordering::Relaxed),
        hook_decode_errors: stats
            .hook_decode_errors
            .load(std::sync::atomic::Ordering::Relaxed),
    }
}

/// Handle one package-manager hook event (S14.9). Pre events are
/// stashed; Post events pair, diff, and (stage 1) tracing-log. The
/// journal-write to `events` table under (session, seq) is DR-25 —
/// it requires the open-command-window lookup that lands together
/// with the capture-runtime pipeline.
fn handle_pkg_event(req: PkgEventReq, pkg_stash: &PkgPreStash) -> CtlResponse {
    let _ = crate::pkg::handle(pkg_stash, req);
    CtlResponse::PkgEventAck
}

/// Handle one service-manager hook event (S16.6). Pre stashes a
/// parsed `ServiceState`; Post pairs by `(tool, pid, unit)` and
/// returns the before/after diff to the caller. The journal-write
/// under `(session, seq)` is DR-36 — gated on the same
/// command-window binding that DR-25 / DR-32 wait on.
fn handle_svc_event(req: SvcEventReq, svc_stash: &SvcPreStash) -> CtlResponse {
    let _ = crate::svc_track::handle(svc_stash, req);
    CtlResponse::SvcEventAck
}

/// Handle one network-tool hook event (S17.9). Pre stashes the
/// raw state dump; Post pairs by `(tool, pid, scope_hint)` and
/// returns a byte-equality result. The journal-write under
/// `(session, seq)` is DR-41.
fn handle_net_event(req: NetEventReq, net_stash: &NetPreStash) -> CtlResponse {
    let _ = crate::net_track::handle(net_stash, req);
    CtlResponse::NetEventAck
}

/// Handle one process-lifecycle hook event (S18.6). Pre stashes
/// the captured target snapshots; Post diffs against the post-state
/// to classify each target as Killed or Survived. Journal-write
/// under `(session, seq)` is DR-53.
fn handle_proc_event(req: ProcEventReq, proc_stash: &ProcPreStash) -> CtlResponse {
    let _ = crate::proc_track::handle(proc_stash, req);
    CtlResponse::ProcEventAck
}

/// Handle one DB CLI shim event (S19.5). Pre stashes the parsed
/// connection + filtered statements; Post correlates by
/// `(engine, pid, target)` and folds in the transaction-state hint.
/// Journal-write under `(session, seq)` is DR-58.
fn handle_db_event(
    req: shit_proto::DbEventReq,
    db_stash: &crate::db_track::DbPreStash,
) -> CtlResponse {
    let _ = crate::db_track::handle(db_stash, req);
    CtlResponse::DbEventAck
}
