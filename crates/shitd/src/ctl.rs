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
    ConflictPolicyWire, CtlRequest, CtlResponse, DaemonStatus, GcRequest, MAX_LARGE_FRAME_SIZE,
    NetEventReq, PkgEventReq, ProcEventReq, SvcEventReq, UndoReportWire, UndoRequest,
    decode_frame_large, encode_frame,
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
    pub active: Arc<crate::active_commands::ActiveCommands>,
    /// AR00.5 / task #105 — per-CommandId readiness rendezvous. Set
    /// to `None` when no helper is connected (degraded mode); the
    /// WaitWatchReady handler returns ready=false / "no helper"
    /// immediately so the shell hook doesn't block on a non-existent
    /// signal.
    pub watch_ready: Option<Arc<crate::watch_ready::WatchReadyMap>>,
}
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

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
        active,
        watch_ready,
    } = state;
    // Length-prefix-first read so we can grow the buffer up to
    // MAX_LARGE_FRAME_SIZE only when a large payload (ContainerEvent
    // tarball, AR03 PR-B) lands. Standard requests stay bounded by
    // MAX_FRAME_SIZE; the per-connection memory cost only blows up
    // for the genuine large-frame path.
    let mut header = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut header).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(());
        }
        return Err(e.into());
    }
    let body_len = u32::from_be_bytes(header) as usize;
    let total_len = 4 + body_len;
    if total_len > MAX_LARGE_FRAME_SIZE {
        let frame = encode_frame(&CtlResponse::Error(format!(
            "frame too large: {total_len} bytes"
        )))?;
        stream.write_all(&frame).await?;
        return Ok(());
    }
    let mut buf = vec![0u8; total_len];
    buf[..4].copy_from_slice(&header);
    if let Err(e) = stream.read_exact(&mut buf[4..]).await {
        let frame = encode_frame(&CtlResponse::Error(format!("read body: {e}")))?;
        stream.write_all(&frame).await?;
        return Ok(());
    }
    let req: CtlRequest = match decode_frame_large(&buf) {
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
        CtlRequest::Bookmark(req) => handle_bookmark(req, index),
        CtlRequest::BookmarkRemove { id, yes: _ } => handle_bookmark_remove(id, index),
        CtlRequest::BookmarkList => handle_bookmark_list(index),
        CtlRequest::ContainerStashesList => handle_container_stashes_list(index),
        CtlRequest::ContainerStashesPrune { older_than_secs } => {
            handle_container_stashes_prune(older_than_secs, index)
        }
        CtlRequest::PkgEvent(req) => handle_pkg_event(req, &pkg_stash, &active, &index),
        CtlRequest::SvcEvent(req) => handle_svc_event(req, &svc_stash, &active, &index),
        CtlRequest::NetEvent(req) => handle_net_event(req, &net_stash, &active, &index),
        CtlRequest::ProcEvent(req) => handle_proc_event(req, &proc_stash, &active, &index),
        CtlRequest::DbEvent(req) => handle_db_event(req, &db_stash, &active, &index),
        CtlRequest::ContainerEvent(req) => {
            handle_container_event(req, &active, &index, &blob_store)
        }
        CtlRequest::CloudEvent(req) => handle_cloud_event(req, &active, &index),
        CtlRequest::Metrics => CtlResponse::Metrics(metrics_snapshot(&stats, &index)),
        CtlRequest::Undo(req) => handle_undo(req, &index, &blob_store),
        CtlRequest::WaitWatchReady {
            session,
            command_seq,
            timeout_ms,
        } => {
            handle_wait_watch_ready(session, command_seq, timeout_ms, watch_ready.as_deref()).await
        }
        CtlRequest::PreStashRedirects {
            session,
            command_seq,
            targets,
        } => crate::redirect_track::handle(
            session,
            command_seq,
            targets,
            &active,
            &index,
            &blob_store,
        ),
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

fn handle_bookmark(req: shit_proto::BookmarkRequest, index: Arc<Index>) -> CtlResponse {
    let (session, seq) = match parse_command_id(&req.id) {
        Ok(p) => p,
        Err(e) => return CtlResponse::Error(format!("bookmark: {e}")),
    };
    let cmd = shit_planner::CommandId { session, seq };
    // Stage 1: synthetic monotonic logical counter, same approach as
    // `handle_pin`. When the daemon's real logical clock lands, replace.
    let created_logical = index.pin_count().map(|n| n + 1).unwrap_or(1);
    match shit_store::bookmarks::create(&index, cmd, created_logical, req.note.as_deref()) {
        Ok(()) => CtlResponse::BookmarkAck,
        Err(e) => CtlResponse::Error(format!("bookmark: {e}")),
    }
}

fn handle_bookmark_remove(id: String, index: Arc<Index>) -> CtlResponse {
    let (session, seq) = match parse_command_id(&id) {
        Ok(p) => p,
        Err(e) => return CtlResponse::Error(format!("bookmark-remove: {e}")),
    };
    let cmd = shit_planner::CommandId { session, seq };
    match shit_store::bookmarks::remove(&index, cmd) {
        Ok(true) => CtlResponse::BookmarkAck,
        Ok(false) => CtlResponse::Error(format!("bookmark-remove: no bookmark for {id}")),
        Err(e) => CtlResponse::Error(format!("bookmark-remove: {e}")),
    }
}

fn handle_bookmark_list(index: Arc<Index>) -> CtlResponse {
    match shit_store::bookmarks::list_all(&index) {
        Ok(rows) => {
            let summaries = rows
                .into_iter()
                .map(|b| shit_proto::BookmarkSummary {
                    id: format!("{}:{}", b.command.session, b.command.seq),
                    created_logical: b.created_logical,
                    note: b.note,
                })
                .collect();
            CtlResponse::Bookmarks(summaries)
        }
        Err(e) => CtlResponse::Error(format!("bookmark list: {e}")),
    }
}

/// C04.7: enumerate container-runtime stashes.
fn handle_container_stashes_list(index: Arc<Index>) -> CtlResponse {
    match shit_store::container_stash::list_all(&index) {
        Ok(rows) => {
            let summaries = rows
                .into_iter()
                .map(|s| shit_proto::ContainerStashSummary {
                    blob_hash: hex_encode(&s.blob_hash),
                    kind: s.kind.as_str().to_string(),
                    runtime: s.runtime,
                    name: s.name,
                    size_bytes: s.size_bytes,
                    created_unix_secs: s.created_unix_secs,
                    command: s.command.map(|c| format!("{}:{}", c.session, c.seq)),
                    note: s.note,
                })
                .collect();
            CtlResponse::ContainerStashes(summaries)
        }
        Err(e) => CtlResponse::Error(format!("container-stashes list: {e}")),
    }
}

/// Hex-encode a 32-byte hash. Lowercase, no separators. Avoids
/// pulling in the `hex` crate for one call site.
fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// C04.7: prune container stashes older than `older_than_secs`.
fn handle_container_stashes_prune(older_than_secs: u64, index: Arc<Index>) -> CtlResponse {
    // Fetch sizes BEFORE the prune so we can report bytes freed.
    let by_hash: std::collections::HashMap<[u8; 32], u64> =
        match shit_store::container_stash::list_all(&index) {
            Ok(rows) => rows
                .into_iter()
                .map(|s| (s.blob_hash, s.size_bytes))
                .collect(),
            Err(e) => {
                return CtlResponse::Error(format!("container-stashes prune (pre-scan): {e}"));
            }
        };
    match shit_store::container_stash::prune_older_than(&index, older_than_secs) {
        Ok(pruned) => {
            let bytes_freed: u64 = pruned.iter().filter_map(|h| by_hash.get(h)).sum();
            CtlResponse::ContainerStashPruneReport {
                pruned_count: pruned.len() as u64,
                bytes_freed,
            }
        }
        Err(e) => CtlResponse::Error(format!("container-stashes prune: {e}")),
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

/// Build a [`MetricsSnapshot`] (S21.4) by combining the in-memory
/// `Stats` with point-in-time store gauges. The store queries are
/// cheap (sqlite count/sum) but we tolerate failure: a gauge that
/// can't be read renders as 0 rather than failing the snapshot.
fn metrics_snapshot(stats: &Stats, index: &Arc<Index>) -> shit_proto::MetricsSnapshot {
    // SAFETY: getpid always succeeds.
    let pid = unsafe { libc::getpid() } as u32;
    let store_size_bytes = index.total_blob_size().unwrap_or(0);
    let store_blob_count = index.blob_count().unwrap_or(0);
    let store_command_count = index.command_count().unwrap_or(0);
    stats.snapshot(pid, store_size_bytes, store_blob_count, store_command_count)
}

/// Handle one package-manager hook event (S14.9). Pre events are
/// stashed; Post events pair, diff, and (stage 1) tracing-log. The
/// journal-write to `events` table under (session, seq) is DR-25 —
/// it requires the open-command-window lookup that lands together
/// with the capture-runtime pipeline.
fn handle_pkg_event(
    req: PkgEventReq,
    pkg_stash: &PkgPreStash,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
) -> CtlResponse {
    let _ = crate::pkg::handle(pkg_stash, req, active, index);
    CtlResponse::PkgEventAck
}

/// Handle one service-manager hook event (S16.6). Pre stashes a
/// parsed `ServiceState`; Post pairs by `(tool, pid, unit)` and
/// returns the before/after diff to the caller. The journal-write
/// under `(session, seq)` is DR-36 — gated on the same
/// command-window binding that DR-25 / DR-32 wait on.
fn handle_svc_event(
    req: SvcEventReq,
    svc_stash: &SvcPreStash,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
) -> CtlResponse {
    let _ = crate::svc_track::handle(svc_stash, req, active, index);
    CtlResponse::SvcEventAck
}

/// Handle one network-tool hook event (S17.9). Pre stashes the
/// raw state dump; Post pairs by `(tool, pid, scope_hint)` and
/// returns a byte-equality result. The journal-write under
/// `(session, seq)` is DR-41.
fn handle_net_event(
    req: NetEventReq,
    net_stash: &NetPreStash,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
) -> CtlResponse {
    let _ = crate::net_track::handle(net_stash, req, active, index);
    CtlResponse::NetEventAck
}

/// Handle one process-lifecycle hook event (S18.6). Pre stashes
/// the captured target snapshots; Post diffs against the post-state
/// to classify each target as Killed or Survived. Journal-write
/// under `(session, seq)` is DR-53.
fn handle_proc_event(
    req: ProcEventReq,
    proc_stash: &ProcPreStash,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
) -> CtlResponse {
    let _ = crate::proc_track::handle(proc_stash, req, active, index);
    CtlResponse::ProcEventAck
}

/// Handle one DB CLI shim event (S19.5). Pre stashes the parsed
/// connection + filtered statements; Post correlates by
/// `(engine, pid, target)` and folds in the transaction-state hint.
/// Journal-write under `(session, seq)` is DR-58.
fn handle_db_event(
    req: shit_proto::DbEventReq,
    db_stash: &crate::db_track::DbPreStash,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
) -> CtlResponse {
    let _ = crate::db_track::handle(db_stash, req, active, index);
    CtlResponse::DbEventAck
}

/// Handle one container-event request (DR-CR-26). PR-B extension:
/// the request may carry tarball bytes inline (small-image fast
/// path); the handler writes them to the blob store + registers a
/// container_stash row BEFORE journaling the ContainerOp event.
/// Always acks regardless of journaling outcome (the warn-log from
/// container_track::handle is the operator's failure signal); the
/// shell-issued container command shouldn't be punished for shit's
/// downstream issues.
fn handle_container_event(
    req: shit_proto::ContainerEventReq,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
    blob_store: &BlobStore,
) -> CtlResponse {
    let _ = crate::container_track::handle(req, active, index, blob_store);
    CtlResponse::ContainerEventAck
}

fn handle_cloud_event(
    req: shit_proto::CloudEventReq,
    active: &crate::active_commands::ActiveCommands,
    index: &Index,
) -> CtlResponse {
    let _ = crate::cloud_track::handle(req, active, index);
    CtlResponse::CloudEventAck
}

/// Adapt `BlobStore::get` into the planner's `BlobReader` trait.
struct BlobReaderShim<'a> {
    blob_store: &'a BlobStore,
}

impl shit_planner::BlobReader for BlobReaderShim<'_> {
    fn read(&self, hash: &shit_planner::BlobHash) -> Result<Vec<u8>, shit_planner::BlobReadError> {
        self.blob_store
            .get(*hash)
            .map_err(|e| shit_planner::BlobReadError::NotFound(format!("{hash:?}: {e}")))
    }
}

/// Multi-tier dispatcher used by `handle_undo`. The Orchestrator
/// takes one `InverseOpExecutor`; in production we need to route ops
/// to the file tier OR the package tier (and, future sprints, env /
/// service / network / proc tiers). Each tier's executor declares
/// which `InverseOp` variants it supports; we route by that.
///
/// Why not a planner-side composite executor: dispatch is daemon
/// policy, not planner logic. The planner doesn't know which tiers
/// the operator wants enabled (a hardened deployment might disable
/// PackageExecutor to refuse pkg rollbacks entirely).
struct MultiTierExecutor<'a> {
    file_executor: shit_planner::FileExecutor<'a, BlobReaderShim<'a>>,
    package_executor: shit_planner::executors::PackageExecutor<PrivilegedPkgRunner>,
    service_executor: shit_planner::executors::ServiceExecutor<PrivilegedSvcRunner>,
    network_executor: shit_planner::executors::NetworkExecutor<PrivilegedNetRunner>,
    container_executor: shit_planner::executors::ContainerExecutor<DaemonContainerRunner<'a>>,
    terraform_executor:
        shit_planner::executors::terraform::TerraformExecutor<DaemonTerraformRunner>,
    kubectl_executor: shit_planner::executors::kubectl::KubectlExecutor<DaemonKubectlRunner>,
    gh_executor: shit_planner::executors::gh::GhExecutor<DaemonGhRunner>,
    /// AR06.1 — shell-state restore. Always present; informational
    /// by default (prints the snippet); `apply_shell_state` flips
    /// it into precmd-queue mode at handle_undo time via a fresh
    /// constructor (not mutable here because we want one
    /// MultiTierExecutor per command-undone with the right
    /// session UUID wired).
    shell_state_executor: shit_planner::executors::shell_state::ShellStateExecutor<
        shit_planner::executors::shell_state::SystemShellStateRunner,
    >,
}

/// AR04.4: gh runner used by the daemon-side GhExecutor. Shells out
/// with `SHIT_DURING_UNDO=1` so the gh-wrapper short-circuits on
/// re-entry. `gh release create --notes-file -` is the canonical
/// reverse for release-delete, hence the stdin path.
struct DaemonGhRunner;

impl shit_planner::executors::gh::GhRunner for DaemonGhRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let status = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }

    fn run_with_stdin(&self, argv: &[String], stdin_bytes: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let mut child = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_bytes)
                .map_err(|e| format!("write stdin to {cmd}: {e}"))?;
        }
        let status = child.wait().map_err(|e| format!("wait {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
}

/// AR04.3: kubectl runner used by the daemon-side KubectlExecutor.
/// Shells out with `SHIT_DURING_UNDO=1` so the kubectl-wrapper
/// short-circuits on re-entry. The reverse path pipes captured
/// YAML to `kubectl apply -f -` via run_with_stdin.
struct DaemonKubectlRunner;

impl shit_planner::executors::kubectl::KubectlRunner for DaemonKubectlRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let status = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }

    fn run_with_stdin(&self, argv: &[String], stdin_bytes: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let mut child = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_bytes)
                .map_err(|e| format!("write stdin to {cmd}: {e}"))?;
        }
        let status = child.wait().map_err(|e| format!("wait {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }

    fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let out = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .output()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{cmd} exited {:?}", out.status.code()));
        }
        Ok(out.stdout)
    }
}

/// AR04 PR-A: terraform runner used by the daemon-side
/// TerraformExecutor. Shells out to the real `terraform` binary with
/// `SHIT_DURING_UNDO=1` (the wrapper short-circuits on re-entry) and
/// stages the captured `terraform state pull` bytes to a tempfile
/// the executor passes to `terraform state push`. The tempfile path
/// lives under the workdir's `.terraform/` if writeable, otherwise
/// `/tmp/` — terraform's state-push API needs a file path, not a
/// pipe.
struct DaemonTerraformRunner;

impl shit_planner::executors::terraform::TerraformRunner for DaemonTerraformRunner {
    fn run(&self, argv: &[String], workdir: &std::path::Path) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let status = std::process::Command::new(cmd)
            .args(args)
            .current_dir(workdir)
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }

    fn stash_bytes(
        &self,
        bytes: &[u8],
        workdir: &std::path::Path,
    ) -> Result<std::path::PathBuf, String> {
        use std::io::Write;
        // Prefer workdir's .terraform/ if it exists + is writable (so
        // the tempfile sits alongside the real state and any side-
        // effects stay contained); fall back to /tmp.
        let dir = {
            let tf_subdir = workdir.join(".terraform");
            if tf_subdir.is_dir() {
                tf_subdir
            } else {
                std::env::temp_dir()
            }
        };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = dir.join(format!("shit-tf-prior-{ts}.tfstate"));
        let mut f = std::fs::File::create(&path).map_err(|e| format!("create {path:?}: {e}"))?;
        f.write_all(bytes)
            .map_err(|e| format!("write {path:?}: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync {path:?}: {e}"))?;
        Ok(path)
    }
}

/// Container runner used by the daemon-side ContainerExecutor.
/// Identical to [`shit_planner::SystemContainerRunner`] for the
/// `docker run` / `docker load` / capture paths (shell out to the
/// real binary with `SHIT_DURING_UNDO=1`), but `load_stash_tarball`
/// resolves through the daemon's blob store rather than returning
/// `None` (the SystemContainerRunner's stub behavior gated on
/// DR-CR-26's wiring, now landed). Built per-undo-request and
/// captures a borrow of the blob store.
struct DaemonContainerRunner<'a> {
    blob_store: &'a BlobStore,
}

impl shit_planner::executors::ContainerRunner for DaemonContainerRunner<'_> {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let status = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
    fn run_with_stdin(&self, argv: &[String], stdin_bytes: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let mut child = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_bytes)
                .map_err(|e| format!("write stdin to {cmd}: {e}"))?;
        }
        let status = child.wait().map_err(|e| format!("wait {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
    fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let out = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .output()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{cmd} exited {:?}", out.status.code()));
        }
        Ok(out.stdout)
    }
    fn load_stash_tarball(&self, hash: &shit_planner::BlobHash) -> Option<Vec<u8>> {
        // AR03 PR-B (DR-CR-26): resolve the stash through the
        // daemon's blob store. `container_track::handle` already
        // ingested + content-addressed the tarball at capture time,
        // so the bytes are sitting under this blake3 key.
        self.blob_store.get(*hash).ok()
    }
}

/// PkgRunner that prefixes `doas` on non-Linux platforms where the
/// daemon runs unprivileged but pkg(8)/apt(8)/etc need root. On
/// Linux we expect `shit-helper` to hold the cap; here on BSD the
/// per-tool wrappers are the standard path. `SHIT_DURING_UNDO=1` is
/// set so the `pkg-event` hook short-circuits on re-entry.
struct PrivilegedPkgRunner;

impl shit_planner::executors::PkgRunner for PrivilegedPkgRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = match argv.split_first() {
            Some(v) => v,
            None => return Err("empty argv".into()),
        };
        // Look up doas / sudo at runtime; refuse if neither is available.
        let escalator = [
            "/usr/local/bin/doas",
            "/usr/local/bin/sudo",
            "/usr/bin/sudo",
        ]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file());
        let mut command = match escalator {
            Some(e) => {
                let mut c = std::process::Command::new(e);
                c.arg(cmd);
                c.args(args);
                c
            }
            None => {
                // Run directly — works if shitd happens to be root or
                // the operator deliberately runs as root. Tests on the
                // dev box go through here.
                let mut c = std::process::Command::new(cmd);
                c.args(args);
                c
            }
        };
        let status = command
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
}

/// Same shape as [`PrivilegedPkgRunner`] for `service(8)` invocations on
/// FreeBSD. Looks up `doas`/`sudo` at runtime; falls back to a direct
/// invocation if neither is present (works when shitd happens to be
/// root). `SHIT_DURING_UNDO=1` short-circuits the helper's svc-event
/// hook on re-entry.
struct PrivilegedSvcRunner;

impl shit_planner::executors::SvcRunner for PrivilegedSvcRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = match argv.split_first() {
            Some(v) => v,
            None => return Err("empty argv".into()),
        };
        let escalator = [
            "/usr/local/bin/doas",
            "/usr/local/bin/sudo",
            "/usr/bin/sudo",
        ]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file());
        let mut command = match escalator {
            Some(e) => {
                let mut c = std::process::Command::new(e);
                c.arg(cmd);
                c.args(args);
                c
            }
            None => {
                let mut c = std::process::Command::new(cmd);
                c.args(args);
                c
            }
        };
        let status = command
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
}

/// Same shape as [`PrivilegedSvcRunner`] for `pfctl`/`iptables`/`nft`
/// /`ufw` etc. The wrappers in `packaging/net-hooks/` intercept the
/// user's invocation and ship a `net-event` to the daemon; on undo
/// the daemon shells out via this runner to restore the prior state.
/// On BSD/macOS that requires root (pfctl needs CAP_NET_ADMIN on
/// Linux; pf-equivalent on BSD); doas/sudo is the privilege bridge.
struct PrivilegedNetRunner;

impl shit_planner::executors::NetRunner for PrivilegedNetRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = match argv.split_first() {
            Some(v) => v,
            None => return Err("empty argv".into()),
        };
        let escalator = [
            "/usr/local/bin/doas",
            "/usr/local/bin/sudo",
            "/usr/bin/sudo",
        ]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file());
        let mut command = match escalator {
            Some(e) => {
                let mut c = std::process::Command::new(e);
                c.arg(cmd);
                c.args(args);
                c
            }
            None => {
                let mut c = std::process::Command::new(cmd);
                c.args(args);
                c
            }
        };
        let status = command
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
    fn stash_bytes(&self, bytes: &[u8]) -> Result<std::path::PathBuf, String> {
        // No privilege needed — write to the daemon's temp dir.
        // The escalated tool (doas pfctl …) reads the file as root
        // and the daemon-owned tempfile is world-readable enough
        // for that path (mode 0644 by default). We set 0644
        // explicitly to be sure.
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let mut path = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("shit-net-{pid}-{nanos}.dump"));
        let mut f = std::fs::File::create(&path).map_err(|e| format!("create tmp: {e}"))?;
        f.write_all(bytes).map_err(|e| format!("write tmp: {e}"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("chmod tmp: {e}"))?;
        Ok(path)
    }
}

impl shit_planner::executor::InverseOpExecutor for MultiTierExecutor<'_> {
    fn supports(&self, op: &shit_planner::InverseOp) -> bool {
        self.file_executor.supports(op)
            || self.package_executor.supports(op)
            || self.service_executor.supports(op)
            || self.network_executor.supports(op)
            || self.container_executor.supports(op)
            || self.terraform_executor.supports(op)
            || self.kubectl_executor.supports(op)
            || self.gh_executor.supports(op)
            || self.shell_state_executor.supports(op)
    }

    fn execute(
        &self,
        op: &shit_planner::InverseOp,
        dry_run: bool,
        policy: shit_planner::ConflictPolicy,
    ) -> shit_planner::ExecutionOutcome {
        if self.file_executor.supports(op) {
            self.file_executor.execute(op, dry_run, policy)
        } else if self.package_executor.supports(op) {
            self.package_executor.execute(op, dry_run, policy)
        } else if self.service_executor.supports(op) {
            self.service_executor.execute(op, dry_run, policy)
        } else if self.network_executor.supports(op) {
            self.network_executor.execute(op, dry_run, policy)
        } else if self.container_executor.supports(op) {
            self.container_executor.execute(op, dry_run, policy)
        } else if self.terraform_executor.supports(op) {
            self.terraform_executor.execute(op, dry_run, policy)
        } else if self.kubectl_executor.supports(op) {
            self.kubectl_executor.execute(op, dry_run, policy)
        } else if self.gh_executor.supports(op) {
            self.gh_executor.execute(op, dry_run, policy)
        } else if self.shell_state_executor.supports(op) {
            self.shell_state_executor.execute(op, dry_run, policy)
        } else {
            shit_planner::ExecutionOutcome::Failed {
                err: format!("no executor wired for tier {:?}", op.tier()),
            }
        }
    }
}

/// AR00.5 / task #105 — handler for `CtlRequest::WaitWatchReady`.
///
/// Blocks the calling ctl client (typically `shit hook-send pre-exec`
/// from a shell PreExec hook) until the helper has signaled
/// `HelperResponse::WatchTreeReady` for the specified (session,
/// command_seq) -- which means kernel-tier capture is genuinely set
/// up and the user's command can safely run without racing the
/// helper's watch_tree handling.
///
/// Returns:
/// - `WatchReady { ready: true, reason: None }` on success.
/// - `WatchReady { ready: false, reason: Some("no helper") }` when
///   no helper is connected (degraded mode); returned immediately
///   so we don't punish the shell for a degraded daemon.
/// - `WatchReady { ready: false, reason: Some("timeout") }` when the
///   caller's `timeout_ms` expires before readiness arrives.
async fn handle_wait_watch_ready(
    session: uuid::Uuid,
    command_seq: u64,
    timeout_ms: u32,
    watch_ready: Option<&crate::watch_ready::WatchReadyMap>,
) -> CtlResponse {
    let Some(map) = watch_ready else {
        return CtlResponse::WatchReady {
            ready: false,
            reason: Some("no helper".to_string()),
        };
    };
    let cmd = shit_planner::events::CommandId {
        session,
        seq: command_seq,
    };
    let rx = map.await_ready(cmd);
    let timeout = std::time::Duration::from_millis(u64::from(timeout_ms));
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(())) => CtlResponse::WatchReady {
            ready: true,
            reason: None,
        },
        Ok(Err(_canceled)) => CtlResponse::WatchReady {
            ready: false,
            reason: Some("canceled".to_string()),
        },
        Err(_) => CtlResponse::WatchReady {
            ready: false,
            reason: Some("timeout".to_string()),
        },
    }
}

/// S24.C — execute an UndoPlan derived from the most recent N completed
/// commands. Returns a wire-friendly report; the CLI prints it as-is.
fn handle_undo(req: UndoRequest, index: &Index, blob_store: &BlobStore) -> CtlResponse {
    use shit_planner::{
        ConflictPolicy, FileExecutor, LiveStateProbe, Orchestrator, OutcomeKind, plan,
    };

    let policy = match req.on_conflict {
        ConflictPolicyWire::Abort => ConflictPolicy::Abort,
        ConflictPolicyWire::Skip => ConflictPolicy::Skip,
        ConflictPolicyWire::Force => ConflictPolicy::Force,
    };

    let paths_filter = match shit_planner::compile_paths_filter(&req.paths) {
        Ok(set) => set,
        Err(e) => {
            return CtlResponse::Error(format!("undo: bad --paths filter: {e}"));
        }
    };

    let commands = match index.list_recent_commands(req.steps.max(1)) {
        Ok(v) => v,
        Err(e) => {
            return CtlResponse::Error(format!("undo: list_recent_commands: {e}"));
        }
    };
    if commands.is_empty() {
        return CtlResponse::UndoReport(UndoReportWire {
            commands_attempted: 0,
            ops_applied: 0,
            ops_skipped: 0,
            ops_failed: 0,
            ops_conflicted: 0,
            ops_refused: 0,
            dry_run: req.dry_run,
            summary: "no completed commands recorded; nothing to undo".to_string(),
            detail_lines: Vec::new(),
            refusal_lines: Vec::new(),
        });
    }

    let probe = LiveStateProbe::new();
    let reader = BlobReaderShim { blob_store };

    let mut commands_attempted = 0u32;
    let mut ops_applied = 0u32;
    let mut ops_skipped = 0u32;
    let mut ops_failed = 0u32;
    let mut ops_conflicted = 0u32;
    let mut ops_refused = 0u32;
    let mut detail_lines: Vec<String> = Vec::new();
    let mut refusal_lines: Vec<String> = Vec::new();

    use shit_planner::PlannerStore;
    for cmd in commands {
        commands_attempted += 1;
        let events = index.events_for_command(cmd.command);
        let undo_plan = plan(cmd.clone(), &events, &probe, index);
        // AR06.1: per-command executor so the shell-state runner
        // can be wired with the session-specific precmd-queue
        // path. Other tier executors are cheap stateless wrappers
        // (PrivilegedXxxRunner = unit struct), so rebuilding every
        // iteration is no measurable cost.
        let mut shell_state_exec = shit_planner::executors::shell_state::ShellStateExecutor::new(
            shit_planner::executors::shell_state::SystemShellStateRunner::new()
                .with_session(cmd.command.session.to_string()),
        );
        if req.apply_shell_state {
            // AR06.6 — pick the snippet target by session shell.
            // Before this, the daemon always handed the bash
            // snippet to the precmd-queue regardless of the user's
            // shell — fine when only bash had a hook, broken once
            // zsh ships its own.
            use shit_planner::executors::shell_state::ShellTarget;
            let target = match cmd.shell_kind {
                shit_proto::ShellKind::Bash => ShellTarget::Bash,
                shit_proto::ShellKind::Zsh => ShellTarget::Zsh,
                shit_proto::ShellKind::Fish => ShellTarget::Fish,
                shit_proto::ShellKind::Unknown => ShellTarget::Bash,
            };
            shell_state_exec = shell_state_exec.with_apply(target);
        }
        let executor = MultiTierExecutor {
            file_executor: FileExecutor::new(&reader),
            package_executor: shit_planner::executors::PackageExecutor::new(PrivilegedPkgRunner),
            service_executor: shit_planner::executors::ServiceExecutor::new(PrivilegedSvcRunner),
            network_executor: shit_planner::executors::NetworkExecutor::new(PrivilegedNetRunner),
            container_executor: shit_planner::executors::ContainerExecutor::new(
                DaemonContainerRunner { blob_store },
            ),
            terraform_executor: shit_planner::executors::terraform::TerraformExecutor::new(
                DaemonTerraformRunner,
            ),
            kubectl_executor: shit_planner::executors::kubectl::KubectlExecutor::new(
                DaemonKubectlRunner,
            ),
            gh_executor: shit_planner::executors::gh::GhExecutor::new(DaemonGhRunner),
            shell_state_executor: shell_state_exec,
        };
        let orch = Orchestrator::new(&executor, &probe).with_paths_filter(paths_filter.clone());
        let report = orch.run(&undo_plan, req.dry_run, policy);
        for rec in &report.records {
            match rec.outcome_kind {
                OutcomeKind::Applied | OutcomeKind::WouldApply => ops_applied += 1,
                OutcomeKind::Skipped => {
                    // AR07.2: separate refuse-list short-circuits
                    // from generic skip (filtered-by-path, conflict-
                    // skip). The orchestrator stamped the detail
                    // string with the catalog class + reason +
                    // remediation; surface it under refusal_lines
                    // so the CLI can render it under its own
                    // "Refused:" header.
                    //
                    // AR07.4: prepend the command-string so the user
                    // can correlate the refusal back to what they
                    // ran. Without this, multi-command undo (`shit
                    // undo --steps N` with N > 1) shows N refusal
                    // lines and the user can't tell which command
                    // triggered which.
                    if matches!(rec.op, shit_planner::InverseOp::Refuse { .. }) {
                        ops_refused += 1;
                        if let Some(d) = rec.detail.as_deref() {
                            let cmd_str = cmd.cmd_string.as_deref().unwrap_or("<unknown command>");
                            refusal_lines.push(format!("`{cmd_str}` -> {d}"));
                        }
                    } else {
                        ops_skipped += 1;
                        // AR06.6 — surface shell-state informational
                        // bodies (fish snippets, default no-apply
                        // mode) so the user actually sees what to
                        // copy-paste. Other skip categories (filtered
                        // by --paths, conflict-skip) stay silent here
                        // — their detail is either obvious from
                        // context or already surfaced elsewhere.
                        if matches!(rec.op, shit_planner::InverseOp::ShellStateRestore { .. })
                            && let Some(d) = rec.detail.as_deref()
                        {
                            detail_lines.push(format!("shell-state: {d}"));
                        }
                    }
                }
                OutcomeKind::Failed => {
                    ops_failed += 1;
                    detail_lines.push(format!(
                        "failed: {:?} — {}",
                        rec.tier,
                        rec.detail.as_deref().unwrap_or("(no detail)")
                    ));
                }
                OutcomeKind::ConflictSoft
                | OutcomeKind::ConflictHard
                | OutcomeKind::ConflictMissing
                | OutcomeKind::ConflictPhantom => {
                    ops_conflicted += 1;
                    detail_lines.push(format!(
                        "conflict ({:?}): {}",
                        rec.outcome_kind,
                        rec.detail.as_deref().unwrap_or("(no detail)")
                    ));
                }
            }
        }
    }

    let summary = format!(
        "undo report: commands={commands_attempted} applied={ops_applied} \
         skipped={ops_skipped} refused={ops_refused} failed={ops_failed} \
         conflicts={ops_conflicted} dry_run={}",
        req.dry_run,
    );
    CtlResponse::UndoReport(UndoReportWire {
        commands_attempted,
        ops_applied,
        ops_skipped,
        ops_failed,
        ops_conflicted,
        ops_refused,
        dry_run: req.dry_run,
        summary,
        detail_lines,
        refusal_lines,
    })
}
