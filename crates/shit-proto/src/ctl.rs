// SPDX-License-Identifier: AGPL-3.0-or-later

//! Control-plane messages exchanged on the daemon's ctl socket. Used by the
//! `shit status` / `shit service status` paths.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CtlRequest {
    /// Ask the daemon for a status snapshot.
    Status,
    /// Liveness ping; daemon must reply with `CtlResponse::Pong`.
    Ping,
    /// Ask the daemon to shut down cleanly.
    Shutdown,
    /// Trigger an immediate GC pass (S13.7). Replaces the periodic
    /// schedule's next tick.
    Gc(GcRequest),
    /// Pin a captured command's savepoint.
    Pin(PinRequest),
    /// Drop a captured command's savepoint.
    Forget { id: String, yes: bool },
    /// List currently pinned commands.
    PinList,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcRequest {
    pub dry_run: bool,
    pub aggressive: bool,
    /// Override the configured size cap for just this run, in bytes.
    pub size_cap_bytes: Option<u64>,
    /// Override the configured age cap for just this run, in logical units.
    pub age_cap_logical: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinRequest {
    /// Command id in `<session-uuid>:<seq>` form.
    pub id: String,
    pub name: Option<String>,
    /// Expiry as a duration string (e.g. "7d", "1h"). None = no expiry.
    pub expire: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcReport {
    pub dry_run: bool,
    pub aggressive_mode_used: bool,
    pub commands_dropped: u64,
    pub events_dropped: u64,
    pub blobs_swept: u64,
    pub bytes_reclaimed: u64,
    pub paths_compacted: u64,
    pub vacuumed: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinSummary {
    pub id: String,
    pub name: Option<String>,
    pub pinned_logical: u64,
    pub expires_logical: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CtlResponse {
    Status(DaemonStatus),
    Pong,
    ShutdownAcked,
    Error(String),
    /// Reply to `Gc`.
    GcReport(GcReport),
    /// Reply to `Pin` / `Forget` — short acknowledgement.
    PinAck,
    /// Reply to `PinList`.
    Pins(Vec<PinSummary>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub version: String,
    pub commit: String,
    pub pid: u32,
    pub uptime_secs: u64,
    pub idle_for_secs: u64,
    pub idle_timeout_secs: u64,
    pub hook_socket_path: String,
    pub ctl_socket_path: String,
    pub hook_messages_received: u64,
    pub hook_decode_errors: u64,
}
