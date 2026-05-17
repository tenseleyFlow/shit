// SPDX-License-Identifier: AGPL-3.0-or-later

//! Control-plane messages exchanged on the daemon's ctl socket. Used by the
//! `shit status` / `shit service status` paths.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    /// Package-manager hook invocation (S14). Sent by `shit-helper
    /// pkg-event ...` once per Pre and once per Post phase of a
    /// package operation. The daemon binds the event to the most
    /// recent open command window for the helper's process tree.
    PkgEvent(PkgEventReq),
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

/// Which side of a package transaction the hook is reporting.
///
/// `Pre` fires before the package manager mutates state — used to
/// stash the "before" version map. `Post` fires after; the daemon
/// pairs them by (session, seq) to compute the diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PkgPhase {
    Pre,
    Post,
}

/// Wire name of a package manager. Kept as a string here (not the
/// planner's `PackageManager` enum) because shit-proto is intentionally
/// dependency-free; the daemon maps this to the planner type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PkgManagerWire {
    Apt,
    Dpkg,
    Pacman,
    Dnf,
    Brew,
    Pkg,
}

impl PkgManagerWire {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dpkg => "dpkg",
            Self::Pacman => "pacman",
            Self::Dnf => "dnf",
            Self::Brew => "brew",
            Self::Pkg => "pkg",
        }
    }
}

impl std::str::FromStr for PkgManagerWire {
    type Err = PkgManagerParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "apt" => Ok(Self::Apt),
            "dpkg" => Ok(Self::Dpkg),
            "pacman" => Ok(Self::Pacman),
            "dnf" => Ok(Self::Dnf),
            "brew" => Ok(Self::Brew),
            "pkg" => Ok(Self::Pkg),
            other => Err(PkgManagerParseError(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown package manager: {0}")]
pub struct PkgManagerParseError(pub String);

/// One package-manager hook invocation as it crosses the wire from
/// `shit-helper pkg-event` to the daemon.
///
/// `pid` is the helper's PID; the daemon uses it (and its session/uid
/// hints) to locate the open command window the package op belongs to.
/// `packages` is a name→version map collected by the per-manager
/// inspector. `op_hint` is the manager's own classification when known
/// (e.g. dpkg passes `arg1=install/upgrade`); `None` means the daemon
/// must classify from the pre/post diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkgEventReq {
    pub manager: PkgManagerWire,
    pub phase: PkgPhase,
    pub pid: u32,
    pub uid: u32,
    pub packages: BTreeMap<String, String>,
    pub op_hint: Option<String>,
    /// Free-form manager-specific extras (apt sources list path, dnf
    /// history id, brew tap list, pacman locked-packages, etc.). The
    /// daemon stores these verbatim alongside the event for the
    /// planner to consult.
    pub extras: BTreeMap<String, String>,
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
    /// Reply to `PkgEvent` — short acknowledgement. The daemon does
    /// not return the diff or anything resembling it; the helper
    /// hook only cares that the event was recorded so it can return
    /// cleanly to its package-manager caller.
    PkgEventAck,
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
