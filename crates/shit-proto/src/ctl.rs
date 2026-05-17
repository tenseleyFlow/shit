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
    /// systemctl/launchctl wrapper invocation (S16). Sent by
    /// `shit-helper svc-event ...` once per Pre and once per Post
    /// phase of a service operation. The daemon pairs by
    /// (pid, unit) — pid because a single shell may run multiple
    /// unrelated `systemctl` invocations, and unit because the same
    /// command can touch multiple units in sequence (rare but legal).
    SvcEvent(SvcEventReq),
    /// Network-tool wrapper invocation (S17). Sent by `shit-helper
    /// net-event ...` once per Pre and once per Post phase of an
    /// iptables/nft/ufw/pfctl/ip/route invocation. The daemon
    /// pairs by (tool, pid, scope_hint).
    NetEvent(NetEventReq),
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

/// Which service-manager CLI the wrapper is fronting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SvcToolWire {
    Systemctl,
    Launchctl,
}

impl SvcToolWire {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Systemctl => "systemctl",
            Self::Launchctl => "launchctl",
        }
    }
}

impl std::str::FromStr for SvcToolWire {
    type Err = SvcToolParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "systemctl" => Ok(Self::Systemctl),
            "launchctl" => Ok(Self::Launchctl),
            other => Err(SvcToolParseError(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown service tool: {0}")]
pub struct SvcToolParseError(pub String);

/// Service-manager scope hint. Mirrors `shit_planner::SystemdScope`
/// without depending on that crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SvcScopeWire {
    User,
    System,
    LaunchdGui,
    LaunchdSystem,
}

impl SvcScopeWire {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
            Self::LaunchdGui => "launchd-gui",
            Self::LaunchdSystem => "launchd-system",
        }
    }
}

/// Which network-tool CLI the wrapper is fronting. Mirrors
/// `shit_planner::NetworkTool` without dragging in that crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetToolWire {
    Iptables,
    Ip6tables,
    Nft,
    Ufw,
    Pfctl,
    IpRoute,
    IpAddr,
    IpLink,
    Route,
    Ifconfig,
    Networksetup,
}

impl NetToolWire {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Iptables => "iptables",
            Self::Ip6tables => "ip6tables",
            Self::Nft => "nft",
            Self::Ufw => "ufw",
            Self::Pfctl => "pfctl",
            Self::IpRoute => "ip-route",
            Self::IpAddr => "ip-addr",
            Self::IpLink => "ip-link",
            Self::Route => "route",
            Self::Ifconfig => "ifconfig",
            Self::Networksetup => "networksetup",
        }
    }
}

impl std::str::FromStr for NetToolWire {
    type Err = NetToolParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "iptables" => Ok(Self::Iptables),
            "ip6tables" => Ok(Self::Ip6tables),
            "nft" => Ok(Self::Nft),
            "ufw" => Ok(Self::Ufw),
            "pfctl" => Ok(Self::Pfctl),
            "ip-route" | "iproute" => Ok(Self::IpRoute),
            "ip-addr" | "ipaddr" => Ok(Self::IpAddr),
            "ip-link" | "iplink" => Ok(Self::IpLink),
            "route" => Ok(Self::Route),
            "ifconfig" => Ok(Self::Ifconfig),
            "networksetup" => Ok(Self::Networksetup),
            other => Err(NetToolParseError(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown network tool: {0}")]
pub struct NetToolParseError(pub String);

/// One network-tool wrapper invocation as it crosses the wire.
///
/// `scope_hint` carries tool-specific context the daemon uses to
/// disambiguate (iptables family, nft table, ufw is global so empty,
/// pfctl anchor path). The daemon doesn't interpret it; the planner
/// does on the inverse side.
///
/// `state_raw` is the raw tool-native dump (`iptables-save -c`,
/// `nft list ruleset -a`, `pfctl -s rules`, `ip -j route show`,
/// etc.). The wrapper script knows what to invoke per tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEventReq {
    pub tool: NetToolWire,
    pub phase: PkgPhase,
    pub verb: String,
    pub scope_hint: String,
    pub pid: u32,
    pub uid: u32,
    pub state_raw: Vec<u8>,
}

/// One service-manager wrapper invocation as it crosses the wire.
///
/// The wrapper invokes `shit-helper svc-event ...` once per phase
/// with the verb (e.g. `start`, `enable`) and the affected unit.
/// `state_raw` is the captured snapshot from the manager's own
/// query interface (`systemctl show -p ...` for systemd,
/// `launchctl print` for launchd); the planner parses it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvcEventReq {
    pub tool: SvcToolWire,
    pub phase: PkgPhase,
    pub scope: SvcScopeWire,
    pub unit: String,
    /// The shell-issued verb (`start`/`enable`/`bootstrap`/...).
    pub verb: String,
    pub pid: u32,
    pub uid: u32,
    /// Raw output of the manager's state-query command. May be
    /// empty if the query failed; the daemon tolerates that.
    pub state_raw: String,
}

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
    /// Reply to `SvcEvent` — same shape as `PkgEventAck`.
    SvcEventAck,
    /// Reply to `NetEvent` — same shape.
    NetEventAck,
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
