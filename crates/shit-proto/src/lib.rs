// SPDX-License-Identifier: AGPL-3.0-or-later

//! IPC protocol types and wire framing for `shit`.
//!
//! Wire format and message catalog are specified in `.docs/sprints/S01-shell-integration.md`.
//!
//! # Wire format
//!
//! Every frame on the wire is:
//!
//! ```text
//! | u32 BE total_payload_len | u8 wire_version | postcard(HookMessage) |
//! ```
//!
//! `total_payload_len` covers `wire_version` plus the postcard payload. For
//! SOCK_DGRAM transports the length prefix is technically redundant with the
//! datagram boundary, but we include it for parity with the FIFO/stream
//! fallback path and for cheap framing-level validation under fuzzing.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod crash;
pub mod ctl;
pub mod fault_inject;
pub mod frame;
pub mod helper;
pub mod shim;

pub use ctl::{
    BookmarkRequest, BookmarkSummary, CloudEventReq, CloudRuntimeWire, CloudVerbWire,
    ConflictPolicyWire, ContainerEventReq, ContainerRuntimeWire, ContainerStashSummary,
    ContainerVerbWire, CtlRequest, CtlResponse, DaemonStatus, DbConnInfo, DbEngineParseError,
    DbEngineWire, DbEventReq, DbTxStateWire, GcReport, GcRequest, MetricsSnapshot, NetEventReq,
    NetToolParseError, NetToolWire, PinRequest, PinSummary, PkgEventReq, PkgManagerParseError,
    PkgManagerWire, PkgPhase, PreStashRedirectError, PreStashRedirectsResult, ProcEventReq,
    ProcSnapshot, ProcToolParseError, ProcToolWire, RedirectOpWire, RedirectTargetWire,
    SvcEventReq, SvcScopeWire, SvcToolParseError, SvcToolWire, UndoReportWire, UndoRequest,
};
pub use frame::{
    DecodeError, EncodeError, MAX_FRAME_SIZE, MAX_LARGE_FRAME_SIZE, WIRE_VERSION, decode_frame,
    decode_frame_large, encode_frame, encode_frame_large,
};
pub use helper::{
    AuthDecision, AuthEventKind, FileKindWire, FileMetadataWire, HELPER_PATH_HINT_MAX,
    HELPER_PROTOCOL_VERSION, HelperCaps, HelperProtoError, HelperRequest, HelperResponse,
    MAX_HELPER_FRAME_SIZE, PrivilegedOpOutcome, TreeOpWire, validate_outgoing,
};
pub use shim::{SHIM_INLINE_PREIMAGE_CAP, ShimAck, ShimNotification, ShimPreImage};

/// One IPC message sent from a shell hook (or the CLI on its behalf) to `shitd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookMessage {
    /// Emitted once when a shell session starts.
    SessionOpen {
        session: Uuid,
        shell_kind: ShellKind,
        parent_pid: u32,
        tty: String,
        ts_unix_nanos: u64,
    },
    /// Emitted before each interactive command runs.
    PreExec {
        session: Uuid,
        seq: u64,
        pid: u32,
        cwd_inode: u64,
        cwd_dev: u64,
        /// Absolute cwd path. B05: capsicum-mode helpers can't resolve
        /// cwd via cross-pid sysctl (`KERN_PROC_CWD` lacks
        /// `CTLFLAG_CAPRD`), so the shell sends the path explicitly
        /// and the daemon forwards it via `HelperRequest::WatchTree`.
        cwd_path: String,
        ts_unix_nanos: u64,
        shell_kind: ShellKind,
        depth: u8,
    },
    /// Emitted after each interactive command exits.
    PostExec {
        session: Uuid,
        seq: u64,
        exit_code: i32,
        ts_unix_nanos: u64,
    },
    /// Optional companion to [`PreExec`] (S15). Carries the full
    /// pre-command env block (sorted `KEY=VALUE` joined by NUL) so
    /// the daemon can compute the post→pre diff once
    /// [`PostExecEnv`] arrives.
    ///
    /// DR-32 changed this from hash-only to block-carrying: the
    /// daemon needs the pre values to emit a real `EnvDiff`, and the
    /// 1–4 KB cost of sending the block over a local UDS is below
    /// noise (env blocks are typically <2 KB; the next biggest hook
    /// message — PostExec frame with argv — already runs larger).
    PreExecEnv {
        session: Uuid,
        seq: u64,
        env_block: Vec<u8>,
        ts_unix_nanos: u64,
    },
    /// Companion to [`PostExec`] (S15). Sent **only** when the env
    /// hash at postexec differs from the preexec one — in the common
    /// case (env unchanged across the command) this message is
    /// omitted entirely.
    ///
    /// `env_block` is the raw post-command env: sorted by key, joined
    /// by NUL as `KEY=VALUE\0KEY=VALUE\0...`. The daemon pairs this
    /// with the cached pre-block (reconstructed or re-requested per
    /// session) and emits a `CaptureEvent::EnvDiff`.
    PostExecEnv {
        session: Uuid,
        seq: u64,
        env_block: Vec<u8>,
        ts_unix_nanos: u64,
    },
    /// AR06.1 — pre-command shell-state snapshot. Carries pwd plus
    /// (AR06.2/.3) optional set-opts and aliases. The bash hook
    /// always sets `pwd`; `opts` and `aliases` are populated when
    /// the hook's shell-state collection routine runs (always-on
    /// since bash 4 — see shell/bash.sh `__shit_collect_state`).
    /// `serde(default)` on the additive fields so an old daemon
    /// reading a new client's envelope (or vice versa) round-trips
    /// cleanly.
    ///
    /// AR06.4 (functions) lands as another `#[serde(default)]` Vec
    /// in a follow-up PR — function-body capture is more delicate
    /// (multi-line bodies, `declare -f` output parsing) and earns
    /// its own focused scope.
    PreExecShellState {
        session: Uuid,
        seq: u64,
        pwd: String,
        /// AR06.2 — `(name, "on"|"off"|stringy-value)` pairs from
        /// `set -o`. Ordered as the shell emits them (typically
        /// alphabetical).
        #[serde(default)]
        opts: Vec<(String, String)>,
        /// AR06.3 — `(name, value)` pairs from the bash `alias`
        /// builtin. Values are the raw alias expansion (the bash
        /// hook strips the surrounding single-quotes and unescapes
        /// `'\\''` -> `'`).
        #[serde(default)]
        aliases: Vec<(String, String)>,
        ts_unix_nanos: u64,
    },
    /// Companion to [`PreExecShellState`]. Same field set; emitted
    /// after the user's command. Daemon pairs with the matching
    /// `PreExecShellState` by `(session, seq)`, diffs all four
    /// dimensions, and emits a `CaptureEventKind::ShellStateDiff`
    /// only when at least one differs.
    PostExecShellState {
        session: Uuid,
        seq: u64,
        pwd: String,
        #[serde(default)]
        opts: Vec<(String, String)>,
        #[serde(default)]
        aliases: Vec<(String, String)>,
        ts_unix_nanos: u64,
    },
    /// Emitted when the shell exits.
    SessionClose { session: Uuid, ts_unix_nanos: u64 },
}

impl HookMessage {
    pub fn session(&self) -> Uuid {
        match self {
            Self::SessionOpen { session, .. }
            | Self::PreExec { session, .. }
            | Self::PostExec { session, .. }
            | Self::PreExecEnv { session, .. }
            | Self::PostExecEnv { session, .. }
            | Self::PreExecShellState { session, .. }
            | Self::PostExecShellState { session, .. }
            | Self::SessionClose { session, .. } => *session,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::SessionOpen { .. } => "session-open",
            Self::PreExec { .. } => "pre-exec",
            Self::PostExec { .. } => "post-exec",
            Self::PreExecEnv { .. } => "pre-exec-env",
            Self::PostExecEnv { .. } => "post-exec-env",
            Self::PreExecShellState { .. } => "pre-exec-shell-state",
            Self::PostExecShellState { .. } => "post-exec-shell-state",
            Self::SessionClose { .. } => "session-close",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellKind {
    Bash,
    Zsh,
    Fish,
    Unknown,
}

impl ShellKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for ShellKind {
    type Err = ShellKindParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            "unknown" => Ok(Self::Unknown),
            other => Err(ShellKindParseError(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown shell kind: {0}")]
pub struct ShellKindParseError(pub String);
