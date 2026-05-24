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
    /// Bookmark a captured command — a metadata-only durable reference
    /// that survives blob-tier GC (and eventually survives the command
    /// row being reaped). C01.7-8.
    Bookmark(BookmarkRequest),
    /// Drop a bookmark.
    BookmarkRemove { id: String, yes: bool },
    /// List bookmarks.
    BookmarkList,
    /// C04.7: list container-runtime stashes (`docker save` image
    /// tarballs and volume tarballs).
    ContainerStashesList,
    /// C04.7: prune container stashes older than `older_than_secs`.
    /// Returns the count + total bytes freed in
    /// `ContainerStashPruneReport`.
    ContainerStashesPrune { older_than_secs: u64 },
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
    /// Process-lifecycle hook invocation (S18). Sent by
    /// `shit-helper proc-event` once per Pre and once per Post
    /// phase of a `kill`/`pkill`/`killall` invocation. Pre carries
    /// the captured argv/cwd/env_summary snapshot for each target
    /// process; Post reports which targets survived vs. went away.
    ProcEvent(ProcEventReq),
    /// Database CLI shim invocation (S19, stretch). Sent by
    /// `shit-helper db-event` once per Pre and once per Post phase of
    /// an opt-in `psql` / `mysql` / `sqlite3` invocation. Pre carries
    /// the parsed connection target and the statements about to run;
    /// Post carries the engine-specific commit/binlog/size delta so
    /// the planner can render a transaction_state hint.
    DbEvent(DbEventReq),
    /// DR-CR-26 — container-runtime destructive verb captured by
    /// `shit-helper container-event <tool>`. The helper has already
    /// run the pre-snapshot (`docker save` / `inspect` / volume tar /
    /// compose config) and registered any tarball stash in the
    /// `container_stashes` table; this request carries the descriptors
    /// the planner needs to emit `CaptureEvent::ContainerOp` into the
    /// journal. Daemon binds to the most recent open command window
    /// for the helper's process tree, same shape as `PkgEvent`.
    ContainerEvent(ContainerEventReq),
    /// AR04 PR-A (DR-CR-06 cloud-event ctl route): the
    /// helper-side cloud wrapper (terraform / kubectl / gh / aws)
    /// shipped a captured cloud event. Daemon binds to the most
    /// recent open command window for the helper's process tree,
    /// same shape as `ContainerEvent`. The `runtime` field
    /// distinguishes which tool (Terraform initially; kubectl /
    /// gh / aws land in AR04.3 / .4 / .5). `prior_state` carries
    /// the pre-mutation snapshot the executor needs for reverse
    /// (e.g. `terraform state pull` output).
    CloudEvent(CloudEventReq),
    /// One-shot perf-counter snapshot for `shit metrics` (S21.4).
    Metrics,
    /// S24.C — `shit undo` plan-fetch + execute. The daemon walks
    /// recent commands, builds an UndoPlan via shit_planner, and
    /// runs it via the Orchestrator. Returns an [`UndoReportWire`].
    /// We execute on the daemon side rather than shipping a serialized
    /// plan because the planner + blob store + index live there already.
    Undo(UndoRequest),
    /// AR00.5 / task #105 — block the caller (a shell hook
    /// `shit hook-send pre-exec ...`) until the helper finishes
    /// setting up capture for this (session, command_seq). The
    /// daemon awaits a `HelperResponse::WatchTreeReady` matching
    /// this command. Returns `WatchReady` with `ready=true` on
    /// success, or `ready=false` with `reason` set on timeout or
    /// when no helper is connected.
    ///
    /// Why this exists at the ctl layer rather than as a synchronous
    /// reply to the existing UDP PreExec hook: the hook socket is a
    /// `SOCK_DGRAM` fire-and-forget by design (sub-millisecond hook
    /// overhead matters); turning it into a request-response would
    /// touch every existing caller. The ctl path is already
    /// request-response so it's the natural home for the wait.
    WaitWatchReady {
        session: uuid::Uuid,
        command_seq: u64,
        /// Cap the wait. The shell hook should pick something large
        /// enough for cold-start helper (~1-2 s on a slow disk + cold
        /// BTF cache) but small enough that a hung helper doesn't
        /// hang the shell forever. Caller responsibility.
        timeout_ms: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoRequest {
    /// How many commands back to undo (LIFO).
    pub steps: u32,
    pub dry_run: bool,
    pub on_conflict: ConflictPolicyWire,
    /// Optional glob filters; ops whose path doesn't match are
    /// recorded as skipped. Empty means "no filter."
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictPolicyWire {
    Abort,
    Skip,
    Force,
}

/// Daemon-side execution report shipped back to the `shit undo` CLI.
/// Mirrors `shit_planner::ExecutionReport`'s essentials in a wire-safe
/// form — we deliberately don't serialize the full ExecutionRecord
/// list because some fields (Path, etc.) need stringification first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UndoReportWire {
    /// How many commands we attempted (after honoring `steps` and
    /// however many are available).
    pub commands_attempted: u32,
    pub ops_applied: u32,
    pub ops_skipped: u32,
    pub ops_failed: u32,
    pub ops_conflicted: u32,
    pub dry_run: bool,
    /// Human-readable summary for `shit undo` to print.
    pub summary: String,
    /// One line per failed/conflicted op, for the user to read.
    pub detail_lines: Vec<String>,
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

/// C01.8: bookmark request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkRequest {
    /// Command id in `<session-uuid>:<seq>` form.
    pub id: String,
    pub note: Option<String>,
}

/// C01.8: bookmark summary returned by `BookmarkList`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarkSummary {
    pub id: String,
    pub created_logical: u64,
    pub note: Option<String>,
}

/// C04.7: one row of `shit container-stashes list`. The wire shape is
/// dependency-free — we don't lift the planner's `ContainerStash`
/// type here because shit-proto stays leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStashSummary {
    /// Hex-encoded blake3 of the tarball bytes.
    pub blob_hash: String,
    /// `"image-save"` or `"volume-tar"`.
    pub kind: String,
    /// `"docker"` or `"podman"`.
    pub runtime: String,
    /// Image name (e.g. `nginx:1.25`) or volume name.
    pub name: String,
    pub size_bytes: u64,
    pub created_unix_secs: u64,
    /// Best-effort link back to the originating command, in
    /// `<session-uuid>:<seq>` form. `None` when the stash was
    /// registered before the command-window closed.
    pub command: Option<String>,
    pub note: Option<String>,
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
    /// FreeBSD's `service(8)` — wrapper around `/etc/rc.d/*` scripts.
    /// S29.6.
    Service,
}

impl SvcToolWire {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Systemctl => "systemctl",
            Self::Launchctl => "launchctl",
            Self::Service => "service",
        }
    }
}

impl std::str::FromStr for SvcToolWire {
    type Err = SvcToolParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "systemctl" => Ok(Self::Systemctl),
            "launchctl" => Ok(Self::Launchctl),
            "service" => Ok(Self::Service),
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
    /// FreeBSD's rc(8) base-system scope. There's no per-user
    /// equivalent in stock FreeBSD; user-spawned daemons typically
    /// run under their own session-tooling. S29.6.
    RcBase,
}

impl SvcScopeWire {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
            Self::LaunchdGui => "launchd-gui",
            Self::LaunchdSystem => "launchd-system",
            Self::RcBase => "rc-base",
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

/// Which kill-family tool the wrapper is fronting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcToolWire {
    Kill,
    Pkill,
    Killall,
}

impl ProcToolWire {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Kill => "kill",
            Self::Pkill => "pkill",
            Self::Killall => "killall",
        }
    }
}

impl std::str::FromStr for ProcToolWire {
    type Err = ProcToolParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "kill" => Ok(Self::Kill),
            "pkill" => Ok(Self::Pkill),
            "killall" => Ok(Self::Killall),
            other => Err(ProcToolParseError(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown process tool: {0}")]
pub struct ProcToolParseError(pub String);

/// One process snapshot captured at Pre time. Used to render a
/// restart suggestion if the kill succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcSnapshot {
    pub pid: u32,
    /// `comm` (15-char kernel-stored short name) — useful when
    /// argv has been overwritten (postgres et al.).
    pub comm: String,
    /// Full argv from `/proc/<pid>/cmdline` (NUL-separated; the
    /// helper splits before sending).
    pub argv: Vec<String>,
    pub cwd: String,
    /// Whitelisted env vars only. The whitelist matches S15's
    /// redaction story: TOKEN/SECRET/PASSWORD/API_KEY values are
    /// already redacted before they cross the wire.
    pub env_summary: std::collections::BTreeMap<String, String>,
    pub parent_pid: u32,
    /// Monotonic-clock start time in seconds since boot. Used for
    /// PID-reuse sanity checking on Post.
    pub start_time_secs: u64,
    /// Controlling tty if any (e.g. `/dev/pts/3`).
    pub tty: Option<String>,
}

/// One process-lifecycle hook invocation as it crosses the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcEventReq {
    pub tool: ProcToolWire,
    pub phase: PkgPhase,
    /// The user's argv (minus the tool name). For `kill -9 1234`
    /// this is `["-9", "1234"]`.
    pub target_argv: Vec<String>,
    /// Pre-state snapshots of each target. On Post this is the
    /// *current* state (or absent entries mean the pid is gone).
    pub targets: Vec<ProcSnapshot>,
    pub pid: u32,
    pub uid: u32,
}

/// Which DB CLI the wrapper is fronting (S19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbEngineWire {
    Postgres,
    Mysql,
    Sqlite3,
}

impl DbEngineWire {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "psql",
            Self::Mysql => "mysql",
            Self::Sqlite3 => "sqlite3",
        }
    }
}

impl std::str::FromStr for DbEngineWire {
    type Err = DbEngineParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "psql" | "postgres" | "postgresql" => Ok(Self::Postgres),
            "mysql" | "mariadb" => Ok(Self::Mysql),
            "sqlite3" | "sqlite" => Ok(Self::Sqlite3),
            other => Err(DbEngineParseError(other.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown db engine: {0}")]
pub struct DbEngineParseError(pub String);

/// Transaction-state hint computed at Post time. Coarse on purpose:
/// the planner uses it for UX ("this committed" / "this rolled back")
/// rather than for behavioral branching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbTxStateWire {
    /// autocommit-on session; each statement is its own tx.
    AutoCommit,
    /// `BEGIN; ... COMMIT;` observed via engine probe.
    Committed,
    /// `BEGIN; ... ROLLBACK;` observed via engine probe.
    RolledBack,
    /// Tx opened but not closed by the captured invocation (psql `-c BEGIN`
    /// without a matching `COMMIT`, or interactive session abandoned).
    Unfinished,
    /// Engine didn't tell us. The DB shim falls back to `Unknown` on
    /// probe failure rather than guessing.
    Unknown,
}

/// Connection-target hint, password ALREADY redacted at the helper.
/// `target` is the human-friendly identifier (db name for psql/mysql;
/// filename for sqlite3). `host` is empty for sqlite3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbConnInfo {
    pub host: String,
    pub port: Option<u16>,
    pub user: String,
    pub target: String,
}

/// One DB CLI shim invocation as it crosses the wire.
///
/// `statements` is the post-filtering list — read-only statements
/// (SELECT/SHOW/EXPLAIN-without-INTO) are dropped at the helper.
/// `transaction_state` is `Unknown` on the Pre side; on Post the
/// helper fills it in from the engine's own observability (binlog
/// position delta, `xact_commit` delta, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbEventReq {
    pub engine: DbEngineWire,
    pub phase: PkgPhase,
    pub conn: DbConnInfo,
    pub statements: Vec<String>,
    pub transaction_state: DbTxStateWire,
    pub pid: u32,
    pub uid: u32,
    /// Engine-specific extras: psql `xact_commit_delta`, mysql
    /// `binlog_position`, sqlite3 `file_path`. Free-form so the
    /// planner can grow new keys without bumping the wire.
    pub extras: BTreeMap<String, String>,
}

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

/// DR-CR-26 — container destructive verb captured by the helper's
/// `container-event <tool>` subcommand. The helper has already done
/// the heavy lifting (run `<tool> inspect` / `<tool> save` / volume
/// tar / compose config, registered any tarball stash in the
/// container_stashes table); this wire carries the descriptors the
/// daemon needs to journal a `CaptureEvent::ContainerOp`.
///
/// `runtime` distinguishes docker / podman delegation paths from
/// docker-compose. `verb` is the destructive verb (rm / rmi /
/// volume-rm / network-rm / compose-down) the wrapper detected from
/// argv. `captured_config` carries the JSON/YAML pre-state in the
/// tool's native format; the executor reads it back unparsed.
/// `stash_image` is the `shit-stash:<id>:<ts>` tag committed for Rm;
/// `stash_tarball` is the blake3-keyed tarball blob hash for Rmi /
/// VolumeRm. Both `None` for ops that don't need a content stash
/// (network-rm relies on inspect JSON alone).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEventReq {
    pub runtime: ContainerRuntimeWire,
    pub verb: ContainerVerbWire,
    pub captured_config: Vec<u8>,
    pub stash_image: Option<String>,
    /// 32-byte blake3 of the tarball stashed under
    /// `container_stashes`. Daemon side resolves to a `BlobHash`.
    pub stash_tarball: Option<[u8; 32]>,
    /// AR03 PR-B (DR-CR-26 inline-bytes path): the raw tarball
    /// bytes for the verb's stash, when present. Daemon writes to
    /// the blob store and registers under `stash_tarball`. Inline
    /// is the small-image fast path (alpine ~5 MB); large images
    /// route through the AR10.8 tempfile/SCM_RIGHTS path that's
    /// not yet implemented. `None` when no tarball (NetworkRm) or
    /// when the helper shipped via the future large-image route.
    pub stash_tarball_bytes: Option<Vec<u8>>,
    /// Verb-specific descriptors: for Rm/Rmi the target image/name,
    /// for VolumeRm the volume name + optional driver, for
    /// ComposeDown the compose-file path + project name, etc.
    /// Free-form so the daemon-side planner can grow new keys
    /// without bumping the wire.
    pub extras: BTreeMap<String, String>,
    pub pid: u32,
    pub uid: u32,
}

/// Container runtime (docker engine or podman). Mirrors
/// [`shit_planner::inverse::ContainerRuntime`] on the wire side so the
/// proto crate doesn't depend on the planner. `docker compose` and
/// `podman compose` both flow through here -- the runtime field
/// identifies which engine owns the compose plugin; the verb field
/// (set to ComposeDown) distinguishes the op shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerRuntimeWire {
    Docker,
    Podman,
}

/// Container destructive verb the wrapper classified from argv.
/// Mirrors [`shit_planner::inverse::ContainerOp`] without its
/// per-variant fields (those travel in `extras`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerVerbWire {
    Rm,
    Rmi,
    VolumeRm,
    NetworkRm,
    ComposeDown,
}

/// AR04 PR-A — cloud / IaC tool event ship from the helper wrappers
/// (terraform / kubectl / gh / aws). The daemon's `cloud_track`
/// handler resolves `pid` → `CommandId` and journals a
/// [`shit_planner::CaptureEventKind::TerraformOp`] (or per-runtime
/// equivalent) which the orchestrator routes to the matching
/// executor at undo time.
///
/// `prior_state` carries the snapshot the executor needs for reverse:
/// `terraform state pull` output for Terraform, the deleted YAML
/// for kubectl, the release metadata blob for gh, etc. May be empty
/// when the verb doesn't carry a state snapshot (e.g. read-only
/// observation that we still want journaled).
///
/// `workdir` is the user's CWD at capture — used by terraform to
/// pin which `.terraform/` dir the restore should reconcile against.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudEventReq {
    pub runtime: CloudRuntimeWire,
    pub verb: CloudVerbWire,
    pub workdir: String,
    pub prior_state: Vec<u8>,
    /// Verb-specific descriptors: for Terraform StateRm the resource
    /// address, for kubectl delete the resource name + namespace,
    /// for gh release the tag, etc. Free-form so the daemon-side
    /// planner can grow new keys without bumping the wire.
    pub extras: BTreeMap<String, String>,
    pub pid: u32,
    pub uid: u32,
}

/// Cloud runtime tool. Initially Terraform only (AR04.1); kubectl /
/// gh / aws variants land in AR04.3 / .4 / .5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudRuntimeWire {
    Terraform,
    Kubectl,
    Gh,
    Aws,
}

/// Cloud destructive verb the wrapper classified from argv.
/// Mirrors [`shit_planner::inverse::TerraformOp`] et al. without
/// per-variant fields (those travel in `extras`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudVerbWire {
    // Terraform
    TerraformApply,
    TerraformDestroy,
    TerraformStateRm,
    TerraformImport,
    // Kubectl (AR04.3)
    KubectlApply,
    KubectlDelete,
    // gh (AR04.4)
    GhReleaseCreate,
    GhReleaseDelete,
    // aws (AR04.5 strategy TBD)
    AwsGeneric,
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
    /// Reply to `Bookmark` / `BookmarkRemove` — short acknowledgement.
    BookmarkAck,
    /// Reply to `BookmarkList`.
    Bookmarks(Vec<BookmarkSummary>),
    /// Reply to `ContainerStashesList` (C04.7).
    ContainerStashes(Vec<ContainerStashSummary>),
    /// Reply to `ContainerStashesPrune` (C04.7).
    ContainerStashPruneReport {
        pruned_count: u64,
        bytes_freed: u64,
    },
    /// Reply to `PkgEvent` — short acknowledgement. The daemon does
    /// not return the diff or anything resembling it; the helper
    /// hook only cares that the event was recorded so it can return
    /// cleanly to its package-manager caller.
    PkgEventAck,
    /// Reply to `SvcEvent` — same shape as `PkgEventAck`.
    SvcEventAck,
    /// Reply to `NetEvent` — same shape.
    NetEventAck,
    /// Reply to `ProcEvent` — same shape.
    ProcEventAck,
    /// Reply to `DbEvent` — same shape.
    DbEventAck,
    /// Reply to `ContainerEvent` (DR-CR-26) — same shape as
    /// `PkgEventAck`. Fire-and-confirm; the daemon-side journaling
    /// happens synchronously before the ack, so by ack time the
    /// `CaptureEvent::ContainerOp` row is in the events table.
    ContainerEventAck,
    /// Reply to `CloudEvent` (AR04 PR-A) — same shape as
    /// `ContainerEventAck`.
    CloudEventAck,
    /// Reply to `Metrics` (S21.4).
    Metrics(MetricsSnapshot),
    /// Reply to `Undo` — execution report.
    UndoReport(UndoReportWire),
    /// Reply to `WaitWatchReady` (task #105). `ready=true` means the
    /// helper signaled `WatchTreeReady` for the requested command
    /// before the caller's timeout expired (or had already done so
    /// before the wait was issued -- the readiness map persists the
    /// state). `ready=false` with `reason` set when:
    ///   - the wait timed out (`reason="timeout"`)
    ///   - no helper is connected (`reason="no helper"`) — the
    ///     daemon answers immediately so the shell isn't punished
    ///     for a degraded-tier setup
    ///   - the daemon was shutting down (`reason="shutdown"`)
    WatchReady {
        ready: bool,
        reason: Option<String>,
    },
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

/// One-shot perf-counter snapshot for `shit metrics` (S21.4).
///
/// All values are point-in-time. The daemon recomputes on every
/// request rather than streaming continuously — the CLI is the
/// pacer (`--watch 1s` polls; `--format prometheus` is one-shot).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Daemon liveness counters.
    pub uptime_secs: u64,
    pub pid: u32,
    /// Hook-frame counters.
    pub hook_messages_received: u64,
    pub hook_decode_errors: u64,
    /// Hook-handling latency percentiles in microseconds.
    /// Recorded per [`crate::ctl::CtlRequest::HookFrame`] handling
    /// (S21.4 instruments `shitd::server::handle`). Empty when no
    /// samples have arrived yet.
    pub hook_latency_us_p50: u64,
    pub hook_latency_us_p99: u64,
    pub hook_latency_samples: u64,
    /// Store-side gauges, queried at snapshot time from sqlite.
    pub store_size_bytes: u64,
    pub store_blob_count: u64,
    pub store_command_count: u64,
    /// GC summary from the last completed pass; zeroed before the
    /// first pass.
    pub last_gc_duration_ms: u64,
    pub last_gc_bytes_reclaimed: u64,
    pub last_gc_at_unix_secs: u64,
    /// Kernel-tier classifier (Linux: "fanotify"/"bpf-lsm"; macOS:
    /// "endpoint-security"; FreeBSD: "kqueue"). Empty when capture
    /// tier not yet initialized.
    pub kernel_tier: String,
}
