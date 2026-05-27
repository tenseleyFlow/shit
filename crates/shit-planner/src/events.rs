// SPDX-License-Identifier: AGPL-3.0-or-later

//! `CaptureEvent` — the atomic unit of recorded state.
//!
//! Each event is the smallest piece of information the planner needs to
//! reason about one mutating operation. Events are produced by the kernel
//! capture tier (S07/S08/S09/S10) or by tier-specific wrappers (package
//! managers, network tools, etc.), persisted via [`PlannerStore`](crate::store),
//! and consumed by the planner.

use crate::inode::{BlobHash, InodeRef};
use crate::inverse::{ContainerOp, ContainerRuntime};
use crate::metadata::{FileKind, FileMetadata};
use crate::time::TimePoint;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use uuid::Uuid;

/// Globally-unique event identifier. Assigned by the store at ingest time.
/// Cheap to clone; opaque to consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EventId(pub u64);

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ev{}", self.0)
    }
}

/// Globally-unique command identifier. The planner uses this to refer to a
/// command's bundle of events. Composed of `(session, seq)` for human
/// readability; opaque equality semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CommandId {
    pub session: Uuid,
    pub seq: u64,
}

impl std::fmt::Display for CommandId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.session, self.seq)
    }
}

/// The atomic unit of recorded state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureEvent {
    pub id: EventId,
    pub command: CommandId,
    pub ts: TimePoint,
    /// `true` when the capture was incomplete (e.g., source mutated mid-copy,
    /// or we got a post-hoc event without a pre-image). The planner treats
    /// partial events as informational and refuses to emit content-restore
    /// inverses for them.
    pub partial: bool,
    pub kind: CaptureEventKind,
}

/// G01.B.3 — Provenance of a `FilePreImage`'s captured bytes.
///
/// The planner's classifier needs to distinguish "the bytes captured
/// before the user's command started" (a faithful pre-command
/// snapshot, safe to restore) from "the bytes captured by some
/// intercept partway through the command" (may be in-command
/// mid-state, restoring it may corrupt user intent).
///
/// Only `BaselineCachePromote` carries a strong guarantee: the
/// W02.B LiveBaseline path on FreeBSD walks the watched subtree at
/// PreExec and caches each file's bytes; the cache is promoted to a
/// `FilePreImage` on first modification — by construction, the
/// captured bytes are exactly the file's content at PreExec time.
///
/// All other paths (LSM intercept, LD_PRELOAD shim, kqueue post-hoc
/// read) are `Other`. They may or may not represent pre-command
/// state — the planner can't tell from the capture alone, so it
/// falls back to its existing conservative event-shape classifier.
///
/// Why a discriminator over symptom-suppression (the BSD producer
/// could just suppress spurious Create events instead): the
/// discriminator surfaces the actual semantic ("we know this is
/// pre-command") at the planner's decision point. Symptom-
/// suppression patches one race in the BSD producer; the
/// discriminator generalizes to any capture tier where we can prove
/// the bytes are pre-command (a future macOS ES path with the same
/// guarantee, for instance, would set `BaselineCachePromote`).
///
/// Default is `Other` so postcard's `#[serde(default)]` deserializes
/// older events (pre-G01.B.3) into the existing conservative
/// classifier behavior — no change for already-journaled events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum FilePreImageSource {
    /// The captured bytes are a faithful pre-command snapshot. Set
    /// by the W02.B LiveBaseline promote path on FreeBSD; the cache
    /// is populated at PreExec and promoted on first modification.
    BaselineCachePromote,
    /// The captured bytes came from a mid-command intercept (LSM
    /// fanotify-perm, LD_PRELOAD shim, kqueue post-hoc). The
    /// classifier treats these conservatively — they may be
    /// pre-command or in-command, the planner can't tell from the
    /// capture alone.
    #[default]
    Other,
}

/// Variant payload of [`CaptureEvent`]. New tiers grow this enum; existing
/// variants are stable on-the-wire (postcard schema evolution rules apply).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureEventKind {
    /// Captured pre-mutation content + metadata of a file. The file existed
    /// before the syscall; we recorded its bytes (`blob`) and stat fields.
    ///
    /// `post_content_hash` records the content hash immediately after the
    /// kernel allowed the mutating syscall to complete. The planner uses it
    /// to detect post-capture modifications: if the current file content
    /// differs from `post_content_hash` at undo time, the file has been
    /// edited since our command and a `Conflict::Hard` is emitted so we
    /// don't silently overwrite the user's later edits.
    ///
    /// `None` means the capture tier didn't (or couldn't) compute the
    /// post-state — e.g. degraded macOS FSEvents-only mode. The planner
    /// proceeds without post-modification conflict detection in that case,
    /// and documentation warns the user.
    ///
    /// G01.B.3 — `source` records which capture path produced this
    /// pre-image. The planner's classifier consults it when deciding
    /// whether to fold "Create + Unlink + PreImage, file gone" into
    /// the line-256 transient safety-net (correct for Linux's
    /// touch+echo+rm shape where the pre-image is in-command empty
    /// bytes) or to override into atomic_replace (correct for BSD's
    /// W02.B baseline-promote where the pre-image is guaranteed
    /// pre-command state). See [`FilePreImageSource`].
    FilePreImage {
        inode: InodeRef,
        path: PathBuf,
        blob: BlobHash,
        meta: FileMetadata,
        post_content_hash: Option<BlobHash>,
        #[serde(default)]
        source: FilePreImageSource,
    },
    /// File metadata changed (chmod/chown/setxattr/setacl/utimes) without a
    /// content change. Stored separately from `FilePreImage` to avoid blob
    /// bloat for metadata-only ops.
    MetadataChange {
        inode: InodeRef,
        path: PathBuf,
        before: FileMetadata,
        after: FileMetadata,
    },
    /// Filesystem tree operations.
    TreeOp(TreeOp),
    /// Environment variable diff observed across a command (shell-side capture).
    /// All maps carry old (pre-command) values where applicable so undo can
    /// restore without re-querying the shell.
    EnvDiff {
        added: BTreeMap<String, String>,              // name -> value (post)
        removed: BTreeMap<String, String>,            // name -> value (pre)
        modified: BTreeMap<String, (String, String)>, // name -> (pre, post)
    },
    /// AR06.1 — shell-state diff observed across a command. The
    /// daemon computes this from the matching `PreExecShellState`
    /// and `PostExecShellState` HookMessages (see shit-helper
    /// `shell_state_track`). All four diff fields are optional;
    /// the daemon emits the event only when at least one is
    /// non-trivial. Planner maps to `InverseOp::ShellStateRestore`
    /// with snippets rendered per shell target.
    ///
    /// `serde(default)` on the additive fields (opts/aliases/funcs)
    /// so an older event journaled by the AR06.1-era daemon (pwd-
    /// only) round-trips cleanly through the v2 planner. Same in
    /// reverse: new events fed to an old planner just lose the
    /// extra diff fields.
    ShellStateDiff {
        pwd_before: PathBuf,
        pwd_after: PathBuf,
        /// AR06.2 — `set -o` option diffs. Each entry is a
        /// `(name, pre, post)` triple; "on"/"off" for booleans,
        /// raw string for stringly-typed options (history-size,
        /// ifs, etc — undo is best-effort for the latter).
        #[serde(default)]
        opts: Vec<(String, String, String)>,
        /// AR06.3 — alias diffs. Each entry is `(name, pre, post)`;
        /// `pre = None` means "didn't exist before this command",
        /// `post = None` means "was unset by this command".
        #[serde(default)]
        aliases: Vec<(String, Option<String>, Option<String>)>,
        /// AR06.4 (deferred) — function diffs. Wire-reserved; the
        /// daemon doesn't populate it yet because the bash hook
        /// doesn't ship function bodies. Same shape as `aliases`.
        #[serde(default)]
        funcs: Vec<(String, Option<String>, Option<String>)>,
    },
    /// Package-manager operation (apt/dpkg/pacman/dnf/brew/pkg).
    PackageOp {
        manager: PackageManager,
        op: PackageOpKind,
        packages_before: BTreeMap<String, String>, // name -> version
        packages_after: BTreeMap<String, String>,
        repo_state_hint: Option<String>,
    },
    /// Network / firewall / routing tool invocation (iptables/nft/ufw/pfctl/ip).
    NetworkOp {
        tool: NetworkTool,
        before_state: Vec<u8>,
        after_state: Vec<u8>,
        inverse_invocations: Vec<Vec<String>>,
    },
    /// systemd / launchd unit operation.
    SystemdOp {
        scope: SystemdScope,
        unit: String,
        before: ServiceState,
        after: ServiceState,
    },
    /// Process lifecycle (best-effort; informational only at undo time).
    ProcessOp {
        kind: ProcessOpKind,
        pid: u32,
        argv: Vec<String>,
        cwd: PathBuf,
        env_summary: BTreeMap<String, String>,
        parent_pid: u32,
        signal: Option<i32>,
    },
    /// DB CLI shim event (S19, DR-58). Captures a list of statements
    /// that crossed a `psql`/`mysql`/`sqlite3` invocation. Informational
    /// only — the planner emits an [`crate::inverse::InverseOp::DbNote`]
    /// pointing the user at a manual rollback. For sqlite3 the file
    /// tier captures the database file directly and the DbOp is a
    /// hint for renderable context.
    DbOp {
        engine: DbEngine,
        /// Connection target (db name for psql/mysql; file path for sqlite3).
        target: String,
        statements: Vec<String>,
        /// Engine-observed transaction state delta. `Unknown` when
        /// the engine probe (DR-56/57) wasn't wired or returned no info.
        transaction_state: DbTxState,
    },
    /// DR-CR-26 — container runtime operation captured by the
    /// `shit-helper container-event` subcommand. Mirrors
    /// [`crate::inverse::InverseOp::ContainerRestore`]'s shape: the
    /// planner's match-arm maps this 1:1 to the reverse InverseOp
    /// with the runtime + op + stash references intact. The capture
    /// side (helper subcommand) is responsible for the
    /// `docker inspect` / `docker save` / `docker volume tar` snapshot
    /// and for registering any tarball stashes in the container_stash
    /// store BEFORE emitting this event -- by event-ingest time the
    /// daemon trusts the stash references are valid.
    ContainerOp {
        runtime: ContainerRuntime,
        op: ContainerOp,
        /// Captured `<tool> inspect` (or compose config) JSON/YAML.
        /// Serialized as-is from the source tool; the executor's
        /// reverse path reads it back without re-parsing.
        captured_config: Vec<u8>,
        /// `shit-stash:<short-id>:<ts>` tag for the rootfs commit.
        /// Only populated by Rm (force-remove of a running container).
        stash_image: Option<String>,
        /// Blake3-addressed tarball in the container-stash store.
        /// Populated by Rmi (image save) and VolumeRm (volume tar).
        stash_tarball: Option<BlobHash>,
    },
    /// AR04 PR-A (DR-CR-06 cloud / IaC capture). The helper-side
    /// cloud-event wrapper (terraform / kubectl / gh / aws) shipped
    /// a captured pre-state snapshot. The orchestrator maps this to
    /// the matching `InverseOp::*Reverse` variant at undo time. The
    /// `runtime` distinguishes which tool (Terraform initially;
    /// kubectl / gh / aws land in AR04.3 / .4 / .5).
    TerraformOp {
        workdir: std::path::PathBuf,
        op: crate::inverse::TerraformOp,
        /// Pre-mutation `terraform state pull` output, captured by
        /// the helper before `apply` / `destroy`. Empty for verbs
        /// that don't carry a state snapshot (StateRm / Import ride
        /// the informational-skip path).
        prior_state: Vec<u8>,
    },
    /// AR04.3 (DR-CR-06 kubectl path). Helper-side cloud-event
    /// captured `kubectl get -o yaml <kind>/<name>` before the
    /// user's destructive verb (delete / apply over existing /
    /// scale / rollout); planner maps to
    /// [`crate::inverse::InverseOp::KubectlReverse`] which pipes
    /// the captured YAML to `kubectl apply -f -` at undo time.
    KubectlOp {
        context: String,
        namespace: Option<String>,
        op: crate::inverse::KubectlOp,
        captured_yaml: Vec<u8>,
    },
    /// AR04.4 (DR-CR-06 gh path). Helper-side cloud-event captured
    /// `gh release view --json ...` (or analogous) before the
    /// user's destructive verb. Planner maps to
    /// [`crate::inverse::InverseOp::GhReverse`] which the executor
    /// dispatches by op shape (release delete → create, issue
    /// close → reopen, etc).
    GhOp {
        op: crate::inverse::GhOp,
        captured_json: Vec<u8>,
    },
    /// AU10 — capture for a path was incomplete and undo MUST refuse
    /// the affected path rather than apply a wrong inverse. The
    /// daemon's shim_listener emits this when it sees a
    /// `ShimNotification::failure` populated; the planner converts
    /// it into a single [`crate::inverse::InverseOp::Refuse`] node
    /// for the path so the user-facing undo report carries an
    /// explicit "Refused (capture incomplete): …" line instead of
    /// silently mis-attributing or skipping.
    ///
    /// `class` is a stable identifier from the refuse-list catalog
    /// (initially `"capture-incomplete"`); `path` is the syscall's
    /// primary argument (rename `from`, unlink target, etc.);
    /// `detail` is the structured shim failure rendered as a
    /// human-readable string.
    CaptureRefused {
        class: String,
        path: PathBuf,
        detail: String,
    },
}

/// Mirror of [`shit_proto::DbEngineWire`] on the planner side so
/// events can serialize without dragging the wire crate into the
/// planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbEngine {
    Postgres,
    Mysql,
    Sqlite3,
}

/// Mirror of [`shit_proto::DbTxStateWire`]. Drives the renderer's
/// "rollback may not be required (transaction rolled back)" hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbTxState {
    /// Autocommit-on session; each statement is its own tx.
    AutoCommit,
    /// Engine reported commit during this command.
    Committed,
    /// Engine reported rollback during this command.
    RolledBack,
    /// Tx opened but not closed by the captured invocation.
    Unfinished,
    /// Engine probe wasn't wired or didn't return a state.
    Unknown,
}

fn default_unlink_kind_event() -> FileKind {
    FileKind::Regular
}
fn default_unlink_mode_event() -> u32 {
    0o100644
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreeOp {
    Create {
        inode: InodeRef,
        path: PathBuf,
        kind: FileKind,
        mode: u32,
    },
    Unlink {
        inode: InodeRef,
        path: PathBuf,
        /// G02 — kind + mode of the entry at unlink time. Used by
        /// `emit_for_tree_op` to drive `InverseOp::RecreatePath`
        /// with the correct file/dir distinction and original mode
        /// bits. `serde(default)` covers older journals (and the
        /// BSD kqueue tier, which doesn't yet plumb this through).
        #[serde(default = "default_unlink_kind_event")]
        kind: FileKind,
        #[serde(default = "default_unlink_mode_event")]
        mode: u32,
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
        inode: InodeRef,
    },
    Link {
        source: InodeRef,
        target: PathBuf,
    },
    Symlink {
        target: String, // symlink contents (string the kernel returns)
        path: PathBuf,  // location of the symlink itself
    },
    /// W09.16.1 — a pre-existing symlink was atomically replaced.
    /// Carries the OLD target so undo can restore it. The planner
    /// inverts this as `CreateSymlink { target, path }`; the
    /// new symlink's Unlink inverse (from the paired `Create`
    /// event) runs first, then this restores the original target.
    SymlinkRemoved {
        target: String, // the OLD symlink's target
        path: PathBuf,  // path of the symlink that was replaced
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageManager {
    Apt,
    Dpkg,
    Pacman,
    Dnf,
    Brew,
    Pkg, // FreeBSD pkg(8)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageOpKind {
    Install,
    Remove,
    Purge,
    Upgrade,
    Downgrade,
    Hold,
    Unhold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkTool {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SystemdScope {
    User,
    System,
    /// macOS launchd UI-attached (`gui/$(uid)`).
    LaunchdGui,
    /// macOS launchd system domain.
    LaunchdSystem,
    /// FreeBSD `service(8)` / rc.d framework. No user-scope split:
    /// scripts live under `/etc/rc.d` (base) or `/usr/local/etc/rc.d`
    /// (ports) and run system-wide.
    RcBase,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceState {
    pub active: bool,
    pub enabled: bool,
    pub masked: bool,
    /// Raw descriptor from the service manager (UnitFileState/ActiveState/etc.).
    /// Opaque to the planner; renders in `shit show`.
    pub raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessOpKind {
    /// A new process started under the user's command.
    Spawned,
    /// A process was killed by the command (e.g., `kill`/`pkill`).
    Killed,
    /// A process became its own session leader / detached (`nohup` / `&`).
    Detached,
    /// A process called `execve` and replaced its image.
    Exec,
}

/// Wraps a group of events that belong to one command, plus the
/// shell-observable metadata about that command. Produced by the store on
/// demand; events themselves are the canonical record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRecord {
    pub command: CommandId,
    pub cmd_string: Option<String>,
    pub cwd: PathBuf,
    pub pid: u32,
    pub shell_kind: shit_proto::ShellKind,
    pub started_at: TimePoint,
    pub ended_at: Option<TimePoint>,
    pub exit_code: Option<i32>,
    pub event_ids: Vec<EventId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inode() -> InodeRef {
        InodeRef::new(1, 42)
    }

    fn sample_meta() -> FileMetadata {
        FileMetadata {
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 100,
            mtime_unix_nanos: 0,
            xattrs: BTreeMap::new(),
            acl: None,
        }
    }

    fn sample_command() -> CommandId {
        CommandId {
            session: Uuid::nil(),
            seq: 1,
        }
    }

    #[test]
    fn capture_event_roundtrip_postcard() {
        let ev = CaptureEvent {
            id: EventId(1),
            command: sample_command(),
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: sample_inode(),
                path: PathBuf::from("/tmp/x"),
                blob: BlobHash::from_bytes([0x11; 32]),
                meta: sample_meta(),
                post_content_hash: Some(BlobHash::from_bytes([0x22; 32])),
                source: crate::FilePreImageSource::Other,
            },
        };
        let bytes = postcard::to_allocvec(&ev).unwrap();
        let back: CaptureEvent = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn event_id_display() {
        assert_eq!(format!("{}", EventId(7)), "ev7");
    }

    #[test]
    fn command_id_display() {
        let c = sample_command();
        let s = format!("{c}");
        assert!(s.contains(":1"));
    }

    #[test]
    fn tree_op_unlink_roundtrip() {
        let ev = CaptureEvent {
            id: EventId(2),
            command: sample_command(),
            ts: TimePoint::new(2, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: sample_inode(),
                path: PathBuf::from("/tmp/x"),
                kind: FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let bytes = postcard::to_allocvec(&ev).unwrap();
        let back: CaptureEvent = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn env_diff_roundtrip() {
        let mut added = BTreeMap::new();
        added.insert("FOO".to_string(), "bar".to_string());
        let ev = CaptureEvent {
            id: EventId(3),
            command: sample_command(),
            ts: TimePoint::new(3, 0),
            partial: false,
            kind: CaptureEventKind::EnvDiff {
                added,
                removed: {
                    let mut m = BTreeMap::new();
                    m.insert("BAZ".to_string(), "old".to_string());
                    m
                },
                modified: BTreeMap::new(),
            },
        };
        let bytes = postcard::to_allocvec(&ev).unwrap();
        let back: CaptureEvent = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(ev, back);
    }
}
