// SPDX-License-Identifier: AGPL-3.0-or-later

//! `CaptureEvent` — the atomic unit of recorded state.
//!
//! Each event is the smallest piece of information the planner needs to
//! reason about one mutating operation. Events are produced by the kernel
//! capture tier (S07/S08/S09/S10) or by tier-specific wrappers (package
//! managers, network tools, etc.), persisted via [`PlannerStore`](crate::store),
//! and consumed by the planner.

use crate::inode::{BlobHash, InodeRef};
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
    FilePreImage {
        inode: InodeRef,
        path: PathBuf,
        blob: BlobHash,
        meta: FileMetadata,
        post_content_hash: Option<BlobHash>,
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
