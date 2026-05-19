// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper IPC protocol — the surface between `shitd` and `shit-helper`.
//!
//! Transport: SOCK_SEQPACKET UDS with [`crate::frame`] framing on each
//! datagram. Each `HelperFrame` carries a single message; fds are
//! attached via `SCM_RIGHTS` out-of-band (see `shit-helper` / `shitd`
//! `helper_link` for the sendmsg/recvmsg plumbing).
//!
//! Wire-version negotiation is the first thing on every connection;
//! every message after `Handshake` is tagged with the same wire version
//! as the framing layer carries in its header byte.
//!
//! See `.docs/audits/helper-protocol.md` for the threat model and
//! mitigation map.

use crate::ShellKind;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum helper frame size. Larger than the shell-hook frame
/// (`MAX_FRAME_SIZE = 4 KiB`) because AuthEvent path_hints can be up to
/// `PATH_MAX`. Helper messages travel over SEQPACKET; we still enforce
/// a hard cap on the decode side to defeat resource exhaustion.
pub const MAX_HELPER_FRAME_SIZE: usize = 8 * 1024;

/// Hard cap for `path_hint` strings. Slightly below PATH_MAX so we can
/// fit the rest of the message comfortably under [`MAX_HELPER_FRAME_SIZE`].
pub const HELPER_PATH_HINT_MAX: usize = 4000;

/// Helper protocol version negotiated at handshake. We bump this whenever
/// the message catalog changes incompatibly. Match-or-fail: helper and
/// daemon must agree exactly; cross-version connections refuse.
///
/// **Version 2 (S24.A):** added `HelperResponse::CapturedPreImage` for
/// the kqueue post-hoc capture path; daemon learns to recvmsg with a
/// cmsg buffer to extract the SCM_RIGHTS-attached staging fd.
pub const HELPER_PROTOCOL_VERSION: u16 = 3;

/// Capabilities the daemon expects the helper to expose. Helper replies
/// with the subset it can actually provide given the current platform
/// and privilege level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HelperCaps {
    /// Tracks a process subtree and reports descendant write-intent syscalls.
    pub watch_tree: bool,
    /// Subscribes to per-syscall auth events (ES / fanotify-perm / eBPF-LSM).
    pub auth_subscribe: bool,
    /// Installs package-manager native hooks (apt/pacman/dnf/brew/pkg).
    pub package_hook: bool,
}

impl HelperCaps {
    pub const fn full() -> Self {
        Self {
            watch_tree: true,
            auth_subscribe: true,
            package_hook: true,
        }
    }

    pub const fn degraded() -> Self {
        Self {
            watch_tree: false,
            auth_subscribe: false,
            package_hook: false,
        }
    }

    pub fn intersect(self, other: Self) -> Self {
        Self {
            watch_tree: self.watch_tree && other.watch_tree,
            auth_subscribe: self.auth_subscribe && other.auth_subscribe,
            package_hook: self.package_hook && other.package_hook,
        }
    }
}

/// Kind of kernel auth event surfaced by the helper. Mirrors the
/// per-platform event taxonomy at a portable level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthEventKind {
    /// File about to be opened for writing.
    OpenForWrite,
    /// File about to be renamed.
    Rename,
    /// File about to be unlinked.
    Unlink,
    /// File about to be mmap'd with PROT_WRITE | MAP_SHARED.
    MmapWrite,
    /// File about to be truncated.
    Truncate,
}

impl AuthEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenForWrite => "open-for-write",
            Self::Rename => "rename",
            Self::Unlink => "unlink",
            Self::MmapWrite => "mmap-write",
            Self::Truncate => "truncate",
        }
    }
}

/// Daemon → helper message catalog. The daemon initiates: handshake,
/// scope watches, decide on pending auth events, ping, shutdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelperRequest {
    /// First message on a fresh connection.
    Handshake {
        daemon_pid: u32,
        daemon_uid: u32,
        protocol_version: u16,
        capability_request: HelperCaps,
    },
    WatchTree {
        root_pid: u32,
        descendants_too: bool,
        session: Uuid,
        command_seq: u64,
        shell_kind: ShellKind,
    },
    UnwatchTree {
        session: Uuid,
        command_seq: u64,
    },
    /// Daemon's decision on a pending `AuthEvent`. Helper unblocks the
    /// kernel syscall after applying.
    AuthDecision {
        session: Uuid,
        seq: u64,
        decision: AuthDecision,
    },
    Ping {
        nonce: u64,
    },
    /// Tell the helper to exit cleanly. `reason` lands in the helper's
    /// shutdown log line — useful for debugging.
    Shutdown {
        reason: String,
    },
    /// DR-15 privileged-op routing: ask the helper to chown a path
    /// the daemon's unprivileged FileExecutor couldn't touch (target
    /// uid/gid differs from the daemon's effective uid, kernel
    /// returned EPERM). Helper validates the path is under the
    /// session's watched scope before applying.
    ApplyChown {
        session: Uuid,
        command_seq: u64,
        path: String,
        uid: u32,
        gid: u32,
        /// `true` = call lchown(2) instead of chown(2). The executor
        /// passes `true` when the target is a symlink — the captured
        /// metadata is the symlink's, not the target's.
        no_dereference: bool,
    },
    /// DR-15 privileged-op routing: mknod for character/block special
    /// files and FIFOs. Same audit shape as ApplyChown — helper
    /// rejects when the path escapes the watched scope.
    ApplyMknod {
        session: Uuid,
        command_seq: u64,
        path: String,
        /// `S_IFCHR | S_IFBLK | S_IFIFO` plus the permission bits.
        mode: u32,
        /// Major + minor packed via libc::makedev. Ignored when
        /// `mode` indicates a FIFO.
        dev: u64,
    },
}

/// Helper → daemon message catalog. The helper reports its capabilities,
/// surfaces kernel events, and replies to pings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelperResponse {
    /// Helper's reply to `HelperRequest::Handshake`.
    HandshakeAck {
        helper_pid: u32,
        helper_uid: u32,
        protocol_version: u16,
        granted: HelperCaps,
        /// Free-form helper version string (e.g. `"shit-helper 0.1.0 (commit abc123)"`).
        helper_version: String,
        /// Capture tier classifier the helper is actually running on
        /// (DR-66). Examples: `"endpoint-security"`, `"fanotify"`,
        /// `"bpf-lsm"`, `"kqueue"`, `"preload-shim"`, `"degraded"`.
        /// Daemon stashes this in `Stats::kernel_tier` so
        /// `shit metrics` surfaces what's actually active.
        kernel_tier: String,
    },
    /// One pending auth event awaiting daemon's `AuthDecision`. The
    /// content fd (when needed) is attached via SCM_RIGHTS — never
    /// inline.
    AuthEvent {
        session: Uuid,
        seq: u64,
        kind: AuthEventKind,
        /// True when the corresponding sendmsg included a writable fd
        /// in `SCM_RIGHTS`. Decoders must recvmsg with a cmsg buffer.
        fd_sent_via_scm: bool,
        /// Optional path hint for telemetry. Bounded by
        /// [`HELPER_PATH_HINT_MAX`]; the authoritative reference is the
        /// fd, not this string.
        path_hint: Option<String>,
        dev: u64,
        inode: u64,
        requesting_pid: u32,
    },
    /// One post-hoc captured pre-image (S24.A, kqueue-tier producer).
    /// The bytes themselves arrive out-of-band via `SCM_RIGHTS` — the
    /// helper opens a staging file (or `memfd_create` on Linux,
    /// `shm_open(SHM_ANON)` on FreeBSD), writes the pre-image, and
    /// attaches the fd to the sendmsg. Daemon recvmsg's with a cmsg
    /// buffer to recover the fd, then reads, hashes (verify against
    /// `blob_hash`), and ingests into the canonical blob store.
    ///
    /// One-way: no daemon decision needed (unlike `AuthEvent`) because
    /// the kqueue path is post-hoc — the user's syscall has already
    /// completed by the time we emit this.
    CapturedPreImage {
        session: Uuid,
        seq: u64,
        /// Inode identity at capture time. Raw `(dev, inode)` rather
        /// than `shit_planner::InodeRef` to keep `shit-proto` free of
        /// the planner dep; daemon converts on ingest.
        dev: u64,
        inode: u64,
        /// Path the helper resolved the fd to at capture time. Bounded
        /// by [`HELPER_PATH_HINT_MAX`]. `None` when path recovery
        /// failed (e.g. inode-only access after unlink + dir close).
        path: Option<String>,
        /// blake3 hash the helper claims over the staging file's bytes.
        /// Daemon recomputes on ingest and refuses on mismatch — this
        /// is the integrity check that justifies the helper writing
        /// blobs the daemon trusts.
        blob_hash: [u8; 32],
        /// Size of the blob the helper claims it wrote. Daemon sizes
        /// its read buffer to this and refuses if the actual read
        /// length disagrees.
        stored_bytes: u64,
        /// Hash of the file's content immediately after the user's
        /// mutation (helper reads the post-state when reachable).
        /// `None` when the file was unlinked (the user `rm`'d it) and
        /// there is no post-state on disk to hash.
        post_content_hash: Option<[u8; 32]>,
        /// Stat-style metadata at capture time. Daemon converts to
        /// `shit_planner::FileMetadata` for `CaptureEvent::FilePreImage`.
        mode: u32,
        uid: u32,
        gid: u32,
        mtime_unix_nanos: i128,
        /// True when this capture was triggered by `NOTE_DELETE`. The
        /// daemon journals a paired `TreeOp::Unlink` so `shit undo`
        /// knows to recreate the file at `path`, not just restore the
        /// blob content to a now-deleted path.
        is_delete: bool,
        /// True when the corresponding sendmsg included the staging
        /// fd via `SCM_RIGHTS`. Decoders must recvmsg with a cmsg
        /// buffer to extract the fd.
        fd_sent_via_scm: bool,
    },
    /// S29.1 — tree-mutation observation (mkdir/rmdir/rename/symlink/link).
    /// One-way: no blob attached; the daemon converts to
    /// `CaptureEventKind::TreeOp(...)` and journals.
    TreeMutation {
        session: Uuid,
        seq: u64,
        op: TreeOpWire,
        ts_unix_nanos: u64,
    },
    /// DR-15 result of `ApplyChown` / `ApplyMknod`. Helper either
    /// applied the op or refused with a category.
    PrivilegedOpResult {
        session: Uuid,
        command_seq: u64,
        outcome: PrivilegedOpOutcome,
    },
    Pong {
        nonce: u64,
    },
    /// Helper is about to exit; no further messages will arrive after this.
    ShutdownAck {
        reason: String,
    },
    /// Helper saw something it couldn't handle. Includes a short reason
    /// for the daemon's logs. Helper does *not* exit on this; the daemon
    /// decides what to do.
    Error {
        message: String,
    },
}

/// DR-15 helper-applied result for a privileged-op request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegedOpOutcome {
    /// Helper applied the op.
    Applied,
    /// Helper refused: target path escaped the session's watched
    /// scope. Likely an executor or planner bug — surfaces as a
    /// clear error rather than silent success.
    OutOfScope,
    /// Helper attempted the op but the kernel still refused (e.g.,
    /// helper isn't running as root and the target uid still
    /// requires CAP_CHOWN). Caller surfaces as a Conflict.
    PermissionDenied,
    /// Path no longer exists. Race between capture and undo.
    NotFound,
    /// Any other helper-side failure.
    Failed { err: String },
}

/// Wire-side mirror of `shit_planner::TreeOp`. Kept duplicated here
/// rather than imported so `shit-proto` stays free of the planner
/// dep. The daemon converts on ingest (`shitd::helper_link::handle_tree_mutation`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TreeOpWire {
    Create {
        dev: u64,
        inode: u64,
        path: String,
        kind: FileKindWire,
        mode: u32,
    },
    Unlink {
        dev: u64,
        inode: u64,
        path: String,
    },
    Rename {
        from: String,
        to: String,
        dev: u64,
        inode: u64,
    },
    Link {
        source_dev: u64,
        source_inode: u64,
        target: String,
    },
    Symlink {
        /// Symlink target as the kernel returns (`readlink` output).
        target: String,
        /// Path of the symlink itself.
        path: String,
    },
}

/// Wire mirror of `shit_planner::FileKind`. Same enum shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileKindWire {
    Regular,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
}

/// Daemon's verdict on a pending kernel auth event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthDecision {
    /// Let the kernel syscall proceed without capture.
    Allow,
    /// Block the syscall (e.g., file already captured, shouldn't re-capture).
    Deny,
    /// Daemon has captured the pre-image and stored it; helper records
    /// the inode→blob mapping in its short-lived table (so a daemon
    /// restart mid-command can resume) and unblocks the syscall.
    AllowWithCapture {
        /// `blake3` hash of the captured pre-image.
        blob_hash: [u8; 32],
    },
}

/// Sanity-check a `HelperResponse` before sending. Returns an error if
/// the message would be obviously wrong on the wire — e.g. an
/// over-long `path_hint`.
pub fn validate_outgoing(resp: &HelperResponse) -> Result<(), HelperProtoError> {
    match resp {
        HelperResponse::AuthEvent { path_hint, .. } => {
            if let Some(p) = path_hint
                && p.len() > HELPER_PATH_HINT_MAX
            {
                return Err(HelperProtoError::PathHintTooLong {
                    got: p.len(),
                    max: HELPER_PATH_HINT_MAX,
                });
            }
        }
        HelperResponse::CapturedPreImage { path, .. } => {
            if let Some(p) = path
                && p.len() > HELPER_PATH_HINT_MAX
            {
                return Err(HelperProtoError::PathHintTooLong {
                    got: p.len(),
                    max: HELPER_PATH_HINT_MAX,
                });
            }
        }
        HelperResponse::TreeMutation { op, .. } => {
            // Validate every path field in the op variant.
            let longest = match op {
                TreeOpWire::Create { path, .. } | TreeOpWire::Unlink { path, .. } => path.len(),
                TreeOpWire::Rename { from, to, .. } => from.len().max(to.len()),
                TreeOpWire::Link { target, .. } => target.len(),
                TreeOpWire::Symlink { target, path } => target.len().max(path.len()),
            };
            if longest > HELPER_PATH_HINT_MAX {
                return Err(HelperProtoError::PathHintTooLong {
                    got: longest,
                    max: HELPER_PATH_HINT_MAX,
                });
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum HelperProtoError {
    #[error("path_hint too long: got {got}, max {max}")]
    PathHintTooLong { got: usize, max: usize },
    #[error("protocol version mismatch: helper {helper}, daemon {daemon}")]
    VersionMismatch { helper: u16, daemon: u16 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{decode_frame, encode_frame};

    #[test]
    fn handshake_round_trip() {
        let req = HelperRequest::Handshake {
            daemon_pid: 4242,
            daemon_uid: 501,
            protocol_version: HELPER_PROTOCOL_VERSION,
            capability_request: HelperCaps::full(),
        };
        let bytes = encode_frame(&req).unwrap();
        let decoded: HelperRequest = decode_frame(&bytes).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn handshake_ack_round_trip() {
        let ack = HelperResponse::HandshakeAck {
            helper_pid: 9000,
            helper_uid: 501,
            protocol_version: HELPER_PROTOCOL_VERSION,
            granted: HelperCaps {
                watch_tree: true,
                auth_subscribe: false,
                package_hook: true,
            },
            helper_version: "shit-helper 0.1.0 (commit deadbeef)".into(),
            kernel_tier: "fanotify".into(),
        };
        let bytes = encode_frame(&ack).unwrap();
        let decoded: HelperResponse = decode_frame(&bytes).unwrap();
        assert_eq!(ack, decoded);
    }

    #[test]
    fn auth_event_round_trip() {
        let ev = HelperResponse::AuthEvent {
            session: Uuid::nil(),
            seq: 42,
            kind: AuthEventKind::OpenForWrite,
            fd_sent_via_scm: true,
            path_hint: Some("/etc/sample".into()),
            dev: 16,
            inode: 12345,
            requesting_pid: 1337,
        };
        let bytes = encode_frame(&ev).unwrap();
        let decoded: HelperResponse = decode_frame(&bytes).unwrap();
        assert_eq!(ev, decoded);
    }

    #[test]
    fn auth_decision_capture_round_trip() {
        let decision = HelperRequest::AuthDecision {
            session: Uuid::nil(),
            seq: 7,
            decision: AuthDecision::AllowWithCapture {
                blob_hash: [0xAB; 32],
            },
        };
        let bytes = encode_frame(&decision).unwrap();
        let decoded: HelperRequest = decode_frame(&bytes).unwrap();
        assert_eq!(decision, decoded);
    }

    #[test]
    fn caps_intersect_is_min() {
        let a = HelperCaps {
            watch_tree: true,
            auth_subscribe: true,
            package_hook: false,
        };
        let b = HelperCaps {
            watch_tree: true,
            auth_subscribe: false,
            package_hook: true,
        };
        assert_eq!(
            a.intersect(b),
            HelperCaps {
                watch_tree: true,
                auth_subscribe: false,
                package_hook: false,
            }
        );
    }

    #[test]
    fn validate_outgoing_rejects_over_long_path_hint() {
        let too_long = "/".repeat(HELPER_PATH_HINT_MAX + 1);
        let ev = HelperResponse::AuthEvent {
            session: Uuid::nil(),
            seq: 0,
            kind: AuthEventKind::OpenForWrite,
            fd_sent_via_scm: false,
            path_hint: Some(too_long),
            dev: 0,
            inode: 0,
            requesting_pid: 1,
        };
        let err = validate_outgoing(&ev).unwrap_err();
        assert!(matches!(err, HelperProtoError::PathHintTooLong { .. }));
    }

    #[test]
    fn validate_outgoing_ok_for_normal_path() {
        let ev = HelperResponse::AuthEvent {
            session: Uuid::nil(),
            seq: 0,
            kind: AuthEventKind::OpenForWrite,
            fd_sent_via_scm: false,
            path_hint: Some("/home/user/file.txt".into()),
            dev: 0,
            inode: 0,
            requesting_pid: 1,
        };
        validate_outgoing(&ev).unwrap();
    }

    #[test]
    fn shutdown_round_trip() {
        let req = HelperRequest::Shutdown {
            reason: "daemon exiting".into(),
        };
        let bytes = encode_frame(&req).unwrap();
        let decoded: HelperRequest = decode_frame(&bytes).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn ping_pong_round_trip() {
        let req = HelperRequest::Ping { nonce: 1234 };
        let bytes = encode_frame(&req).unwrap();
        let decoded: HelperRequest = decode_frame(&bytes).unwrap();
        assert_eq!(req, decoded);

        let resp = HelperResponse::Pong { nonce: 1234 };
        let bytes = encode_frame(&resp).unwrap();
        let decoded: HelperResponse = decode_frame(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn protocol_version_constant_is_three() {
        // Bumping this is intentional and should be paired with an
        // explicit migration plan; this test catches accidental bumps.
        //   Version 2 (S24.A) added `HelperResponse::CapturedPreImage`
        //     for the kqueue post-hoc capture path.
        //   Version 3 (S29.1) added `HelperResponse::TreeMutation`
        //     for mkdir/rmdir/rename/symlink/link observations.
        assert_eq!(HELPER_PROTOCOL_VERSION, 3);
    }

    #[test]
    fn tree_mutation_round_trip() {
        let ev = HelperResponse::TreeMutation {
            session: Uuid::nil(),
            seq: 17,
            op: TreeOpWire::Create {
                dev: 1,
                inode: 42,
                path: "/tmp/foo/bar".into(),
                kind: FileKindWire::Directory,
                mode: 0o40755,
            },
            ts_unix_nanos: 1_700_000_000_000_000_000,
        };
        let encoded = crate::frame::encode_frame(&ev).expect("encode");
        let decoded: HelperResponse =
            crate::frame::decode_frame(&encoded).expect("decode");
        assert_eq!(decoded, ev);
    }

    #[test]
    fn captured_pre_image_round_trip() {
        let ev = HelperResponse::CapturedPreImage {
            session: Uuid::nil(),
            seq: 17,
            dev: 64,
            inode: 999,
            path: Some("/tmp/shit-vm-test/foo".into()),
            blob_hash: [0xCD; 32],
            stored_bytes: 1024,
            post_content_hash: None,
            mode: 0o100644,
            uid: 1001,
            gid: 1001,
            mtime_unix_nanos: 1_700_000_000_000_000_000,
            is_delete: true,
            fd_sent_via_scm: true,
        };
        let bytes = encode_frame(&ev).unwrap();
        let decoded: HelperResponse = decode_frame(&bytes).unwrap();
        assert_eq!(ev, decoded);
    }

    #[test]
    fn validate_outgoing_rejects_over_long_captured_pre_image_path() {
        let too_long = "/".repeat(HELPER_PATH_HINT_MAX + 1);
        let ev = HelperResponse::CapturedPreImage {
            session: Uuid::nil(),
            seq: 0,
            dev: 0,
            inode: 0,
            path: Some(too_long),
            blob_hash: [0; 32],
            stored_bytes: 0,
            post_content_hash: None,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            mtime_unix_nanos: 0,
            is_delete: false,
            fd_sent_via_scm: true,
        };
        let err = validate_outgoing(&ev).unwrap_err();
        assert!(matches!(err, HelperProtoError::PathHintTooLong { .. }));
    }
}
