// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire protocol between the LD_PRELOAD shim (`shit-preload-shim`) and
//! the daemon's shim_listener (`shitd::shim_listener`).
//!
//! ## Shape
//!
//! - Length-prefixed `postcard`-encoded frames, same framing as ctl/helper.
//! - SOCK_STREAM (not SEQPACKET): some libc versions and `select(2)`
//!   wakeup semantics interact poorly with SEQPACKET in dynamically-
//!   loaded code, and we don't need preserved message boundaries for
//!   the one-shot notify pattern.
//! - One request → one ack per connection. Connections are short-lived;
//!   the shim opens, sends, waits ≤50 ms, closes.
//!
//! ## Scope
//!
//! S24.D.2 ships the protocol skeleton + an `Allow`-always ack. Future
//! sub-sprints add `Deny` and `AllowWithCapture { blob_hash }` so the
//! daemon can route pre-mutation events through the helper's
//! `HelperRequest::AuthDecision` flow without changing the on-the-wire
//! shape.
//!
//! Kept deliberately small (no Path types, just strings) so the shim's
//! send-path does no allocation beyond the postcard buffer itself.

use serde::{Deserialize, Serialize};

/// Inline pre-image payload for content-mutating syscalls. Carried in
/// `ShimNotification::pre_image` when the shim was able to read the
/// file's pre-mutation state. None when:
///   - the target path doesn't exist (e.g. `open(O_CREAT|O_EXCL)`),
///   - the file exceeds [`SHIM_INLINE_PREIMAGE_CAP`],
///   - the read itself failed (permissions, EIO).
///
/// W06.A.4 ships inline-only. A streaming SCM_RIGHTS variant for files
/// over the cap is a follow-up; for now over-cap files log a warning
/// and we proceed without a pre-image (planner emits a
/// Conflict::Missing at undo time, surfacing the gap to the user
/// rather than silently dropping it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimPreImage {
    /// Resolved (absolute) path the shim read content from. For
    /// `openat(AT_FDCWD, relpath, ...)` the shim's resolver canonicalizes
    /// before reading.
    pub path: String,
    pub dev: u64,
    pub inode: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_unix_nanos: i128,
    /// File bytes at pre-mutation time. Length == `size`.
    pub bytes: Vec<u8>,
    /// M07.B.4.1 — for xattr-mutating syscalls (setxattr /
    /// fsetxattr / removexattr / fremovexattr), the shim
    /// captures the (name, value) pair as seen on disk
    /// pre-syscall. `None` means either this notification is
    /// not for an xattr syscall, OR the shim couldn't read
    /// xattrs (rare). When `Some(XattrPreImage{ value: None })`
    /// the xattr did not exist pre-syscall (setxattr undo is
    /// then "removexattr"; removexattr undo is a no-op).
    ///
    /// serde-default so pre-M07.B.4.1 daemons deserialize new-
    /// shim acks (and vice versa: pre-M07.B.4.1 shims emit no
    /// `xattr` field, new daemons see `None`).
    #[serde(default)]
    pub xattr: Option<XattrPreImage>,
    /// M03.x.SETATTR — BSD/macOS st_flags at capture time. 0 on
    /// Linux and on pre-M03.x.SETATTR shim acks; `#[serde(default)]`
    /// keeps backward compat in both directions.
    #[serde(default)]
    pub flags: u32,
}

/// M07.B.4.1 — pre-syscall snapshot of one extended attribute.
/// Attached to a [`ShimPreImage`] when the shim notification is
/// for a `setxattr` / `removexattr` family syscall.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XattrPreImage {
    /// Xattr name as passed by the user — `com.apple.metadata:...`,
    /// `user.shit.test`, etc. UTF-8; macOS xattrs are required to
    /// be NUL-terminated C strings on the API surface.
    pub name: String,
    /// Pre-syscall value bytes. `None` means the xattr did not
    /// exist on disk before the syscall (so a `setxattr` undo is
    /// `removexattr` and a `removexattr` undo is a no-op).
    pub value: Option<Vec<u8>>,
}

/// Max inline pre-image size the shim will capture. Above this the
/// notification ships without `pre_image` and the daemon logs a
/// telemetry event.
///
/// **W06.A.4.1 raise (2026-05-25):** 256 KiB → 32 MiB. The original
/// 256 KiB cap was a defensive choice for W06.A.4's first ship; it
/// excluded all `make install` of normally-sized binaries and most
/// archive extracts. 32 MiB sits well below the wire's
/// [`crate::MAX_LARGE_FRAME_SIZE`] (64 MiB) ceiling, leaves
/// comfortable headroom for postcard metadata, and covers ~all
/// realistic cross-watch overwrite targets:
/// - ELF binaries for typical CLI apps: 1–20 MB.
/// - Static-linked Go/Rust binaries: 5–30 MB.
/// - Database files / blobs: usually < 32 MB at the point a
///   single command overwrites them; larger DBs use partial
///   pwrite which the live-baseline tier already covers (W02.B).
///
/// A truly streaming SCM_RIGHTS-via-fd variant (no ceiling) is
/// deferred to W06.A.4.2 — needed only if 32 MiB proves tight in
/// practice. The daemon's `shim_listener` allocates its recv
/// buffer dynamically from the wire's length prefix, so the
/// 32 MiB ceiling has no fixed memory cost when smaller payloads
/// arrive.
pub const SHIM_INLINE_PREIMAGE_CAP: u64 = 32 * 1024 * 1024;

/// One pre-mutation notification from the shim. Sent once per
/// interposed call when `SHIT_SHIM_DISABLE` is not set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimNotification {
    /// PID of the user process that triggered the interposer. The
    /// daemon uses this to attribute the event to an active command
    /// via the same shell-pid lookup tier-event handlers use.
    pub pid: u32,
    /// libc symbol name that was interposed (e.g. "unlink", "truncate",
    /// "open", "pwrite", "mmap_shared_w"). Static-string in the shim;
    /// arrives as an owned String here so the serializer doesn't need
    /// borrow lifetime tracking across the wire.
    pub syscall: String,
    /// First-line argument: a path for the path-taking interposers
    /// (`unlink`, `open`, `truncate`), or `"fd:N"` for the fd-taking
    /// ones (`ftruncate`, `pwrite`, `mmap_shared_w`).
    pub arg: String,
    /// Wall-clock timestamp at notification time. Helper uses this for
    /// stale-event detection (the shim's send may be delayed under
    /// load).
    pub ts_unix_nanos: u64,
    /// W06.A.4: inline pre-image for content-mutating syscalls
    /// (`open(O_TRUNC|O_WRONLY|O_RDWR)`, `openat` ditto, `truncate`).
    /// `None` for non-content syscalls and for cases listed in
    /// [`ShimPreImage`]'s docstring.
    pub pre_image: Option<ShimPreImage>,
    /// DR-CR-54 — additional pre-images for paths *under* the
    /// primary `arg` path. Populated by the shim's rename
    /// interposer when `from` is a directory: every regular
    /// file in the source subtree is captured into one of these
    /// entries, attributed to its **original** (pre-rename) path.
    ///
    /// Daemon-side, each entry is ingested via the same path as
    /// the primary `pre_image` — they become FilePreImage events
    /// keyed by their original absolute path. The planner then
    /// emits a RestoreContent per entry.
    ///
    /// Empty for non-rename notifications (including current
    /// rename-of-file, which only fills `pre_image`).
    ///
    /// The shim and daemon always ship as a matched pair (the
    /// shim is loaded by the install's `auto-inject-install-env`
    /// from a path inside the same release), so adding fields
    /// here is forward-only; we don't try to round-trip with an
    /// older shim.
    pub extra_pre_images: Vec<ShimPreImage>,
    /// AU10 — structured failure surfaced by the shim when a
    /// previously-silent fallback path tripped (canonicalize
    /// failure on rename arguments being the canonical example).
    /// `None` for successful captures.
    ///
    /// postcard is not self-describing, so `#[serde(default)]` does not
    /// make an older or newer frame readable: compatibility comes from
    /// the frame's [`crate::SHIM_WIRE_VERSION`] byte, and a mismatch is
    /// rejected by name.
    #[serde(default)]
    pub failure: Option<ShimFailure>,
    /// The target's lstat before the call. Sent for `unlink`/`unlinkat`
    /// (L4b), so the shim's report and the kernel tier's report of one
    /// removal pair exactly; for removals the shim reports after they
    /// succeed (`rmdir`, `unlinkat(AT_REMOVEDIR)`), when the daemon has
    /// nothing left to stat; and for a rename's destination when it is a
    /// symlink, so undo can recreate the link (L5). Adding it changed the
    /// frame shape; [`crate::SHIM_WIRE_VERSION`] says so.
    #[serde(default)]
    pub pre_stat: Option<ShimStat>,
    /// L5 (PR B): the shim's id for one rename-family call, unique per
    /// process (with `pid`, per call). The call's pre-syscall note and its
    /// outcome carry the same id, and the daemon journals it on the rows
    /// each produces, so the planner joins them by id. 0 for every other
    /// note.
    #[serde(default)]
    pub call_id: u64,
    /// L5 (PR B): set on the note the shim sends after a rename-family
    /// call returns.
    #[serde(default)]
    pub outcome: Option<ShimRenameOutcome>,
    /// R8 (#210): the command the sender belongs to, read by the shim
    /// from the environment the shell hook exports
    /// ([`ShimCommandKey`]). The daemon attributes the note by this key,
    /// so a sender that exits before the daemon reads the note is still
    /// joined to its command. `None` when the sender's environment had
    /// no key (not started from a hooked shell); the daemon then walks
    /// the sender's pid ancestry. Added in shim wire version 5.
    #[serde(default)]
    pub command_key: Option<ShimCommandKey>,
}

/// R8 (#210): the shell session and command sequence number a shim
/// note belongs to. The shell hooks export them as `_SHIT_SESSION` and
/// `_SHIT_SEQ` before each command runs, so every process the command
/// starts inherits them. The daemon accepts a key only from a peer with
/// its own uid, and only for a command it knows.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ShimCommandKey {
    pub session: uuid::Uuid,
    pub seq: u64,
}

/// The version-4 shape of [`ShimNotification`], before `command_key`.
/// A daemon still reads these (from shells started before an upgrade)
/// and attributes them by pid ancestry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ShimNotificationV4 {
    pid: u32,
    syscall: String,
    arg: String,
    ts_unix_nanos: u64,
    pre_image: Option<ShimPreImage>,
    extra_pre_images: Vec<ShimPreImage>,
    failure: Option<ShimFailure>,
    pre_stat: Option<ShimStat>,
    call_id: u64,
    outcome: Option<ShimRenameOutcome>,
}

impl From<ShimNotificationV4> for ShimNotification {
    fn from(n: ShimNotificationV4) -> Self {
        ShimNotification {
            pid: n.pid,
            syscall: n.syscall,
            arg: n.arg,
            ts_unix_nanos: n.ts_unix_nanos,
            pre_image: n.pre_image,
            extra_pre_images: n.extra_pre_images,
            failure: n.failure,
            pre_stat: n.pre_stat,
            call_id: n.call_id,
            outcome: n.outcome,
            command_key: None,
        }
    }
}

/// Decode a shim notification frame of the current
/// [`crate::SHIM_WIRE_VERSION`] or of version 4 (no `command_key`).
/// Any other version is [`crate::DecodeError::UnsupportedVersion`].
pub fn decode_shim_notification(buf: &[u8]) -> Result<ShimNotification, crate::DecodeError> {
    match crate::frame::decode_shim_frame::<ShimNotification>(buf) {
        Err(crate::DecodeError::UnsupportedVersion(4)) => {
            crate::frame::decode_versioned_large::<ShimNotificationV4>(buf, 4).map(Into::into)
        }
        other => other,
    }
}

/// L5 (PR B): what a rename-family call did, as the shim saw it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimRenameOutcome {
    /// 0 when the call returned 0, else its errno.
    pub errno: i32,
    /// lstat of `from`, read before the call whether or not the call
    /// then succeeded; `(0, 0)` when that lstat failed.
    pub source_dev: u64,
    pub source_inode: u64,
}

/// Identity and mode of a path, as the shim read it (lstat).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShimStat {
    pub dev: u64,
    pub inode: u64,
    pub mode: u32,
    /// The link's target, read before the call, when the entry is a
    /// symlink. `None` for other kinds, or when readlink failed.
    pub link_target: Option<String>,
}

/// AU10 — structured failure reported by the shim when capture
/// preparation tripped a step that previously fell back silently to
/// raw user-passed paths.
///
/// The shim still allows the syscall to proceed (we never block the
/// user's command); this variant signals the daemon that the capture
/// for this notification is **incomplete** and undo must refuse the
/// affected path rather than silently apply a wrong inverse.
///
/// Carried as `Option<ShimFailure>` on [`ShimNotification`] so the
/// wire stays backwards-compatible with older shims (the field
/// deserializes to `None` when absent thanks to `#[serde(default)]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShimFailure {
    /// `canonicalize` failed for the named argument AND for its
    /// parent. The shim has no resolved absolute path to attribute
    /// the captured pre-image to, so the daemon journals a refusal
    /// instead of an inverse op.
    ///
    /// `which_arg` is the human-facing label of the failed positional
    /// (e.g. "from" or "to" for rename; "path" for single-path
    /// syscalls). `attempted_path` is the raw argv the shim received.
    /// `error_chain` is the formatted `Debug` of the underlying io
    /// errors — kept as a single owned String so the proto crate
    /// doesn't have to model errno.
    CanonicalizeFailed {
        which_arg: String,
        attempted_path: String,
        error_chain: String,
    },
    /// L5 — a write-capable open or truncate of a file that existed
    /// before the call, whose bytes the shim could not capture (over the
    /// inline cap, unreadable, or its prior state unknown). The daemon
    /// journals a refusal and never a Create for it.
    PreImageUncaptured { path: String, reason: String },
}

/// Ack the daemon sends back. S24.D.2 ships `Allow` only; the broader
/// auth-decision shape lands once helper-routing is in place.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShimAck {
    /// Daemon recorded the notification (or didn't — fire-and-forget
    /// is allowed). Shim may proceed with the syscall.
    Allow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{decode_frame, encode_frame};

    #[test]
    fn shim_notification_round_trips() {
        let n = ShimNotification {
            pid: 12345,
            syscall: "unlink".into(),
            arg: "/tmp/probe".into(),
            ts_unix_nanos: 1_700_000_000_000_000_000,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let frame = crate::frame::encode_shim_frame(&n).expect("encode");
        let decoded: ShimNotification = crate::frame::decode_shim_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
    }

    #[test]
    fn shim_notification_with_pre_image_round_trips() {
        let n = ShimNotification {
            pid: 4242,
            syscall: "open".into(),
            arg: "/tmp/file.txt".into(),
            ts_unix_nanos: 1_700_000_000_000_000_000,
            pre_image: Some(ShimPreImage {
                path: "/tmp/file.txt".into(),
                dev: 64,
                inode: 7777,
                mode: 0o100644,
                uid: 1000,
                gid: 1000,
                size: 5,
                mtime_unix_nanos: 1_700_000_000_000_000_000,
                bytes: b"hello".to_vec(),
                xattr: None,
                flags: 0,
            }),
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let frame = crate::frame::encode_shim_frame(&n).expect("encode");
        let decoded: ShimNotification = crate::frame::decode_shim_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
    }

    /// AU10 — a notification carrying a failure (capture incomplete)
    /// round-trips both encoders. Pinning this guards the
    /// #[serde(default)] forward-compat path: older shims serialize
    /// without the field and the new daemon must still decode them.
    #[test]
    fn shim_notification_with_failure_round_trips() {
        let n = ShimNotification {
            pid: 9000,
            syscall: "rename".into(),
            arg: "foo/bar/baz\tfoo/bar/qux".into(),
            ts_unix_nanos: 1_700_000_000_000_000_000,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: Some(ShimFailure::CanonicalizeFailed {
                which_arg: "from".into(),
                attempted_path: "foo/bar/baz".into(),
                error_chain: "ENOENT (path), ENOENT (parent)".into(),
            }),
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let frame = crate::frame::encode_shim_frame(&n).expect("encode");
        let decoded: ShimNotification = crate::frame::decode_shim_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
        match decoded.failure {
            Some(ShimFailure::CanonicalizeFailed { which_arg, .. }) => {
                assert_eq!(which_arg, "from");
            }
            _ => panic!("expected CanonicalizeFailed"),
        }
    }

    /// `pre_stat` survives the shim wire.
    #[test]
    fn shim_notification_with_pre_stat_round_trips() {
        let n = ShimNotification {
            pid: 1,
            syscall: "rmdir".into(),
            arg: "/tmp/d".into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: Some(ShimStat {
                dev: 1,
                inode: 2,
                mode: 0o040700,
                link_target: None,
            }),
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let frame = encode_frame(&n).expect("encode");
        let decoded: ShimNotification = decode_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
    }

    /// M07.B.4.1 — pin the xattr-pre-image wire shape on the
    /// shim → daemon hop. Two halves: `Some(value)` (xattr
    /// existed pre-syscall) and `None` (xattr absent pre-syscall;
    /// undo's setxattr → removexattr OR removexattr → no-op).
    #[test]
    fn shim_notification_with_xattr_pre_image_round_trips() {
        let n = ShimNotification {
            pid: 7777,
            syscall: "setxattr".into(),
            arg: "/private/tmp/file.txt".into(),
            ts_unix_nanos: 1_700_000_000_000_000_000,
            pre_image: Some(ShimPreImage {
                path: "/private/tmp/file.txt".into(),
                dev: 16777230,
                inode: 1234,
                mode: 0o100644,
                uid: 501,
                gid: 20,
                size: 0,
                mtime_unix_nanos: 1_700_000_000_000_000_000,
                flags: 0,
                bytes: Vec::new(),
                xattr: Some(XattrPreImage {
                    name: "user.shit.test".into(),
                    value: Some(b"alpha".to_vec()),
                }),
            }),
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let frame = crate::frame::encode_shim_frame(&n).expect("encode");
        let decoded: ShimNotification = crate::frame::decode_shim_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
        let xattr = decoded.pre_image.unwrap().xattr.unwrap();
        assert_eq!(xattr.name, "user.shit.test");
        assert_eq!(xattr.value.as_deref(), Some(b"alpha" as &[u8]));
    }

    #[test]
    fn shim_notification_xattr_absent_pre_image_round_trips() {
        let n = ShimNotification {
            pid: 7777,
            syscall: "setxattr".into(),
            arg: "/private/tmp/fresh.txt".into(),
            ts_unix_nanos: 1_700_000_000_000_000_000,
            pre_image: Some(ShimPreImage {
                path: "/private/tmp/fresh.txt".into(),
                dev: 16777230,
                inode: 1234,
                mode: 0o100644,
                uid: 501,
                gid: 20,
                size: 0,
                mtime_unix_nanos: 1_700_000_000_000_000_000,
                flags: 0,
                bytes: Vec::new(),
                xattr: Some(XattrPreImage {
                    name: "user.shit.fresh".into(),
                    value: None, // absent pre-syscall
                }),
            }),
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let frame = crate::frame::encode_shim_frame(&n).expect("encode");
        let decoded: ShimNotification = crate::frame::decode_shim_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
        assert!(decoded.pre_image.unwrap().xattr.unwrap().value.is_none());
    }

    #[test]
    fn shim_ack_round_trips() {
        let frame = encode_frame(&ShimAck::Allow).expect("encode");
        let decoded: ShimAck = decode_frame(&frame).expect("decode");
        assert_eq!(decoded, ShimAck::Allow);
    }

    /// DR-CR-54 — a rename whose source was a directory ships
    /// per-file pre-images for every regular file in the subtree.
    /// Round-trip a representative payload to pin both the new
    /// field and the encoder choice (must be `_large`).
    #[test]
    fn shim_notification_with_recursive_pre_images_round_trips() {
        fn pre(path: &str, bytes: &[u8]) -> ShimPreImage {
            ShimPreImage {
                path: path.into(),
                dev: 64,
                inode: 0,
                mode: 0o100644,
                uid: 0,
                gid: 0,
                size: bytes.len() as u64,
                mtime_unix_nanos: 1_700_000_000_000_000_000,
                bytes: bytes.to_vec(),
                xattr: None,
                flags: 0,
            }
        }
        let n = ShimNotification {
            pid: 5555,
            syscall: "rename".into(),
            arg: "/abs/site-packages\t/abs/.shit-stage".into(),
            ts_unix_nanos: 1_700_000_000_000_000_000,
            pre_image: None,
            extra_pre_images: vec![
                pre("/abs/site-packages/pkg/__init__.py", b""),
                pre("/abs/site-packages/pkg/mod.py", b"def main(): pass\n"),
                pre("/abs/site-packages/pkg/sub/inner.py", b"x = 1\n"),
            ],
            failure: None,
            pre_stat: None,
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let frame = crate::frame::encode_shim_frame(&n).expect("encode");
        let decoded: ShimNotification = crate::frame::decode_shim_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
        assert_eq!(decoded.extra_pre_images.len(), 3);
        assert_eq!(
            decoded.extra_pre_images[1].path,
            "/abs/site-packages/pkg/mod.py"
        );
    }

    /// Shim frames carry their own version byte. A version-1 frame (a
    /// shim loaded before the upgrade, without `pre_stat`) is rejected
    /// by name rather than misread.
    #[test]
    fn shim_frames_are_versioned_and_old_ones_are_rejected() {
        use crate::frame::{
            DecodeError, SHIM_WIRE_VERSION, decode_shim_frame, encode_frame_large,
            encode_shim_frame,
        };
        let n = ShimNotification {
            pid: 1,
            syscall: "unlink".into(),
            arg: "/w/x".into(),
            ts_unix_nanos: 0,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: Some(ShimStat {
                dev: 1,
                inode: 2,
                mode: 0o020640,
                link_target: None,
            }),
            call_id: 0,
            outcome: None,
            command_key: None,
        };
        let frame = encode_shim_frame(&n).unwrap();
        assert_eq!(frame[4], SHIM_WIRE_VERSION);
        assert_eq!(decode_shim_frame::<ShimNotification>(&frame).unwrap(), n);
        let old = encode_frame_large(&n).unwrap();
        assert!(matches!(
            decode_shim_frame::<ShimNotification>(&old),
            Err(DecodeError::UnsupportedVersion(1))
        ));
        // Version-2, -3 and -4 frames (#223's, #232's and #224's shims)
        // are refused by name too by the strict decoder.
        for v in [2u8, 3, 4] {
            let mut old = frame.clone();
            old[4] = v;
            assert!(matches!(
                decode_shim_frame::<ShimNotification>(&old),
                Err(DecodeError::UnsupportedVersion(got)) if got == v
            ));
        }
        assert_eq!(SHIM_WIRE_VERSION, 5);
    }

    /// R8 (#210): the key round-trips, and a version-4 frame (a shell
    /// started before the upgrade) still decodes, with no key, through
    /// `decode_shim_notification`. Versions 1-3 stay refused.
    #[test]
    fn version_4_frames_decode_without_a_key() {
        use crate::frame::{DecodeError, encode_shim_frame, encode_versioned_for_test};
        let v4 = ShimNotificationV4 {
            pid: 7,
            syscall: "mkfifo".into(),
            arg: "/w/fifo".into(),
            ts_unix_nanos: 9,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: None,
            pre_stat: None,
            call_id: 3,
            outcome: None,
        };
        let frame = encode_versioned_for_test(&v4, 4);
        let got = decode_shim_notification(&frame).unwrap();
        assert_eq!(got, ShimNotification::from(v4.clone()));
        assert_eq!(got.command_key, None);
        assert_eq!(got.call_id, 3);

        let mut keyed = got.clone();
        keyed.command_key = Some(ShimCommandKey {
            session: uuid::Uuid::from_u128(0xabc),
            seq: 12,
        });
        let frame = encode_shim_frame(&keyed).unwrap();
        assert_eq!(decode_shim_notification(&frame).unwrap(), keyed);

        for v in [1u8, 2, 3] {
            let old = encode_versioned_for_test(&v4, v);
            assert!(matches!(
                decode_shim_notification(&old),
                Err(DecodeError::UnsupportedVersion(got)) if got == v
            ));
        }
    }
}
