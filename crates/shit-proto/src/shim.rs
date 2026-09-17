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
use std::collections::BTreeMap;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The dedicated shim codec preserves this legacy field's byte layout for
    /// mixed-version installs.
    pub xattr: Option<XattrPreImage>,
    /// M03.x.SETATTR — BSD/macOS st_flags at capture time. 0 on
    /// Linux and on pre-M03.x.SETATTR shim acks.
    pub flags: u32,
    /// Complete, pre-mutation snapshot of every restorable xattr on this
    /// object. `Some(empty)` means the producer positively observed no
    /// restorable xattrs. `None` means the snapshot is unavailable (including
    /// notifications decoded from the legacy shim wire layout) and must never
    /// be interpreted as an authoritative empty set.
    ///
    /// This field is carried in a trailing notification-level wire extension,
    /// rather than inserted into the nested postcard struct. Postcard encodes
    /// structs positionally: inserting a nested field would make an old daemon
    /// consume it as `ShimNotification::extra_pre_images`. The dedicated codec
    /// below keeps the old nested layout byte-for-byte and binds this sidecar
    /// back to the pre-image by position.
    pub xattrs: Option<BTreeMap<String, Vec<u8>>>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The dedicated shim codec keeps this field in the legacy position and
    /// appends newer extensions after it.
    pub failure: Option<ShimFailure>,
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
    /// The path existed before a destructive syscall, but its content could
    /// not be captured (for example it exceeded the inline cap, was
    /// unreadable, or was a kind the content snapshot cannot represent).
    /// Treating this as a fresh create would make undo unlink pre-existing
    /// data, so the daemon must journal a refusal instead of an inverse.
    PreImageUnavailable {
        attempted_path: String,
        reason: String,
    },
    /// The shim recognized a syscall shape whose inverse is not modeled
    /// faithfully (for example Linux `renameat2(RENAME_EXCHANGE)`). The
    /// original syscall remains fail-open, but undo must surface this gap.
    UnsupportedOperation {
        attempted_path: String,
        reason: String,
    },
}

/// Ack the daemon sends back. S24.D.2 ships `Allow` only; the broader
/// auth-decision shape lands once helper-routing is in place.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ShimAck {
    /// Daemon recorded the notification (or didn't — fire-and-forget
    /// is allowed). Shim may proceed with the syscall.
    Allow,
}

// Keep this positional postcard layout exactly equal to the ShimPreImage
// shape shipped before the authoritative-xattr extension. It is deliberately
// private: callers must use the dedicated notification codec below so a future
// field cannot accidentally be inserted into the nested wire shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ShimPreImageWireV1 {
    path: String,
    dev: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime_unix_nanos: i128,
    bytes: Vec<u8>,
    xattr: Option<XattrPreImage>,
    flags: u32,
}

#[derive(Serialize)]
struct ShimPreImageWireV1Ref<'a> {
    path: &'a str,
    dev: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    mtime_unix_nanos: i128,
    bytes: &'a [u8],
    xattr: Option<&'a XattrPreImage>,
    flags: u32,
}

impl<'a> From<&'a ShimPreImage> for ShimPreImageWireV1Ref<'a> {
    fn from(value: &'a ShimPreImage) -> Self {
        Self {
            path: &value.path,
            dev: value.dev,
            inode: value.inode,
            mode: value.mode,
            uid: value.uid,
            gid: value.gid,
            size: value.size,
            mtime_unix_nanos: value.mtime_unix_nanos,
            bytes: &value.bytes,
            xattr: value.xattr.as_ref(),
            flags: value.flags,
        }
    }
}

impl ShimPreImageWireV1 {
    fn into_pre_image(self, xattrs: Option<BTreeMap<String, Vec<u8>>>) -> ShimPreImage {
        ShimPreImage {
            path: self.path,
            dev: self.dev,
            inode: self.inode,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            size: self.size,
            mtime_unix_nanos: self.mtime_unix_nanos,
            bytes: self.bytes,
            xattr: self.xattr,
            flags: self.flags,
            xattrs,
        }
    }
}

/// Exact notification layout shipped before full xattr snapshots. New
/// daemons accept it and mark every decoded pre-image snapshot unavailable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ShimNotificationWireV1 {
    pid: u32,
    syscall: String,
    arg: String,
    ts_unix_nanos: u64,
    pre_image: Option<ShimPreImageWireV1>,
    extra_pre_images: Vec<ShimPreImageWireV1>,
    failure: Option<ShimFailure>,
}

const SHIM_XATTR_WIRE_EXTENSION_V1: u8 = 1;

/// V2 appends fields only at the end of the legacy notification. Because
/// postcard's `from_bytes` accepts unused trailing bytes, old daemons decode
/// the V1 prefix normally and ignore this extension. The nested pre-images
/// remain byte-for-byte V1.
#[derive(Serialize)]
struct ShimNotificationWireV2Ref<'a> {
    pid: u32,
    syscall: &'a str,
    arg: &'a str,
    ts_unix_nanos: u64,
    pre_image: Option<ShimPreImageWireV1Ref<'a>>,
    extra_pre_images: Vec<ShimPreImageWireV1Ref<'a>>,
    failure: Option<&'a ShimFailure>,
    extension_version: u8,
    pre_image_xattrs: Option<&'a BTreeMap<String, Vec<u8>>>,
    extra_pre_image_xattrs: Vec<Option<&'a BTreeMap<String, Vec<u8>>>>,
}

#[derive(Deserialize)]
struct ShimNotificationWireV2 {
    pid: u32,
    syscall: String,
    arg: String,
    ts_unix_nanos: u64,
    pre_image: Option<ShimPreImageWireV1>,
    extra_pre_images: Vec<ShimPreImageWireV1>,
    failure: Option<ShimFailure>,
    extension_version: u8,
    pre_image_xattrs: Option<BTreeMap<String, Vec<u8>>>,
    extra_pre_image_xattrs: Vec<Option<BTreeMap<String, Vec<u8>>>>,
}

fn notification_wire(note: &ShimNotification) -> ShimNotificationWireV2Ref<'_> {
    ShimNotificationWireV2Ref {
        pid: note.pid,
        syscall: &note.syscall,
        arg: &note.arg,
        ts_unix_nanos: note.ts_unix_nanos,
        pre_image: note.pre_image.as_ref().map(Into::into),
        extra_pre_images: note.extra_pre_images.iter().map(Into::into).collect(),
        failure: note.failure.as_ref(),
        extension_version: SHIM_XATTR_WIRE_EXTENSION_V1,
        pre_image_xattrs: note.pre_image.as_ref().and_then(|pre| pre.xattrs.as_ref()),
        extra_pre_image_xattrs: note
            .extra_pre_images
            .iter()
            .map(|pre| pre.xattrs.as_ref())
            .collect(),
    }
}

/// Encode a shim notification while preserving the legacy nested pre-image
/// layout. Use this instead of the generic frame encoder.
pub fn encode_shim_notification_frame(
    note: &ShimNotification,
) -> Result<Vec<u8>, crate::EncodeError> {
    crate::frame::encode_frame(&notification_wire(note))
}

/// Large-frame variant of [`encode_shim_notification_frame`].
pub fn encode_shim_notification_frame_large(
    note: &ShimNotification,
) -> Result<Vec<u8>, crate::EncodeError> {
    crate::frame::encode_frame_large(&notification_wire(note))
}

fn checked_payload(buf: &[u8], cap: usize) -> Result<&[u8], crate::DecodeError> {
    if buf.len() < 5 {
        return Err(crate::DecodeError::Truncated(buf.len()));
    }
    if buf.len() > cap {
        return Err(crate::DecodeError::TooLarge(buf.len()));
    }
    let declared = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let actual = buf.len() - 4;
    if declared != actual {
        return Err(crate::DecodeError::LengthMismatch { declared, actual });
    }
    if buf[4] != crate::WIRE_VERSION {
        return Err(crate::DecodeError::UnsupportedVersion(buf[4]));
    }
    Ok(&buf[5..])
}

fn decode_notification_with_cap(
    buf: &[u8],
    cap: usize,
) -> Result<ShimNotification, crate::DecodeError> {
    let payload = checked_payload(buf, cap)?;

    // `take_from_bytes` is essential here. Generic postcard `from_bytes`
    // intentionally ignores trailing bytes, which is what lets an old daemon
    // accept V2, but a new daemon must distinguish an exact V1 payload from a
    // malformed/truncated V2 extension instead of silently downgrading it.
    let (legacy, trailing) = postcard::take_from_bytes::<ShimNotificationWireV1>(payload)?;
    if trailing.is_empty() {
        return Ok(ShimNotification {
            pid: legacy.pid,
            syscall: legacy.syscall,
            arg: legacy.arg,
            ts_unix_nanos: legacy.ts_unix_nanos,
            pre_image: legacy.pre_image.map(|pre| pre.into_pre_image(None)),
            extra_pre_images: legacy
                .extra_pre_images
                .into_iter()
                .map(|pre| pre.into_pre_image(None))
                .collect(),
            failure: legacy.failure,
        });
    }

    let (wire, remainder) = postcard::take_from_bytes::<ShimNotificationWireV2>(payload)?;
    if !remainder.is_empty() {
        return Err(crate::DecodeError::InvalidShimExtension(
            "unexpected bytes after xattr snapshot extension",
        ));
    }
    if wire.extension_version != SHIM_XATTR_WIRE_EXTENSION_V1 {
        return Err(crate::DecodeError::UnsupportedShimExtension(
            wire.extension_version,
        ));
    }
    if wire.extra_pre_images.len() != wire.extra_pre_image_xattrs.len() {
        return Err(crate::DecodeError::InvalidShimExtension(
            "recursive pre-image/xattr snapshot count mismatch",
        ));
    }
    if wire.pre_image.is_none() && wire.pre_image_xattrs.is_some() {
        return Err(crate::DecodeError::InvalidShimExtension(
            "primary xattr snapshot has no primary pre-image",
        ));
    }

    Ok(ShimNotification {
        pid: wire.pid,
        syscall: wire.syscall,
        arg: wire.arg,
        ts_unix_nanos: wire.ts_unix_nanos,
        pre_image: wire
            .pre_image
            .map(|pre| pre.into_pre_image(wire.pre_image_xattrs)),
        extra_pre_images: wire
            .extra_pre_images
            .into_iter()
            .zip(wire.extra_pre_image_xattrs)
            .map(|(pre, xattrs)| pre.into_pre_image(xattrs))
            .collect(),
        failure: wire.failure,
    })
}

/// Decode either the current shim notification or the exact immediately
/// preceding wire layout using the ordinary frame-size cap.
pub fn decode_shim_notification_frame(buf: &[u8]) -> Result<ShimNotification, crate::DecodeError> {
    decode_notification_with_cap(buf, crate::MAX_FRAME_SIZE)
}

/// Large-frame variant of [`decode_shim_notification_frame`].
pub fn decode_shim_notification_frame_large(
    buf: &[u8],
) -> Result<ShimNotification, crate::DecodeError> {
    decode_notification_with_cap(buf, crate::MAX_LARGE_FRAME_SIZE)
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
        };
        let frame = encode_shim_notification_frame(&n).expect("encode");
        let decoded = decode_shim_notification_frame(&frame).expect("decode");
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
                xattrs: Some(BTreeMap::new()),
            }),
            extra_pre_images: Vec::new(),
            failure: None,
        };
        let frame = encode_shim_notification_frame_large(&n).expect("encode");
        let decoded = decode_shim_notification_frame_large(&frame).expect("decode");
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
        };
        let frame = encode_shim_notification_frame(&n).expect("encode");
        let decoded = decode_shim_notification_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
        match decoded.failure {
            Some(ShimFailure::CanonicalizeFailed { which_arg, .. }) => {
                assert_eq!(which_arg, "from");
            }
            _ => panic!("expected CanonicalizeFailed"),
        }
    }

    #[test]
    fn shim_notification_with_unavailable_pre_image_round_trips() {
        let n = ShimNotification {
            pid: 9001,
            syscall: "open".into(),
            arg: "/tmp/too-large".into(),
            ts_unix_nanos: 1_700_000_000_000_000_000,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: Some(ShimFailure::PreImageUnavailable {
                attempted_path: "/tmp/too-large".into(),
                reason: "existing path exceeded inline capture cap".into(),
            }),
        };
        let frame = encode_shim_notification_frame(&n).expect("encode");
        let decoded = decode_shim_notification_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
    }

    #[test]
    fn shim_notification_with_unsupported_operation_round_trips() {
        let n = ShimNotification {
            pid: 9002,
            syscall: "renameat2".into(),
            arg: "/tmp/from\t/tmp/to".into(),
            ts_unix_nanos: 1_700_000_000_000_000_000,
            pre_image: None,
            extra_pre_images: Vec::new(),
            failure: Some(ShimFailure::UnsupportedOperation {
                attempted_path: "/tmp/to".into(),
                reason: "renameat2 flags 0x2 are not modeled".into(),
            }),
        };
        let frame = encode_shim_notification_frame(&n).expect("encode");
        let decoded = decode_shim_notification_frame(&frame).expect("decode");
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
                xattrs: Some(BTreeMap::from([
                    ("user.shit.test".into(), b"alpha".to_vec()),
                    ("user.shit.other".into(), b"beta".to_vec()),
                ])),
            }),
            extra_pre_images: Vec::new(),
            failure: None,
        };
        let frame = encode_shim_notification_frame(&n).expect("encode");
        let decoded = decode_shim_notification_frame(&frame).expect("decode");
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
                xattrs: Some(BTreeMap::new()),
            }),
            extra_pre_images: Vec::new(),
            failure: None,
        };
        let frame = encode_shim_notification_frame(&n).expect("encode");
        let decoded = decode_shim_notification_frame(&frame).expect("decode");
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
                xattrs: Some(BTreeMap::new()),
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
        };
        let frame = encode_shim_notification_frame_large(&n).expect("encode");
        let decoded = decode_shim_notification_frame_large(&frame).expect("decode");
        assert_eq!(decoded, n);
        assert_eq!(decoded.extra_pre_images.len(), 3);
        assert_eq!(
            decoded.extra_pre_images[1].path,
            "/abs/site-packages/pkg/mod.py"
        );
    }

    #[test]
    fn legacy_daemon_decodes_new_trailing_extension_and_postcard_exposes_remainder() {
        let n = ShimNotification {
            pid: 42,
            syscall: "unlink".into(),
            arg: "/tmp/old-daemon".into(),
            ts_unix_nanos: 7,
            pre_image: Some(ShimPreImage {
                path: "/tmp/old-daemon".into(),
                dev: 1,
                inode: 2,
                mode: 0o100600,
                uid: 3,
                gid: 4,
                size: 3,
                mtime_unix_nanos: 5,
                bytes: b"old".to_vec(),
                xattr: None,
                flags: 0,
                xattrs: Some(BTreeMap::from([("user.keep".into(), b"yes".to_vec())])),
            }),
            extra_pre_images: Vec::new(),
            failure: None,
        };
        let frame = encode_shim_notification_frame(&n).expect("encode V2");

        // This is exactly what the pre-extension daemon did: generic frame
        // decoding into the old positional shape. Postcard's `from_bytes`
        // accepts and ignores trailing bytes, so this direction is compatible.
        let old: ShimNotificationWireV1 = decode_frame(&frame).expect("old daemon decode");
        assert_eq!(old.pre_image.unwrap().bytes, b"old");

        // Pin the underlying behavior explicitly: `take_from_bytes` exposes
        // the extension that generic `from_bytes` intentionally ignores.
        let payload = checked_payload(&frame, crate::MAX_FRAME_SIZE).unwrap();
        let (_old, remainder) =
            postcard::take_from_bytes::<ShimNotificationWireV1>(payload).unwrap();
        assert!(
            !remainder.is_empty(),
            "new frame must carry a trailing extension"
        );
    }

    #[test]
    fn new_daemon_decodes_legacy_frame_as_unavailable_not_empty() {
        let legacy = ShimNotificationWireV1 {
            pid: 43,
            syscall: "unlink".into(),
            arg: "/tmp/new-daemon".into(),
            ts_unix_nanos: 8,
            pre_image: Some(ShimPreImageWireV1 {
                path: "/tmp/new-daemon".into(),
                dev: 1,
                inode: 9,
                mode: 0o100600,
                uid: 3,
                gid: 4,
                size: 3,
                mtime_unix_nanos: 6,
                bytes: b"old".to_vec(),
                xattr: None,
                flags: 0,
            }),
            extra_pre_images: Vec::new(),
            failure: None,
        };
        let frame = encode_frame(&legacy).expect("legacy encode");
        let decoded = decode_shim_notification_frame(&frame).expect("new daemon decode");
        assert_eq!(decoded.pre_image.as_ref().unwrap().bytes, b"old");
        assert_eq!(decoded.pre_image.unwrap().xattrs, None);
    }
}
