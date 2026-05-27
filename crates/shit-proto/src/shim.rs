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
    /// `#[serde(default)]` keeps the wire backwards-compatible with
    /// pre-AU10 shims; older daemons see the field as absent and
    /// older shims serialize without it. Postcard's optional encoding
    /// is one byte (`0` for None) so the cost on the happy path is
    /// negligible.
    #[serde(default)]
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
        };
        let frame = encode_frame(&n).expect("encode");
        let decoded: ShimNotification = decode_frame(&frame).expect("decode");
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
            }),
            extra_pre_images: Vec::new(),
            failure: None,
        };
        let frame = crate::frame::encode_frame_large(&n).expect("encode");
        let decoded: ShimNotification = crate::frame::decode_frame_large(&frame).expect("decode");
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
        let frame = encode_frame(&n).expect("encode");
        let decoded: ShimNotification = decode_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
        match decoded.failure {
            Some(ShimFailure::CanonicalizeFailed { which_arg, .. }) => {
                assert_eq!(which_arg, "from");
            }
            _ => panic!("expected CanonicalizeFailed"),
        }
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
        let frame = crate::frame::encode_frame_large(&n).expect("encode");
        let decoded: ShimNotification = crate::frame::decode_frame_large(&frame).expect("decode");
        assert_eq!(decoded, n);
        assert_eq!(decoded.extra_pre_images.len(), 3);
        assert_eq!(
            decoded.extra_pre_images[1].path,
            "/abs/site-packages/pkg/mod.py"
        );
    }
}
