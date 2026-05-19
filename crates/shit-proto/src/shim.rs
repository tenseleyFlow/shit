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
        };
        let frame = encode_frame(&n).expect("encode");
        let decoded: ShimNotification = decode_frame(&frame).expect("decode");
        assert_eq!(decoded, n);
    }

    #[test]
    fn shim_ack_round_trips() {
        let frame = encode_frame(&ShimAck::Allow).expect("encode");
        let decoded: ShimAck = decode_frame(&frame).expect("decode");
        assert_eq!(decoded, ShimAck::Allow);
    }
}
