// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper-side capture producers (S24.B+).
//!
//! Each platform has its own producer module that consumes kernel-tier
//! events (kqueue / fanotify / ES) and ships `HelperResponse::CapturedPreImage`
//! to the daemon. The wire format is shared (see `shit-proto`); the
//! producer logic is platform-specific because the syscalls are.
//!
//! S24.B lands the FreeBSD/kqueue producer ([`bsd`]). L01 lands the
//! Linux/fanotify producer ([`linux`]). M01.A lands the macOS/FSEvents
//! degraded-tier producer ([`macos`]); M03.1.I layers the ES producer
//! ([`macos_es`]) alongside it (both run in parallel per the M03.1.I
//! design's defense-in-depth posture).

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub mod bsd;

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub mod cwd;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "macos")]
pub mod macos_es;

// xattr capture is consumed by the BSD, Linux, and macOS producers
// (macOS via M03.x.XATTR — reads off the staging fd post-clonefile).
pub mod xattr;

// Streaming pre-image primitives shared between BSD/kqueue and
// Linux/LSM (AU25). macOS has its own streaming impl in
// `macos_es.rs` (M03.x.STREAMING) — a future sprint may consolidate
// onto this module. The `pread(2)` + `openat(2)` + blake3 dance is
// portable; the module is cfg-gated only because macOS doesn't use
// it today.
#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub mod streaming;

/// Sends `UnwatchTreeFlushed` when the last clone is dropped.
///
/// macOS can run two producers for one command, and the daemon's barrier
/// ends at the first marker, so one marker has to mean both are done. The
/// request loop hands each pump a clone inside its `Detach`. The marker
/// goes out once every pump has finished with its clone. A `Detach` the
/// control channel rejected drops its clone straight away, so a full
/// channel or a stopped pump cannot withhold the marker.
#[cfg(any(target_os = "macos", test))]
pub struct UnwatchFlushMarker {
    conn: std::sync::Arc<crate::ipc::Conn>,
    command: shit_planner::events::CommandId,
}

#[cfg(any(target_os = "macos", test))]
impl UnwatchFlushMarker {
    pub fn new(
        conn: std::sync::Arc<crate::ipc::Conn>,
        command: shit_planner::events::CommandId,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self { conn, command })
    }
}

#[cfg(any(target_os = "macos", test))]
impl Drop for UnwatchFlushMarker {
    fn drop(&mut self) {
        let flushed = shit_proto::HelperResponse::UnwatchTreeFlushed {
            session: self.command.session,
            command_seq: self.command.seq,
        };
        if let Err(e) = self.conn.send_response(&flushed) {
            tracing::warn!(
                err = %e,
                command = %self.command,
                "UnwatchTreeFlushed send failed; daemon close will time out"
            );
        }
    }
}

#[cfg(test)]
mod flush_marker_tests {
    use super::*;
    use shit_proto::HelperResponse;
    use std::sync::Arc;

    #[test]
    fn marker_is_sent_once_after_the_last_producer_finishes() {
        let (helper, daemon) = crate::ipc::socketpair().unwrap();
        daemon.set_nonblocking_for_test();
        let command = shit_planner::events::CommandId {
            session: uuid::Uuid::from_u128(5),
            seq: 8,
        };
        let marker = UnwatchFlushMarker::new(Arc::new(helper), command);
        let fsevents = Arc::clone(&marker);
        let endpoint_security = Arc::clone(&marker);
        drop(marker);
        drop(fsevents);
        assert!(
            daemon.recv_response().is_err(),
            "a producer still holds the marker"
        );
        drop(endpoint_security);
        assert!(matches!(
            daemon.recv_response().unwrap(),
            HelperResponse::UnwatchTreeFlushed { command_seq: 8, .. }
        ));
        assert!(daemon.recv_response().is_err(), "marker sent twice");
    }
}
