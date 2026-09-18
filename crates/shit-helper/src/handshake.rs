// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper-side handshake. The daemon initiates by sending a
//! `HelperRequest::Handshake`; we verify the peer's PID/UID matches
//! what we were spawned with, refuse on mismatch, and reply with a
//! `HelperResponse::HandshakeAck` advertising the capability set we can
//! actually provide.

use shit_proto::{
    HELPER_PROTOCOL_VERSION, HelperCaps, HelperRequest, HelperResponse, SelfVerifyReport,
};
use std::os::fd::RawFd;

use crate::ipc::{Conn, ConnError};

/// Capture tier resolved by the caller after the real producer has started.
///
/// A probe or compile-time platform guess is not sufficient for the handshake:
/// Linux may fall back from eBPF-LSM to fanotify, and macOS/BSD producer startup
/// may fail after their prerequisites appeared usable.  Keeping this value as
/// an explicit input makes `HandshakeAck` a statement about live runtime state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveCaptureTier {
    pub kernel_tier: String,
    pub degraded_reason: Option<String>,
}

impl ActiveCaptureTier {
    pub fn new(kernel_tier: impl Into<String>, degraded_reason: Option<String>) -> Self {
        Self {
            kernel_tier: kernel_tier.into(),
            degraded_reason,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("ipc: {0}")]
    Ipc(#[from] ConnError),
    #[error("peer pid mismatch: expected {expected}, got {actual}")]
    PidMismatch { expected: u32, actual: u32 },
    #[error("peer uid mismatch: expected {expected}, got {actual}")]
    UidMismatch { expected: u32, actual: u32 },
    #[error("protocol version mismatch: helper {helper}, daemon {daemon}")]
    VersionMismatch { helper: u16, daemon: u16 },
    #[error("first message was not Handshake")]
    NotHandshake,
    #[error("could not query peer credentials: {0}")]
    PeerCred(String),
}

/// Outcome of a successful handshake — the cap set both sides agreed to.
#[derive(Debug, Clone)]
pub struct HandshakeOutcome {
    pub daemon_pid: u32,
    pub daemon_uid: u32,
    pub granted: HelperCaps,
    pub kernel_tier: String,
    pub degraded_reason: Option<String>,
}

/// Authenticated first half of the helper handshake.
///
/// The fields are private so only this module can mint a value after checking
/// both socket peer credentials and the daemon's `Handshake` payload. Runtime
/// capture producers may start only after the caller holds this token.
#[derive(Debug)]
pub struct AuthenticatedHandshake {
    daemon_pid: u32,
    daemon_uid: u32,
    capability_request: HelperCaps,
}

impl AuthenticatedHandshake {
    pub fn daemon_pid(&self) -> u32 {
        self.daemon_pid
    }

    pub fn daemon_uid(&self) -> u32 {
        self.daemon_uid
    }
}

/// Authenticate the socket peer and consume its handshake hello without
/// sending an acknowledgment yet.
///
/// Splitting authentication from acknowledgment lets the caller start the
/// real producer against an authenticated daemon, then truthfully report the
/// producer and capabilities that reached their live boundary.
pub fn authenticate_helper_side(
    conn: &Conn,
    expected_daemon_pid: u32,
    expected_daemon_uid: u32,
) -> Result<AuthenticatedHandshake, HandshakeError> {
    let (peer_pid, peer_uid) = peer_cred(conn.as_raw_fd())?;
    if peer_pid != expected_daemon_pid {
        return Err(HandshakeError::PidMismatch {
            expected: expected_daemon_pid,
            actual: peer_pid,
        });
    }
    if peer_uid != expected_daemon_uid {
        return Err(HandshakeError::UidMismatch {
            expected: expected_daemon_uid,
            actual: peer_uid,
        });
    }

    let req = conn.recv_request()?;
    let HelperRequest::Handshake {
        daemon_pid,
        daemon_uid,
        protocol_version,
        capability_request,
    } = req
    else {
        return Err(HandshakeError::NotHandshake);
    };

    if protocol_version != HELPER_PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch {
            helper: HELPER_PROTOCOL_VERSION,
            daemon: protocol_version,
        });
    }

    // The body of the Handshake should agree with the peer-cred we
    // already verified. Disagreement here means the daemon binary is
    // confused about its own identity — refuse.
    if daemon_pid != expected_daemon_pid {
        return Err(HandshakeError::PidMismatch {
            expected: expected_daemon_pid,
            actual: daemon_pid,
        });
    }
    if daemon_uid != expected_daemon_uid {
        return Err(HandshakeError::UidMismatch {
            expected: expected_daemon_uid,
            actual: daemon_uid,
        });
    }

    Ok(AuthenticatedHandshake {
        daemon_pid,
        daemon_uid,
        capability_request,
    })
}

/// Finish an authenticated handshake after capture startup has resolved.
/// `local_caps` and `active_capture` must describe the same live producers.
pub fn acknowledge_helper_side(
    conn: &Conn,
    authenticated: AuthenticatedHandshake,
    local_caps: HelperCaps,
    active_capture: ActiveCaptureTier,
) -> Result<HandshakeOutcome, HandshakeError> {
    let granted = authenticated.capability_request.intersect(local_caps);
    let self_verify = self_verify_report();
    let ack = HelperResponse::HandshakeAck {
        helper_pid: std::process::id(),
        helper_uid: current_uid(),
        protocol_version: HELPER_PROTOCOL_VERSION,
        granted,
        helper_version: env!("CARGO_PKG_VERSION").to_string(),
        kernel_tier: active_capture.kernel_tier.clone(),
        degraded_reason: active_capture.degraded_reason.clone(),
        self_verify,
    };
    // DR-64 fault-injection: crash mid-reply. The daemon must
    // observe the disconnect, log the failed handshake, and
    // re-spawn the helper rather than treating the dropped socket
    // as a permanent failure.
    shit_proto::fault_inject::maybe_inject("helper.handshake.before_ack_send");
    conn.send_response(&ack)?;
    shit_proto::fault_inject::maybe_inject("helper.handshake.after_ack_send");

    Ok(HandshakeOutcome {
        daemon_pid: authenticated.daemon_pid,
        daemon_uid: authenticated.daemon_uid,
        granted,
        kernel_tier: active_capture.kernel_tier,
        degraded_reason: active_capture.degraded_reason,
    })
}

/// Drive the daemon side of the handshake. Used by tests and by
/// `shitd::helper_link`. Sends Handshake then waits for HandshakeAck.
#[allow(dead_code)]
pub fn perform_daemon_side(
    conn: &Conn,
    capability_request: HelperCaps,
) -> Result<HandshakeOutcome, HandshakeError> {
    let req = HelperRequest::Handshake {
        daemon_pid: std::process::id(),
        daemon_uid: current_uid(),
        protocol_version: HELPER_PROTOCOL_VERSION,
        capability_request,
    };
    conn.send_request(&req)?;
    let resp = conn.recv_response()?;
    let HelperResponse::HandshakeAck {
        helper_pid,
        helper_uid,
        protocol_version,
        granted,
        helper_version: _,
        kernel_tier,
        degraded_reason,
        self_verify: _,
    } = resp
    else {
        return Err(HandshakeError::NotHandshake);
    };
    if protocol_version != HELPER_PROTOCOL_VERSION {
        return Err(HandshakeError::VersionMismatch {
            helper: protocol_version,
            daemon: HELPER_PROTOCOL_VERSION,
        });
    }
    Ok(HandshakeOutcome {
        daemon_pid: helper_pid,
        daemon_uid: helper_uid,
        granted,
        kernel_tier,
        degraded_reason,
    })
}

/// Read peer credentials from a connected Unix socket. Per-OS:
/// - Linux: `SO_PEERCRED` returns `struct ucred { pid, uid, gid }`.
/// - macOS: `LOCAL_PEERPID` for pid; `getpeereid` for uid.
/// - FreeBSD/NetBSD: `LOCAL_PEERCRED` for both.
#[cfg(target_os = "linux")]
fn peer_cred(fd: RawFd) -> Result<(u32, u32), HandshakeError> {
    use std::os::fd::BorrowedFd;
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let cred = nix::sys::socket::getsockopt(&borrowed, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|e| HandshakeError::PeerCred(e.to_string()))?;
    Ok((cred.pid() as u32, cred.uid()))
}

#[cfg(target_os = "macos")]
fn peer_cred(fd: RawFd) -> Result<(u32, u32), HandshakeError> {
    use std::os::fd::BorrowedFd;
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let pid = nix::sys::socket::getsockopt(&borrowed, nix::sys::socket::sockopt::LocalPeerPid)
        .map_err(|e| HandshakeError::PeerCred(e.to_string()))?;
    // getpeereid for uid on macOS — pull it via libc directly since
    // nix doesn't expose it as a sockopt.
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(fd, &mut euid as *mut _, &mut egid as *mut _) };
    if rc != 0 {
        return Err(HandshakeError::PeerCred(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok((pid as u32, euid))
}

#[cfg(target_os = "freebsd")]
fn peer_cred(fd: RawFd) -> Result<(u32, u32), HandshakeError> {
    // FreeBSD: SOL_LOCAL/LOCAL_PEERCRED getsockopt returns a full
    // `struct xucred` including `cr_pid` (FreeBSD 12+). On socketpair-
    // created pairs the kernel returns ENOTCONN; in that case both
    // ends started in the same process, so falling back to local
    // pid/uid is correct. The daemon ↔ helper production path uses
    // listen/connect/accept where this returns the peer's real pid.
    use std::mem::MaybeUninit;
    let mut xucred: MaybeUninit<libc::xucred> = MaybeUninit::zeroed();
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            0, // SOL_LOCAL on FreeBSD
            libc::LOCAL_PEERCRED,
            xucred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTCONN) {
            return Ok((std::process::id(), current_uid()));
        }
        return Err(HandshakeError::PeerCred(err.to_string()));
    }
    let xucred = unsafe { xucred.assume_init() };
    // SAFETY: the kernel filled in `cr_pid` as part of the xucred
    // payload; the union access reads that same pid_t.
    let pid = unsafe { xucred.cr_pid__c_anonymous_union.cr_pid };
    Ok((pid as u32, xucred.cr_uid))
}

#[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
fn peer_cred(fd: RawFd) -> Result<(u32, u32), HandshakeError> {
    // NetBSD/OpenBSD: getpeereid gives uid only; no portable pid.
    // We accept best-effort pid=0 — DR-49/50 track full peer auth
    // on those BSDs when we have VM targets in CI.
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(fd, &mut euid as *mut _, &mut egid as *mut _) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTCONN) {
            return Ok((std::process::id(), current_uid()));
        }
        return Err(HandshakeError::PeerCred(err.to_string()));
    }
    Ok((0, euid))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
fn peer_cred(_fd: RawFd) -> Result<(u32, u32), HandshakeError> {
    Err(HandshakeError::PeerCred("unsupported os".into()))
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// Build the `SelfVerifyReport` the handshake ack carries
/// (M07.C.3). macOS shells out to `codesign --verify --strict
/// --deep`; other platforms return the `NotApplicable` sentinel
/// so the wire shape is uniform.
fn self_verify_report() -> SelfVerifyReport {
    #[cfg(target_os = "macos")]
    {
        crate::codesign_verify::verify_self()
    }
    #[cfg(not(target_os = "macos"))]
    {
        SelfVerifyReport::not_applicable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::socketpair;
    use std::thread;

    fn active_tier(name: &str) -> ActiveCaptureTier {
        ActiveCaptureTier::new(name, None)
    }

    fn complete_handshake(
        conn: &Conn,
        expected_pid: u32,
        expected_uid: u32,
        local_caps: HelperCaps,
        tier: ActiveCaptureTier,
    ) -> Result<HandshakeOutcome, HandshakeError> {
        let authenticated = authenticate_helper_side(conn, expected_pid, expected_uid)?;
        acknowledge_helper_side(conn, authenticated, local_caps, tier)
    }

    #[test]
    fn handshake_round_trip_via_socketpair() {
        let (client, server) = socketpair().unwrap();
        let expected_pid = std::process::id();
        let expected_uid = current_uid();

        let (authenticated_tx, authenticated_rx) = std::sync::mpsc::channel();
        let (ack_tx, ack_rx) = std::sync::mpsc::channel();
        let server_thread = thread::spawn(move || -> Result<_, HandshakeError> {
            let authenticated = authenticate_helper_side(&server, expected_pid, expected_uid)?;
            authenticated_tx.send(()).unwrap();
            ack_rx.recv().unwrap();
            acknowledge_helper_side(
                &server,
                authenticated,
                HelperCaps::full(),
                active_tier("bpf-lsm"),
            )
        });

        let daemon_thread = thread::spawn(move || perform_daemon_side(&client, HelperCaps::full()));
        authenticated_rx.recv().unwrap();
        assert!(
            !daemon_thread.is_finished(),
            "authentication must not send HandshakeAck before capture startup resolves"
        );
        ack_tx.send(()).unwrap();
        let outcome_daemon = daemon_thread.join().unwrap().unwrap();
        let outcome_helper = server_thread.join().unwrap().unwrap();
        assert_eq!(outcome_helper.daemon_pid, expected_pid);
        assert_eq!(outcome_helper.daemon_uid, expected_uid);
        assert_eq!(outcome_helper.granted, HelperCaps::full());
        assert_eq!(outcome_daemon.granted, HelperCaps::full());
        assert_eq!(outcome_helper.kernel_tier, "bpf-lsm");
        assert_eq!(outcome_daemon.kernel_tier, "bpf-lsm");
        assert_eq!(outcome_daemon.degraded_reason, None);
    }

    #[test]
    fn handshake_caps_intersect_with_helper_local() {
        let (client, server) = socketpair().unwrap();
        let expected_pid = std::process::id();
        let expected_uid = current_uid();
        let helper_local = HelperCaps {
            watch_tree: true,
            auth_subscribe: false,
            package_hook: true,
        };

        let server_thread = thread::spawn(move || {
            complete_handshake(
                &server,
                expected_pid,
                expected_uid,
                helper_local,
                active_tier("fanotify"),
            )
        });
        let outcome = perform_daemon_side(&client, HelperCaps::full()).unwrap();
        let helper_outcome = server_thread.join().unwrap().unwrap();
        assert_eq!(outcome.granted, helper_local);
        assert_eq!(helper_outcome.granted, helper_local);
        assert_eq!(outcome.kernel_tier, "fanotify");
    }

    #[test]
    fn handshake_refuses_wrong_pid() {
        let (_client, server) = socketpair().unwrap();
        let wrong_pid = std::process::id().wrapping_add(1);
        let res = authenticate_helper_side(&server, wrong_pid, current_uid());
        assert!(matches!(res, Err(HandshakeError::PidMismatch { .. })));
    }

    #[test]
    fn handshake_ack_uses_resolved_tier_and_reason_exactly() {
        let (client, server) = socketpair().unwrap();
        let expected_pid = std::process::id();
        let expected_uid = current_uid();
        let reason = "EndpointSecurity producer startup failed: NotEntitled".to_string();
        let expected_reason = reason.clone();

        let server_thread = thread::spawn(move || {
            complete_handshake(
                &server,
                expected_pid,
                expected_uid,
                HelperCaps::full(),
                ActiveCaptureTier::new("fsevents-degraded", Some(reason)),
            )
        });
        let outcome = perform_daemon_side(&client, HelperCaps::full()).unwrap();
        server_thread.join().unwrap().unwrap();

        assert_eq!(outcome.kernel_tier, "fsevents-degraded");
        assert_eq!(outcome.degraded_reason, Some(expected_reason));
    }
}
