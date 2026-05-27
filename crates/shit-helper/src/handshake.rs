// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper-side handshake. The daemon initiates by sending a
//! `HelperRequest::Handshake`; we verify the peer's PID/UID matches
//! what we were spawned with, refuse on mismatch, and reply with a
//! `HelperResponse::HandshakeAck` advertising the capability set we can
//! actually provide.

use shit_proto::{HELPER_PROTOCOL_VERSION, HelperCaps, HelperRequest, HelperResponse};
use std::os::fd::RawFd;

use crate::ipc::{Conn, ConnError};

/// Per-platform capture-tier classifier reported in the handshake
/// ack (DR-66). The string surfaces in `shit metrics` and the
/// telemetry stream so operators can tell *which* tier is actually
/// running — Linux can degrade from bpf-lsm → fanotify → inotify;
/// FreeBSD's preload-shim is best-effort; the daemon needs to know.
pub fn kernel_tier_classifier() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        // DR-01..04 light up bpf-lsm; until then the helper falls
        // back to fanotify-perm (DR-08). The string mirrors the
        // expected production tier so the operator sees the right
        // banner during Stage 1 even though the runtime is degraded.
        "fanotify"
    }
    #[cfg(target_os = "macos")]
    {
        // M03.1.I.6: runtime probe of EndpointSecurity. The probe
        // creates + immediately drops a minimal ES client (a few µs)
        // and returns Success when the binary is entitled + the
        // env (SIP+AuthRoot+AMFI bypass in dev, signed binary in
        // prod) accepts the entitlement. Anywhere else → still on
        // FSEvents degraded tier. The producer (`capture::macos_es`)
        // ALSO runs alongside FSEvents per Decision 3 of the
        // M03.1.I design; this string just tells the daemon which
        // tier is the source of truth for content-bearing events.
        use crate::es::probe::{ProbeResult, probe_client_creation};
        match probe_client_creation() {
            ProbeResult::Success => "endpoint-security",
            _ => "fsevents-degraded",
        }
    }
    #[cfg(target_os = "freebsd")]
    {
        "kqueue"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        "unsupported"
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
#[derive(Debug, Clone, Copy)]
pub struct HandshakeOutcome {
    pub daemon_pid: u32,
    pub daemon_uid: u32,
    pub granted: HelperCaps,
}

/// Drive the helper side of the handshake.
///
/// `expected_daemon_pid` / `expected_daemon_uid` come from the CLI args
/// the daemon-spawned helper was given. `local_caps` is what we *can*
/// offer (computed by the caller from platform + privilege). We grant
/// the intersection of what the daemon asks for and what we can do.
pub fn perform_helper_side(
    conn: &Conn,
    expected_daemon_pid: u32,
    expected_daemon_uid: u32,
    local_caps: HelperCaps,
) -> Result<HandshakeOutcome, HandshakeError> {
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

    let granted = capability_request.intersect(local_caps);
    let ack = HelperResponse::HandshakeAck {
        helper_pid: std::process::id(),
        helper_uid: current_uid(),
        protocol_version: HELPER_PROTOCOL_VERSION,
        granted,
        helper_version: env!("CARGO_PKG_VERSION").to_string(),
        kernel_tier: kernel_tier_classifier().to_string(),
    };
    // DR-64 fault-injection: crash mid-reply. The daemon must
    // observe the disconnect, log the failed handshake, and
    // re-spawn the helper rather than treating the dropped socket
    // as a permanent failure.
    shit_proto::fault_inject::maybe_inject("helper.handshake.before_ack_send");
    conn.send_response(&ack)?;
    shit_proto::fault_inject::maybe_inject("helper.handshake.after_ack_send");

    Ok(HandshakeOutcome {
        daemon_pid,
        daemon_uid,
        granted,
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
        kernel_tier: _,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::socketpair;
    use std::thread;

    #[test]
    fn handshake_round_trip_via_socketpair() {
        let (client, server) = socketpair().unwrap();
        let expected_pid = std::process::id();
        let expected_uid = current_uid();

        let server_thread = thread::spawn(move || {
            perform_helper_side(&server, expected_pid, expected_uid, HelperCaps::full())
        });

        let outcome_daemon = perform_daemon_side(&client, HelperCaps::full()).unwrap();
        let outcome_helper = server_thread.join().unwrap().unwrap();
        assert_eq!(outcome_helper.daemon_pid, expected_pid);
        assert_eq!(outcome_helper.daemon_uid, expected_uid);
        assert_eq!(outcome_helper.granted, HelperCaps::full());
        assert_eq!(outcome_daemon.granted, HelperCaps::full());
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
            perform_helper_side(&server, expected_pid, expected_uid, helper_local)
        });
        let outcome = perform_daemon_side(&client, HelperCaps::full()).unwrap();
        let helper_outcome = server_thread.join().unwrap().unwrap();
        assert_eq!(outcome.granted, helper_local);
        assert_eq!(helper_outcome.granted, helper_local);
    }

    #[test]
    fn handshake_refuses_wrong_pid() {
        let (_client, server) = socketpair().unwrap();
        let wrong_pid = std::process::id().wrapping_add(1);
        let res = perform_helper_side(&server, wrong_pid, current_uid(), HelperCaps::full());
        assert!(matches!(res, Err(HandshakeError::PidMismatch { .. })));
    }
}
