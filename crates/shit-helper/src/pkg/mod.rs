// SPDX-License-Identifier: AGPL-3.0-or-later

//! Package-manager hook integration (S14).
//!
//! Each native package manager has its own inspector module
//! ([`apt`], [`pacman`], [`dnf`], [`brew`], [`freebsd`]). They all
//! implement [`PkgInspector`]: a trait that returns a
//! `name → version` map plus an opaque extras bag of
//! manager-specific bookkeeping (apt sources, dnf history id, brew
//! tap list, …).
//!
//! The transient `shit-helper pkg-event <manager> <phase>` mode lives
//! here. It reads package state via the manager's inspector, ships a
//! [`PkgEventReq`] to the daemon over the ctl socket, and exits.
//!
//! **Hook-friendly error policy.** Package-manager hooks MUST NOT
//! break the user's transaction on shit-side failures. Every
//! recoverable error path in this module logs and returns `Ok(())` so
//! the calling apt/pacman/dnf/brew/pkg sees a zero exit and proceeds.
//! Only flag-parsing errors (an unknown manager / phase) surface
//! non-zero, because those indicate a misconfigured hook script that
//! the operator wants to fix.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shit_proto::{
    CtlRequest, CtlResponse, PkgEventReq, PkgManagerWire, PkgPhase, decode_frame, encode_frame,
};

pub mod apt;
pub mod brew;
pub mod dnf;
pub mod freebsd;
pub mod pacman;

/// One package-manager state collector. Implementations are small
/// shell-out wrappers around the manager's own query CLI.
///
/// Implementors carry no state — the inspector struct is a marker
/// type so the dispatcher can switch on manager kind. The
/// `manager()` method exists on the trait so consumers don't have to
/// re-thread the kind through the call stack alongside the boxed dyn.
pub trait PkgInspector {
    fn manager(&self) -> PkgManagerWire;
    /// Snapshot all currently-installed packages as a `name → version`
    /// map. Used for both Pre and Post phases; the daemon diffs them.
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>>;
    /// Manager-specific extras. The daemon stores these verbatim; the
    /// planner consults them when synthesizing the inverse op.
    fn extras(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
}

/// Map a CLI-supplied manager identifier to its inspector.
fn inspector_for(m: PkgManagerWire) -> Box<dyn PkgInspector> {
    match m {
        PkgManagerWire::Apt | PkgManagerWire::Dpkg => Box::new(apt::AptInspector),
        PkgManagerWire::Pacman => Box::new(pacman::PacmanInspector),
        PkgManagerWire::Dnf => Box::new(dnf::DnfInspector),
        PkgManagerWire::Brew => Box::new(brew::BrewInspector),
        PkgManagerWire::Pkg => Box::new(freebsd::PkgInspector),
    }
}

/// Dispatch a `pkg-event` invocation. The dispatcher (in `main.rs`)
/// hands us the manager/phase strings as parsed by clap; we validate,
/// run the inspector, and ship the event.
pub async fn run_event(manager: &str, phase: &str, ctl_sock: Option<&Path>) -> anyhow::Result<()> {
    let manager: PkgManagerWire = match manager.parse() {
        Ok(m) => m,
        Err(e) => {
            // Misconfigured hook script: surface non-zero so the
            // operator notices. This is exactly the case where
            // hook-friendly silent failure would mask a real bug.
            return Err(anyhow::anyhow!(e));
        }
    };
    let phase: PkgPhase = match phase {
        "pre" => PkgPhase::Pre,
        "post" => PkgPhase::Post,
        other => {
            return Err(anyhow::anyhow!(
                "unknown phase: {other:?} (expected 'pre' or 'post')"
            ));
        }
    };

    // SHIT_DURING_UNDO=1 is set by the planner's PackageExecutor when
    // it shells out to a pkg manager during an undo. The hook firing
    // *during* an undo would loop; short-circuit cleanly.
    if std::env::var_os("SHIT_DURING_UNDO").is_some() {
        tracing::info!(
            manager = manager.as_str(),
            phase = ?phase,
            "pkg-event suppressed (SHIT_DURING_UNDO=1)"
        );
        return Ok(());
    }

    let inspector = inspector_for(manager);
    debug_assert_eq!(inspector.manager(), manager);
    let packages = inspector.collect_state().unwrap_or_else(|e| {
        tracing::warn!(
            manager = manager.as_str(),
            phase = ?phase,
            err = %e,
            "pkg-event: failed to collect state; sending empty map"
        );
        BTreeMap::new()
    });
    let extras = inspector.extras();

    // SAFETY: getpid/getuid always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let req = PkgEventReq {
        manager,
        phase,
        pid,
        uid,
        packages,
        op_hint: op_hint_from_env(manager),
        extras,
    };

    let ctl = match ctl_sock {
        Some(p) => p.to_path_buf(),
        None => default_ctl_socket_path(),
    };

    if let Err(e) = send_event(&ctl, &req) {
        // Hook-friendly: log, swallow, return Ok. A torn daemon must
        // not break apt.
        tracing::warn!(
            manager = manager.as_str(),
            phase = ?req.phase,
            ctl = %ctl.display(),
            err = %e,
            "pkg-event: failed to ship to daemon; continuing"
        );
    }
    Ok(())
}

/// Per-manager environment-variable probing for the operation kind.
///
/// apt sets `DPKG_HOOK_ACTION` (in recent versions) and passes
/// `install`/`remove`/`configure`/`upgrade` arguments on the
/// `Pre-Invoke`/`Post-Invoke` command line. dnf sets the operation
/// in its plugin context. pacman passes the operation via the hook's
/// `[Trigger]` block, which we can't read at runtime — pacman writes
/// the affected pkgs to stdin. brew has no native hook env.
///
/// For Stage 1 we read what's cheap and let the daemon classify from
/// the diff for the rest.
fn op_hint_from_env(m: PkgManagerWire) -> Option<String> {
    match m {
        PkgManagerWire::Apt | PkgManagerWire::Dpkg => std::env::var("DPKG_HOOK_ACTION").ok(),
        PkgManagerWire::Dnf => std::env::var("DNF_OP").ok(),
        _ => None,
    }
}

/// Discover the daemon ctl socket the same way `shit` does. Mirrors
/// `shit::paths::default_ctl_socket_path`; duplicated rather than
/// pulled in because `shit-helper` does not (and should not) depend on
/// the CLI crate.
fn default_ctl_socket_path() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("shit-ctl.sock");
    }
    let tmp = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    // SAFETY: getuid always succeeds.
    let uid = unsafe { libc::getuid() };
    tmp.join(format!("shit-ctl-{uid}.sock"))
}

const CTL_TIMEOUT: Duration = Duration::from_secs(10);

/// Send one PkgEvent request and read one ack. Synchronous because
/// this binary is a one-shot; the tokio runtime in `main` is just
/// there for the `async fn` signature parity.
fn send_event(path: &Path, req: &PkgEventReq) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CTL_TIMEOUT))?;
    stream.set_write_timeout(Some(CTL_TIMEOUT))?;
    let frame = encode_frame(&CtlRequest::PkgEvent(req.clone()))?;
    stream.write_all(&frame)?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf)?;
    let resp: CtlResponse = decode_frame(&buf[..n])?;
    match resp {
        CtlResponse::PkgEventAck => Ok(()),
        CtlResponse::Error(e) => Err(anyhow::anyhow!("daemon: {e}")),
        other => Err(anyhow::anyhow!("unexpected daemon response: {other:?}")),
    }
}
