// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-manager hook integration (S16).
//!
//! Mirrors the [`crate::pkg`] structure: the transient
//! `shit-helper svc-event ...` mode lives here, plus per-tool
//! inspectors for systemctl ([`systemd`]) and launchctl
//! ([`launchd`]). Each inspector shells out to the manager's own
//! query interface to snapshot the unit's state at Pre and Post
//! phases.
//!
//! **Hook-friendly error policy** (same as pkg): shit-side failures
//! MUST NOT break the user's `systemctl`/`launchctl` invocation.
//! Every recoverable error logs and returns `Ok(())`. Only flag-
//! parsing errors (unknown tool, bad phase) surface non-zero.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shit_proto::{
    CtlRequest, CtlResponse, PkgPhase, SvcEventReq, SvcScopeWire, SvcToolWire, decode_frame,
    encode_frame,
};

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
pub mod freebsd;
pub mod launchd;
pub mod systemd;

/// One service-manager state inspector. Implementations shell out to
/// the manager's own query interface to capture the unit's current
/// state. The returned string is the raw output the planner parses
/// (via `shit_planner::services::parse_systemctl_show` /
/// `parse_launchctl_print`).
pub trait SvcInspector {
    fn tool(&self) -> SvcToolWire;
    /// Snapshot the unit's current state. Returns the raw text from
    /// the manager's query; the daemon and renderer parse it.
    fn collect_state(&self, scope: SvcScopeWire, unit: &str) -> anyhow::Result<String>;
}

fn inspector_for(t: SvcToolWire) -> Box<dyn SvcInspector> {
    match t {
        SvcToolWire::Systemctl => Box::new(systemd::SystemdInspector),
        SvcToolWire::Launchctl => Box::new(launchd::LaunchdInspector),
        #[cfg(any(
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
        ))]
        SvcToolWire::Service => Box::new(freebsd::ServiceInspector),
        #[cfg(not(any(
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
        )))]
        SvcToolWire::Service => Box::new(UnsupportedSvcInspector(SvcToolWire::Service)),
    }
}

/// Stub inspector used when the tool isn't supported on the current
/// platform (e.g. `service(8)` on Linux). The hook wrapper should
/// gate before invocation, but if it gets here we return a clear
/// error rather than a confusing successful empty state.
struct UnsupportedSvcInspector(SvcToolWire);

#[allow(dead_code)]
impl SvcInspector for UnsupportedSvcInspector {
    fn tool(&self) -> SvcToolWire {
        self.0
    }
    fn collect_state(&self, _scope: SvcScopeWire, _unit: &str) -> anyhow::Result<String> {
        Err(anyhow::anyhow!(
            "svc tool {:?} not supported on this platform",
            self.0
        ))
    }
}

/// Dispatch a `svc-event` invocation. The dispatcher (in `main.rs`)
/// hands us the tool/phase/scope/unit/verb strings as parsed by
/// clap; we validate, run the inspector, and ship the event.
pub async fn run_event(
    tool: &str,
    phase: &str,
    scope: &str,
    unit: &str,
    verb: &str,
    ctl_sock: Option<&Path>,
) -> anyhow::Result<()> {
    let tool: SvcToolWire = tool.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    let phase: PkgPhase = match phase {
        "pre" => PkgPhase::Pre,
        "post" => PkgPhase::Post,
        other => {
            return Err(anyhow::anyhow!(
                "unknown phase: {other:?} (expected 'pre' or 'post')"
            ));
        }
    };
    let scope = parse_scope(scope)?;

    // SHIT_DURING_UNDO=1 → suppress entirely. The planner sets this
    // when it shells out to systemctl/launchctl during an undo so
    // the wrapper short-circuits instead of capturing a synthetic
    // "user ran systemctl" event.
    if std::env::var_os("SHIT_DURING_UNDO").is_some() {
        tracing::info!(
            tool = tool.as_str(),
            phase = ?phase,
            unit,
            verb,
            "svc-event suppressed (SHIT_DURING_UNDO=1)"
        );
        return Ok(());
    }

    let inspector = inspector_for(tool);
    debug_assert_eq!(inspector.tool(), tool);
    let state_raw = inspector.collect_state(scope, unit).unwrap_or_else(|e| {
        tracing::warn!(
            tool = tool.as_str(),
            phase = ?phase,
            unit,
            err = %e,
            "svc-event: failed to query state; sending empty"
        );
        String::new()
    });

    // SAFETY: getpid/getuid always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let req = SvcEventReq {
        tool,
        phase,
        scope,
        unit: unit.to_string(),
        verb: verb.to_string(),
        pid,
        uid,
        state_raw,
    };

    let ctl = match ctl_sock {
        Some(p) => p.to_path_buf(),
        None => default_ctl_socket_path(),
    };

    if let Err(e) = send_event(&ctl, &req) {
        // Hook-friendly: log, swallow.
        tracing::warn!(
            tool = tool.as_str(),
            phase = ?req.phase,
            ctl = %ctl.display(),
            err = %e,
            "svc-event: failed to ship to daemon; continuing"
        );
    }
    Ok(())
}

fn parse_scope(s: &str) -> anyhow::Result<SvcScopeWire> {
    match s {
        "user" => Ok(SvcScopeWire::User),
        "system" => Ok(SvcScopeWire::System),
        "launchd-gui" => Ok(SvcScopeWire::LaunchdGui),
        "launchd-system" => Ok(SvcScopeWire::LaunchdSystem),
        "rc-base" => Ok(SvcScopeWire::RcBase),
        other => Err(anyhow::anyhow!(
            "unknown scope: {other:?} (expected user|system|launchd-gui|launchd-system|rc-base)"
        )),
    }
}

/// Mirrors `shit::paths::default_ctl_socket_path`; duplicated rather
/// than depended-on. Same rationale as `pkg::default_ctl_socket_path`.
fn default_ctl_socket_path() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("shit-ctl.sock");
    }
    let tmp = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let uid = unsafe { libc::getuid() };
    tmp.join(format!("shit-ctl-{uid}.sock"))
}

const CTL_TIMEOUT: Duration = Duration::from_secs(10);

fn send_event(path: &Path, req: &SvcEventReq) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CTL_TIMEOUT))?;
    stream.set_write_timeout(Some(CTL_TIMEOUT))?;
    let frame = encode_frame(&CtlRequest::SvcEvent(req.clone()))?;
    stream.write_all(&frame)?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf)?;
    let resp: CtlResponse = decode_frame(&buf[..n])?;
    match resp {
        CtlResponse::SvcEventAck => Ok(()),
        CtlResponse::Error(e) => Err(anyhow::anyhow!("daemon: {e}")),
        other => Err(anyhow::anyhow!("unexpected daemon response: {other:?}")),
    }
}
