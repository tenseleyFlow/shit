// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network-tool hook integration (S17).
//!
//! Mirrors [`crate::pkg`] and [`crate::svc`]: a transient
//! `shit-helper net-event ...` mode that snapshots the tool's
//! state and ships it to the daemon.
//!
//! Per-tool inspectors implement [`NetInspector::collect_state`] by
//! shelling out to the tool's own dump command (`iptables-save -c`,
//! `nft list ruleset -a`, `pfctl -s rules`, etc.). The dump is sent
//! verbatim; the daemon doesn't try to parse it (the executor will
//! pipe it back through the same tool's restore command on undo).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shit_proto::{
    CtlRequest, CtlResponse, NetEventReq, NetToolWire, PkgPhase, decode_frame, encode_frame,
};

pub mod ip;
pub mod iptables;
#[cfg(target_os = "macos")]
pub mod networksetup;
pub mod nft;
pub mod pfctl;
#[cfg(target_os = "macos")]
pub mod route_ifconfig;
pub mod ufw;

pub trait NetInspector {
    fn tool(&self) -> NetToolWire;
    /// Snapshot the tool's current state. Bytes, not text — some
    /// tools (`pfctl -s rules`) include trailing nulls.
    fn collect_state(&self, scope_hint: &str) -> anyhow::Result<Vec<u8>>;
}

fn inspector_for(t: NetToolWire) -> Option<Box<dyn NetInspector>> {
    match t {
        NetToolWire::Iptables => Some(Box::new(iptables::IptablesInspector { v6: false })),
        NetToolWire::Ip6tables => Some(Box::new(iptables::IptablesInspector { v6: true })),
        NetToolWire::Nft => Some(Box::new(nft::NftInspector)),
        NetToolWire::Ufw => Some(Box::new(ufw::UfwInspector)),
        NetToolWire::Pfctl => Some(Box::new(pfctl::PfctlInspector)),
        NetToolWire::IpRoute | NetToolWire::IpAddr | NetToolWire::IpLink => {
            Some(Box::new(ip::IpInspector::for_object(t)))
        }
        // M06.3 — legacy macOS route/ifconfig (DR-44). Linux uses
        // `ip` (ip.rs) and never reaches route/ifconfig; non-macOS
        // BSDs aren't a v1 target.
        #[cfg(target_os = "macos")]
        NetToolWire::Route => Some(Box::new(route_ifconfig::RouteInspector)),
        #[cfg(target_os = "macos")]
        NetToolWire::Ifconfig => Some(Box::new(route_ifconfig::IfconfigInspector)),
        #[cfg(not(target_os = "macos"))]
        NetToolWire::Route | NetToolWire::Ifconfig => None,
        // M06.1 — `networksetup` ships DNS-only first ship.
        // macOS-only; the cfg gate on the `networksetup` module
        // mirrors here.
        #[cfg(target_os = "macos")]
        NetToolWire::Networksetup => Some(Box::new(networksetup::NetworksetupInspector)),
        #[cfg(not(target_os = "macos"))]
        NetToolWire::Networksetup => None,
    }
}

pub async fn run_event(
    tool: &str,
    phase: &str,
    verb: &str,
    scope_hint: &str,
    ctl_sock: Option<&Path>,
) -> anyhow::Result<()> {
    let tool: NetToolWire = tool.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    let phase: PkgPhase = match phase {
        "pre" => PkgPhase::Pre,
        "post" => PkgPhase::Post,
        other => {
            return Err(anyhow::anyhow!(
                "unknown phase: {other:?} (expected 'pre' or 'post')"
            ));
        }
    };

    if std::env::var_os("SHIT_DURING_UNDO").is_some() {
        tracing::info!(
            tool = tool.as_str(),
            phase = ?phase,
            verb,
            "net-event suppressed (SHIT_DURING_UNDO=1)"
        );
        return Ok(());
    }

    let Some(inspector) = inspector_for(tool) else {
        tracing::warn!(
            tool = tool.as_str(),
            "net-event: tool inspector not implemented; logging and dropping"
        );
        return Ok(());
    };
    debug_assert_eq!(inspector.tool(), tool);

    let state_raw = inspector.collect_state(scope_hint).unwrap_or_else(|e| {
        tracing::warn!(
            tool = tool.as_str(),
            phase = ?phase,
            err = %e,
            "net-event: failed to snapshot state; sending empty"
        );
        Vec::new()
    });

    // SAFETY: getpid/getuid always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let req = NetEventReq {
        tool,
        phase,
        verb: verb.to_string(),
        scope_hint: scope_hint.to_string(),
        pid,
        uid,
        state_raw,
    };

    let ctl = match ctl_sock {
        Some(p) => p.to_path_buf(),
        None => default_ctl_socket_path(),
    };
    if let Err(e) = send_event(&ctl, &req) {
        tracing::warn!(
            tool = tool.as_str(),
            phase = ?req.phase,
            ctl = %ctl.display(),
            err = %e,
            "net-event: failed to ship to daemon; continuing"
        );
    }
    Ok(())
}

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

fn send_event(path: &Path, req: &NetEventReq) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CTL_TIMEOUT))?;
    stream.set_write_timeout(Some(CTL_TIMEOUT))?;
    let frame = encode_frame(&CtlRequest::NetEvent(req.clone()))?;
    stream.write_all(&frame)?;
    let mut buf = vec![0u8; 256 * 1024];
    let n = stream.read(&mut buf)?;
    let resp: CtlResponse = decode_frame(&buf[..n])?;
    match resp {
        CtlResponse::NetEventAck => Ok(()),
        CtlResponse::Error(e) => Err(anyhow::anyhow!("daemon: {e}")),
        other => Err(anyhow::anyhow!("unexpected daemon response: {other:?}")),
    }
}
