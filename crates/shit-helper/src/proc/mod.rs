// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-lifecycle hook integration (S18).
//!
//! Mirrors [`crate::pkg`] / [`crate::svc`] / [`crate::net`]:
//! transient `shit-helper proc-event ...` mode that snapshots the
//! target processes of a kill-family command and ships the
//! snapshots to the daemon.
//!
//! On Pre, we resolve the user's argv to a set of target pids and
//! snapshot each one. On Post, we re-enumerate the same pids and
//! report which ones survived vs. went away. The planner uses the
//! Pre snapshots to render a restart suggestion (`InverseOp::
//! ProcessNote`); the actual undo never resurrects a process.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use shit_planner::{KillCommand, KillTarget, parse_kill, parse_pattern_kill};
use shit_proto::{
    CtlRequest, CtlResponse, PkgPhase, ProcEventReq, ProcToolWire, decode_frame, encode_frame,
};

pub mod enumerate;
pub mod kill_targets;

pub async fn run_event(
    tool: &str,
    phase: &str,
    target_argv_joined: &str,
    ctl_sock: Option<&Path>,
) -> anyhow::Result<()> {
    let tool: ProcToolWire = tool.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
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
            "proc-event suppressed (SHIT_DURING_UNDO=1)"
        );
        return Ok(());
    }

    let target_argv: Vec<String> = if target_argv_joined.is_empty() {
        Vec::new()
    } else {
        target_argv_joined.lines().map(str::to_string).collect()
    };

    // Parse argv into kill targets per the planner's grammar.
    let parsed: Option<KillCommand> = match tool {
        ProcToolWire::Kill => parse_kill(&target_argv),
        ProcToolWire::Pkill | ProcToolWire::Killall => parse_pattern_kill(&target_argv),
    };
    let Some(parsed) = parsed else {
        tracing::info!(
            tool = tool.as_str(),
            "proc-event: argv parsed to no targets; nothing to capture"
        );
        return Ok(());
    };

    // Resolve targets to pids. On Pre this is the canonical
    // list; on Post we re-resolve to see which are still alive.
    let pids = resolve_pids(&parsed.targets);

    // Snapshot each target.
    let mut targets = Vec::new();
    for pid in pids {
        match enumerate::read_proc_snapshot(pid) {
            Ok(snap) => targets.push(snap),
            Err(e) => {
                tracing::debug!(pid, err = %e, "proc-event: snapshot failed; pid likely gone");
            }
        }
    }

    // SAFETY: getpid/getuid always succeed.
    let my_pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let req = ProcEventReq {
        tool,
        phase,
        target_argv,
        targets,
        pid: my_pid,
        uid,
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
            "proc-event: failed to ship to daemon; continuing"
        );
    }
    Ok(())
}

/// Translate parsed kill targets into a flat list of pids the
/// snapshotter can enumerate.
fn resolve_pids(targets: &[KillTarget]) -> Vec<u32> {
    let mut out = Vec::new();
    for t in targets {
        match t {
            KillTarget::Pid(pid) => {
                if *pid > 0 {
                    out.push(*pid as u32);
                } else if let Some(group) = kill_targets::resolve_pgroup(-*pid as u32) {
                    out.extend(group);
                }
            }
            KillTarget::JobSpec(spec) => {
                if let Some(pid) = kill_targets::resolve_job_spec(spec) {
                    out.push(pid);
                }
            }
            KillTarget::Pattern { pattern, filters } => {
                out.extend(kill_targets::resolve_pattern(pattern, filters));
            }
        }
    }
    // Deduplicate while preserving order.
    let mut seen = std::collections::BTreeSet::new();
    out.retain(|p| seen.insert(*p));
    out
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

fn send_event(path: &Path, req: &ProcEventReq) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CTL_TIMEOUT))?;
    stream.set_write_timeout(Some(CTL_TIMEOUT))?;
    let frame = encode_frame(&CtlRequest::ProcEvent(req.clone()))?;
    stream.write_all(&frame)?;
    let mut buf = vec![0u8; 256 * 1024];
    let n = stream.read(&mut buf)?;
    let resp: CtlResponse = decode_frame(&buf[..n])?;
    match resp {
        CtlResponse::ProcEventAck => Ok(()),
        CtlResponse::Error(e) => Err(anyhow::anyhow!("daemon: {e}")),
        other => Err(anyhow::anyhow!("unexpected daemon response: {other:?}")),
    }
}
