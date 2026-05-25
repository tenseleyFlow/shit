// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit-helper cloud-event` — capture-time hook for cloud / IaC
//! destructive verbs (DR-CR-06 helper side, AR04 PR-B).
//!
//! Flow (terraform path; kubectl / gh / aws land in AR04.3 / .4 / .5):
//! 1. Parse the user's argv (newline-separated in `target_argv`),
//!    classify via [`super::terraform::classify_terraform_argv`].
//! 2. For verbs that mutate state (Apply / Destroy), run `terraform
//!    state pull` to capture the pre-mutation state as JSON bytes.
//! 3. Build [`CloudEventReq`] with the prior_state + workdir + verb
//!    descriptors in `extras`.
//! 4. Ship to the daemon ctl socket. Daemon journals
//!    `CaptureEvent::TerraformOp` against the active command window.
//!
//! Hook-friendliness: any failure to capture or ship is logged and
//! swallowed; the wrapper script must still exec the real terraform.
//! A torn daemon cannot break the user's CLI. Hard-fail protection
//! is the user-facing `shit` policy, not this hook.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use shit_proto::{
    CloudEventReq, CloudRuntimeWire, CloudVerbWire, CtlRequest, CtlResponse, decode_frame,
    encode_frame,
};

use super::terraform::{TerraformVerb, classify_terraform_argv};

const CTL_TIMEOUT: Duration = Duration::from_secs(60);

/// CLI entrypoint dispatched from `main.rs` for the `cloud-event`
/// subcommand.
pub async fn run_event(
    tool: &str,
    phase: &str,
    target_argv: &str,
    ctl_sock: Option<&Path>,
) -> anyhow::Result<()> {
    // Avoid re-entry when an undo plan is shelling out to terraform /
    // kubectl / gh / aws to perform restoration; the hook would loop.
    if std::env::var_os("SHIT_DURING_UNDO").is_some() {
        tracing::info!(tool, phase, "cloud-event suppressed (SHIT_DURING_UNDO=1)");
        return Ok(());
    }

    if phase != "pre" {
        tracing::debug!(tool, phase, "cloud-event: non-pre phase, ignoring");
        return Ok(());
    }

    let mut argv: Vec<String> = vec![tool.to_string()];
    for tok in target_argv.split('\n') {
        if !tok.is_empty() {
            argv.push(tok.to_string());
        }
    }

    let prepared = match tool {
        "terraform" => match classify_terraform_argv(&argv) {
            Some(v) => prepare_terraform(v),
            None => {
                tracing::debug!(
                    ?argv,
                    "terraform argv didn't classify as destructive; skipping"
                );
                return Ok(());
            }
        },
        // AR04.3 / .4 / .5 will route here.
        other => {
            tracing::debug!(
                tool = other,
                "cloud-event: tool not yet implemented in AR04.1"
            );
            return Ok(());
        }
    };

    let Some(prepared) = prepared else {
        return Ok(());
    };

    let workdir = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    // SAFETY: getpid/getuid always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let req = CloudEventReq {
        runtime: prepared.runtime,
        verb: prepared.verb,
        workdir,
        prior_state: prepared.prior_state,
        extras: prepared.extras,
        pid,
        uid,
    };

    let ctl = match ctl_sock {
        Some(p) => p.to_path_buf(),
        None => default_ctl_socket_path(),
    };

    if let Err(e) = send_event(&ctl, &req) {
        tracing::warn!(
            tool,
            ctl = %ctl.display(),
            err = %e,
            "cloud-event: ship to daemon failed; continuing"
        );
    }
    Ok(())
}

struct PreparedEvent {
    runtime: CloudRuntimeWire,
    verb: CloudVerbWire,
    prior_state: Vec<u8>,
    extras: BTreeMap<String, String>,
}

/// AR04.1 (DR-CR-06 terraform path): for Apply / Destroy capture the
/// pre-mutation state via `terraform state pull`. For StateRm /
/// Import we ship the verb + the affected address so the planner can
/// surface the captured intent in `shit show`, but reverse is
/// informational (DR-CR-22 has a parallel for container Rm).
fn prepare_terraform(verb: TerraformVerb) -> Option<PreparedEvent> {
    let (wire_verb, extras) = match &verb {
        TerraformVerb::Apply => (CloudVerbWire::TerraformApply, BTreeMap::new()),
        TerraformVerb::Destroy => (CloudVerbWire::TerraformDestroy, BTreeMap::new()),
        TerraformVerb::StateRm { addr } => {
            let mut e = BTreeMap::new();
            e.insert("addr".into(), addr.clone());
            (CloudVerbWire::TerraformStateRm, e)
        }
        TerraformVerb::Import { addr, id } => {
            let mut e = BTreeMap::new();
            e.insert("addr".into(), addr.clone());
            e.insert("id".into(), id.clone());
            (CloudVerbWire::TerraformImport, e)
        }
    };

    // Only Apply / Destroy carry a state snapshot; StateRm / Import
    // are surgical (and the executor refuses-cleanly anyway), so we
    // skip the pull cost for them.
    let prior_state = match verb {
        TerraformVerb::Apply | TerraformVerb::Destroy => match terraform_state_pull() {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    "cloud-event: terraform state pull failed; event will ship without prior_state \
                     (undo will fail-closed at apply -refresh-only time)"
                );
                Vec::new()
            }
        },
        TerraformVerb::StateRm { .. } | TerraformVerb::Import { .. } => Vec::new(),
    };

    Some(PreparedEvent {
        runtime: CloudRuntimeWire::Terraform,
        verb: wire_verb,
        prior_state,
        extras,
    })
}

/// Run `terraform state pull` in the current dir and return the raw
/// JSON bytes. Empty state file is valid (uninitialised module);
/// pull still succeeds and emits the empty-state JSON.
fn terraform_state_pull() -> std::io::Result<Vec<u8>> {
    let out = Command::new("terraform").args(["state", "pull"]).output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "terraform state pull exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Mirror of [`super::super::pkg::default_ctl_socket_path`] /
/// [`super::super::container::event::default_ctl_socket_path`].
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

fn send_event(path: &Path, req: &CloudEventReq) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CTL_TIMEOUT))?;
    stream.set_write_timeout(Some(CTL_TIMEOUT))?;
    // CloudEvent payloads are small (terraform state JSON is typically
    // a few KB to maybe 1 MB for moderate modules — well under the
    // 256 KiB MAX_FRAME_SIZE in the common case; large-module
    // capture is a follow-up that'd switch to encode_frame_large).
    let frame = encode_frame(&CtlRequest::CloudEvent(req.clone()))?;
    stream.write_all(&frame)?;
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf)?;
    let resp: CtlResponse = decode_frame(&buf[..n])?;
    match resp {
        CtlResponse::CloudEventAck => Ok(()),
        CtlResponse::Error(e) => Err(anyhow::anyhow!("daemon: {e}")),
        other => Err(anyhow::anyhow!("unexpected daemon response: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_apply_packs_verb_and_empty_extras() {
        let prepared = prepare_terraform(TerraformVerb::Apply).unwrap();
        assert!(matches!(prepared.runtime, CloudRuntimeWire::Terraform));
        assert!(matches!(prepared.verb, CloudVerbWire::TerraformApply));
        assert!(prepared.extras.is_empty());
        // prior_state may be empty (no terraform binary in test env) —
        // the warn-fallback path still ships the event.
    }

    #[test]
    fn prepare_destroy_packs_verb() {
        let prepared = prepare_terraform(TerraformVerb::Destroy).unwrap();
        assert!(matches!(prepared.verb, CloudVerbWire::TerraformDestroy));
    }

    #[test]
    fn prepare_state_rm_packs_addr_extras_no_state_pull() {
        let prepared = prepare_terraform(TerraformVerb::StateRm {
            addr: "aws_instance.web".into(),
        })
        .unwrap();
        assert!(matches!(prepared.verb, CloudVerbWire::TerraformStateRm));
        assert_eq!(
            prepared.extras.get("addr").map(String::as_str),
            Some("aws_instance.web")
        );
        // StateRm doesn't pull state.
        assert!(prepared.prior_state.is_empty());
    }

    #[test]
    fn prepare_import_packs_addr_and_id() {
        let prepared = prepare_terraform(TerraformVerb::Import {
            addr: "aws_instance.web".into(),
            id: "i-0123".into(),
        })
        .unwrap();
        assert!(matches!(prepared.verb, CloudVerbWire::TerraformImport));
        assert_eq!(
            prepared.extras.get("addr").map(String::as_str),
            Some("aws_instance.web")
        );
        assert_eq!(
            prepared.extras.get("id").map(String::as_str),
            Some("i-0123")
        );
    }
}
