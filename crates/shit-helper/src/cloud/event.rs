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

use super::gh::{GhVerb, classify_gh_argv};
use super::kubectl::{KubectlVerb, classify_kubectl_argv};
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
        "kubectl" => match classify_kubectl_argv(&argv) {
            Some(v) => prepare_kubectl(v),
            None => {
                tracing::debug!(
                    ?argv,
                    "kubectl argv didn't classify as destructive; skipping"
                );
                return Ok(());
            }
        },
        "gh" => match classify_gh_argv(&argv) {
            Some(v) => prepare_gh(v),
            None => {
                tracing::debug!(?argv, "gh argv didn't classify as destructive; skipping");
                return Ok(());
            }
        },
        // AR04.5 (aws) will route here.
        other => {
            tracing::debug!(
                tool = other,
                "cloud-event: tool not yet implemented (AR04.4/.5 will route)"
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

/// AR04.3 (DR-CR-06 kubectl path): capture `kubectl get -o yaml
/// <kind>/<name> [-n <namespace>]` before the user's destructive
/// verb. Pack the captured YAML into prior_state; pack
/// context+namespace+kind+name into extras so the daemon's
/// cloud_track can build a typed KubectlOp event.
///
/// Verb mapping to wire:
/// - Delete{kind,name,namespace} → KubectlDelete + extras
/// - DeleteFile{path}             → KubectlDelete; helper resolves the
///   file's first resource (multi-doc files are a follow-up)
/// - ApplyFile{path}              → KubectlApply; same one-resource
///   simplification
/// - Scale{kind,name,namespace}   → KubectlApply (reverse pipes the
///   captured YAML with the pre-scale replica count)
fn prepare_kubectl(verb: KubectlVerb) -> Option<PreparedEvent> {
    let (kind, name, namespace, wire_verb) = match &verb {
        KubectlVerb::Delete {
            kind,
            name,
            namespace,
        } => (
            kind.clone(),
            name.clone(),
            namespace.clone(),
            CloudVerbWire::KubectlDelete,
        ),
        KubectlVerb::Scale {
            kind,
            name,
            namespace,
        } => (
            kind.clone(),
            name.clone(),
            namespace.clone(),
            CloudVerbWire::KubectlApply,
        ),
        KubectlVerb::DeleteFile { path } => {
            let (kind, name, namespace) = first_resource_from_yaml_file(path)?;
            (kind, name, namespace, CloudVerbWire::KubectlDelete)
        }
        KubectlVerb::ApplyFile { path } => {
            let (kind, name, namespace) = first_resource_from_yaml_file(path)?;
            (kind, name, namespace, CloudVerbWire::KubectlApply)
        }
    };

    // Capture the live YAML before the destructive verb runs.
    let captured = match kubectl_get_yaml(&kind, &name, namespace.as_deref()) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                err = %e,
                "cloud-event: kubectl get -o yaml failed; event will ship without captured_yaml \
                 (undo will fail-closed)"
            );
            Vec::new()
        }
    };

    // Capture the current kube-context too — the executor's guard
    // refuses to apply if the live context drifted at undo time.
    let context = kubectl_current_context().unwrap_or_else(|| "<unknown>".to_string());

    let mut extras = BTreeMap::new();
    extras.insert("kind".into(), kind);
    extras.insert("name".into(), name);
    extras.insert("context".into(), context);
    if let Some(ns) = namespace {
        extras.insert("namespace".into(), ns);
    }

    Some(PreparedEvent {
        runtime: CloudRuntimeWire::Kubectl,
        verb: wire_verb,
        prior_state: captured,
        extras,
    })
}

/// Run `kubectl get <kind>/<name> [-n <ns>] -o yaml` and return the
/// raw YAML bytes.
fn kubectl_get_yaml(kind: &str, name: &str, namespace: Option<&str>) -> std::io::Result<Vec<u8>> {
    let resource = format!("{kind}/{name}");
    let mut cmd = Command::new("kubectl");
    cmd.args(["get", &resource, "-o", "yaml"]);
    if let Some(ns) = namespace {
        cmd.args(["-n", ns]);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "kubectl get {resource}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Read the current context with `kubectl config current-context`.
/// Returns None if kubectl is unavailable or the call fails.
fn kubectl_current_context() -> Option<String> {
    let out = Command::new("kubectl")
        .args(["config", "current-context"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Best-effort first-resource extractor for `kubectl apply -f` /
/// `kubectl delete -f` paths. Multi-document YAML files (separated
/// by `---`) are a v1.x follow-up — for v1 the helper captures the
/// FIRST resource only and the planner journal records that.
/// Returns (kind, name, namespace).
fn first_resource_from_yaml_file(path: &str) -> Option<(String, String, Option<String>)> {
    let content = std::fs::read_to_string(path).ok()?;
    // First doc only — split on YAML doc separator.
    let first_doc = content.split("\n---").next().unwrap_or(&content);
    let mut kind = None;
    let mut name = None;
    let mut namespace = None;
    let mut in_metadata = false;
    for line in first_doc.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("kind:") && kind.is_none() {
            kind = Some(
                trimmed["kind:".len()..]
                    .trim()
                    .trim_matches('"')
                    .to_string(),
            );
        }
        if trimmed.starts_with("metadata:") {
            in_metadata = true;
            continue;
        }
        if in_metadata {
            if !line.starts_with(' ') && !trimmed.is_empty() && !trimmed.starts_with('#') {
                in_metadata = false;
            } else if trimmed.starts_with("name:") && name.is_none() {
                name = Some(
                    trimmed["name:".len()..]
                        .trim()
                        .trim_matches('"')
                        .to_string(),
                );
            } else if trimmed.starts_with("namespace:") && namespace.is_none() {
                namespace = Some(
                    trimmed["namespace:".len()..]
                        .trim()
                        .trim_matches('"')
                        .to_string(),
                );
            }
        }
    }
    Some((kind?, name?, namespace))
}

/// AR04.4 (DR-CR-06 gh path): capture the resource's pre-state JSON
/// before the user's destructive verb. For ReleaseDelete: `gh release
/// view <tag> --json tagName,name,body,isPrerelease,isDraft,assets`
/// captures everything the executor's `build_reverse` synthesis path
/// needs to re-create. Other gh verbs (issue/PR close) capture
/// nothing — the reverse is a stateless reopen.
fn prepare_gh(verb: GhVerb) -> Option<PreparedEvent> {
    let (wire_verb, captured, mut extras) = match &verb {
        GhVerb::ReleaseDelete { tag } => {
            let captured = match gh_release_view_json(tag) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!(
                        tag = %tag,
                        err = %e,
                        "cloud-event: gh release view failed; event will ship without captured_json \
                         (undo will fail-closed)"
                    );
                    Vec::new()
                }
            };
            let mut e = BTreeMap::new();
            e.insert("tag".into(), tag.clone());
            (CloudVerbWire::GhReleaseDelete, captured, e)
        }
        // ReleaseDeleteAsset / IssueClose / PrClose deferred — the
        // executor surfaces them as Informational anyway. We don't
        // ship those events to keep the journal clean.
        _ => {
            tracing::debug!(
                ?verb,
                "cloud-event: gh verb not yet shipped in AR04.4 (informational reverse only)"
            );
            return None;
        }
    };

    // Stash a redacted source for traceability — useful when we
    // expand to more verbs.
    let _ = &mut extras;

    Some(PreparedEvent {
        runtime: CloudRuntimeWire::Gh,
        verb: wire_verb,
        prior_state: captured,
        extras,
    })
}

/// Run `gh release view <tag> --json <fields>` against the auto-
/// detected repo (gh figures out the slug from the current git
/// origin) and return the raw JSON bytes. Empty stdout on failure.
fn gh_release_view_json(tag: &str) -> std::io::Result<Vec<u8>> {
    let out = Command::new("gh")
        .args([
            "release",
            "view",
            tag,
            "--json",
            "tagName,name,body,isPrerelease,isDraft,targetCommitish,assets",
        ])
        .output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!(
            "gh release view {tag}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
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

    #[test]
    fn prepare_kubectl_delete_packs_kind_name_namespace() {
        // No kubectl on PATH → captured_yaml is empty (warn-fallback)
        // but extras still populated from the classifier output.
        let prepared = prepare_kubectl(KubectlVerb::Delete {
            kind: "Pod".into(),
            name: "busybox".into(),
            namespace: Some("default".into()),
        })
        .unwrap();
        assert!(matches!(prepared.verb, CloudVerbWire::KubectlDelete));
        assert_eq!(prepared.extras.get("kind").map(String::as_str), Some("Pod"));
        assert_eq!(
            prepared.extras.get("name").map(String::as_str),
            Some("busybox")
        );
        assert_eq!(
            prepared.extras.get("namespace").map(String::as_str),
            Some("default")
        );
    }

    #[test]
    fn prepare_kubectl_scale_maps_to_apply_wire_verb() {
        // Scale reverse pipes the captured YAML (with pre-scale
        // replica count) through `kubectl apply -f -`, so wire-side
        // it's KubectlApply.
        let prepared = prepare_kubectl(KubectlVerb::Scale {
            kind: "Deployment".into(),
            name: "web".into(),
            namespace: None,
        })
        .unwrap();
        assert!(matches!(prepared.verb, CloudVerbWire::KubectlApply));
        assert!(!prepared.extras.contains_key("namespace"));
    }

    #[test]
    fn first_resource_from_yaml_extracts_kind_name_namespace() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: probe\n  namespace: kube-system\nspec:\n  containers: []\n",
        )
        .unwrap();
        let (kind, name, ns) = first_resource_from_yaml_file(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(kind, "Pod");
        assert_eq!(name, "probe");
        assert_eq!(ns.as_deref(), Some("kube-system"));
    }

    #[test]
    fn prepare_gh_release_delete_packs_tag_in_extras() {
        // No gh on PATH → captured_json empty (warn-fallback), but
        // tag extras still populated.
        let prepared = prepare_gh(GhVerb::ReleaseDelete {
            tag: "v0.0.0-test".into(),
        })
        .unwrap();
        assert!(matches!(prepared.verb, CloudVerbWire::GhReleaseDelete));
        assert_eq!(
            prepared.extras.get("tag").map(String::as_str),
            Some("v0.0.0-test")
        );
    }

    #[test]
    fn prepare_gh_issue_close_returns_none_v1() {
        // IssueClose's reverse (issue reopen) is stateless — no
        // capture needed. Helper skips shipping the event in v1.
        assert!(prepare_gh(GhVerb::IssueClose { number: 42 }).is_none());
    }

    #[test]
    fn first_resource_from_yaml_handles_missing_namespace() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: probe\n",
        )
        .unwrap();
        let (kind, name, ns) = first_resource_from_yaml_file(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(kind, "ConfigMap");
        assert_eq!(name, "probe");
        assert!(ns.is_none());
    }
}
