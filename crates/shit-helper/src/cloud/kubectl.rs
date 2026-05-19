// SPDX-License-Identifier: AGPL-3.0-or-later

//! kubectl argv classifier — used by the capture-time hook to decide
//! which verb a `kubectl ...` invocation maps to. The hook calls
//! `classify_kubectl_argv(argv)`; on a destructive verb, it captures
//! `kubectl get -o yaml <kind>/<name>` before the real exec.
//!
//! Stage 1 of C03.2 ships the classifier + tests; wiring the helper
//! `cloud-event` ctl request and the daemon-side pairing is DR-CR-06.

/// What the argv signalled. `None` means "no capture needed" (read-only
/// or unrecognized verb).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubectlVerb {
    /// `kubectl delete <kind> <name> [-n <ns>]` — capture pre-state.
    Delete {
        kind: String,
        name: String,
        namespace: Option<String>,
    },
    /// `kubectl delete -f <file>` — capture each manifest's pre-state.
    DeleteFile { path: String },
    /// `kubectl apply -f <file>` — capture each manifest's pre-state.
    ApplyFile { path: String },
    /// `kubectl scale <kind>/<name> --replicas=<N>` — capture the
    /// resource's current replica count.
    Scale {
        kind: String,
        name: String,
        namespace: Option<String>,
    },
}

/// Classify an argv as a destructive kubectl verb. Returns `None` for
/// read-only verbs (get, describe, logs, exec --stdin, etc.) and for
/// argv that don't look like kubectl at all.
pub fn classify_kubectl_argv(argv: &[String]) -> Option<KubectlVerb> {
    if argv.first().map(String::as_str) != Some("kubectl") {
        return None;
    }
    // Peel global flags before the verb. The full set is much larger;
    // we only need the ones likely to appear before the verb. Pairs
    // like `--kubeconfig <path>` count as 2 args; bare flags like
    // `--validate=false` count as 1.
    let mut idx = 1;
    while idx < argv.len() {
        let tok = &argv[idx];
        if tok.starts_with("--") || tok.starts_with('-') {
            // Glob: assume any flag with explicit `=` is one token;
            // otherwise consume the next as its value, unless it
            // looks like a verb.
            if tok.contains('=') {
                idx += 1;
            } else if idx + 1 < argv.len() && !is_verb_or_kind(&argv[idx + 1]) {
                idx += 2;
            } else {
                idx += 1;
            }
        } else {
            break;
        }
    }
    let verb = argv.get(idx)?;
    let rest = &argv[idx + 1..];
    match verb.as_str() {
        "delete" => classify_delete(rest),
        "apply" => classify_apply_file(rest),
        "scale" => classify_scale(rest),
        _ => None,
    }
}

fn is_verb_or_kind(s: &str) -> bool {
    matches!(
        s,
        "get"
            | "describe"
            | "delete"
            | "apply"
            | "create"
            | "scale"
            | "rollout"
            | "exec"
            | "logs"
            | "edit"
            | "patch"
            | "label"
            | "annotate"
            | "expose"
            | "run"
    )
}

fn classify_delete(rest: &[String]) -> Option<KubectlVerb> {
    // Two shapes: `delete <kind> <name>` and `delete -f <file>`.
    let mut namespace = None;
    let mut positional: Vec<&str> = Vec::new();
    let mut file_arg: Option<String> = None;
    let mut iter = rest.iter().peekable();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-n" | "--namespace" => {
                if let Some(v) = iter.next() {
                    namespace = Some(v.clone());
                }
            }
            "-f" | "--filename" => {
                if let Some(v) = iter.next() {
                    file_arg = Some(v.clone());
                }
            }
            s if s.starts_with('-') => {
                // Skip other flags that take a value pair-style. We
                // don't need fine-grained handling here.
                if !s.contains('=')
                    && let Some(next) = iter.peek()
                    && !next.starts_with('-')
                {
                    iter.next();
                }
            }
            _ => positional.push(tok),
        }
    }
    if let Some(path) = file_arg {
        return Some(KubectlVerb::DeleteFile { path });
    }
    let (kind, name) = match positional.as_slice() {
        [kind, name] => (kind.to_string(), name.to_string()),
        // `delete pod/foo` short form
        [combined] if combined.contains('/') => {
            let (k, n) = combined.split_once('/').unwrap();
            (k.to_string(), n.to_string())
        }
        _ => return None,
    };
    Some(KubectlVerb::Delete {
        kind,
        name,
        namespace,
    })
}

fn classify_apply_file(rest: &[String]) -> Option<KubectlVerb> {
    let mut iter = rest.iter();
    while let Some(tok) = iter.next() {
        if tok == "-f" || tok == "--filename" {
            return iter
                .next()
                .map(|v| KubectlVerb::ApplyFile { path: v.clone() });
        }
    }
    None
}

fn classify_scale(rest: &[String]) -> Option<KubectlVerb> {
    let mut namespace = None;
    let mut positional: Vec<&str> = Vec::new();
    let mut iter = rest.iter().peekable();
    while let Some(tok) = iter.next() {
        match tok.as_str() {
            "-n" | "--namespace" => {
                if let Some(v) = iter.next() {
                    namespace = Some(v.clone());
                }
            }
            s if s.starts_with('-') => {
                if !s.contains('=')
                    && let Some(next) = iter.peek()
                    && !next.starts_with('-')
                {
                    iter.next();
                }
            }
            _ => positional.push(tok),
        }
    }
    let target = positional.first()?;
    let (kind, name) = if let Some((k, n)) = target.split_once('/') {
        (k.to_string(), n.to_string())
    } else if positional.len() >= 2 {
        (target.to_string(), positional[1].to_string())
    } else {
        return None;
    };
    Some(KubectlVerb::Scale {
        kind,
        name,
        namespace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn non_kubectl_returns_none() {
        assert!(classify_kubectl_argv(&argv(&["echo", "hi"])).is_none());
    }

    #[test]
    fn read_only_verbs_return_none() {
        for verb in ["get", "describe", "logs", "exec", "edit"] {
            assert!(
                classify_kubectl_argv(&argv(&["kubectl", verb, "pod", "x"])).is_none(),
                "verb {verb}"
            );
        }
    }

    #[test]
    fn delete_kind_name_classified() {
        let v = classify_kubectl_argv(&argv(&["kubectl", "delete", "pod", "api"])).unwrap();
        assert_eq!(
            v,
            KubectlVerb::Delete {
                kind: "pod".into(),
                name: "api".into(),
                namespace: None
            }
        );
    }

    #[test]
    fn delete_with_namespace_classified() {
        let v = classify_kubectl_argv(&argv(&["kubectl", "delete", "pod", "api", "-n", "prod"]))
            .unwrap();
        assert_eq!(
            v,
            KubectlVerb::Delete {
                kind: "pod".into(),
                name: "api".into(),
                namespace: Some("prod".into())
            }
        );
    }

    #[test]
    fn delete_short_slash_form_classified() {
        let v = classify_kubectl_argv(&argv(&["kubectl", "delete", "deployment/api"])).unwrap();
        assert_eq!(
            v,
            KubectlVerb::Delete {
                kind: "deployment".into(),
                name: "api".into(),
                namespace: None
            }
        );
    }

    #[test]
    fn delete_file_classified() {
        let v = classify_kubectl_argv(&argv(&["kubectl", "delete", "-f", "deploy.yaml"])).unwrap();
        assert_eq!(
            v,
            KubectlVerb::DeleteFile {
                path: "deploy.yaml".into()
            }
        );
    }

    #[test]
    fn apply_file_classified() {
        let v = classify_kubectl_argv(&argv(&["kubectl", "apply", "-f", "deploy.yaml"])).unwrap();
        assert_eq!(
            v,
            KubectlVerb::ApplyFile {
                path: "deploy.yaml".into()
            }
        );
    }

    #[test]
    fn apply_without_file_returns_none() {
        assert!(classify_kubectl_argv(&argv(&["kubectl", "apply", "--dry-run"])).is_none());
    }

    #[test]
    fn scale_classified() {
        let v = classify_kubectl_argv(&argv(&[
            "kubectl",
            "scale",
            "deployment/api",
            "--replicas=3",
        ]))
        .unwrap();
        assert_eq!(
            v,
            KubectlVerb::Scale {
                kind: "deployment".into(),
                name: "api".into(),
                namespace: None
            }
        );
    }

    #[test]
    fn global_flags_before_verb_skipped() {
        // `kubectl --context kind-c1 delete pod api` should still
        // classify as Delete.
        let v = classify_kubectl_argv(&argv(&[
            "kubectl",
            "--context",
            "kind-c1",
            "delete",
            "pod",
            "api",
        ]))
        .unwrap();
        assert!(matches!(v, KubectlVerb::Delete { .. }));
    }

    #[test]
    fn global_flag_with_equals_skipped() {
        let v = classify_kubectl_argv(&argv(&[
            "kubectl",
            "--kubeconfig=/tmp/x",
            "delete",
            "pod",
            "api",
        ]))
        .unwrap();
        assert!(matches!(v, KubectlVerb::Delete { .. }));
    }
}
