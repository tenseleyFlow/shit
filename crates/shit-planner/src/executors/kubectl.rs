// SPDX-License-Identifier: AGPL-3.0-or-later

//! kubectl tier executor (C03.2).
//!
//! Applies [`InverseOp::KubectlReverse`]. The capture path stashed the
//! resource YAML via `kubectl get -o yaml`; the reverse runs
//! `kubectl apply -f -` against the captured manifest, piped on stdin.
//!
//! Context guard: at apply time, the executor re-queries
//! `kubectl config current-context` and refuses if it has changed
//! since capture. Pointing at a different cluster between capture and
//! undo is a common foot-shoot (especially for agents); default-deny
//! is safer than default-apply.

use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::{InverseOp, KubectlOp};

/// Subprocess + stdin-piping abstraction. Tests inject a spy.
pub trait KubectlRunner {
    /// Run an argv (without stdin). Returns Ok on exit 0.
    fn run(&self, argv: &[String]) -> Result<(), String>;
    /// Run an argv with `stdin_bytes` piped to stdin. Used for
    /// `kubectl apply -f -` reverse.
    fn run_with_stdin(&self, argv: &[String], stdin_bytes: &[u8]) -> Result<(), String>;
    /// Capture stdout of a guard command (used by the context check).
    fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String>;
}

/// Production runner: real `std::process::Command`. The
/// `SHIT_DURING_UNDO=1` env-var prevents a kubectl wrapper (when
/// installed via `shit cloud-hooks`) from re-capturing our own
/// reverse invocation.
#[derive(Debug, Default)]
pub struct SystemKubectlRunner;

impl KubectlRunner for SystemKubectlRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let status = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
    fn run_with_stdin(&self, argv: &[String], stdin_bytes: &[u8]) -> Result<(), String> {
        use std::io::Write;
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let mut child = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_bytes)
                .map_err(|e| format!("write stdin: {e}"))?;
        }
        let status = child.wait().map_err(|e| format!("wait {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
    fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let out = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .output()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!("{cmd} exited {:?}", out.status.code()));
        }
        Ok(out.stdout)
    }
}

pub struct KubectlExecutor<R: KubectlRunner> {
    runner: R,
    /// When `false`, the context-drift guard is skipped. Tests use
    /// this; production should always leave it `true`.
    enforce_context_guard: bool,
}

impl<R: KubectlRunner> KubectlExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            enforce_context_guard: true,
        }
    }

    /// Test-only escape hatch. Production code does not call this.
    pub fn with_context_guard(mut self, enforce: bool) -> Self {
        self.enforce_context_guard = enforce;
        self
    }
}

impl<R: KubectlRunner> InverseOpExecutor for KubectlExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::KubectlReverse { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::KubectlReverse {
            context,
            namespace: _,
            op: kop,
            captured_yaml,
            requires_confirmation: _,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "kubectl executor reached non-kubectl op".into(),
            };
        };

        // Context guard: cluster identity must match capture time.
        // Caller can disable this via `with_context_guard(false)` for
        // tests; production runs it.
        if self.enforce_context_guard {
            let guard_argv = vec![
                "kubectl".to_string(),
                "config".to_string(),
                "current-context".to_string(),
            ];
            match self.runner.capture(&guard_argv) {
                Ok(stdout) => {
                    let live = String::from_utf8_lossy(&stdout).trim().to_string();
                    if live != *context {
                        return ExecutionOutcome::Failed {
                            err: format!(
                                "kube-context drift: captured `{context}`, live `{live}` \
                                 (use --allow-context-change to override)"
                            ),
                        };
                    }
                }
                Err(e) => {
                    return ExecutionOutcome::Failed {
                        err: format!("context check: {e}"),
                    };
                }
            }
        }

        // Synthesize the reverse argv per op kind. Apply uses stdin to
        // avoid touching the filesystem.
        let argv = reverse_argv(kop);
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }

        match kop {
            KubectlOp::Delete { .. }
            | KubectlOp::Apply { .. }
            | KubectlOp::Scale { .. }
            | KubectlOp::Rollout { .. } => match self.runner.run_with_stdin(&argv, captured_yaml) {
                Ok(()) => ExecutionOutcome::Applied,
                Err(e) => ExecutionOutcome::Failed {
                    err: format!("kubectl: {e}"),
                },
            },
        }
    }
}

/// Pure: derive the reverse argv from a kubectl op. The captured YAML
/// is piped to stdin so we don't need the resource name in argv (apply
/// reads the resource identity from the manifest itself).
pub fn reverse_argv(_op: &KubectlOp) -> Vec<String> {
    // All four ops use `kubectl apply -f -` as the reverse; the
    // captured YAML on stdin restores the pre-state resource.
    // (Scale uses apply too — the YAML has the old replica count.)
    vec![
        "kubectl".to_string(),
        "apply".to_string(),
        "-f".to_string(),
        "-".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// One recorded call: which trait method was invoked, with what
    /// argv and (for run_with_stdin) what bytes piped on stdin.
    type CallRecord = (String, Vec<String>, Vec<u8>);

    #[derive(Default)]
    struct SpyRunner {
        calls: RefCell<Vec<CallRecord>>,
        canned_context: RefCell<Vec<u8>>,
        context_should_fail: RefCell<bool>,
        apply_should_fail: RefCell<bool>,
    }

    impl KubectlRunner for SpyRunner {
        fn run(&self, argv: &[String]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(("run".into(), argv.to_vec(), Vec::new()));
            Ok(())
        }
        fn run_with_stdin(&self, argv: &[String], stdin: &[u8]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(("run_stdin".into(), argv.to_vec(), stdin.to_vec()));
            if *self.apply_should_fail.borrow() {
                Err("simulated apply failure".into())
            } else {
                Ok(())
            }
        }
        fn capture(&self, argv: &[String]) -> Result<Vec<u8>, String> {
            self.calls
                .borrow_mut()
                .push(("capture".into(), argv.to_vec(), Vec::new()));
            if *self.context_should_fail.borrow() {
                Err("kubectl: not found".into())
            } else {
                Ok(self.canned_context.borrow().clone())
            }
        }
    }

    fn delete_op(ctx: &str) -> InverseOp {
        InverseOp::KubectlReverse {
            context: ctx.into(),
            namespace: Some("default".into()),
            op: KubectlOp::Delete {
                kind: "Deployment".into(),
                name: "api".into(),
            },
            captured_yaml: b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n"
                .to_vec(),
            requires_confirmation: true,
        }
    }

    #[test]
    fn delete_reverse_runs_apply_with_yaml_on_stdin() {
        let runner = SpyRunner::default();
        *runner.canned_context.borrow_mut() = b"kind-c1\n".to_vec();
        let exe = KubectlExecutor::new(runner);
        let outcome = exe.execute(&delete_op("kind-c1"), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "capture"); // context guard
        assert_eq!(calls[1].0, "run_stdin");
        assert_eq!(
            calls[1].1,
            vec!["kubectl", "apply", "-f", "-"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
        assert!(!calls[1].2.is_empty(), "stdin must carry captured YAML");
    }

    #[test]
    fn context_drift_refuses_apply() {
        let runner = SpyRunner::default();
        *runner.canned_context.borrow_mut() = b"different-cluster\n".to_vec();
        let exe = KubectlExecutor::new(runner);
        let outcome = exe.execute(&delete_op("kind-c1"), false, ConflictPolicy::Abort);
        match outcome {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("context drift"), "got: {err}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Guard ran; apply did NOT.
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "capture");
    }

    #[test]
    fn context_check_can_be_disabled_for_tests() {
        let runner = SpyRunner::default();
        *runner.canned_context.borrow_mut() = b"different-cluster\n".to_vec();
        let exe = KubectlExecutor::new(runner).with_context_guard(false);
        let outcome = exe.execute(&delete_op("kind-c1"), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        // Only the apply ran; context check was skipped.
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "run_stdin");
    }

    #[test]
    fn dry_run_skips_runner_invocation() {
        let runner = SpyRunner::default();
        *runner.canned_context.borrow_mut() = b"kind-c1\n".to_vec();
        let exe = KubectlExecutor::new(runner);
        let outcome = exe.execute(&delete_op("kind-c1"), true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        // Guard still runs (it's read-only) but the apply does not.
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "capture");
    }

    #[test]
    fn apply_failure_surfaces_as_failed() {
        let runner = SpyRunner::default();
        *runner.canned_context.borrow_mut() = b"kind-c1\n".to_vec();
        *runner.apply_should_fail.borrow_mut() = true;
        let exe = KubectlExecutor::new(runner);
        let outcome = exe.execute(&delete_op("kind-c1"), false, ConflictPolicy::Abort);
        match outcome {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("kubectl") && err.contains("simulated"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn supports_only_kubectl_variant() {
        let exe = KubectlExecutor::new(SpyRunner::default());
        assert!(exe.supports(&delete_op("kind-c1")));
        assert!(!exe.supports(&InverseOp::SetEnv {
            name: "X".into(),
            value: "Y".into(),
        }));
    }

    #[test]
    fn reverse_argv_always_apply_dash() {
        // All KubectlOp variants reverse via `kubectl apply -f -`.
        let cases = [
            KubectlOp::Delete {
                kind: "x".into(),
                name: "y".into(),
            },
            KubectlOp::Apply {
                kind: "x".into(),
                name: "y".into(),
            },
            KubectlOp::Scale {
                kind: "x".into(),
                name: "y".into(),
            },
            KubectlOp::Rollout {
                kind: "x".into(),
                name: "y".into(),
            },
        ];
        for op in &cases {
            assert_eq!(
                reverse_argv(op),
                vec!["kubectl", "apply", "-f", "-"]
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>()
            );
        }
    }
}
