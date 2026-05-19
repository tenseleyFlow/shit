// SPDX-License-Identifier: AGPL-3.0-or-later

//! Descriptor-tier executor (C02.6).
//!
//! Applies [`InverseOp::DescriptorReverse`]. The descriptor's
//! `reverse_argv` was rendered at capture time; the executor re-renders
//! defensively from `captured_state` in case the descriptor was edited
//! between capture and undo (the captured state is authoritative).
//!
//! Privileged descriptors route through `shit-helper`. Stage 1 of C02
//! exposes the executor with a `DescRunner` trait so unit tests can
//! drive it with a spy.

use std::collections::BTreeMap;

use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::{DescriptorGuardOp, InverseOp};

/// Abstraction over subprocess invocation and helper routing. Tests
/// inject a spy; production uses [`SystemDescRunner`].
pub trait DescRunner {
    /// Run `argv` directly (non-privileged). Implementations should
    /// set `SHIT_DURING_UNDO=1` to short-circuit recursive captures by
    /// wrappers that would otherwise re-enter `shit`.
    fn run(&self, argv: &[String]) -> Result<(), String>;

    /// Run `argv` via the helper (privileged). The helper enforces the
    /// per-binary whitelist; anything outside is refused.
    fn run_privileged(&self, argv: &[String]) -> Result<(), String>;

    /// Capture stdout of a guard command, run as the invoking user.
    /// Used by [`InverseOp::DescriptorReverse::guard`] to check that
    /// the world is still in a shape consistent with the captured
    /// state before applying the reverse.
    fn capture_guard(&self, argv: &[String]) -> Result<Vec<u8>, String>;
}

/// Production runner: real `std::process::Command`. The helper-routed
/// path uses the same `shit-helper` IPC the other executors use; for
/// C02.6 stage 1 we approximate it with `run_privileged` calling the
/// argv directly (with the same `SHIT_DURING_UNDO` env). A future chunk
/// wires the real helper IPC.
#[derive(Debug, Default)]
pub struct SystemDescRunner;

impl DescRunner for SystemDescRunner {
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
    fn run_privileged(&self, argv: &[String]) -> Result<(), String> {
        // Stage 1: run directly with the same env-strip. The real
        // helper-IPC route lands when the desc-event ctl handler is
        // added in a follow-up to C02 (mirrors S14's pkg-event path).
        self.run(argv)
    }
    fn capture_guard(&self, argv: &[String]) -> Result<Vec<u8>, String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let out = std::process::Command::new(cmd)
            .args(args)
            .env("SHIT_DURING_UNDO", "1")
            .output()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if !out.status.success() {
            return Err(format!("guard {cmd} exited {:?}", out.status.code()));
        }
        Ok(out.stdout)
    }
}

pub struct DescriptorExecutor<R: DescRunner> {
    runner: R,
}

impl<R: DescRunner> DescriptorExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: DescRunner> InverseOpExecutor for DescriptorExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::DescriptorReverse { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::DescriptorReverse {
            descriptor_name: _,
            descriptor_version: _,
            captured_state,
            reverse_argv,
            privileged,
            requires_confirmation: _,
            guard,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "descriptor executor reached non-descriptor op".into(),
            };
        };

        // Defensive re-interpolation: the stored `reverse_argv` is
        // already rendered, but if any `{{var}}` tokens survived (e.g.,
        // because the inspector emitted them un-rendered), interpolate
        // now from captured_state. If the result still contains
        // `{{var}}`, fail loudly — silently passing through is a worse
        // failure mode than a clear executor error.
        let argv = match interpolate_argv(reverse_argv, captured_state) {
            Ok(a) => a,
            Err(e) => {
                return ExecutionOutcome::Skipped {
                    reason: format!("descriptor interpolate: {e}"),
                };
            }
        };
        for tok in &argv {
            if tok.contains("{{") {
                return ExecutionOutcome::Skipped {
                    reason: format!(
                        "unresolved `{{{{var}}}}` in reverse argv after interpolation: `{tok}`"
                    ),
                };
            }
        }

        // Guard, if any. Runs as the invoking user; even privileged
        // descriptors don't need root to read state.
        if let Some(g) = guard
            && let Err(e) = run_guard(&self.runner, g, captured_state)
        {
            return ExecutionOutcome::Failed {
                err: format!("guard: {e}"),
            };
        }

        if dry_run {
            return ExecutionOutcome::WouldApply;
        }

        let result = if *privileged {
            self.runner.run_privileged(&argv)
        } else {
            self.runner.run(&argv)
        };
        match result {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed { err: e },
        }
    }
}

fn interpolate_argv(
    argv: &[String],
    state: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    argv.iter()
        .map(|tok| interpolate_token(tok, state))
        .collect()
}

fn interpolate_token(tok: &str, state: &BTreeMap<String, String>) -> Result<String, String> {
    let mut out = String::with_capacity(tok.len());
    let mut rest = tok;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let close = match after.find("}}") {
            Some(p) => p,
            None => return Err(format!("unterminated template in `{tok}`")),
        };
        let name = &after[..close];
        if !is_var_name(name) {
            return Err(format!("malformed variable name `{name}`"));
        }
        let value = state
            .get(name)
            .ok_or_else(|| format!("missing variable `{name}`"))?;
        if value.is_empty() {
            return Err(format!("empty value for variable `{name}`"));
        }
        out.push_str(value);
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn is_var_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let first_ok = bytes[0].is_ascii_alphabetic() || bytes[0] == b'_';
    if !first_ok {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

fn run_guard<R: DescRunner>(
    runner: &R,
    guard: &DescriptorGuardOp,
    state: &BTreeMap<String, String>,
) -> Result<(), String> {
    let expected = interpolate_token(&guard.expected_substring, state)?;
    let stdout = runner.capture_guard(&guard.command)?;
    let stdout_str = String::from_utf8_lossy(&stdout);
    if stdout_str.contains(&expected) {
        Ok(())
    } else {
        Err(format!(
            "guard mismatch: expected substring `{expected}` not found in `{}`",
            stdout_str.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Spy runner that records every call and emits canned responses.
    #[derive(Default)]
    struct Spy {
        calls: RefCell<Vec<(String, Vec<String>)>>,
        guard_response: RefCell<Vec<u8>>,
        run_should_fail: RefCell<bool>,
    }

    impl DescRunner for Spy {
        fn run(&self, argv: &[String]) -> Result<(), String> {
            self.calls.borrow_mut().push(("run".into(), argv.to_vec()));
            if *self.run_should_fail.borrow() {
                Err("simulated".into())
            } else {
                Ok(())
            }
        }
        fn run_privileged(&self, argv: &[String]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(("run_privileged".into(), argv.to_vec()));
            if *self.run_should_fail.borrow() {
                Err("simulated".into())
            } else {
                Ok(())
            }
        }
        fn capture_guard(&self, argv: &[String]) -> Result<Vec<u8>, String> {
            self.calls
                .borrow_mut()
                .push(("guard".into(), argv.to_vec()));
            Ok(self.guard_response.borrow().clone())
        }
    }

    fn state(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn op(reverse_argv: Vec<&str>, privileged: bool) -> InverseOp {
        InverseOp::DescriptorReverse {
            descriptor_name: "test".into(),
            descriptor_version: 1,
            captured_state: state(&[("v", "hello")]),
            reverse_argv: reverse_argv.into_iter().map(String::from).collect(),
            privileged,
            requires_confirmation: false,
            guard: None,
        }
    }

    #[test]
    fn applies_non_privileged_path() {
        let spy = Spy::default();
        let exe = DescriptorExecutor::new(spy);
        let outcome = exe.execute(
            &op(vec!["echo", "{{v}}"], false),
            false,
            ConflictPolicy::Abort,
        );
        assert!(matches!(outcome, ExecutionOutcome::Applied));
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "run");
        assert_eq!(calls[0].1, vec!["echo".to_string(), "hello".to_string()]);
    }

    #[test]
    fn applies_privileged_path() {
        let spy = Spy::default();
        let exe = DescriptorExecutor::new(spy);
        let outcome = exe.execute(
            &op(vec!["echo", "{{v}}"], true),
            false,
            ConflictPolicy::Abort,
        );
        assert!(matches!(outcome, ExecutionOutcome::Applied));
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls[0].0, "run_privileged");
    }

    #[test]
    fn dry_run_does_not_invoke_runner() {
        let spy = Spy::default();
        let exe = DescriptorExecutor::new(spy);
        let outcome = exe.execute(
            &op(vec!["echo", "{{v}}"], false),
            true,
            ConflictPolicy::Abort,
        );
        assert!(matches!(outcome, ExecutionOutcome::WouldApply));
        assert!(exe.runner.calls.borrow().is_empty());
    }

    #[test]
    fn missing_var_skips_with_clear_reason() {
        let spy = Spy::default();
        let exe = DescriptorExecutor::new(spy);
        let bad_op = InverseOp::DescriptorReverse {
            descriptor_name: "test".into(),
            descriptor_version: 1,
            captured_state: BTreeMap::new(),
            reverse_argv: vec!["echo".into(), "{{nope}}".into()],
            privileged: false,
            requires_confirmation: false,
            guard: None,
        };
        let outcome = exe.execute(&bad_op, false, ConflictPolicy::Abort);
        match outcome {
            ExecutionOutcome::Skipped { reason } => {
                assert!(reason.contains("missing variable"));
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(exe.runner.calls.borrow().is_empty());
    }

    #[test]
    fn guard_pass_proceeds() {
        let spy = Spy::default();
        *spy.guard_response.borrow_mut() = b"hostname: hello".to_vec();
        let exe = DescriptorExecutor::new(spy);
        let op = InverseOp::DescriptorReverse {
            descriptor_name: "test".into(),
            descriptor_version: 1,
            captured_state: state(&[("v", "hello")]),
            reverse_argv: vec!["echo".into(), "{{v}}".into()],
            privileged: false,
            requires_confirmation: false,
            guard: Some(DescriptorGuardOp {
                command: vec!["hostname".into()],
                expected_substring: "{{v}}".into(),
            }),
        };
        let outcome = exe.execute(&op, false, ConflictPolicy::Abort);
        assert!(matches!(outcome, ExecutionOutcome::Applied));
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "guard");
        assert_eq!(calls[1].0, "run");
    }

    #[test]
    fn guard_fail_refuses_apply() {
        let spy = Spy::default();
        *spy.guard_response.borrow_mut() = b"hostname: different".to_vec();
        let exe = DescriptorExecutor::new(spy);
        let op = InverseOp::DescriptorReverse {
            descriptor_name: "test".into(),
            descriptor_version: 1,
            captured_state: state(&[("v", "hello")]),
            reverse_argv: vec!["echo".into(), "{{v}}".into()],
            privileged: false,
            requires_confirmation: false,
            guard: Some(DescriptorGuardOp {
                command: vec!["hostname".into()],
                expected_substring: "{{v}}".into(),
            }),
        };
        let outcome = exe.execute(&op, false, ConflictPolicy::Abort);
        match outcome {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("guard mismatch"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Guard ran; run did NOT.
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "guard");
    }

    #[test]
    fn supports_only_descriptor_variant() {
        let spy = Spy::default();
        let exe = DescriptorExecutor::new(spy);
        assert!(exe.supports(&op(vec!["x"], false)));
        let other = InverseOp::SetEnv {
            name: "X".into(),
            value: "Y".into(),
        };
        assert!(!exe.supports(&other));
    }

    #[test]
    fn run_failure_surfaces_as_failed() {
        let spy = Spy::default();
        *spy.run_should_fail.borrow_mut() = true;
        let exe = DescriptorExecutor::new(spy);
        let outcome = exe.execute(
            &op(vec!["echo", "{{v}}"], false),
            false,
            ConflictPolicy::Abort,
        );
        assert!(matches!(outcome, ExecutionOutcome::Failed { .. }));
    }
}
