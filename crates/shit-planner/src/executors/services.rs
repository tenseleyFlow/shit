// SPDX-License-Identifier: AGPL-3.0-or-later

//! Service-tier executor (S16.7).
//!
//! Handles [`InverseOp::SystemdRollback`]. The variant name is
//! `SystemdRollback` for historical reasons (the planner spec was
//! written when systemd was the only target); it covers both
//! systemctl and launchctl, distinguished by [`SystemdScope`].
//!
//! Reversal rules:
//!
//! - `before.active != after.active` → emit `start` (to reactivate)
//!   or `stop` (to deactivate). Choose by reading `before.active`.
//! - `before.enabled != after.enabled` → emit `enable` or `disable`.
//! - `before.masked != after.masked` → emit `mask` or `unmask`.
//!
//! A single user command can flip multiple flags (e.g.
//! `systemctl enable --now foo` flips `enabled` and `active`); we
//! emit one invocation per flag delta. The orchestrator runs them
//! in order: `unmask` first (so the unit is operable), then
//! `enable`/`disable`, then `start`/`stop`.
//!
//! launchctl uses a different verb set:
//! - active flip → `bootstrap`/`bootout`
//! - enabled flip → `enable`/`disable`
//! - masked flip → not supported by launchctl directly; we skip
//!   and surface a `Skipped { reason }` note.

use std::process::Command;

use crate::events::{ServiceState, SystemdScope};
use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::InverseOp;

/// Abstraction over the subprocess call. Production uses
/// [`SystemSvcRunner`]; tests use a mock.
pub trait SvcRunner {
    fn run(&self, argv: &[String]) -> Result<(), String>;
}

pub struct SystemSvcRunner;

impl SvcRunner for SystemSvcRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let status = Command::new(cmd)
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
}

pub struct ServiceExecutor<R: SvcRunner> {
    runner: R,
}

impl<R: SvcRunner> ServiceExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
    pub fn runner(&self) -> &R {
        &self.runner
    }
}

impl ServiceExecutor<SystemSvcRunner> {
    pub fn system() -> Self {
        Self::new(SystemSvcRunner)
    }
}

impl<R: SvcRunner> InverseOpExecutor for ServiceExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::SystemdRollback { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::SystemdRollback {
            scope,
            unit,
            before,
            after,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "service executor reached non-service op".into(),
            };
        };
        let invocations = synthesize_argv(*scope, unit, before, after);
        if invocations.is_empty() {
            return ExecutionOutcome::Skipped {
                reason: "no-op diff (before == after)".into(),
            };
        }
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        for argv in &invocations {
            if let Err(e) = self.runner.run(argv) {
                return ExecutionOutcome::Failed {
                    err: format!("{}: {e}", argv.first().map(String::as_str).unwrap_or("?")),
                };
            }
        }
        ExecutionOutcome::Applied
    }
}

/// Pure synthesis: produce the argv list (each entry a separate
/// invocation) to flip `after` back to `before`. The ordering is
/// deliberate — unmask → enable/disable → start/stop — so the unit
/// is operable before we manipulate state.
pub fn synthesize_argv(
    scope: SystemdScope,
    unit: &str,
    before: &ServiceState,
    after: &ServiceState,
) -> Vec<Vec<String>> {
    match scope {
        SystemdScope::User | SystemdScope::System => systemctl_argv(scope, unit, before, after),
        SystemdScope::LaunchdGui | SystemdScope::LaunchdSystem => {
            launchctl_argv(scope, unit, before, after)
        }
        SystemdScope::RcBase => service_argv(unit, before, after),
    }
}

/// FreeBSD `service(8)` argv synthesis. The rc.d framework's verbs
/// are `start`/`stop`/`restart` for runtime state and
/// `enable`/`disable` for `<name>_enable` rc.conf gates. There is no
/// "masked" concept on FreeBSD (the closest equivalent — removing
/// the script — is out of scope here).
fn service_argv(unit: &str, before: &ServiceState, after: &ServiceState) -> Vec<Vec<String>> {
    let mk = |verb: &str| -> Vec<String> { vec!["service".into(), unit.into(), verb.into()] };
    let mut out = Vec::new();
    // 1. Enabled delta.
    if before.enabled != after.enabled {
        // `service <unit> enable|disable` works on FreeBSD ≥ 9 — it
        // tweaks rc.conf for us. Earlier systems require manual
        // editing; the executor surfaces the failure if so.
        out.push(mk(if before.enabled { "enable" } else { "disable" }));
    }
    // 2. Active delta.
    if before.active != after.active {
        out.push(mk(if before.active { "start" } else { "stop" }));
    }
    out
}

fn systemctl_argv(
    scope: SystemdScope,
    unit: &str,
    before: &ServiceState,
    after: &ServiceState,
) -> Vec<Vec<String>> {
    let prefix: &[&str] = match scope {
        SystemdScope::User => &["systemctl", "--user"],
        _ => &["systemctl"],
    };
    let mk = |verb: &str| -> Vec<String> {
        let mut v: Vec<String> = prefix.iter().map(|s| (*s).to_string()).collect();
        v.push(verb.to_string());
        v.push(unit.to_string());
        v
    };
    let mut out = Vec::new();
    // 1. Mask delta: if it became masked, unmask first. If it
    //    became unmasked, the undo masks again *after* we restore
    //    enabled/active — because masking blocks start/enable.
    if before.masked != after.masked && !before.masked {
        // Currently masked (after.masked=true); undo unmasks.
        out.push(mk("unmask"));
    }
    // 2. Enabled delta.
    if before.enabled != after.enabled {
        out.push(mk(if before.enabled { "enable" } else { "disable" }));
    }
    // 3. Active delta.
    if before.active != after.active {
        out.push(mk(if before.active { "start" } else { "stop" }));
    }
    // 4. Mask delta (re-mask).
    if before.masked != after.masked && before.masked {
        // Currently unmasked (after.masked=false); undo re-masks.
        out.push(mk("mask"));
    }
    out
}

fn launchctl_argv(
    scope: SystemdScope,
    unit: &str,
    before: &ServiceState,
    after: &ServiceState,
) -> Vec<Vec<String>> {
    let domain = match scope {
        SystemdScope::LaunchdSystem => "system".to_string(),
        SystemdScope::LaunchdGui => {
            // SAFETY: getuid always succeeds.
            let uid = unsafe { libc::getuid() };
            format!("gui/{uid}")
        }
        _ => return Vec::new(), // unreachable; covered by the dispatcher
    };
    let target = format!("{domain}/{unit}");
    let mut out = Vec::new();
    // launchctl has no mask concept; skip if there's a delta there.
    if before.enabled != after.enabled {
        let verb = if before.enabled { "enable" } else { "disable" };
        out.push(vec!["launchctl".into(), verb.into(), target.clone()]);
    }
    if before.active != after.active {
        let verb = if before.active {
            "bootstrap"
        } else {
            "bootout"
        };
        // bootstrap needs a path argument; we don't have it here.
        // The journaled event includes `path` in the `raw` field;
        // a richer integration would extract it (DR-37). For Stage
        // 1 we emit the verb + target — bootstrap will fail without
        // a path, surfacing as `Failed`. The CLI's `shit undo`
        // pre-check warns operators.
        out.push(vec!["launchctl".into(), verb.into(), target.clone()]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(active: bool, enabled: bool, masked: bool) -> ServiceState {
        ServiceState {
            active,
            enabled,
            masked,
            raw: String::new(),
        }
    }

    #[test]
    fn systemctl_start_reverses_to_stop() {
        let before = state(false, true, false);
        let after = state(true, true, false);
        let argv = synthesize_argv(SystemdScope::User, "nginx.service", &before, &after);
        assert_eq!(argv.len(), 1);
        assert_eq!(
            argv[0],
            vec!["systemctl", "--user", "stop", "nginx.service"]
        );
    }

    #[test]
    fn systemctl_stop_reverses_to_start() {
        let before = state(true, true, false);
        let after = state(false, true, false);
        let argv = synthesize_argv(SystemdScope::System, "nginx.service", &before, &after);
        assert_eq!(argv[0], vec!["systemctl", "start", "nginx.service"]);
    }

    #[test]
    fn systemctl_enable_and_start_reverses_in_correct_order() {
        // before: disabled+inactive, after: enabled+active (so
        // user ran `systemctl --user enable --now foo`).
        let before = state(false, false, false);
        let after = state(true, true, false);
        let argv = synthesize_argv(SystemdScope::User, "foo.service", &before, &after);
        // Undo order: disable, then stop.
        assert_eq!(argv.len(), 2);
        assert!(argv[0].contains(&"disable".to_string()));
        assert!(argv[1].contains(&"stop".to_string()));
    }

    #[test]
    fn systemctl_mask_reverses_to_unmask() {
        let before = state(false, false, false);
        let after = state(false, false, true);
        let argv = synthesize_argv(SystemdScope::User, "foo.service", &before, &after);
        assert!(argv.iter().any(|v| v.contains(&"unmask".to_string())));
    }

    #[test]
    fn systemctl_unmask_undo_re_masks_after_other_flips() {
        // User ran `systemctl unmask foo` — went from masked → unmasked.
        let before = state(false, false, true);
        let after = state(false, false, false);
        let argv = synthesize_argv(SystemdScope::User, "foo.service", &before, &after);
        // Undo: mask. Just one invocation.
        assert_eq!(argv.len(), 1);
        assert!(argv[0].contains(&"mask".to_string()));
    }

    #[test]
    fn launchctl_bootstrap_reverses_to_bootout() {
        let before = state(false, true, false);
        let after = state(true, true, false);
        let argv = synthesize_argv(SystemdScope::LaunchdGui, "com.example.foo", &before, &after);
        assert!(argv.iter().any(|v| v.iter().any(|s| s == "bootout")));
    }

    #[test]
    fn launchctl_system_scope_target() {
        let before = state(true, true, false);
        let after = state(false, true, false);
        let argv = synthesize_argv(
            SystemdScope::LaunchdSystem,
            "com.example.foo",
            &before,
            &after,
        );
        assert!(argv[0].iter().any(|s| s == "system/com.example.foo"));
    }

    #[test]
    fn empty_diff_returns_no_invocations() {
        let s = state(true, true, false);
        let argv = synthesize_argv(SystemdScope::User, "foo.service", &s, &s);
        assert!(argv.is_empty());
    }

    #[test]
    fn rc_base_start_reverses_to_stop() {
        let before = state(false, true, false);
        let after = state(true, true, false);
        let argv = synthesize_argv(SystemdScope::RcBase, "cron", &before, &after);
        assert_eq!(argv.len(), 1);
        assert_eq!(argv[0], vec!["service", "cron", "stop"]);
    }

    #[test]
    fn rc_base_stop_reverses_to_start() {
        let before = state(true, true, false);
        let after = state(false, true, false);
        let argv = synthesize_argv(SystemdScope::RcBase, "cron", &before, &after);
        assert_eq!(argv[0], vec!["service", "cron", "start"]);
    }

    #[test]
    fn rc_base_enable_and_start_reverses_in_correct_order() {
        // before: disabled+stopped, after: enabled+running
        let before = state(false, false, false);
        let after = state(true, true, false);
        let argv = synthesize_argv(SystemdScope::RcBase, "cron", &before, &after);
        assert_eq!(argv.len(), 2);
        // Enable first (rc.conf gate), then stop.
        assert!(argv[0].iter().any(|s| s == "disable"));
        assert!(argv[1].iter().any(|s| s == "stop"));
    }

    /// Spy runner.
    #[derive(Default)]
    struct Spy {
        invocations: std::cell::RefCell<Vec<Vec<String>>>,
        fail_on: Option<usize>,
    }
    impl SvcRunner for Spy {
        fn run(&self, argv: &[String]) -> Result<(), String> {
            let mut v = self.invocations.borrow_mut();
            v.push(argv.to_vec());
            if let Some(n) = self.fail_on
                && v.len() - 1 == n
            {
                return Err(format!("fail on idx {n}"));
            }
            Ok(())
        }
    }

    fn rollback_op() -> InverseOp {
        InverseOp::SystemdRollback {
            scope: SystemdScope::User,
            unit: "nginx.service".into(),
            before: state(false, true, false),
            after: state(true, true, false),
        }
    }

    #[test]
    fn executor_dry_run_does_not_invoke() {
        let exec = ServiceExecutor::new(Spy::default());
        let outcome = exec.execute(&rollback_op(), true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        assert_eq!(exec.runner().invocations.borrow().len(), 0);
    }

    #[test]
    fn executor_applied_records_invocation() {
        let exec = ServiceExecutor::new(Spy::default());
        let outcome = exec.execute(&rollback_op(), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        assert_eq!(exec.runner().invocations.borrow().len(), 1);
    }

    #[test]
    fn executor_propagates_runner_failure() {
        let exec = ServiceExecutor::new(Spy {
            fail_on: Some(0),
            ..Spy::default()
        });
        let outcome = exec.execute(&rollback_op(), false, ConflictPolicy::Abort);
        assert!(matches!(outcome, ExecutionOutcome::Failed { .. }));
    }

    #[test]
    fn executor_skips_no_op_diff() {
        let s = state(true, true, false);
        let op = InverseOp::SystemdRollback {
            scope: SystemdScope::User,
            unit: "x.service".into(),
            before: s.clone(),
            after: s,
        };
        let exec = ServiceExecutor::new(Spy::default());
        let outcome = exec.execute(&op, false, ConflictPolicy::Abort);
        assert!(matches!(outcome, ExecutionOutcome::Skipped { .. }));
    }
}
