// SPDX-License-Identifier: AGPL-3.0-or-later

//! terraform tier executor (C03.5).
//!
//! Reverses `terraform apply` / `destroy` by pushing the captured
//! prior state back. The flow:
//!
//!   1. Write `prior_state` bytes to a tempfile in `workdir`.
//!   2. Run `terraform state push <tempfile>` to overwrite the
//!      current state.
//!   3. Run `terraform apply -refresh-only -auto-approve` to
//!      reconcile.
//!
//! Caveats:
//! - Cloud-side resources created after capture are NOT auto-destroyed;
//!   the state push tells terraform "you don't manage these anymore".
//!   The user must manually delete them (terraform plan after our undo
//!   shows them as orphan).
//! - Partial-apply failures leave a dirty state that we can still
//!   restore from, but the user should run `terraform plan` after the
//!   undo to verify reconciliation.

use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::{InverseOp, TerraformOp};
use std::path::PathBuf;

pub trait TerraformRunner {
    /// Run terraform with the given argv in `workdir`. Returns Ok on
    /// exit code 0.
    fn run(&self, argv: &[String], workdir: &std::path::Path) -> Result<(), String>;
    /// Write `bytes` to a tempfile in `workdir` and return its path.
    /// The executor invokes this to materialize the captured state
    /// before `terraform state push`.
    fn stash_bytes(&self, bytes: &[u8], workdir: &std::path::Path) -> Result<PathBuf, String>;
}

#[derive(Debug, Default)]
pub struct SystemTerraformRunner;

impl TerraformRunner for SystemTerraformRunner {
    fn run(&self, argv: &[String], workdir: &std::path::Path) -> Result<(), String> {
        let (cmd, args) = argv.split_first().ok_or_else(|| "empty argv".to_string())?;
        let status = std::process::Command::new(cmd)
            .args(args)
            .current_dir(workdir)
            .env("SHIT_DURING_UNDO", "1")
            .status()
            .map_err(|e| format!("spawn {cmd}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{cmd} exited {:?}", status.code()))
        }
    }
    fn stash_bytes(&self, bytes: &[u8], workdir: &std::path::Path) -> Result<PathBuf, String> {
        use std::io::Write;
        // We can't pull `tempfile` into the planner crate (already a
        // dev-dep only); roll a tiny tempfile via `pid + ts`. Path
        // ends `.tfstate` so terraform parses it correctly.
        let pid = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = workdir.join(format!("shit-tf-restore-{pid}-{ts}.tfstate"));
        let mut f = std::fs::File::create(&path).map_err(|e| format!("create {path:?}: {e}"))?;
        f.write_all(bytes)
            .map_err(|e| format!("write {path:?}: {e}"))?;
        Ok(path)
    }
}

pub struct TerraformExecutor<R: TerraformRunner> {
    runner: R,
}

impl<R: TerraformRunner> TerraformExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: TerraformRunner> InverseOpExecutor for TerraformExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::TerraformReverse { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::TerraformReverse {
            workdir,
            op: tf_op,
            prior_state,
            plan_json: _,
            requires_confirmation: _,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "terraform executor reached non-terraform op".into(),
            };
        };

        // StateRm and Import are out-of-scope for v1's auto-restore;
        // surface informationally.
        match tf_op {
            TerraformOp::StateRm | TerraformOp::Import => {
                return ExecutionOutcome::Skipped {
                    reason: format!(
                        "terraform {tf_op:?} undo requires manual state surgery; see `shit show` \
                         for the captured pre-state"
                    ),
                };
            }
            TerraformOp::Apply | TerraformOp::Destroy => {}
        }

        if prior_state.is_empty() {
            return ExecutionOutcome::Skipped {
                reason: "no prior state captured (was `terraform apply` run with -auto-approve \
                         outside a shit-hooked shell?)"
                    .into(),
            };
        }

        if dry_run {
            return ExecutionOutcome::WouldApply;
        }

        // 1. Stash the captured state to a tempfile.
        let state_file = match self.runner.stash_bytes(prior_state, workdir) {
            Ok(p) => p,
            Err(e) => {
                return ExecutionOutcome::Failed {
                    err: format!("stash state: {e}"),
                };
            }
        };

        // 2. terraform state push <tempfile>
        let push_argv = vec![
            "terraform".to_string(),
            "state".to_string(),
            "push".to_string(),
            state_file.display().to_string(),
        ];
        if let Err(e) = self.runner.run(&push_argv, workdir) {
            return ExecutionOutcome::Failed {
                err: format!("terraform state push: {e}"),
            };
        }

        // 3. terraform apply -refresh-only -auto-approve to reconcile.
        let reconcile_argv = vec![
            "terraform".to_string(),
            "apply".to_string(),
            "-refresh-only".to_string(),
            "-auto-approve".to_string(),
        ];
        if let Err(e) = self.runner.run(&reconcile_argv, workdir) {
            return ExecutionOutcome::Failed {
                err: format!("terraform apply -refresh-only: {e}"),
            };
        }

        ExecutionOutcome::Applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Spy {
        runs: RefCell<Vec<Vec<String>>>,
        stashed: RefCell<Vec<Vec<u8>>>,
        stash_fail: RefCell<bool>,
        run_fail_on: RefCell<Option<usize>>,
    }
    impl TerraformRunner for Spy {
        fn run(&self, argv: &[String], _workdir: &std::path::Path) -> Result<(), String> {
            let mut r = self.runs.borrow_mut();
            r.push(argv.to_vec());
            if let Some(idx) = *self.run_fail_on.borrow()
                && r.len() - 1 == idx
            {
                return Err(format!("simulated failure at idx {idx}"));
            }
            Ok(())
        }
        fn stash_bytes(&self, bytes: &[u8], _workdir: &std::path::Path) -> Result<PathBuf, String> {
            if *self.stash_fail.borrow() {
                return Err("simulated stash failure".into());
            }
            self.stashed.borrow_mut().push(bytes.to_vec());
            Ok(PathBuf::from("/tmp/shit-tf-fake.tfstate"))
        }
    }

    fn apply_op() -> InverseOp {
        InverseOp::TerraformReverse {
            workdir: PathBuf::from("/tmp/tf"),
            op: TerraformOp::Apply,
            prior_state: b"{\"version\": 4}".to_vec(),
            plan_json: None,
            requires_confirmation: true,
        }
    }

    #[test]
    fn apply_reverse_pushes_state_then_reconciles() {
        let exe = TerraformExecutor::new(Spy::default());
        let outcome = exe.execute(&apply_op(), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let runs = exe.runner.runs.borrow();
        assert_eq!(runs.len(), 2);
        assert_eq!(
            runs[0],
            vec!["terraform", "state", "push", "/tmp/shit-tf-fake.tfstate"]
        );
        assert!(runs[1].iter().any(|t| t == "apply"));
        assert!(runs[1].iter().any(|t| t == "-refresh-only"));
        assert!(runs[1].iter().any(|t| t == "-auto-approve"));
        // The stash actually got the captured bytes.
        let stashed = exe.runner.stashed.borrow();
        assert_eq!(stashed.len(), 1);
        assert_eq!(stashed[0], b"{\"version\": 4}");
    }

    #[test]
    fn destroy_reverse_uses_same_state_push_path() {
        let mut op = apply_op();
        if let InverseOp::TerraformReverse { op: ref mut k, .. } = op {
            *k = TerraformOp::Destroy;
        }
        let exe = TerraformExecutor::new(Spy::default());
        let outcome = exe.execute(&op, false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let runs = exe.runner.runs.borrow();
        assert_eq!(runs[0][0], "terraform");
        assert_eq!(runs[0][1], "state");
        assert_eq!(runs[0][2], "push");
    }

    #[test]
    fn state_rm_is_skipped_informationally() {
        let mut op = apply_op();
        if let InverseOp::TerraformReverse { op: ref mut k, .. } = op {
            *k = TerraformOp::StateRm;
        }
        let exe = TerraformExecutor::new(Spy::default());
        let outcome = exe.execute(&op, false, ConflictPolicy::Abort);
        match outcome {
            ExecutionOutcome::Skipped { reason } => {
                assert!(reason.contains("manual state surgery"));
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(exe.runner.runs.borrow().is_empty());
    }

    #[test]
    fn empty_prior_state_skips() {
        let mut op = apply_op();
        if let InverseOp::TerraformReverse {
            prior_state: ref mut s,
            ..
        } = op
        {
            s.clear();
        }
        let exe = TerraformExecutor::new(Spy::default());
        let outcome = exe.execute(&op, false, ConflictPolicy::Abort);
        match outcome {
            ExecutionOutcome::Skipped { reason } => {
                assert!(reason.contains("no prior state"));
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn stash_failure_surfaces_as_failed() {
        let exe = TerraformExecutor::new(Spy::default());
        *exe.runner.stash_fail.borrow_mut() = true;
        match exe.execute(&apply_op(), false, ConflictPolicy::Abort) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("stash"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn state_push_failure_aborts_before_reconcile() {
        let exe = TerraformExecutor::new(Spy::default());
        *exe.runner.run_fail_on.borrow_mut() = Some(0); // fail first run = state push
        match exe.execute(&apply_op(), false, ConflictPolicy::Abort) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("state push"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Reconcile never ran.
        let runs = exe.runner.runs.borrow();
        assert_eq!(runs.len(), 1);
    }

    #[test]
    fn dry_run_skips_stash_and_runs() {
        let exe = TerraformExecutor::new(Spy::default());
        let outcome = exe.execute(&apply_op(), true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        assert!(exe.runner.runs.borrow().is_empty());
        assert!(exe.runner.stashed.borrow().is_empty());
    }

    #[test]
    fn supports_only_terraform_variant() {
        let exe = TerraformExecutor::new(Spy::default());
        assert!(exe.supports(&apply_op()));
        assert!(!exe.supports(&InverseOp::SetEnv {
            name: "X".into(),
            value: "Y".into(),
        }));
    }
}
