// SPDX-License-Identifier: AGPL-3.0-or-later

//! aws-cli tier executor (C03.4).
//!
//! Per-service reverse logic. The capture phase populates
//! `captured_state` with service-specific fields (e.g. `version_id`
//! for S3, `instance_id` + the describe-instances JSON for EC2);
//! the executor dispatches on `op` to synthesize the right reverse
//! argv. IAM is out of v1 scope (it's where most cross-service
//! state lives and warrants its own design pass).

use crate::BlobHash;
use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::{AwsOp, InverseOp};

pub trait AwsRunner {
    fn run(&self, argv: &[String]) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct SystemAwsRunner;

impl AwsRunner for SystemAwsRunner {
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
}

pub struct AwsExecutor<R: AwsRunner> {
    runner: R,
}

impl<R: AwsRunner> AwsExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: AwsRunner> InverseOpExecutor for AwsExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::AwsReverse { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::AwsReverse {
            service: _,
            op: aws_op,
            captured_state,
            stashed_content_hash,
            requires_confirmation: _,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "aws executor reached non-aws op".into(),
            };
        };

        let plan = match build_reverse(aws_op, captured_state, stashed_content_hash.as_ref()) {
            Ok(p) => p,
            Err(e) => {
                return ExecutionOutcome::Skipped {
                    reason: format!("aws reverse: {e}"),
                };
            }
        };

        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        match plan {
            AwsReversePlan::Run(argv) => match self.runner.run(&argv) {
                Ok(()) => ExecutionOutcome::Applied,
                Err(e) => ExecutionOutcome::Failed {
                    err: format!("aws: {e}"),
                },
            },
            AwsReversePlan::Informational(msg) => ExecutionOutcome::Skipped { reason: msg },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AwsReversePlan {
    Run(Vec<String>),
    /// Informational only (e.g. EC2 terminate needs explicit re-launch).
    Informational(String),
}

/// Pure: derive the reverse argv per AWS op. Extracted for unit tests.
pub fn build_reverse(
    op: &AwsOp,
    state: &std::collections::BTreeMap<String, String>,
    _stashed: Option<&BlobHash>,
) -> Result<AwsReversePlan, String> {
    match op {
        AwsOp::S3Cp { bucket, key } => {
            // S3 cp put a new object. The reverse depends on whether
            // the bucket is versioned. If `version_id` is present, the
            // reverse is delete-object at that version; otherwise it's
            // s3 rm (which may also create a delete marker on
            // versioned buckets).
            let version_id = state.get("version_id").cloned();
            let mut argv = vec![
                "aws".to_string(),
                "s3api".to_string(),
                "delete-object".to_string(),
                "--bucket".to_string(),
                bucket.clone(),
                "--key".to_string(),
                key.clone(),
            ];
            if let Some(vid) = version_id
                && !vid.is_empty()
            {
                argv.push("--version-id".into());
                argv.push(vid);
            }
            Ok(AwsReversePlan::Run(argv))
        }
        AwsOp::S3Rm { bucket, key } => {
            // S3 rm deleted an object. For versioned buckets, AWS
            // creates a delete marker; the reverse is delete-object
            // against that delete-marker's version-id (undeletes).
            // For unversioned buckets, recovery needs the stashed
            // bytes. v1 surfaces an informational note for the
            // unversioned case rather than failing silently.
            let marker_vid = state.get("delete_marker_version_id");
            if let Some(vid) = marker_vid
                && !vid.is_empty()
            {
                let argv = vec![
                    "aws".to_string(),
                    "s3api".to_string(),
                    "delete-object".to_string(),
                    "--bucket".to_string(),
                    bucket.clone(),
                    "--key".to_string(),
                    key.clone(),
                    "--version-id".to_string(),
                    vid.clone(),
                ];
                return Ok(AwsReversePlan::Run(argv));
            }
            Ok(AwsReversePlan::Informational(format!(
                "s3 rm of unversioned object `{bucket}/{key}`: cannot mechanically restore. \
                 If you need the bytes, run `aws s3 cp <local> s3://{bucket}/{key}` from a \
                 backup."
            )))
        }
        AwsOp::Ec2Terminate { instance_id } => {
            // Terminate is irreversible at the AWS API level. Surface
            // the captured descriptor so the user can manually
            // re-launch via `aws ec2 run-instances`.
            Ok(AwsReversePlan::Informational(format!(
                "ec2 terminate of `{instance_id}` is irreversible. Captured descriptor in \
                 `shit show`; re-launch with `aws ec2 run-instances` using the captured \
                 image-id/instance-type/security-groups/etc."
            )))
        }
        AwsOp::Ec2Stop { instance_id } => Ok(AwsReversePlan::Run(vec![
            "aws".to_string(),
            "ec2".to_string(),
            "start-instances".to_string(),
            "--instance-ids".to_string(),
            instance_id.clone(),
        ])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Spy {
        invocations: RefCell<Vec<Vec<String>>>,
    }
    impl AwsRunner for Spy {
        fn run(&self, argv: &[String]) -> Result<(), String> {
            self.invocations.borrow_mut().push(argv.to_vec());
            Ok(())
        }
    }

    fn state(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn s3_cp_versioned_reverses_to_delete_object_with_vid() {
        let plan = build_reverse(
            &AwsOp::S3Cp {
                bucket: "b".into(),
                key: "k".into(),
            },
            &state(&[("version_id", "v123")]),
            None,
        )
        .unwrap();
        match plan {
            AwsReversePlan::Run(argv) => {
                assert!(argv.iter().any(|t| t == "delete-object"));
                assert!(argv.iter().any(|t| t == "v123"));
                assert!(argv.iter().any(|t| t == "--version-id"));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn s3_cp_unversioned_omits_version_id_flag() {
        let plan = build_reverse(
            &AwsOp::S3Cp {
                bucket: "b".into(),
                key: "k".into(),
            },
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        match plan {
            AwsReversePlan::Run(argv) => {
                assert!(!argv.iter().any(|t| t == "--version-id"));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn s3_rm_with_delete_marker_undeletes() {
        let plan = build_reverse(
            &AwsOp::S3Rm {
                bucket: "b".into(),
                key: "k".into(),
            },
            &state(&[("delete_marker_version_id", "marker-1")]),
            None,
        )
        .unwrap();
        match plan {
            AwsReversePlan::Run(argv) => {
                assert!(argv.iter().any(|t| t == "marker-1"));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn s3_rm_unversioned_is_informational() {
        let plan = build_reverse(
            &AwsOp::S3Rm {
                bucket: "b".into(),
                key: "k".into(),
            },
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        assert!(matches!(plan, AwsReversePlan::Informational(_)));
    }

    #[test]
    fn ec2_terminate_is_informational() {
        let plan = build_reverse(
            &AwsOp::Ec2Terminate {
                instance_id: "i-abc".into(),
            },
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        match plan {
            AwsReversePlan::Informational(msg) => {
                assert!(msg.contains("i-abc"));
                assert!(msg.contains("irreversible"));
            }
            other => panic!("expected Informational, got {other:?}"),
        }
    }

    #[test]
    fn ec2_stop_reverses_to_start() {
        let plan = build_reverse(
            &AwsOp::Ec2Stop {
                instance_id: "i-xyz".into(),
            },
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        match plan {
            AwsReversePlan::Run(argv) => {
                assert_eq!(argv[0], "aws");
                assert_eq!(argv[1], "ec2");
                assert_eq!(argv[2], "start-instances");
                assert!(argv.iter().any(|t| t == "i-xyz"));
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn executor_dry_run_skips_runner() {
        let exe = AwsExecutor::new(Spy::default());
        let op = InverseOp::AwsReverse {
            service: "ec2".into(),
            op: AwsOp::Ec2Stop {
                instance_id: "i-1".into(),
            },
            captured_state: BTreeMap::new(),
            stashed_content_hash: None,
            requires_confirmation: true,
        };
        assert_eq!(
            exe.execute(&op, true, ConflictPolicy::Abort),
            ExecutionOutcome::WouldApply
        );
        assert!(exe.runner.invocations.borrow().is_empty());
    }

    #[test]
    fn executor_applied_runs_through_runner() {
        let exe = AwsExecutor::new(Spy::default());
        let op = InverseOp::AwsReverse {
            service: "ec2".into(),
            op: AwsOp::Ec2Stop {
                instance_id: "i-1".into(),
            },
            captured_state: BTreeMap::new(),
            stashed_content_hash: None,
            requires_confirmation: true,
        };
        assert_eq!(
            exe.execute(&op, false, ConflictPolicy::Abort),
            ExecutionOutcome::Applied
        );
        assert_eq!(exe.runner.invocations.borrow().len(), 1);
    }

    #[test]
    fn informational_plan_returns_skipped() {
        let exe = AwsExecutor::new(Spy::default());
        let op = InverseOp::AwsReverse {
            service: "ec2".into(),
            op: AwsOp::Ec2Terminate {
                instance_id: "i-doomed".into(),
            },
            captured_state: BTreeMap::new(),
            stashed_content_hash: None,
            requires_confirmation: true,
        };
        match exe.execute(&op, false, ConflictPolicy::Abort) {
            ExecutionOutcome::Skipped { reason } => {
                assert!(reason.contains("irreversible"));
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(exe.runner.invocations.borrow().is_empty());
    }

    #[test]
    fn supports_only_aws_variant() {
        let exe = AwsExecutor::new(Spy::default());
        let op = InverseOp::AwsReverse {
            service: "s3".into(),
            op: AwsOp::S3Rm {
                bucket: "b".into(),
                key: "k".into(),
            },
            captured_state: BTreeMap::new(),
            stashed_content_hash: None,
            requires_confirmation: true,
        };
        assert!(exe.supports(&op));
        assert!(!exe.supports(&InverseOp::SetEnv {
            name: "X".into(),
            value: "Y".into(),
        }));
    }
}
