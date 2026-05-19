// SPDX-License-Identifier: AGPL-3.0-or-later

//! gh-cli tier executor (C03.3).
//!
//! Reverses GitHub-CLI operations by re-creating / re-opening the
//! resource. Captured JSON describes the pre-state; the executor
//! synthesizes the reverse argv per op:
//!
//! - `release delete <tag>` → `gh release create <tag>` with captured
//!   title + body.
//! - `release delete-asset <tag> <asset>` → informational (asset
//!   bytes aren't stashed in v1; the JSON URL is surfaced).
//! - `issue close <n>` → `gh issue reopen <n>`.
//! - `pr close <n>` → `gh pr reopen <n>`.

use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::{GhOp, InverseOp};

pub trait GhRunner {
    fn run(&self, argv: &[String]) -> Result<(), String>;
    /// Run with stdin (used for `gh release create --notes-file -`
    /// when the body is large).
    fn run_with_stdin(&self, argv: &[String], stdin_bytes: &[u8]) -> Result<(), String>;
}

#[derive(Debug, Default)]
pub struct SystemGhRunner;

impl GhRunner for SystemGhRunner {
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
}

pub struct GhExecutor<R: GhRunner> {
    runner: R,
}

impl<R: GhRunner> GhExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: GhRunner> InverseOpExecutor for GhExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::GhReverse { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::GhReverse {
            op: gh_op,
            captured_json,
            requires_confirmation: _,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "gh executor reached non-gh op".into(),
            };
        };

        let plan = match build_reverse(gh_op, captured_json) {
            Ok(p) => p,
            Err(e) => {
                return ExecutionOutcome::Skipped {
                    reason: format!("gh reverse: {e}"),
                };
            }
        };

        if dry_run {
            return ExecutionOutcome::WouldApply;
        }

        match plan {
            ReversePlan::Run(argv) => match self.runner.run(&argv) {
                Ok(()) => ExecutionOutcome::Applied,
                Err(e) => ExecutionOutcome::Failed {
                    err: format!("gh: {e}"),
                },
            },
            ReversePlan::RunWithStdin(argv, stdin) => {
                match self.runner.run_with_stdin(&argv, &stdin) {
                    Ok(()) => ExecutionOutcome::Applied,
                    Err(e) => ExecutionOutcome::Failed {
                        err: format!("gh: {e}"),
                    },
                }
            }
            ReversePlan::Informational(msg) => ExecutionOutcome::Skipped { reason: msg },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReversePlan {
    Run(Vec<String>),
    RunWithStdin(Vec<String>, Vec<u8>),
    /// Cannot mechanically reverse; surface a description.
    Informational(String),
}

/// Pure: synthesize the reverse plan for a `GhOp` from the captured
/// JSON. Extracted so tests can drive it without a runner.
pub fn build_reverse(op: &GhOp, captured_json: &[u8]) -> Result<ReversePlan, String> {
    match op {
        GhOp::ReleaseDelete { tag } => {
            // Captured JSON shape (from `gh release view --json
            // tagName,name,body,isDraft,isPrerelease`):
            //   {"tagName": "...", "name": "...", "body": "...",
            //    "isDraft": false, "isPrerelease": false}
            let v: serde_json::Value = serde_json::from_slice(captured_json)
                .map_err(|e| format!("parse release JSON: {e}"))?;
            let title = v
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(tag);
            let body = v
                .get("body")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let mut argv = vec![
                "gh".to_string(),
                "release".to_string(),
                "create".to_string(),
                tag.clone(),
                "--title".to_string(),
                title.to_string(),
                "--notes-file".to_string(),
                "-".to_string(),
            ];
            if v.get("isDraft")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                argv.push("--draft".into());
            }
            if v.get("isPrerelease")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                argv.push("--prerelease".into());
            }
            Ok(ReversePlan::RunWithStdin(argv, body.into_bytes()))
        }
        GhOp::ReleaseDeleteAsset { tag, asset } => Ok(ReversePlan::Informational(format!(
            "asset `{asset}` was deleted from release `{tag}`; v1 does not auto-restore asset \
             bytes. Re-upload manually with `gh release upload {tag} <local-path>`."
        ))),
        GhOp::IssueClose { number } => Ok(ReversePlan::Run(vec![
            "gh".to_string(),
            "issue".to_string(),
            "reopen".to_string(),
            number.to_string(),
        ])),
        GhOp::PrClose { number } => Ok(ReversePlan::Run(vec![
            "gh".to_string(),
            "pr".to_string(),
            "reopen".to_string(),
            number.to_string(),
        ])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    type CallRecord = (String, Vec<String>, Vec<u8>);

    #[derive(Default)]
    struct Spy {
        calls: RefCell<Vec<CallRecord>>,
    }
    impl GhRunner for Spy {
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
            Ok(())
        }
    }

    #[test]
    fn issue_close_reverses_to_reopen() {
        let plan = build_reverse(&GhOp::IssueClose { number: 42 }, b"{}").unwrap();
        assert_eq!(
            plan,
            ReversePlan::Run(vec![
                "gh".into(),
                "issue".into(),
                "reopen".into(),
                "42".into(),
            ])
        );
    }

    #[test]
    fn pr_close_reverses_to_reopen() {
        let plan = build_reverse(&GhOp::PrClose { number: 7 }, b"{}").unwrap();
        match plan {
            ReversePlan::Run(argv) => {
                assert_eq!(argv, vec!["gh", "pr", "reopen", "7"]);
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn release_delete_reverses_to_create_with_body_on_stdin() {
        let json = br#"{
            "tagName": "v1.0",
            "name": "Version 1.0",
            "body": "Release notes here.",
            "isDraft": false,
            "isPrerelease": false
        }"#;
        let plan = build_reverse(&GhOp::ReleaseDelete { tag: "v1.0".into() }, json).unwrap();
        match plan {
            ReversePlan::RunWithStdin(argv, stdin) => {
                assert_eq!(argv[0], "gh");
                assert_eq!(argv[1], "release");
                assert_eq!(argv[2], "create");
                assert_eq!(argv[3], "v1.0");
                assert!(argv.iter().any(|t| t == "--title"));
                assert!(argv.iter().any(|t| t == "Version 1.0"));
                assert!(argv.iter().any(|t| t == "--notes-file"));
                assert_eq!(std::str::from_utf8(&stdin).unwrap(), "Release notes here.");
            }
            other => panic!("expected RunWithStdin, got {other:?}"),
        }
    }

    #[test]
    fn release_delete_preserves_draft_and_prerelease_flags() {
        let json = br#"{
            "tagName": "v0.9-rc",
            "name": "v0.9-rc",
            "body": "",
            "isDraft": true,
            "isPrerelease": true
        }"#;
        let plan = build_reverse(
            &GhOp::ReleaseDelete {
                tag: "v0.9-rc".into(),
            },
            json,
        )
        .unwrap();
        match plan {
            ReversePlan::RunWithStdin(argv, _) => {
                assert!(argv.iter().any(|t| t == "--draft"));
                assert!(argv.iter().any(|t| t == "--prerelease"));
            }
            other => panic!("expected RunWithStdin, got {other:?}"),
        }
    }

    #[test]
    fn release_delete_asset_is_informational() {
        let plan = build_reverse(
            &GhOp::ReleaseDeleteAsset {
                tag: "v1".into(),
                asset: "shit-x86_64.tar.gz".into(),
            },
            b"{}",
        )
        .unwrap();
        match plan {
            ReversePlan::Informational(msg) => {
                assert!(msg.contains("shit-x86_64.tar.gz"));
                assert!(msg.contains("gh release upload"));
            }
            other => panic!("expected Informational, got {other:?}"),
        }
    }

    #[test]
    fn malformed_release_json_is_skip() {
        let exe = GhExecutor::new(Spy::default());
        let op = InverseOp::GhReverse {
            op: GhOp::ReleaseDelete { tag: "v1".into() },
            captured_json: b"not json".to_vec(),
            requires_confirmation: true,
        };
        let outcome = exe.execute(&op, false, ConflictPolicy::Abort);
        match outcome {
            ExecutionOutcome::Skipped { reason } => {
                assert!(reason.contains("parse"), "got: {reason}");
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn dry_run_does_not_invoke_runner() {
        let exe = GhExecutor::new(Spy::default());
        let op = InverseOp::GhReverse {
            op: GhOp::IssueClose { number: 1 },
            captured_json: b"{}".to_vec(),
            requires_confirmation: true,
        };
        let outcome = exe.execute(&op, true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        assert!(exe.runner.calls.borrow().is_empty());
    }

    #[test]
    fn applied_runs_through_runner() {
        let exe = GhExecutor::new(Spy::default());
        let op = InverseOp::GhReverse {
            op: GhOp::IssueClose { number: 5 },
            captured_json: b"{}".to_vec(),
            requires_confirmation: true,
        };
        assert_eq!(
            exe.execute(&op, false, ConflictPolicy::Abort),
            ExecutionOutcome::Applied
        );
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "run");
        assert_eq!(calls[0].1, vec!["gh", "issue", "reopen", "5"]);
    }

    #[test]
    fn supports_only_gh_variant() {
        let exe = GhExecutor::new(Spy::default());
        let op = InverseOp::GhReverse {
            op: GhOp::IssueClose { number: 1 },
            captured_json: b"{}".to_vec(),
            requires_confirmation: false,
        };
        assert!(exe.supports(&op));
        assert!(!exe.supports(&InverseOp::SetEnv {
            name: "X".into(),
            value: "Y".into(),
        }));
    }
}
