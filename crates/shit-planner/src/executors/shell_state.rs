// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shell-state tier executor (C06.5).
//!
//! Handles [`InverseOp::ShellStateRestore`]. v1 ships **informational
//! by default** — `execute` returns [`ExecutionOutcome::Skipped`]
//! carrying the pre-rendered bash / zsh / fish snippet so `shit show`
//! can surface it for the user to source manually.
//!
//! With `--apply-shell-state` (off by default; off because surprise-
//! mutating the user's interactive shell is a worse UX than missing
//! one undo step) the executor calls into a [`ShellStateRunner`] that
//! the orchestrator wires to the DR-30 precmd-queue mechanism for
//! bash / zsh. Fish always emits informational only — fish's design
//! has no safe equivalent to bash's `PROMPT_COMMAND` queue.
//!
//! ## Why the runner trait
//!
//! Same shape as the other tier executors (descriptor, kubectl,
//! container): a small Runner trait lets tests inject a spy. The
//! production runner's actual queue-to-precmd path is out of v1
//! (DR-30 / `DR-CR-50`); for stage 1 it returns an error so any
//! caller that forgets to disable apply gets a clear "not wired" hit.

use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::InverseOp;

/// What shell the user was running when the snippet was captured.
/// Drives which pre-rendered body the executor picks from the
/// `ShellStateRestore` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellTarget {
    Bash,
    Zsh,
    Fish,
}

impl ShellTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }
}

/// Test-injectable abstraction for the actual precmd-queue dispatch.
/// Production wires this to the DR-30 mechanism.
pub trait ShellStateRunner {
    /// Push `snippet` onto the shell's precmd queue so it runs
    /// before the next prompt. `target` discriminates the syntax.
    fn queue_to_precmd(&self, snippet: &str, target: ShellTarget) -> Result<(), String>;
}

/// Production runner. AR06.1 / DR-CR-50 — appends the rendered
/// snippet to a per-session file at
/// `$XDG_STATE_HOME/shit/precmd-queue/<session-uuid>`. The
/// bash hook's `__shit_drain_precmd_queue` (in `shell/bash.sh`)
/// sources + truncates this file on every PROMPT_COMMAND fire,
/// so the snippet runs exactly once before the next prompt.
///
/// Session-uuid keying ensures concurrent shells stay isolated:
/// shell A's `cd '/etc' && shit undo --apply-shell-state` doesn't
/// re-cd shell B.
#[derive(Debug, Default)]
pub struct SystemShellStateRunner {
    /// UUID of the shell session whose queue to write to.
    /// Optional — `with_session()` injects it; if absent the
    /// runner falls back to the error path so the caller learns
    /// they forgot to plumb it.
    session: Option<String>,
}

impl SystemShellStateRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the target session UUID. Required before
    /// `queue_to_precmd` can succeed.
    pub fn with_session(mut self, session: String) -> Self {
        self.session = Some(session);
        self
    }
}

impl ShellStateRunner for SystemShellStateRunner {
    fn queue_to_precmd(&self, snippet: &str, _target: ShellTarget) -> Result<(), String> {
        let session = self
            .session
            .as_deref()
            .ok_or("SystemShellStateRunner: no session UUID set; call with_session() first")?;
        let state_home = std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local/state"))
            })
            .ok_or("neither XDG_STATE_HOME nor HOME is set")?;
        let queue_dir = state_home.join("shit").join("precmd-queue");
        std::fs::create_dir_all(&queue_dir)
            .map_err(|e| format!("create precmd-queue dir {}: {e}", queue_dir.display()))?;
        let queue_path = queue_dir.join(session);
        // Append so concurrent `shit undo --apply-shell-state`
        // invocations don't clobber each other. The hook's drain
        // sources the file as a single bash unit and truncates;
        // worst case is two snippets running in the order they
        // were queued, which is what we want.
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&queue_path)
            .map_err(|e| format!("open precmd-queue file {}: {e}", queue_path.display()))?;
        f.write_all(snippet.as_bytes())
            .map_err(|e| format!("write to precmd-queue file: {e}"))?;
        if !snippet.ends_with('\n') {
            f.write_all(b"\n")
                .map_err(|e| format!("write newline to precmd-queue: {e}"))?;
        }
        Ok(())
    }
}

pub struct ShellStateExecutor<R: ShellStateRunner> {
    runner: R,
    /// Default `false`. `shit undo --apply-shell-state` flips this
    /// on (bash / zsh only — fish always refuses).
    apply_to_live_shell: bool,
    /// Which shell to target when `apply_to_live_shell` is true.
    /// `None` means we don't know — render Skipped with all three
    /// snippets.
    target: Option<ShellTarget>,
}

impl<R: ShellStateRunner> ShellStateExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            apply_to_live_shell: false,
            target: None,
        }
    }

    /// Opt into precmd-queue dispatch. Mirrors `shit undo
    /// --apply-shell-state`.
    pub fn with_apply(mut self, target: ShellTarget) -> Self {
        self.apply_to_live_shell = true;
        self.target = Some(target);
        self
    }
}

impl<R: ShellStateRunner> InverseOpExecutor for ShellStateExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::ShellStateRestore { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::ShellStateRestore {
            snippet_bash,
            snippet_zsh,
            snippet_fish,
            ..
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "shell-state executor reached non-shell-state op".into(),
            };
        };

        if dry_run {
            return ExecutionOutcome::WouldApply;
        }

        if !self.apply_to_live_shell {
            // Informational. Caller is `shit show` / `shit undo`
            // without `--apply-shell-state` — surface the available
            // snippets via Skipped::reason so the rendering layer
            // can pull them out.
            return ExecutionOutcome::Skipped {
                reason: build_informational_reason(
                    snippet_bash.as_deref(),
                    snippet_zsh.as_deref(),
                    snippet_fish.as_deref(),
                ),
            };
        }

        // Apply path.
        let target = match self.target {
            Some(t) => t,
            None => {
                return ExecutionOutcome::Failed {
                    err: "--apply-shell-state requires a known shell target".into(),
                };
            }
        };

        if matches!(target, ShellTarget::Fish) {
            // AR06.6 — surface the rendered body so a fish user
            // has something to copy-paste instead of just a
            // doc-pointer. DR-30 still applies (we don't write
            // to a precmd-queue for fish), but informational has
            // to actually inform.
            let body = snippet_fish.as_deref().unwrap_or("");
            let reason = if body.is_empty() {
                "fish has no safe precmd-queue equivalent (see DR-30); no fish snippet was \
                 rendered for this diff"
                    .to_string()
            } else {
                format!(
                    "fish has no safe precmd-queue equivalent (see DR-30); source this manually:\n\
                     {body}"
                )
            };
            return ExecutionOutcome::Skipped { reason };
        }

        let snippet = match target {
            ShellTarget::Bash => snippet_bash.as_deref(),
            ShellTarget::Zsh => snippet_zsh.as_deref(),
            ShellTarget::Fish => unreachable!(),
        };

        let Some(body) = snippet else {
            return ExecutionOutcome::Failed {
                err: format!("no {} snippet recorded on this op", target.as_str()),
            };
        };
        match self.runner.queue_to_precmd(body, target) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed {
                err: format!("queue-to-precmd: {e}"),
            },
        }
    }
}

fn build_informational_reason(bash: Option<&str>, zsh: Option<&str>, fish: Option<&str>) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if bash.is_some() {
        parts.push("bash");
    }
    if zsh.is_some() {
        parts.push("zsh");
    }
    if fish.is_some() {
        parts.push("fish");
    }
    if parts.is_empty() {
        return "no shell snippet rendered (empty diff)".into();
    }
    format!(
        "shell-state restore is informational (snippets available for {}); \
         pass `--apply-shell-state` to queue via precmd",
        parts.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;

    #[derive(Default)]
    struct SpyRunner {
        calls: RefCell<Vec<(String, ShellTarget)>>,
        should_fail: RefCell<bool>,
    }

    impl ShellStateRunner for SpyRunner {
        fn queue_to_precmd(&self, snippet: &str, target: ShellTarget) -> Result<(), String> {
            self.calls.borrow_mut().push((snippet.to_string(), target));
            if *self.should_fail.borrow() {
                Err("simulated".into())
            } else {
                Ok(())
            }
        }
    }

    fn sample_op() -> InverseOp {
        InverseOp::ShellStateRestore {
            pwd_before: Some(PathBuf::from("/home/u")),
            opts_diff: vec![],
            aliases_diff: vec![],
            funcs_diff: vec![],
            snippet_bash: Some("cd '/home/u'\nset -o errexit\n".into()),
            snippet_zsh: Some("cd '/home/u'\nsetopt errexit\n".into()),
            snippet_fish: Some("cd '/home/u'\n".into()),
        }
    }

    #[test]
    fn supports_only_shell_state_variant() {
        let exe = ShellStateExecutor::new(SpyRunner::default());
        assert!(exe.supports(&sample_op()));
        assert!(!exe.supports(&InverseOp::SetEnv {
            name: "X".into(),
            value: "Y".into(),
        }));
    }

    #[test]
    fn default_executor_returns_skipped_with_informational_reason() {
        let exe = ShellStateExecutor::new(SpyRunner::default());
        match exe.execute(&sample_op(), false, ConflictPolicy::Abort) {
            ExecutionOutcome::Skipped { reason } => {
                assert!(reason.contains("informational"), "got: {reason}");
                assert!(reason.contains("bash"));
                assert!(reason.contains("zsh"));
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        // Runner was NOT called.
        assert!(exe.runner.calls.borrow().is_empty());
    }

    #[test]
    fn dry_run_returns_would_apply_even_with_apply_flag() {
        let exe = ShellStateExecutor::new(SpyRunner::default()).with_apply(ShellTarget::Bash);
        let outcome = exe.execute(&sample_op(), true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        assert!(exe.runner.calls.borrow().is_empty());
    }

    #[test]
    fn apply_to_bash_calls_runner_with_bash_snippet() {
        let exe = ShellStateExecutor::new(SpyRunner::default()).with_apply(ShellTarget::Bash);
        let outcome = exe.execute(&sample_op(), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, ShellTarget::Bash);
        assert!(calls[0].0.contains("set -o errexit"));
    }

    #[test]
    fn apply_to_zsh_calls_runner_with_zsh_snippet() {
        let exe = ShellStateExecutor::new(SpyRunner::default()).with_apply(ShellTarget::Zsh);
        let outcome = exe.execute(&sample_op(), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exe.runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, ShellTarget::Zsh);
        assert!(calls[0].0.contains("setopt errexit"));
    }

    #[test]
    fn fish_with_apply_is_skipped_with_dr30_note() {
        let exe = ShellStateExecutor::new(SpyRunner::default()).with_apply(ShellTarget::Fish);
        match exe.execute(&sample_op(), false, ConflictPolicy::Abort) {
            ExecutionOutcome::Skipped { reason } => {
                assert!(reason.contains("DR-30"), "got: {reason}");
                // AR06.6 — the rendered body must be in the reason so
                // a fish user can copy-paste without re-running `shit show`.
                assert!(
                    reason.contains("cd '/home/u'"),
                    "skip reason should embed snippet body; got: {reason}"
                );
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
        assert!(exe.runner.calls.borrow().is_empty());
    }

    #[test]
    fn apply_missing_snippet_for_target_fails() {
        let mut op = sample_op();
        if let InverseOp::ShellStateRestore { snippet_bash, .. } = &mut op {
            *snippet_bash = None;
        }
        let exe = ShellStateExecutor::new(SpyRunner::default()).with_apply(ShellTarget::Bash);
        match exe.execute(&op, false, ConflictPolicy::Abort) {
            ExecutionOutcome::Failed { err } => {
                assert!(err.contains("no bash snippet"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn runner_failure_surfaces_as_failed() {
        let runner = SpyRunner::default();
        *runner.should_fail.borrow_mut() = true;
        let exe = ShellStateExecutor::new(runner).with_apply(ShellTarget::Bash);
        match exe.execute(&sample_op(), false, ConflictPolicy::Abort) {
            ExecutionOutcome::Failed { err } => assert!(err.contains("simulated")),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn system_runner_without_session_errors_loud() {
        let r = SystemShellStateRunner::new();
        let err = r.queue_to_precmd("cd /", ShellTarget::Bash).unwrap_err();
        assert!(err.contains("session"), "got: {err}");
    }

    #[test]
    fn system_runner_with_session_writes_to_precmd_queue_file() {
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: single-threaded test, only env mutation; restored
        // implicitly when tmpdir drops cleanly. We don't call any
        // other test that reads XDG_STATE_HOME concurrently.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", tmp.path());
        }
        let r = SystemShellStateRunner::new().with_session("abc-123".into());
        r.queue_to_precmd("cd '/home/u'\n", ShellTarget::Bash)
            .expect("queue_to_precmd");
        let q = tmp.path().join("shit/precmd-queue/abc-123");
        let body = std::fs::read_to_string(&q).expect("queue file");
        assert!(body.contains("cd '/home/u'"));
        // Append semantics: a second call adds to the same file.
        r.queue_to_precmd("cd '/tmp'\n", ShellTarget::Bash)
            .expect("queue_to_precmd 2");
        let body2 = std::fs::read_to_string(&q).expect("queue file");
        assert!(body2.contains("cd '/home/u'"));
        assert!(body2.contains("cd '/tmp'"));
    }

    #[test]
    fn shell_target_as_str_renders_for_cli() {
        assert_eq!(ShellTarget::Bash.as_str(), "bash");
        assert_eq!(ShellTarget::Zsh.as_str(), "zsh");
        assert_eq!(ShellTarget::Fish.as_str(), "fish");
    }
}
