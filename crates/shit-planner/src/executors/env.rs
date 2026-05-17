// SPDX-License-Identifier: AGPL-3.0-or-later

//! Env-tier executor (S15.5).
//!
//! Handles [`InverseOp::SetEnv`] and [`InverseOp::UnsetEnv`].
//!
//! ## Why this executor is "produce a snippet" not "mutate the shell"
//!
//! Unix has no clean way to write into a running shell's environ
//! from outside the process. The honest UX is to emit a snippet
//! (`export FOO=bar` / `unset FOO`) that the user `source`s, or
//! that an opportunistic hook in bash/zsh runs at the next precmd.
//! See [S15](.docs/sprints/S15-env-tracking.md) and DR-30 (the
//! precmd-queue injection variant).
//!
//! ## Redacted values
//!
//! A value stored as `<redacted:<hash>>` (per
//! [`shit_planner::env::redact_value`]) was scrubbed at capture
//! time. The original is unrecoverable. The executor recognises
//! the marker and emits `unset FOO` instead of `export FOO=...`
//! — honestly admitting we lost the value rather than silently
//! restoring a `<redacted:...>` string into the user's env.

use std::cell::RefCell;

use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::InverseOp;

/// Marker prefix for redacted values, matching
/// [`shit_planner::env::redact_value`]'s `<redacted:HHHHHHHH>` shape.
const REDACTED_PREFIX: &str = "<redacted:";

/// Sink for snippets the executor produces. Production uses
/// [`StringSnippetSink`] (gathers everything for the caller to write
/// to a tempfile and display); tests can implement their own.
pub trait SnippetSink {
    fn append_line(&self, line: &str);
}

/// Default sink — collects all emitted lines in a RefCell-protected
/// string. `take()` drains the buffer for the caller. Single-threaded
/// by design: the env executor runs in the orchestrator's sequential
/// path.
#[derive(Default, Debug)]
pub struct StringSnippetSink {
    buf: RefCell<String>,
}

impl StringSnippetSink {
    pub fn new() -> Self {
        Self::default()
    }
    /// Drain the accumulated snippet and reset the buffer.
    pub fn take(&self) -> String {
        std::mem::take(&mut *self.buf.borrow_mut())
    }
}

impl SnippetSink for StringSnippetSink {
    fn append_line(&self, line: &str) {
        let mut b = self.buf.borrow_mut();
        if !b.is_empty() && !b.ends_with('\n') {
            b.push('\n');
        }
        b.push_str(line);
        b.push('\n');
    }
}

/// Env-tier executor. Carries a [`SnippetSink`] the orchestrator
/// owns; each call to `execute` appends a line.
pub struct EnvExecutor<S: SnippetSink> {
    sink: S,
}

impl<S: SnippetSink> EnvExecutor<S> {
    pub fn new(sink: S) -> Self {
        Self { sink }
    }
    pub fn sink(&self) -> &S {
        &self.sink
    }
}

impl EnvExecutor<StringSnippetSink> {
    pub fn with_string_sink() -> Self {
        Self::new(StringSnippetSink::new())
    }
}

impl<S: SnippetSink> InverseOpExecutor for EnvExecutor<S> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::SetEnv { .. } | InverseOp::UnsetEnv { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let line = match op {
            InverseOp::SetEnv { name, value } => {
                if !is_valid_name(name) {
                    return ExecutionOutcome::Failed {
                        err: format!("invalid env var name: {name:?}"),
                    };
                }
                if value.starts_with(REDACTED_PREFIX) {
                    // Original value was scrubbed at capture. Best we
                    // can do is unset — surface clearly.
                    format!("unset {name}  # original value was redacted at capture")
                } else {
                    format!("export {}={}", name, posix_single_quote(value))
                }
            }
            InverseOp::UnsetEnv { name } => {
                if !is_valid_name(name) {
                    return ExecutionOutcome::Failed {
                        err: format!("invalid env var name: {name:?}"),
                    };
                }
                format!("unset {name}")
            }
            _ => {
                return ExecutionOutcome::Skipped {
                    reason: "env executor reached non-env op".into(),
                };
            }
        };
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        self.sink.append_line(&line);
        ExecutionOutcome::Applied
    }
}

/// POSIX single-quote a value. Embedded single-quotes become
/// `'\''`, which closes the quoted run, inserts a literal `'`, and
/// re-opens. Safe across bash/zsh; fish accepts the same spelling
/// (single-quoted strings in fish are literal except for embedded
/// `'` which fish writes as `\'` — but `'\''` parses cleanly too).
pub fn posix_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Cheap whitelist for env var names: `[A-Za-z_][A-Za-z0-9_]*`.
/// Rejects names that would be unsafe to splat into a shell snippet.
fn is_valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_env_emits_export_with_single_quotes() {
        let exec = EnvExecutor::with_string_sink();
        let op = InverseOp::SetEnv {
            name: "FOO".into(),
            value: "bar".into(),
        };
        let outcome = exec.execute(&op, false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let s = exec.sink().take();
        assert_eq!(s.trim_end(), "export FOO='bar'");
    }

    #[test]
    fn set_env_quotes_embedded_single_quotes() {
        let exec = EnvExecutor::with_string_sink();
        let op = InverseOp::SetEnv {
            name: "MSG".into(),
            value: "it's fine".into(),
        };
        exec.execute(&op, false, ConflictPolicy::Abort);
        let s = exec.sink().take();
        assert_eq!(s.trim_end(), r"export MSG='it'\''s fine'");
    }

    #[test]
    fn unset_env_emits_unset() {
        let exec = EnvExecutor::with_string_sink();
        let op = InverseOp::UnsetEnv { name: "FOO".into() };
        exec.execute(&op, false, ConflictPolicy::Abort);
        assert_eq!(exec.sink().take().trim_end(), "unset FOO");
    }

    #[test]
    fn redacted_set_falls_back_to_unset() {
        let exec = EnvExecutor::with_string_sink();
        let op = InverseOp::SetEnv {
            name: "GITHUB_TOKEN".into(),
            value: "<redacted:deadbeef>".into(),
        };
        let outcome = exec.execute(&op, false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let s = exec.sink().take();
        assert!(s.contains("unset GITHUB_TOKEN"));
        assert!(s.contains("redacted"));
    }

    #[test]
    fn dry_run_does_not_emit() {
        let exec = EnvExecutor::with_string_sink();
        let op = InverseOp::SetEnv {
            name: "FOO".into(),
            value: "bar".into(),
        };
        let outcome = exec.execute(&op, true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        assert!(exec.sink().take().is_empty());
    }

    #[test]
    fn invalid_name_returns_failed() {
        let exec = EnvExecutor::with_string_sink();
        for bad in &["1FOO", "FOO BAR", "FOO;rm", "", "FOO=BAR"] {
            let op = InverseOp::SetEnv {
                name: (*bad).into(),
                value: "x".into(),
            };
            assert!(
                matches!(
                    exec.execute(&op, false, ConflictPolicy::Abort),
                    ExecutionOutcome::Failed { .. }
                ),
                "expected Failed for {bad:?}",
            );
        }
    }

    #[test]
    fn does_not_handle_non_env_ops() {
        let exec = EnvExecutor::with_string_sink();
        let op = InverseOp::Unlink {
            path: std::path::PathBuf::from("/tmp/x"),
        };
        assert!(!exec.supports(&op));
    }

    #[test]
    fn multiple_calls_accumulate() {
        let exec = EnvExecutor::with_string_sink();
        exec.execute(
            &InverseOp::SetEnv {
                name: "A".into(),
                value: "1".into(),
            },
            false,
            ConflictPolicy::Abort,
        );
        exec.execute(
            &InverseOp::UnsetEnv { name: "B".into() },
            false,
            ConflictPolicy::Abort,
        );
        let s = exec.sink().take();
        assert!(s.contains("export A='1'"));
        assert!(s.contains("unset B"));
        assert_eq!(s.lines().count(), 2);
    }
}
