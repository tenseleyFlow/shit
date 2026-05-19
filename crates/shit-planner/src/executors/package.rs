// SPDX-License-Identifier: AGPL-3.0-or-later

//! Package-tier executor (S14.10).
//!
//! Translates an [`InverseOp::PackageRollback`] into one or more
//! invocations of the relevant package manager's CLI, then runs them
//! with `SHIT_DURING_UNDO=1` in the environment so the
//! `shit-helper pkg-event` hook short-circuits and we don't recurse.
//!
//! The synthesis logic is testable in isolation:
//! [`synthesize_argv`] is pure (it takes a diff and returns a
//! `Vec<Vec<String>>`). The shell-out is gated behind the
//! [`PkgRunner`] trait so tests don't actually exec apt.

use std::collections::BTreeMap;
use std::process::Command;

use crate::events::{PackageManager, PackageOpKind};
use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::InverseOp;

/// Abstraction over the subprocess call. Production uses
/// [`SystemPkgRunner`]; tests use a mock that records argv and
/// returns canned exit codes.
pub trait PkgRunner {
    /// Run one invocation. Returns `Ok(())` on exit code zero,
    /// `Err(detail)` otherwise.
    fn run(&self, argv: &[String]) -> Result<(), String>;
}

/// The default runner: shells out via `std::process::Command`,
/// inheriting stdout/stderr so the user sees apt's own output.
pub struct SystemPkgRunner;

impl PkgRunner for SystemPkgRunner {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let (cmd, args) = match argv.split_first() {
            Some(v) => v,
            None => return Err("empty argv".into()),
        };
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

/// Concrete tier executor. Holds a [`PkgRunner`] so tests can swap it.
pub struct PackageExecutor<R: PkgRunner> {
    runner: R,
}

impl<R: PkgRunner> PackageExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl PackageExecutor<SystemPkgRunner> {
    pub fn system() -> Self {
        Self::new(SystemPkgRunner)
    }
}

impl<R: PkgRunner> InverseOpExecutor for PackageExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::PackageRollback { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::PackageRollback {
            manager,
            original_op,
            packages_before,
            packages_after,
            repo_state_hint,
        } = op
        else {
            // Defensive: orchestrator should not route here otherwise.
            return ExecutionOutcome::Skipped {
                reason: "package executor reached non-package op".into(),
            };
        };

        let invocations = synthesize_argv(
            *manager,
            *original_op,
            packages_before,
            packages_after,
            repo_state_hint.as_deref(),
        );
        if invocations.is_empty() {
            return ExecutionOutcome::Skipped {
                reason: "no-op diff (packages_before == packages_after)".into(),
            };
        }
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        for argv in &invocations {
            if let Err(e) = self.runner.run(argv) {
                return ExecutionOutcome::Failed {
                    err: format!("{}: {e}", argv.first().map(|s| s.as_str()).unwrap_or("?")),
                };
            }
        }
        ExecutionOutcome::Applied
    }
}

/// Pure synthesis: given a manager + the captured diff, produce the
/// argv list (or lists) that, when executed in order, reverse the
/// transaction. Each `Vec<String>` is one process invocation; the
/// runner runs them sequentially.
///
/// Per-manager strategy:
/// - apt: one `apt-get -y --allow-downgrades` invocation that
///   removes installed pkgs and re-installs removed/changed pkgs at
///   their old versions. apt handles dep math.
/// - pacman: one `pacman -R --noconfirm` for installs, plus one
///   `pacman -U` per removed/changed pkg (cache lookup happens at
///   exec time; if the cache file is missing pacman returns
///   non-zero and we surface `Failed`).
/// - dnf: a single `dnf history undo <id>` if the history-id extras
///   are present (the daemon stored them on Pre); else fall back to
///   `dnf install`/`dnf remove`.
/// - brew: `brew uninstall` for installs, `brew install pkg@v` for
///   removed/changed where the version is still tappable.
/// - pkg (FreeBSD): `pkg delete -y` for installs, `pkg install -y
///   <name>-<oldver>` for removed/changed.
///
/// Helper-routing (DR-15) for privileged invocations is out of scope
/// here — the apt/pacman/dnf/pkg invocations require sudo to actually
/// do anything, and the caller is expected to invoke the executor
/// from an already-privileged context (e.g. `sudo shit undo`). brew
/// is unprivileged.
pub fn synthesize_argv(
    manager: PackageManager,
    _original_op: PackageOpKind,
    packages_before: &BTreeMap<String, String>,
    packages_after: &BTreeMap<String, String>,
    repo_state_hint: Option<&str>,
) -> Vec<Vec<String>> {
    let installed: Vec<&String> = packages_after
        .keys()
        .filter(|k| !packages_before.contains_key(*k))
        .collect();
    let removed: Vec<(&String, &String)> = packages_before
        .iter()
        .filter(|(k, _)| !packages_after.contains_key(*k))
        .collect();
    let changed: Vec<(&String, &String)> = packages_before
        .iter()
        .filter_map(|(k, v)| {
            packages_after
                .get(k)
                .filter(|v_after| v_after != &v)
                .map(|_| (k, v))
        })
        .collect();

    if installed.is_empty() && removed.is_empty() && changed.is_empty() {
        return Vec::new();
    }

    match manager {
        PackageManager::Apt | PackageManager::Dpkg => apt_argv(&installed, &removed, &changed),
        PackageManager::Pacman => pacman_argv(&installed, &removed, &changed),
        PackageManager::Dnf => dnf_argv(&installed, &removed, &changed, repo_state_hint),
        PackageManager::Brew => brew_argv(&installed, &removed, &changed),
        PackageManager::Pkg => pkg_argv(&installed, &removed, &changed),
    }
}

fn apt_argv(
    installed: &[&String],
    removed: &[(&String, &String)],
    changed: &[(&String, &String)],
) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    if !installed.is_empty() {
        let mut argv = vec!["apt-get".into(), "remove".into(), "-y".into()];
        for name in installed {
            argv.push((*name).clone());
        }
        out.push(argv);
    }
    let reinstall: Vec<(&String, &String)> =
        removed.iter().chain(changed.iter()).copied().collect();
    if !reinstall.is_empty() {
        let mut argv = vec![
            "apt-get".into(),
            "install".into(),
            "-y".into(),
            "--allow-downgrades".into(),
        ];
        for (name, version) in &reinstall {
            argv.push(format!("{name}={version}"));
        }
        out.push(argv);
    }
    out
}

fn pacman_argv(
    installed: &[&String],
    removed: &[(&String, &String)],
    changed: &[(&String, &String)],
) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    if !installed.is_empty() {
        let mut argv = vec!["pacman".into(), "-R".into(), "--noconfirm".into()];
        for name in installed {
            argv.push((*name).clone());
        }
        out.push(argv);
    }
    for (name, version) in removed.iter().chain(changed.iter()) {
        // pacman -U requires a path to a cached .pkg.tar.zst. The
        // canonical cache location is /var/cache/pacman/pkg/.
        let cache_path = format!("/var/cache/pacman/pkg/{name}-{version}-x86_64.pkg.tar.zst");
        out.push(vec![
            "pacman".into(),
            "-U".into(),
            "--noconfirm".into(),
            cache_path,
        ]);
    }
    out
}

fn dnf_argv(
    installed: &[&String],
    removed: &[(&String, &String)],
    changed: &[(&String, &String)],
    history_id: Option<&str>,
) -> Vec<Vec<String>> {
    // dnf history undo is the canonical inverse if the daemon stored
    // the history id (DR-26). It handles dep math correctly and
    // restores the system to its pre-transaction state. The id must
    // look numeric — `dnf history undo` only accepts integers.
    if let Some(id) = history_id
        && id.chars().all(|c| c.is_ascii_digit())
        && !id.is_empty()
    {
        return vec![vec![
            "dnf".into(),
            "history".into(),
            "undo".into(),
            "-y".into(),
            id.to_string(),
        ]];
    }
    // Fallback: per-package install/remove. Used when the pre stash
    // didn't see a history id (e.g. an `rpm` invocation) or when the
    // id is malformed.
    let mut out = Vec::new();
    if !installed.is_empty() {
        let mut argv = vec!["dnf".into(), "remove".into(), "-y".into()];
        for name in installed {
            argv.push((*name).clone());
        }
        out.push(argv);
    }
    let reinstall: Vec<(&String, &String)> =
        removed.iter().chain(changed.iter()).copied().collect();
    if !reinstall.is_empty() {
        let mut argv = vec!["dnf".into(), "install".into(), "-y".into()];
        for (name, version) in &reinstall {
            argv.push(format!("{name}-{version}"));
        }
        out.push(argv);
    }
    out
}

fn brew_argv(
    installed: &[&String],
    removed: &[(&String, &String)],
    changed: &[(&String, &String)],
) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for name in installed {
        out.push(vec!["brew".into(), "uninstall".into(), (*name).clone()]);
    }
    for (name, _version) in removed.iter().chain(changed.iter()) {
        // brew install pkg@version is the form for pinned versions;
        // when the formula is a versioned one (jq@1.7), brew accepts
        // the @-form directly. When it's a moving target, brew falls
        // back to "whatever HEAD is" and we surface Failed in tests.
        out.push(vec!["brew".into(), "install".into(), (*name).clone()]);
    }
    out
}

fn pkg_argv(
    installed: &[&String],
    removed: &[(&String, &String)],
    changed: &[(&String, &String)],
) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    if !installed.is_empty() {
        let mut argv = vec!["pkg".into(), "delete".into(), "-y".into()];
        for name in installed {
            argv.push((*name).clone());
        }
        out.push(argv);
    }
    for (name, version) in removed.iter().chain(changed.iter()) {
        out.push(vec![
            "pkg".into(),
            "install".into(),
            "-y".into(),
            format!("{name}-{version}"),
        ]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkgs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn apt_install_reverses_to_remove() {
        let before = pkgs(&[("bash", "5.1")]);
        let after = pkgs(&[("bash", "5.1"), ("jq", "1.7")]);
        let argv = synthesize_argv(
            PackageManager::Apt,
            PackageOpKind::Install,
            &before,
            &after,
            None,
        );
        assert_eq!(argv.len(), 1);
        assert_eq!(argv[0][0], "apt-get");
        assert_eq!(argv[0][1], "remove");
        assert!(argv[0].contains(&"jq".to_string()));
    }

    #[test]
    fn apt_upgrade_reverses_to_downgrade() {
        let before = pkgs(&[("bash", "5.1")]);
        let after = pkgs(&[("bash", "5.2")]);
        let argv = synthesize_argv(
            PackageManager::Apt,
            PackageOpKind::Upgrade,
            &before,
            &after,
            None,
        );
        assert_eq!(argv.len(), 1);
        assert_eq!(argv[0][0], "apt-get");
        assert_eq!(argv[0][1], "install");
        assert!(argv[0].contains(&"--allow-downgrades".to_string()));
        assert!(argv[0].contains(&"bash=5.1".to_string()));
    }

    #[test]
    fn apt_remove_reverses_to_install_at_old_version() {
        let before = pkgs(&[("bash", "5.1"), ("jq", "1.7")]);
        let after = pkgs(&[("bash", "5.1")]);
        let argv = synthesize_argv(
            PackageManager::Apt,
            PackageOpKind::Remove,
            &before,
            &after,
            None,
        );
        assert!(argv.iter().any(|v| v.contains(&"jq=1.7".to_string())));
    }

    #[test]
    fn pacman_install_reverses_to_remove() {
        let before = pkgs(&[]);
        let after = pkgs(&[("jq", "1.7-1")]);
        let argv = synthesize_argv(
            PackageManager::Pacman,
            PackageOpKind::Install,
            &before,
            &after,
            None,
        );
        assert_eq!(argv[0][0], "pacman");
        assert_eq!(argv[0][1], "-R");
    }

    #[test]
    fn brew_install_reverses_to_uninstall() {
        let before = pkgs(&[]);
        let after = pkgs(&[("jq", "1.7.1")]);
        let argv = synthesize_argv(
            PackageManager::Brew,
            PackageOpKind::Install,
            &before,
            &after,
            None,
        );
        assert_eq!(argv[0][0], "brew");
        assert_eq!(argv[0][1], "uninstall");
        assert!(argv[0].contains(&"jq".to_string()));
    }

    #[test]
    fn freebsd_pkg_install_reverses_to_delete() {
        let before = pkgs(&[]);
        let after = pkgs(&[("jq", "1.7.1")]);
        let argv = synthesize_argv(
            PackageManager::Pkg,
            PackageOpKind::Install,
            &before,
            &after,
            None,
        );
        assert_eq!(argv[0][0], "pkg");
        assert_eq!(argv[0][1], "delete");
    }

    #[test]
    fn empty_diff_is_no_op() {
        let same = pkgs(&[("bash", "5.1")]);
        let argv = synthesize_argv(
            PackageManager::Apt,
            PackageOpKind::Install,
            &same,
            &same,
            None,
        );
        assert!(argv.is_empty());
    }

    #[test]
    fn dnf_with_history_id_uses_single_undo_invocation() {
        let before = pkgs(&[]);
        let after = pkgs(&[("jq", "1.7.1-1")]);
        let argv = synthesize_argv(
            PackageManager::Dnf,
            PackageOpKind::Install,
            &before,
            &after,
            Some("42"),
        );
        assert_eq!(argv.len(), 1);
        assert_eq!(argv[0], vec!["dnf", "history", "undo", "-y", "42"]);
    }

    #[test]
    fn dnf_without_history_id_falls_back_to_per_package() {
        let before = pkgs(&[]);
        let after = pkgs(&[("jq", "1.7.1-1")]);
        let argv = synthesize_argv(
            PackageManager::Dnf,
            PackageOpKind::Install,
            &before,
            &after,
            None,
        );
        assert_eq!(argv.len(), 1);
        assert_eq!(argv[0][0], "dnf");
        assert_eq!(argv[0][1], "remove");
        assert!(argv[0].contains(&"jq".to_string()));
    }

    #[test]
    fn dnf_with_malformed_history_id_falls_back() {
        // Non-numeric or empty IDs should not reach `dnf history undo`.
        for bad in ["", "abc", "12.3", "-1"] {
            let argv = synthesize_argv(
                PackageManager::Dnf,
                PackageOpKind::Install,
                &pkgs(&[]),
                &pkgs(&[("jq", "1.7-1")]),
                Some(bad),
            );
            assert!(
                argv[0][0] == "dnf" && argv[0][1] == "remove",
                "expected fallback for {bad:?}, got {argv:?}"
            );
        }
    }

    #[test]
    fn dnf_with_history_id_ignores_diff_details() {
        // When history id is present, the per-package diff is
        // entirely subsumed by `dnf history undo`. The argv should
        // not echo the package names.
        let before = pkgs(&[("a", "1"), ("b", "1")]);
        let after = pkgs(&[("a", "2"), ("c", "1")]);
        let argv = synthesize_argv(
            PackageManager::Dnf,
            PackageOpKind::Upgrade,
            &before,
            &after,
            Some("7"),
        );
        assert_eq!(argv.len(), 1);
        assert!(!argv[0].iter().any(|t| t == "a" || t == "b" || t == "c"));
    }

    /// Spy runner: records every argv that would have executed.
    #[derive(Default)]
    struct SpyRunner {
        invocations: std::cell::RefCell<Vec<Vec<String>>>,
        fail_on: Option<usize>,
    }
    impl PkgRunner for SpyRunner {
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
        InverseOp::PackageRollback {
            manager: PackageManager::Apt,
            original_op: PackageOpKind::Install,
            packages_before: pkgs(&[]),
            packages_after: pkgs(&[("jq", "1.7")]),
            repo_state_hint: None,
        }
    }

    #[test]
    fn executor_dry_run_does_not_invoke() {
        let runner = SpyRunner::default();
        let exec = PackageExecutor::new(runner);
        let outcome = exec.execute(&rollback_op(), true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        assert_eq!(exec.runner.invocations.borrow().len(), 0);
    }

    #[test]
    fn executor_applied_records_invocation() {
        let runner = SpyRunner::default();
        let exec = PackageExecutor::new(runner);
        let outcome = exec.execute(&rollback_op(), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exec.runner.invocations.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0], "apt-get");
    }

    #[test]
    fn executor_propagates_runner_failure() {
        let runner = SpyRunner {
            fail_on: Some(0),
            ..SpyRunner::default()
        };
        let exec = PackageExecutor::new(runner);
        let outcome = exec.execute(&rollback_op(), false, ConflictPolicy::Abort);
        assert!(matches!(outcome, ExecutionOutcome::Failed { .. }));
    }

    #[test]
    fn executor_skips_no_op_diff() {
        let same = pkgs(&[("bash", "5.1")]);
        let op = InverseOp::PackageRollback {
            manager: PackageManager::Apt,
            original_op: PackageOpKind::Install,
            packages_before: same.clone(),
            packages_after: same,
            repo_state_hint: None,
        };
        let runner = SpyRunner::default();
        let exec = PackageExecutor::new(runner);
        let outcome = exec.execute(&op, false, ConflictPolicy::Abort);
        assert!(matches!(outcome, ExecutionOutcome::Skipped { .. }));
    }
}
