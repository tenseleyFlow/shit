// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network-tier executor (S17.10).
//!
//! Handles [`InverseOp::NetworkRollback`]. Two execution paths,
//! switched by [`shit_planner::restore_method`]:
//!
//! - **FullReload**: write `before_state` to a tempfile, then run
//!   the tool's native restore (`iptables-restore < f`,
//!   `nft -f f`, `pfctl -f f`). Atomic for the tools that support
//!   it.
//! - **DiffApply**: replay `inverse_invocations` (each a `Vec<String>`
//!   argv) sequentially.
//!
//! ufw's hybrid `DiffApplyWithReset` currently falls through to
//! `DiffApply` — the "reset + reapply" fallback path lives in the
//! planner's inverse-synthesis layer (which decides when to emit
//! `inverse_invocations = [ufw reset, ...replay]` vs.
//! `[ufw delete <rule>, ...]`).

use std::io::Write;
use std::process::Command;

use crate::events::NetworkTool;
use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::inverse::InverseOp;
use crate::network::{RestoreMethod, restore_method};

/// Abstraction over subprocess invocation. Tests inject a spy.
pub trait NetRunner {
    /// Run one command with optional bytes piped to stdin (for the
    /// `tool-restore < file` flow we either write to a tempfile or
    /// pipe directly — depending on which is more reliable across
    /// platforms; current impl uses a tempfile path).
    fn run(&self, argv: &[String]) -> Result<(), String>;
    /// Write bytes to a freshly-created tempfile and return its
    /// path. The executor uses this when restoring tool dumps so
    /// the underlying tool can `read(2)` from a real fd.
    fn stash_bytes(&self, bytes: &[u8]) -> Result<std::path::PathBuf, String>;
}

pub struct SystemNetRunner;

impl NetRunner for SystemNetRunner {
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
    fn stash_bytes(&self, bytes: &[u8]) -> Result<std::path::PathBuf, String> {
        // Use the std lib's temp-file primitive directly; we don't
        // want to pull `tempfile` into the planner crate just for
        // this. The path is created uniquely-named and we return
        // it; the executor unlinks it after use is the caller's
        // job (currently we leave the file behind on success — pf
        // bench keeps copies around, harmless).
        let mut path = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("shit-net-{pid}-{nanos}.dump"));
        let mut f = std::fs::File::create(&path).map_err(|e| format!("create tmp: {e}"))?;
        f.write_all(bytes).map_err(|e| format!("write tmp: {e}"))?;
        Ok(path)
    }
}

pub struct NetworkExecutor<R: NetRunner> {
    runner: R,
}

impl<R: NetRunner> NetworkExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
    pub fn runner(&self) -> &R {
        &self.runner
    }
}

impl NetworkExecutor<SystemNetRunner> {
    pub fn system() -> Self {
        Self::new(SystemNetRunner)
    }
}

impl<R: NetRunner> InverseOpExecutor for NetworkExecutor<R> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::NetworkRollback { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::NetworkRollback {
            tool,
            before_state,
            inverse_invocations,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "network executor reached non-network op".into(),
            };
        };
        match restore_method(*tool) {
            RestoreMethod::FullReload => self.full_reload(*tool, before_state, dry_run),
            RestoreMethod::DiffApply | RestoreMethod::DiffApplyWithReset => {
                self.diff_apply(inverse_invocations, dry_run)
            }
        }
    }
}

impl<R: NetRunner> NetworkExecutor<R> {
    fn full_reload(
        &self,
        tool: NetworkTool,
        before_state: &[u8],
        dry_run: bool,
    ) -> ExecutionOutcome {
        if before_state.is_empty() {
            return ExecutionOutcome::Skipped {
                reason: "no captured before_state to restore from".into(),
            };
        }
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        let tmp = match self.runner.stash_bytes(before_state) {
            Ok(p) => p,
            Err(e) => return ExecutionOutcome::Failed { err: e },
        };
        let argv = full_reload_argv(tool, &tmp);
        match self.runner.run(&argv) {
            Ok(()) => ExecutionOutcome::Applied,
            Err(e) => ExecutionOutcome::Failed { err: e },
        }
    }

    fn diff_apply(&self, inverse_invocations: &[Vec<String>], dry_run: bool) -> ExecutionOutcome {
        if inverse_invocations.is_empty() {
            return ExecutionOutcome::Skipped {
                reason: "no inverse invocations to replay".into(),
            };
        }
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        for argv in inverse_invocations {
            if let Err(e) = self.runner.run(argv) {
                return ExecutionOutcome::Failed {
                    err: format!("{}: {e}", argv.first().map(String::as_str).unwrap_or("?")),
                };
            }
        }
        ExecutionOutcome::Applied
    }
}

/// Argv synthesizer for the FullReload path. Pure; used by the
/// executor and exposed for tests + the renderer.
pub fn full_reload_argv(tool: NetworkTool, dump_path: &std::path::Path) -> Vec<String> {
    let p = dump_path.to_string_lossy().to_string();
    match tool {
        NetworkTool::Iptables => vec!["iptables-restore".into(), p],
        NetworkTool::Ip6tables => vec!["ip6tables-restore".into(), p],
        NetworkTool::Nft => {
            // The actual sequence is: `nft flush ruleset; nft -f
            // <dump>`. We can't put a semicolon in argv; for the
            // single-invocation flow the user is expected to embed
            // the flush in the dump itself (nft -f handles "flush
            // ruleset" as the first statement). Our captured
            // dumps do include the live state, so a `flush
            // ruleset` prefix in the executor's tempfile body is
            // synthesized at write-time by the dump preparer (see
            // `with_nft_flush_prefix`).
            vec!["nft".into(), "-f".into(), p]
        }
        // Absolute path: `doas pfctl ...` runs with a reduced PATH
        // that typically omits /sbin (same situation as S29.5's
        // /usr/sbin/pkg and S29.6's /usr/sbin/service). pfctl lives
        // at /sbin/pfctl on FreeBSD/macOS.
        NetworkTool::Pfctl => vec!["/sbin/pfctl".into(), "-f".into(), p],
        NetworkTool::Ufw
        | NetworkTool::IpRoute
        | NetworkTool::IpAddr
        | NetworkTool::IpLink
        | NetworkTool::Route
        | NetworkTool::Ifconfig
        | NetworkTool::Networksetup => {
            // DiffApply tools should not reach this synthesizer.
            // Return an obviously-bogus argv so a misroute
            // surfaces as a Failed rather than silent success.
            vec!["false".into(), "wrong-restore-path".into()]
        }
    }
}

/// Prepend `flush ruleset` to a captured nft dump so the
/// FullReload path runs atomically. Used by `prepare_dump`.
pub fn with_nft_flush_prefix(dump: &[u8]) -> Vec<u8> {
    const PREFIX: &[u8] = b"flush ruleset\n";
    if dump.starts_with(PREFIX) {
        return dump.to_vec();
    }
    let mut out = Vec::with_capacity(PREFIX.len() + dump.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(dump);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spy runner.
    #[derive(Default)]
    struct Spy {
        invocations: std::cell::RefCell<Vec<Vec<String>>>,
        stashed: std::cell::RefCell<Vec<Vec<u8>>>,
        fail_on: Option<usize>,
    }
    impl NetRunner for Spy {
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
        fn stash_bytes(&self, bytes: &[u8]) -> Result<std::path::PathBuf, String> {
            self.stashed.borrow_mut().push(bytes.to_vec());
            Ok(std::path::PathBuf::from("/tmp/fake-dump"))
        }
    }

    fn iptables_op(before: &[u8]) -> InverseOp {
        InverseOp::NetworkRollback {
            tool: NetworkTool::Iptables,
            before_state: before.to_vec(),
            inverse_invocations: vec![],
        }
    }

    fn ip_route_op(invs: Vec<Vec<String>>) -> InverseOp {
        InverseOp::NetworkRollback {
            tool: NetworkTool::IpRoute,
            before_state: vec![],
            inverse_invocations: invs,
        }
    }

    #[test]
    fn full_reload_argv_iptables() {
        let p = std::path::Path::new("/tmp/d.dump");
        let argv = full_reload_argv(NetworkTool::Iptables, p);
        assert_eq!(argv, vec!["iptables-restore", "/tmp/d.dump"]);
    }

    #[test]
    fn full_reload_argv_nft() {
        let argv = full_reload_argv(NetworkTool::Nft, std::path::Path::new("/tmp/x"));
        assert_eq!(argv[0], "nft");
        assert!(argv.contains(&"-f".to_string()));
    }

    #[test]
    fn nft_flush_prefix_idempotent() {
        let dump = b"table inet filter { }";
        let with = with_nft_flush_prefix(dump);
        assert!(with.starts_with(b"flush ruleset\n"));
        let twice = with_nft_flush_prefix(&with);
        assert_eq!(
            twice, with,
            "already-prefixed dump should not be re-prefixed"
        );
    }

    #[test]
    fn full_reload_executes_with_stashed_bytes() {
        let exec = NetworkExecutor::new(Spy::default());
        let outcome = exec.execute(&iptables_op(b"*filter\n"), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exec.runner().invocations.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0], "iptables-restore");
        assert_eq!(exec.runner().stashed.borrow()[0], b"*filter\n".to_vec());
    }

    #[test]
    fn full_reload_dry_run() {
        let exec = NetworkExecutor::new(Spy::default());
        let outcome = exec.execute(&iptables_op(b"*filter\n"), true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        assert!(exec.runner().invocations.borrow().is_empty());
    }

    #[test]
    fn full_reload_skips_empty_before_state() {
        let exec = NetworkExecutor::new(Spy::default());
        let outcome = exec.execute(&iptables_op(b""), false, ConflictPolicy::Abort);
        assert!(matches!(outcome, ExecutionOutcome::Skipped { .. }));
    }

    #[test]
    fn diff_apply_runs_each_invocation() {
        let invs = vec![
            vec![
                "ip".into(),
                "route".into(),
                "del".into(),
                "10.0.0.0/8".into(),
            ],
            vec![
                "ip".into(),
                "route".into(),
                "add".into(),
                "172.16.0.0/12".into(),
            ],
        ];
        let exec = NetworkExecutor::new(Spy::default());
        let outcome = exec.execute(&ip_route_op(invs), false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        let calls = exec.runner().invocations.borrow();
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn diff_apply_propagates_failure_and_stops() {
        let invs = vec![
            vec![
                "ip".into(),
                "route".into(),
                "del".into(),
                "10.0.0.0/8".into(),
            ],
            vec![
                "ip".into(),
                "route".into(),
                "add".into(),
                "172.16.0.0/12".into(),
            ],
        ];
        let exec = NetworkExecutor::new(Spy {
            fail_on: Some(0),
            ..Spy::default()
        });
        let outcome = exec.execute(&ip_route_op(invs), false, ConflictPolicy::Abort);
        assert!(matches!(outcome, ExecutionOutcome::Failed { .. }));
        // Stopped after the failed invocation — second never ran.
        let calls = exec.runner().invocations.borrow();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn diff_apply_skips_empty_invocations() {
        let exec = NetworkExecutor::new(Spy::default());
        let outcome = exec.execute(&ip_route_op(vec![]), false, ConflictPolicy::Abort);
        assert!(matches!(outcome, ExecutionOutcome::Skipped { .. }));
    }
}
