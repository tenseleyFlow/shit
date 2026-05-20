// SPDX-License-Identifier: AGPL-3.0-or-later

//! `plan()` — derive an [`UndoPlan`] from a command's events.
//!
//! Pure function: input is captured events + a `StateProbe` over the current
//! filesystem + a `PlannerStore` (consulted only for blob presence). Output is
//! a topologically-ordered DAG of inverse ops.
//!
//! ## v1 semantics
//!
//! - One inverse op per relevant event field (no within-command coalescing yet).
//! - All ops land in cohort `0` (sequential execution). Cohort partitioning
//!   for parallelism is a v2 optimization.
//! - Events emitted in **reverse-chronological** order so tree-recreate ops
//!   come before content-restore ops naturally (file is created before bytes
//!   land in it).
//! - Conflict detection is path/inode + post-image-hash. When the capture
//!   tier recorded `post_content_hash` and the current file content differs,
//!   we emit `Conflict::Hard` rather than silently overwrite the user's
//!   later edits.
//! - Partial events are dropped with a warning; the rest of the plan still
//!   produces actionable output.

use crate::events::{CaptureEvent, CaptureEventKind, CommandRecord, PackageManager, TreeOp};
use crate::inode::InodeRef;
use crate::inverse::{Conflict, InverseOp, NativeDelegation, PlanNode, PlanWarning, UndoPlan};
use crate::probe::StateProbe;
use crate::store::PlannerStore;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub fn plan(
    command: CommandRecord,
    events: &[CaptureEvent],
    probe: &dyn StateProbe,
    store: &dyn PlannerStore,
) -> UndoPlan {
    let mut nodes = Vec::new();
    let mut warnings = Vec::new();

    let partial_count = events.iter().filter(|e| e.partial).count();
    if partial_count > 0 {
        warnings.push(PlanWarning::PartialEvents {
            dropped: partial_count,
        });
    }

    if command.ended_at.is_none() {
        warnings.push(PlanWarning::UnclosedCommand);
    }

    let mut live: Vec<&CaptureEvent> = events.iter().filter(|e| !e.partial).collect();
    // Reverse-chronological: latest events first.
    live.sort_by_key(|e| std::cmp::Reverse((e.ts, e.id)));

    // W01.B.fix-rename-coalescing — recognize atomic-rename / replace
    // patterns (git commit, vim :wq, sed -i, etc.) where a single
    // logical "edit P" produces three events:
    //   - TreeOp::Create at P (the new inode appears via rename)
    //   - FilePreImage of P (the OLD inode's bytes, captured before unlink)
    //   - TreeOp::Unlink at P (the old inode disappears)
    //
    // Two semantic flavors of the signature:
    //   a) ATOMIC REPLACE — path EXISTS at undo time (rename completed,
    //      different inode lives there). User's mental model is "edit
    //      P"; inverse is "restore P from FilePreImage blob". Skip the
    //      Tree-op inverses; keep RestoreContent.
    //   b) TRANSIENT LOCK — path DOES NOT EXIST at undo time (e.g.
    //      git's `.git/index.lock` is created, written, renamed-away
    //      within one command; the captured FilePreImage is of an
    //      already-gone file). No user-meaningful change to undo.
    //      Skip all three inverses entirely.
    let (atomic_replace_paths, transient_paths) =
        classify_replace_paths(&live, probe);

    for ev in &live {
        // W01.B.fix-rename-coalescing: skip the entire event if the
        // path is transient (Create+PreImage+Unlink AND gone at undo).
        if let Some(p) = event_path(ev)
            && transient_paths.contains(p)
        {
            continue;
        }
        emit_for_event(
            ev,
            probe,
            store,
            &atomic_replace_paths,
            &mut nodes,
            &mut warnings,
        );
    }

    // DR-14: partition nodes into cohorts so the orchestrator's
    // `run_parallel` only runs commuting ops concurrently. Without
    // this pass every node would land in cohort 0 and the parallel
    // path would race conflicting ops on the same path/inode.
    crate::cohort::assign_cohorts(&mut nodes);

    UndoPlan {
        command,
        nodes,
        warnings,
    }
}

/// Scan events for paths with the Create+PreImage+Unlink signature
/// and bucket them into:
///   - `atomic_replace_paths` — path exists at undo time; the
///     `FilePreImage` inverse restores the original bytes over the
///     current inode; Tree-op inverses are suppressed.
///   - `transient_paths` — path does NOT exist at undo time; the
///     command created+wrote+unlinked it within one logical step
///     (e.g. a lock file). All inverses are suppressed.
fn classify_replace_paths(
    events: &[&CaptureEvent],
    probe: &dyn StateProbe,
) -> (HashSet<PathBuf>, HashSet<PathBuf>) {
    let mut creates: HashSet<PathBuf> = HashSet::new();
    let mut unlinks: HashSet<PathBuf> = HashSet::new();
    let mut pre_images: HashSet<PathBuf> = HashSet::new();
    for ev in events {
        match &ev.kind {
            CaptureEventKind::FilePreImage { path, .. } => {
                pre_images.insert(path.clone());
            }
            CaptureEventKind::TreeOp(TreeOp::Create { path, .. }) => {
                creates.insert(path.clone());
            }
            CaptureEventKind::TreeOp(TreeOp::Unlink { path, .. }) => {
                unlinks.insert(path.clone());
            }
            _ => {}
        }
    }
    let mut atomic = HashSet::new();
    let mut transient = HashSet::new();
    for p in creates {
        if !unlinks.contains(&p) {
            continue;
        }
        // Two transient shapes, one atomic shape:
        //   - Create + Unlink, NO pre-image → pure scratch (e.g.
        //     .git/index.lock that never had prior content). Inverse
        //     is a no-op.
        //   - Create + Unlink + pre-image, path GONE at undo → file
        //     existed, was renamed away, never restored. Same no-op.
        //   - Create + Unlink + pre-image, path EXISTS at undo →
        //     atomic-replace: restore bytes over the current inode,
        //     suppress Tree-op inverses (which would rmdir/recreate
        //     and conflict with the new inode).
        if !pre_images.contains(&p) {
            transient.insert(p);
            continue;
        }
        if probe.stat(&p).is_some() {
            atomic.insert(p);
        } else {
            transient.insert(p);
        }
    }
    (atomic, transient)
}

/// Path the event targets (for the event-level skip in the transient
/// case). Returns `None` for events with no single path (env diffs,
/// tier ops). The caller's only use is "is this path in the transient
/// set?" — non-path events fall through naturally.
fn event_path(ev: &CaptureEvent) -> Option<&PathBuf> {
    match &ev.kind {
        CaptureEventKind::FilePreImage { path, .. } => Some(path),
        CaptureEventKind::TreeOp(TreeOp::Create { path, .. })
        | CaptureEventKind::TreeOp(TreeOp::Unlink { path, .. })
        | CaptureEventKind::TreeOp(TreeOp::Symlink { path, .. }) => Some(path),
        _ => None,
    }
}

fn emit_for_event(
    ev: &CaptureEvent,
    probe: &dyn StateProbe,
    store: &dyn PlannerStore,
    atomic_replace_paths: &HashSet<PathBuf>,
    nodes: &mut Vec<PlanNode>,
    warnings: &mut Vec<PlanWarning>,
) {
    match &ev.kind {
        CaptureEventKind::FilePreImage {
            inode,
            path,
            blob,
            meta,
            post_content_hash,
        } => {
            // W01.B.fix-rename-coalescing: skip the inode-match check
            // for atomic-replace paths. The captured inode IS supposed
            // to differ from what's on disk now — that's the signature.
            // We still check existence (Missing branch) below by
            // re-probing.
            let mut conflict = if atomic_replace_paths.contains(path) {
                if probe.stat(path).is_none() {
                    Some(Conflict::Missing {
                        detail: format!("{} no longer exists", path.display()),
                    })
                } else {
                    None
                }
            } else {
                file_path_conflict(path, *inode, probe)
            };
            if conflict.is_none() && store.blob_size_hint(*blob).is_none() {
                conflict = Some(Conflict::Missing {
                    detail: format!("blob {blob} no longer in store (GC'd or evicted)"),
                });
            }
            // Post-image check: if the capture tier recorded the post-mutation
            // content hash and the current content doesn't match, the user has
            // edited the file since our command — applying the restore would
            // clobber those edits. Surface as Hard so the user must opt in.
            if conflict.is_none()
                && let Some(expected_post) = post_content_hash
                && let Some(current) = probe.content_hash(path)
                && &current != expected_post
            {
                conflict = Some(Conflict::Hard {
                    detail: format!(
                        "{} has been modified since the original command; \
                         restore would overwrite the later edits",
                        path.display()
                    ),
                });
            }
            nodes.push(PlanNode {
                op: InverseOp::RestoreContent {
                    inode: *inode,
                    path: path.clone(),
                    blob: *blob,
                },
                cohort: 0,
                conflict: conflict.clone(),
            });
            nodes.push(PlanNode {
                op: InverseOp::RestoreMetadata {
                    inode: *inode,
                    path: path.clone(),
                    target: meta.clone(),
                },
                cohort: 0,
                conflict,
            });
        }
        CaptureEventKind::MetadataChange {
            inode,
            path,
            before,
            ..
        } => {
            let conflict = file_path_conflict(path, *inode, probe);
            nodes.push(PlanNode {
                op: InverseOp::RestoreMetadata {
                    inode: *inode,
                    path: path.clone(),
                    target: before.clone(),
                },
                cohort: 0,
                conflict,
            });
        }
        CaptureEventKind::TreeOp(op) => {
            emit_for_tree_op(op, probe, atomic_replace_paths, nodes)
        }
        CaptureEventKind::EnvDiff {
            added,
            removed,
            modified,
        } => {
            // Inverse: unset what was added, restore what was removed,
            // restore old value for modified.
            for name in added.keys() {
                nodes.push(PlanNode {
                    op: InverseOp::UnsetEnv { name: name.clone() },
                    cohort: 0,
                    conflict: None,
                });
            }
            for (name, old_value) in removed {
                nodes.push(PlanNode {
                    op: InverseOp::SetEnv {
                        name: name.clone(),
                        value: old_value.clone(),
                    },
                    cohort: 0,
                    conflict: None,
                });
            }
            for (name, (before, _after)) in modified {
                nodes.push(PlanNode {
                    op: InverseOp::SetEnv {
                        name: name.clone(),
                        value: before.clone(),
                    },
                    cohort: 0,
                    conflict: None,
                });
            }
        }
        CaptureEventKind::PackageOp {
            manager,
            op,
            packages_before,
            packages_after,
            repo_state_hint,
        } => {
            // C02.7: when the capture tier supplied a manager-native
            // transaction id (apt 3.2 `apt_tx_id`, dnf `dnf_history_id`),
            // emit a delegation hint so the executor runs the native
            // rollback verb instead of synthesizing per-package
            // install/remove. Falls through to `None` for managers and
            // versions that don't support native rollback.
            let delegation = native_delegation_for(*manager, repo_state_hint.as_deref());
            nodes.push(PlanNode {
                op: InverseOp::PackageRollback {
                    manager: *manager,
                    original_op: *op,
                    packages_before: packages_before.clone(),
                    packages_after: packages_after.clone(),
                    repo_state_hint: repo_state_hint.clone(),
                    delegation,
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::NetworkOp {
            tool,
            before_state,
            after_state,
            inverse_invocations,
        } => {
            // DR-46: for DiffApply tools the capture path leaves
            // inverse_invocations empty; synthesise them from the
            // pre/after JSON dumps here. FullReload tools (iptables,
            // nft, pfctl) reload before_state directly so we don't
            // synthesise. DR-47: ufw is DiffApplyWithReset — its
            // synthesiser decides between per-rule delete/add and a
            // single `ufw --force reset` + reapply based on a
            // threshold.
            let mut invs = inverse_invocations.clone();
            if invs.is_empty() {
                match crate::network::restore_method(*tool) {
                    crate::network::RestoreMethod::DiffApply => {
                        invs = crate::network_diff::synthesise_diff_apply_inverse(
                            *tool,
                            before_state,
                            after_state,
                        );
                    }
                    crate::network::RestoreMethod::DiffApplyWithReset => {
                        if matches!(*tool, crate::events::NetworkTool::Ufw) {
                            invs = crate::network_diff::synthesise_ufw_inverse(
                                before_state,
                                after_state,
                            );
                        }
                    }
                    _ => {}
                }
                if invs.is_empty() {
                    warnings.push(PlanWarning::Informational {
                        tier: crate::inverse::InverseTier::Network,
                        message: format!(
                            "no DiffApply inverse synthesised for {tool:?}; \
                             review captured before/after states for manual rollback"
                        ),
                    });
                }
            }
            nodes.push(PlanNode {
                op: InverseOp::NetworkRollback {
                    tool: *tool,
                    before_state: before_state.clone(),
                    inverse_invocations: invs,
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::SystemdOp {
            scope,
            unit,
            before,
            after,
        } => {
            nodes.push(PlanNode {
                op: InverseOp::SystemdRollback {
                    scope: *scope,
                    unit: unit.clone(),
                    before: before.clone(),
                    after: after.clone(),
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::ProcessOp {
            argv,
            cwd,
            env_summary,
            ..
        } => {
            nodes.push(PlanNode {
                op: InverseOp::ProcessNote {
                    argv: argv.clone(),
                    cwd: cwd.clone(),
                    env_summary: env_summary.clone(),
                    message: "process lifecycle is informational — undo cannot resurrect"
                        .to_string(),
                },
                cohort: 0,
                conflict: None,
            });
            warnings.push(PlanWarning::Informational {
                tier: crate::inverse::InverseTier::Processes,
                message: "process events cannot be mechanically undone".to_string(),
            });
        }
        CaptureEventKind::DbOp {
            engine,
            target,
            statements,
            transaction_state,
        } => {
            // DR-58: every DbOp becomes an InverseOp::DbNote. For
            // sqlite3 the file tier captures the database file
            // separately, so the rollback hint just records the path;
            // the actual restore happens via the file tier's
            // RestoreContent op. For psql/mysql the hint is
            // informational only — the planner never executes SQL.
            let inverse_engine = match engine {
                crate::events::DbEngine::Postgres => crate::inverse::DbEngine::Postgres,
                crate::events::DbEngine::Mysql => crate::inverse::DbEngine::Mysql,
                crate::events::DbEngine::Sqlite3 => crate::inverse::DbEngine::Sqlite3,
            };
            let rollback_hint = match engine {
                crate::events::DbEngine::Postgres => crate::inverse::RollbackHint::Postgres {
                    pitr_recommended: matches!(
                        transaction_state,
                        crate::events::DbTxState::Committed
                    ),
                    wal_position: None,
                    statements_for_review: statements.clone(),
                },
                crate::events::DbEngine::Mysql => crate::inverse::RollbackHint::Mysql {
                    binlog_position: None,
                    statements_for_review: statements.clone(),
                },
                crate::events::DbEngine::Sqlite3 => crate::inverse::RollbackHint::Sqlite {
                    path: std::path::PathBuf::from(target),
                    file_blob: None,
                },
            };
            // If the engine explicitly observed a rollback, skip
            // emitting the hint — there's nothing to undo. We still
            // surface the tier in warnings so the renderer can say
            // "DB statements were observed but engine rolled back."
            if *transaction_state == crate::events::DbTxState::RolledBack {
                warnings.push(PlanWarning::Informational {
                    tier: crate::inverse::InverseTier::Database,
                    message: format!(
                        "{} statements observed against `{target}` but engine rolled back",
                        engine_label(*engine)
                    ),
                });
                return;
            }
            nodes.push(PlanNode {
                op: InverseOp::DbNote {
                    engine: inverse_engine,
                    target: target.clone(),
                    statements: statements.clone(),
                    rollback_hint,
                },
                cohort: 0,
                conflict: None,
            });
            warnings.push(PlanWarning::Informational {
                tier: crate::inverse::InverseTier::Database,
                message: format!(
                    "{} statements against `{target}` need manual rollback review",
                    engine_label(*engine)
                ),
            });
        }
    }
}

fn engine_label(e: crate::events::DbEngine) -> &'static str {
    match e {
        crate::events::DbEngine::Postgres => "psql",
        crate::events::DbEngine::Mysql => "mysql",
        crate::events::DbEngine::Sqlite3 => "sqlite3",
    }
}

/// C02.7: synthesize a `NativeDelegation` from the captured transaction
/// id when the manager exposes a native rollback verb. Returns `None`
/// to fall through to the per-package synthesis path in the package
/// executor (the historical behavior).
///
/// Native verbs covered:
/// - apt ≥3.2: `apt history-rollback <id>`. The inspector emits the id
///   under `extras["apt_tx_id"]` (gated on `apt --version` ≥ 3.2); the
///   daemon forwards it into `repo_state_hint`.
/// - dnf: `dnf history undo -y <id>`. Inspector key `dnf_history_id`
///   (DR-26, S14.6).
///
/// Brew / pacman / pkg do not have a native transaction-id-keyed
/// rollback, so they always synthesize.
///
/// The guard re-queries the manager's history to confirm the captured
/// transaction is still the most recent. If a subsequent install
/// happened in the interim, the rollback would also undo it
/// (transaction history is a stack), so we refuse rather than corrupt.
fn native_delegation_for(
    manager: PackageManager,
    repo_state_hint: Option<&str>,
) -> Option<NativeDelegation> {
    let id = repo_state_hint?;
    let id = id.trim();
    if id.is_empty() {
        return None;
    }
    match manager {
        PackageManager::Apt => Some(NativeDelegation {
            argv: vec![
                "apt".to_string(),
                "history-rollback".to_string(),
                id.to_string(),
            ],
            privileged: true,
            guard_command: Some(vec![
                "apt".to_string(),
                "history".to_string(),
                "list".to_string(),
            ]),
            // `apt history list` prints lines like `<id>: <date> ...`;
            // we look for the captured id as the most-recent entry.
            guard_match: Some(format!("{id}:")),
        }),
        PackageManager::Dnf => Some(NativeDelegation {
            argv: vec![
                "dnf".to_string(),
                "history".to_string(),
                "undo".to_string(),
                "-y".to_string(),
                id.to_string(),
            ],
            privileged: true,
            guard_command: Some(vec![
                "dnf".to_string(),
                "history".to_string(),
                "list".to_string(),
                "--reverse".to_string(),
            ]),
            // `dnf history list --reverse` prints the most-recent first;
            // the first column is the id. Confirm the captured id is
            // still the top entry by looking for `^ *<id> ` shape.
            guard_match: Some(format!("{id} ")),
        }),
        PackageManager::Dpkg
        | PackageManager::Pacman
        | PackageManager::Brew
        | PackageManager::Pkg => None,
    }
}

fn emit_for_tree_op(
    op: &TreeOp,
    probe: &dyn StateProbe,
    atomic_replace_paths: &HashSet<PathBuf>,
    nodes: &mut Vec<PlanNode>,
) {
    match op {
        TreeOp::Create { path, .. } => {
            // W01.B.fix-rename-coalescing: if this path was atomically
            // replaced (Create + PreImage + Unlink all observed for one
            // logical edit), the FilePreImage's RestoreContent handles
            // the full undo. Emitting an Unlink here would race with it.
            if atomic_replace_paths.contains(path) {
                return;
            }
            // The user's command created this path; inverse is unlink.
            // Phantom conflict if the path was *deleted* since capture
            // (an unlink of a non-existent path will succeed-or-noop).
            let conflict = match probe.stat(path) {
                None => Some(Conflict::Missing {
                    detail: format!("{} already gone; unlink will no-op", path.display()),
                }),
                Some(_) => None,
            };
            nodes.push(PlanNode {
                op: InverseOp::Unlink { path: path.clone() },
                cohort: 0,
                conflict,
            });
        }
        TreeOp::Unlink { path, .. } => {
            // W01.B.fix-rename-coalescing: ditto Create's note above —
            // atomic-replace paths get their inverse from FilePreImage.
            if atomic_replace_paths.contains(path) {
                return;
            }
            // The user's command deleted this path; we want to recreate it.
            // We don't know mode/kind from the unlink alone — those come from
            // a paired FilePreImage / FileMetadata. Recreate with conservative
            // defaults; the FilePreImage's RestoreMetadata will overwrite.
            let conflict = probe.stat(path).map(|_| Conflict::Phantom {
                detail: format!("{} exists now but didn't expect it to", path.display()),
            });
            nodes.push(PlanNode {
                op: InverseOp::RecreatePath {
                    path: path.clone(),
                    kind: crate::metadata::FileKind::Regular,
                    mode: 0o100644,
                },
                cohort: 0,
                conflict,
            });
        }
        TreeOp::Rename { from, to, .. } => {
            // Inverse of `from -> to` is `to -> from`.
            nodes.push(PlanNode {
                op: InverseOp::Rename {
                    from: to.clone(),
                    to: from.clone(),
                },
                cohort: 0,
                conflict: None,
            });
        }
        TreeOp::Link { target, .. } => {
            nodes.push(PlanNode {
                op: InverseOp::Unlink {
                    path: target.clone(),
                },
                cohort: 0,
                conflict: None,
            });
        }
        TreeOp::Symlink { path, .. } => {
            nodes.push(PlanNode {
                op: InverseOp::Unlink { path: path.clone() },
                cohort: 0,
                conflict: None,
            });
        }
    }
}

fn file_path_conflict(
    path: &Path,
    expected_inode: InodeRef,
    probe: &dyn StateProbe,
) -> Option<Conflict> {
    match probe.stat(path) {
        None => Some(Conflict::Missing {
            detail: format!("{} no longer exists", path.display()),
        }),
        Some(s) if s.inode != expected_inode => Some(Conflict::Phantom {
            detail: format!(
                "{} now points at inode {} (was {})",
                path.display(),
                s.inode,
                expected_inode
            ),
        }),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{CaptureEvent, CaptureEventKind, CommandId, EventId};
    use crate::inode::{BlobHash, InodeRef};
    use crate::metadata::FileMetadata;
    use crate::probe::ProbeStat;
    use crate::probe::mock::InMemoryProbe;
    use crate::store::mock::InMemoryStore;
    use crate::time::TimePoint;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn meta(size: u64) -> FileMetadata {
        FileMetadata {
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size,
            mtime_unix_nanos: 0,
            xattrs: BTreeMap::new(),
            acl: None,
        }
    }

    fn dummy_command() -> CommandRecord {
        CommandRecord {
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            cmd_string: Some("touch /tmp/x".to_string()),
            cwd: PathBuf::from("/tmp"),
            pid: 0,
            shell_kind: shit_proto::ShellKind::Bash,
            started_at: TimePoint::new(1, 0),
            ended_at: Some(TimePoint::new(2, 0)),
            exit_code: Some(0),
            event_ids: vec![EventId(1)],
        }
    }

    #[test]
    fn empty_events_yields_empty_plan() {
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let plan = plan(dummy_command(), &[], &probe, &store);
        assert!(plan.is_empty());
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn unclosed_command_warns() {
        let mut cmd = dummy_command();
        cmd.ended_at = None;
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let plan = plan(cmd, &[], &probe, &store);
        assert!(
            plan.warnings
                .iter()
                .any(|w| matches!(w, PlanWarning::UnclosedCommand))
        );
    }

    #[test]
    fn partial_events_are_dropped_with_warning() {
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: true,
            kind: CaptureEventKind::FilePreImage {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/tmp/x"),
                blob: BlobHash::from_bytes([1; 32]),
                meta: meta(0),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(p.is_empty());
        assert!(
            p.warnings
                .iter()
                .any(|w| matches!(w, PlanWarning::PartialEvents { dropped: 1 }))
        );
    }

    #[test]
    fn file_pre_image_emits_content_and_metadata() {
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 5);
        let blob = BlobHash::from_bytes([0xAB; 32]);
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(100),
            },
            None,
        );
        store.put_blob(blob, 50);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: path.clone(),
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert_eq!(p.nodes.len(), 2);
        assert!(matches!(p.nodes[0].op, InverseOp::RestoreContent { .. }));
        assert!(matches!(p.nodes[1].op, InverseOp::RestoreMetadata { .. }));
        assert!(p.nodes[0].conflict.is_none(), "{:?}", p.nodes[0].conflict);
        assert!(!p.has_blocking_conflicts());
        assert_eq!(p.content_restore_count(), 1);
    }

    #[test]
    fn missing_blob_yields_missing_conflict() {
        let mut probe = InMemoryProbe::new();
        let store = InMemoryStore::new(); // no blobs inserted
        let inode = InodeRef::new(1, 5);
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(100),
            },
            None,
        );
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path,
                blob: BlobHash::from_bytes([0xFF; 32]),
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(matches!(
            p.nodes[0].conflict,
            Some(Conflict::Missing { .. })
        ));
    }

    #[test]
    fn missing_path_yields_missing_conflict() {
        let probe = InMemoryProbe::new(); // path not inserted
        let mut store = InMemoryStore::new();
        let blob = BlobHash::from_bytes([0xCD; 32]);
        store.put_blob(blob, 10);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: InodeRef::new(1, 5),
                path: PathBuf::from("/tmp/gone"),
                blob,
                meta: meta(10),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(matches!(
            p.nodes[0].conflict,
            Some(Conflict::Missing { .. })
        ));
    }

    #[test]
    fn inode_changed_yields_phantom_conflict() {
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let captured_inode = InodeRef::new(1, 5);
        let current_inode = InodeRef::new(1, 999); // different
        let path = PathBuf::from("/tmp/x");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode: current_inode,
                meta: meta(100),
            },
            None,
        );
        let blob = BlobHash::from_bytes([0xAA; 32]);
        store.put_blob(blob, 10);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: captured_inode,
                path,
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(matches!(
            p.nodes[0].conflict,
            Some(Conflict::Phantom { .. })
        ));
        assert!(p.has_blocking_conflicts());
    }

    #[test]
    fn reverse_chronological_order_puts_unlink_before_preimage() {
        // Simulate `rm foo`: T1 = FilePreImage, T2 = TreeOp::Unlink.
        // Reverse order should put RecreatePath (from Unlink) before
        // RestoreContent (from FilePreImage).
        let probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 7);
        let blob = BlobHash::from_bytes([1; 32]);
        store.put_blob(blob, 10);
        let path = PathBuf::from("/tmp/foo");
        let pre = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: path.clone(),
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let unlink = CaptureEvent {
            id: EventId(2),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(2, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode,
                path: path.clone(),
            }),
        };
        let p = plan(dummy_command(), &[pre, unlink], &probe, &store);
        assert!(matches!(p.nodes[0].op, InverseOp::RecreatePath { .. }));
        assert!(matches!(p.nodes[1].op, InverseOp::RestoreContent { .. }));
        assert!(matches!(p.nodes[2].op, InverseOp::RestoreMetadata { .. }));
    }

    #[test]
    fn atomic_rename_coalesces_to_single_restore() {
        // W01.B.fix-rename-coalescing — the signature is:
        //   TreeOp::Create at P (new inode appears via rename)
        //   FilePreImage of P (OLD inode bytes, captured pre-unlink)
        //   TreeOp::Unlink at P (old inode disappears)
        // The user wrote "modify P"; the inverse is just RestoreContent(P).
        // We must NOT emit Unlink (from Create) or RecreatePath (from
        // Unlink) for that path — they'd race with RestoreContent and
        // trip the orchestrator's precondition_conflict.
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let old_inode = InodeRef::new(1, 100);
        let new_inode = InodeRef::new(1, 200);
        let path = PathBuf::from("/tmp/atomic-replace");
        // Current state on disk: the NEW inode lives at the path
        // (mirrors what's on disk after the user's atomic-rename).
        probe.insert(
            path.clone(),
            ProbeStat {
                inode: new_inode,
                meta: meta(60),
            },
            None,
        );
        let blob = BlobHash::from_bytes([0xCC; 32]);
        store.put_blob(blob, 42);

        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let create = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode: new_inode,
                path: path.clone(),
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let pre = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode: old_inode,
                path: path.clone(),
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let unlink = CaptureEvent {
            id: EventId(3),
            command: cmd,
            ts: TimePoint::new(12, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: old_inode,
                path: path.clone(),
            }),
        };
        let p = plan(dummy_command(), &[create, pre, unlink], &probe, &store);

        // Expect ONLY RestoreContent + RestoreMetadata (from FilePreImage).
        // NO Unlink (from Create) and NO RecreatePath (from Unlink).
        let has_restore_content = p.nodes.iter().any(|n| matches!(n.op, InverseOp::RestoreContent { .. }));
        let has_restore_metadata = p.nodes.iter().any(|n| matches!(n.op, InverseOp::RestoreMetadata { .. }));
        let has_unlink = p.nodes.iter().any(|n| matches!(&n.op, InverseOp::Unlink { path: p } if p == &PathBuf::from("/tmp/atomic-replace")));
        let has_recreate = p.nodes.iter().any(|n| matches!(&n.op, InverseOp::RecreatePath { path: p, .. } if p == &PathBuf::from("/tmp/atomic-replace")));

        assert!(has_restore_content, "RestoreContent inverse missing");
        assert!(has_restore_metadata, "RestoreMetadata inverse missing");
        assert!(!has_unlink, "atomic-replace path should NOT get a Unlink inverse");
        assert!(!has_recreate, "atomic-replace path should NOT get a RecreatePath inverse");
        assert!(!p.has_blocking_conflicts(), "plan should not have blocking conflicts");
    }

    #[test]
    fn transient_lock_pattern_suppresses_all_inverses() {
        // Signature: TreeOp::Create + FilePreImage + TreeOp::Unlink
        // for one path, AND the path is gone at undo time. Real-world
        // example: git's `.git/index.lock` — created, written,
        // renamed-away within one command. The user has no
        // meaningful state to undo here. We should produce ZERO
        // inverses for this path.
        let probe = InMemoryProbe::new(); // NOTE: path NOT inserted.
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 333);
        let path = PathBuf::from("/tmp/git/index.lock");
        let blob = BlobHash::from_bytes([0xDD; 32]);
        store.put_blob(blob, 0);

        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let create = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path: path.clone(),
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let pre = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path: path.clone(),
                blob,
                meta: meta(50),
                post_content_hash: None,
            },
        };
        let unlink = CaptureEvent {
            id: EventId(3),
            command: cmd,
            ts: TimePoint::new(12, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode,
                path: path.clone(),
            }),
        };
        let p = plan(dummy_command(), &[create, pre, unlink], &probe, &store);

        let nodes_for_path: Vec<_> = p
            .nodes
            .iter()
            .filter(|n| matches!(&n.op,
                InverseOp::RestoreContent { path: p, .. }
                | InverseOp::RestoreMetadata { path: p, .. }
                | InverseOp::Unlink { path: p }
                | InverseOp::RecreatePath { path: p, .. }
                if p == &PathBuf::from("/tmp/git/index.lock")
            ))
            .collect();
        assert!(
            nodes_for_path.is_empty(),
            "transient lock should produce zero inverses, got: {:?}",
            nodes_for_path.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
    }

    #[test]
    fn scratch_file_no_preimage_suppresses_inverses() {
        // A file created AND unlinked in the same command with NO
        // pre-image (it never existed before): the inverse is a no-op.
        // Real-world example: git creates `.git/index.lock` as a
        // brand-new file then renames it onto `.git/index`. The lock
        // path itself has no pre-existing content to restore — the
        // planner used to emit Unlink+RecreatePath, the latter
        // tripping ConflictMissing because we have no bytes for it.
        let probe = InMemoryProbe::new(); // path absent at undo
        let store = InMemoryStore::new();
        let inode = InodeRef::new(1, 999);
        let path = PathBuf::from("/tmp/git/index.lock");
        let cmd = CommandId {
            session: Uuid::nil(),
            seq: 1,
        };
        let create = CaptureEvent {
            id: EventId(1),
            command: cmd,
            ts: TimePoint::new(10, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path: path.clone(),
                kind: crate::metadata::FileKind::Regular,
                mode: 0o100644,
            }),
        };
        let unlink = CaptureEvent {
            id: EventId(2),
            command: cmd,
            ts: TimePoint::new(11, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode,
                path: path.clone(),
            }),
        };
        let p = plan(dummy_command(), &[create, unlink], &probe, &store);
        let nodes_for_path: Vec<_> = p
            .nodes
            .iter()
            .filter(|n| matches!(&n.op,
                InverseOp::Unlink { path: p } | InverseOp::RecreatePath { path: p, .. }
                if p == &PathBuf::from("/tmp/git/index.lock")
            ))
            .collect();
        assert!(
            nodes_for_path.is_empty(),
            "scratch file with no pre-image should produce zero inverses, got: {:?}",
            nodes_for_path.iter().map(|n| &n.op).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pure_create_still_gets_unlink_inverse() {
        // Coalescing should ONLY trigger when all three signatures
        // (Create + PreImage + Unlink) match. A pure TreeOp::Create
        // with no PreImage and no Unlink keeps its Unlink inverse.
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let inode = InodeRef::new(1, 42);
        let path = PathBuf::from("/tmp/newdir");
        let create = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::TreeOp(TreeOp::Create {
                inode,
                path: path.clone(),
                kind: crate::metadata::FileKind::Directory,
                mode: 0o040755,
            }),
        };
        let p = plan(dummy_command(), &[create], &probe, &store);
        assert!(matches!(p.nodes[0].op, InverseOp::Unlink { .. }));
    }

    #[test]
    fn env_diff_emits_inverses_with_old_values() {
        let probe = InMemoryProbe::new();
        let store = InMemoryStore::new();
        let mut added = BTreeMap::new();
        added.insert("NEW".to_string(), "v".to_string());
        let mut removed = BTreeMap::new();
        removed.insert("OLD".to_string(), "was-here".to_string());
        let mut modified = BTreeMap::new();
        modified.insert(
            "CHANGED".to_string(),
            ("pre".to_string(), "post".to_string()),
        );
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::EnvDiff {
                added,
                removed,
                modified,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert_eq!(p.nodes.len(), 3);

        let has = |needle: &InverseOp| p.nodes.iter().any(|n| &n.op == needle);
        assert!(has(&InverseOp::UnsetEnv {
            name: "NEW".to_string(),
        }));
        assert!(has(&InverseOp::SetEnv {
            name: "OLD".to_string(),
            value: "was-here".to_string(),
        }));
        assert!(has(&InverseOp::SetEnv {
            name: "CHANGED".to_string(),
            value: "pre".to_string(),
        }));
    }

    #[test]
    fn post_image_match_no_conflict() {
        // Captured post_hash matches current content → undo is safe; the
        // file is still in the post-mutation state.
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 5);
        let blob = BlobHash::from_bytes([0xAA; 32]); // pre-image content
        let post = BlobHash::from_bytes([0xBB; 32]); // post-mutation content
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(50),
            },
            Some(post), // current content matches expected post
        );
        store.put_blob(blob, 50);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path,
                blob,
                meta: meta(100),
                post_content_hash: Some(post),
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(p.nodes[0].conflict.is_none(), "{:?}", p.nodes[0].conflict);
    }

    #[test]
    fn post_image_mismatch_yields_hard_conflict() {
        // Captured post_hash differs from current content → user has edited
        // the file since the original command. Hard conflict.
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 5);
        let blob = BlobHash::from_bytes([0xAA; 32]);
        let expected_post = BlobHash::from_bytes([0xBB; 32]);
        let current = BlobHash::from_bytes([0xCC; 32]); // != expected_post
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(50),
            },
            Some(current),
        );
        store.put_blob(blob, 50);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path,
                blob,
                meta: meta(100),
                post_content_hash: Some(expected_post),
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(matches!(p.nodes[0].conflict, Some(Conflict::Hard { .. })));
        assert!(p.has_blocking_conflicts());
    }

    #[test]
    fn post_image_none_disables_check() {
        // Degraded tier: no post_content_hash recorded. Even if current
        // content is "wrong", we can't detect it; plan proceeds without
        // Hard conflict.
        let mut probe = InMemoryProbe::new();
        let mut store = InMemoryStore::new();
        let inode = InodeRef::new(1, 5);
        let blob = BlobHash::from_bytes([0xAA; 32]);
        let path = PathBuf::from("/tmp/foo");
        probe.insert(
            path.clone(),
            ProbeStat {
                inode,
                meta: meta(50),
            },
            Some(BlobHash::from_bytes([0xFF; 32])),
        );
        store.put_blob(blob, 50);
        let ev = CaptureEvent {
            id: EventId(1),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(1, 0),
            partial: false,
            kind: CaptureEventKind::FilePreImage {
                inode,
                path,
                blob,
                meta: meta(100),
                post_content_hash: None,
            },
        };
        let p = plan(dummy_command(), &[ev], &probe, &store);
        assert!(p.nodes[0].conflict.is_none());
    }

    // ----- C02.7: native_delegation_for -----

    #[test]
    fn delegation_for_apt_with_tx_id_emits_history_rollback() {
        let d = native_delegation_for(PackageManager::Apt, Some("42")).unwrap();
        assert_eq!(d.argv, vec!["apt", "history-rollback", "42"]);
        assert!(d.privileged);
        assert!(d.guard_command.is_some());
        assert_eq!(d.guard_match.as_deref(), Some("42:"));
    }

    #[test]
    fn delegation_for_dnf_with_history_id_emits_history_undo() {
        let d = native_delegation_for(PackageManager::Dnf, Some("7")).unwrap();
        assert_eq!(d.argv, vec!["dnf", "history", "undo", "-y", "7"]);
        assert!(d.privileged);
        assert_eq!(d.guard_match.as_deref(), Some("7 "));
    }

    #[test]
    fn delegation_for_managers_without_native_rollback_is_none() {
        for mgr in [
            PackageManager::Dpkg,
            PackageManager::Pacman,
            PackageManager::Brew,
            PackageManager::Pkg,
        ] {
            assert!(
                native_delegation_for(mgr, Some("99")).is_none(),
                "expected None for {mgr:?}"
            );
        }
    }

    #[test]
    fn delegation_for_missing_hint_is_none_even_for_supported_manager() {
        assert!(native_delegation_for(PackageManager::Apt, None).is_none());
        assert!(native_delegation_for(PackageManager::Dnf, None).is_none());
    }

    #[test]
    fn delegation_for_empty_or_whitespace_hint_is_none() {
        assert!(native_delegation_for(PackageManager::Apt, Some("")).is_none());
        assert!(native_delegation_for(PackageManager::Dnf, Some("   ")).is_none());
    }
}
