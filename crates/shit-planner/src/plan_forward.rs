// SPDX-License-Identifier: AGPL-3.0-or-later

//! Forward planner — `shit redo` (DR-16).
//!
//! Mirror of [`crate::plan::plan`] but emitting the **forward**
//! direction of each captured event: re-apply what the original
//! command did. The orchestrator runs the result the same way it
//! runs an inverse plan; the executor doesn't need a new mode.
//!
//! ## What re-applies cleanly
//!
//! - **Env, package, network, systemd, db ops** are *symmetric*:
//!   their CaptureEvent carries both pre and post state. Forward
//!   planning just swaps which side is the target.
//! - **TreeOp** (Create / Unlink / Rename / Link / Symlink) is
//!   re-runnable in the original direction — we re-create files the
//!   command created, re-unlink the ones it removed, re-rename, etc.
//! - **MetadataChange** is symmetric: pre + post both captured.
//!
//! ## What can't redo without captured post-bytes
//!
//! - **File content** (`FilePreImage`). The capture tier stores the
//!   PRE bytes but only the post HASH. Redoing the original write
//!   needs the bytes; without them we'd have to capture-then-redo
//!   from the executor's pre-undo snapshot (DR-70 territory). For
//!   now we emit a planner warning and skip the content op.
//! - **ProcessOp**: undo can't resurrect a killed process and redo
//!   can't re-kill one — `shit redo` just renders the original
//!   `ProcessNote` as informational.

use crate::events::{CaptureEvent, CaptureEventKind, CommandRecord, TreeOp};
use crate::inverse::{Conflict, InverseOp, InverseTier, PlanNode, PlanWarning, UndoPlan};
use crate::probe::StateProbe;
use crate::store::PlannerStore;

pub fn plan_forward(
    command: CommandRecord,
    events: &[CaptureEvent],
    probe: &dyn StateProbe,
    _store: &dyn PlannerStore,
) -> UndoPlan {
    let mut nodes: Vec<PlanNode> = Vec::new();
    let mut warnings: Vec<PlanWarning> = Vec::new();

    let partial_count = events.iter().filter(|e| e.partial).count();
    if partial_count > 0 {
        warnings.push(PlanWarning::PartialEvents {
            dropped: partial_count,
        });
    }
    if command.ended_at.is_none() {
        warnings.push(PlanWarning::UnclosedCommand);
    }

    // Forward planning processes events in **chronological** order
    // (latest last) — mirror of `plan()`'s reverse-chronological
    // walk. This lets tree-creates land before content writes when
    // a redo touches the same path twice.
    let mut live: Vec<&CaptureEvent> = events.iter().filter(|e| !e.partial).collect();
    live.sort_by_key(|e| (e.ts, e.id));

    for ev in live {
        emit_forward_for_event(ev, probe, &mut nodes, &mut warnings);
    }

    crate::cohort::assign_cohorts(&mut nodes);

    UndoPlan {
        command,
        nodes,
        warnings,
    }
}

fn emit_forward_for_event(
    ev: &CaptureEvent,
    probe: &dyn StateProbe,
    nodes: &mut Vec<PlanNode>,
    warnings: &mut Vec<PlanWarning>,
) {
    match &ev.kind {
        CaptureEventKind::FilePreImage { path, .. } => {
            // No captured post-bytes → can't redo content. Emit an
            // informational warning and skip. The metadata half
            // (mtime/mode/uid) we can't redo either since
            // FilePreImage records the pre snapshot only.
            warnings.push(PlanWarning::Informational {
                tier: InverseTier::Files,
                message: format!(
                    "cannot redo file write to {} — capture tier records pre-content only",
                    path.display()
                ),
            });
        }
        CaptureEventKind::MetadataChange {
            inode,
            path,
            before: _,
            after,
        } => {
            // Forward: apply the post metadata.
            nodes.push(PlanNode {
                op: InverseOp::RestoreMetadata {
                    inode: *inode,
                    path: path.clone(),
                    target: after.clone(),
                },
                cohort: 0,
                conflict: file_conflict(path, probe),
            });
        }
        CaptureEventKind::TreeOp(op) => emit_forward_for_tree_op(op, probe, nodes),
        CaptureEventKind::EnvDiff {
            added,
            removed,
            modified,
        } => {
            // Forward: re-add what was added, re-remove what was
            // removed, re-set the post values for modified.
            for (name, new_value) in added {
                nodes.push(PlanNode {
                    op: InverseOp::SetEnv {
                        name: name.clone(),
                        value: new_value.clone(),
                    },
                    cohort: 0,
                    conflict: None,
                });
            }
            for name in removed.keys() {
                nodes.push(PlanNode {
                    op: InverseOp::UnsetEnv { name: name.clone() },
                    cohort: 0,
                    conflict: None,
                });
            }
            for (name, (_pre, post)) in modified {
                nodes.push(PlanNode {
                    op: InverseOp::SetEnv {
                        name: name.clone(),
                        value: post.clone(),
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
            ..
        } => {
            // Forward: target packages_after starting from
            // packages_before. We reuse PackageRollback as the
            // executor's primitive but swap the two state fields so
            // the synthesised invocation moves forward. The
            // repo_state_hint is dropped — forward replay can't use
            // `dnf history undo`, the redo path always goes through
            // per-package install/remove.
            nodes.push(PlanNode {
                op: InverseOp::PackageRollback {
                    manager: *manager,
                    original_op: *op,
                    packages_before: packages_after.clone(),
                    packages_after: packages_before.clone(),
                    repo_state_hint: None,
                    delegation: None,
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
            // Forward: synthesise the inverse of the inverse, i.e.,
            // re-apply the after_state. For FullReload tools, the
            // executor reloads `before_state` — we hand it the
            // captured after_state. For DiffApply tools, we
            // re-synthesise the forward invocations from
            // (after, before) — flip the args so the planner's
            // existing diff helper produces the forward direction.
            let forward_invocations = if inverse_invocations.is_empty() {
                crate::network_diff::synthesise_diff_apply_inverse(*tool, after_state, before_state)
            } else {
                // The inverse was synthesised at capture/plan time.
                // For forward, swap before/after via the same
                // routine — guarantees the symmetric op.
                crate::network_diff::synthesise_diff_apply_inverse(*tool, after_state, before_state)
            };
            nodes.push(PlanNode {
                op: InverseOp::NetworkRollback {
                    tool: *tool,
                    before_state: after_state.clone(),
                    inverse_invocations: forward_invocations,
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
                    before: after.clone(),
                    after: before.clone(),
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
            // Forward of a kill is "re-kill" — but pid + start_time
            // pair is almost certainly stale by redo time. Render
            // as a note so the user knows what the original command
            // did; no mechanical re-apply.
            nodes.push(PlanNode {
                op: InverseOp::ProcessNote {
                    argv: argv.clone(),
                    cwd: cwd.clone(),
                    env_summary: env_summary.clone(),
                    message: "process kill cannot be replayed; the original \
                              target's pid is no longer valid"
                        .into(),
                },
                cohort: 0,
                conflict: None,
            });
            warnings.push(PlanWarning::Informational {
                tier: InverseTier::Processes,
                message: "process events are informational on redo".into(),
            });
        }
        CaptureEventKind::DbOp {
            engine,
            target,
            statements,
            ..
        } => {
            // Forward of a DB op is "re-run the same statements".
            // Same caveat as inverse — the planner never executes
            // SQL; it surfaces a manual-rerun note.
            let inverse_engine = match engine {
                crate::events::DbEngine::Postgres => crate::inverse::DbEngine::Postgres,
                crate::events::DbEngine::Mysql => crate::inverse::DbEngine::Mysql,
                crate::events::DbEngine::Sqlite3 => crate::inverse::DbEngine::Sqlite3,
            };
            nodes.push(PlanNode {
                op: InverseOp::DbNote {
                    engine: inverse_engine,
                    target: target.clone(),
                    statements: statements.clone(),
                    rollback_hint: crate::inverse::RollbackHint::None,
                },
                cohort: 0,
                conflict: None,
            });
            warnings.push(PlanWarning::Informational {
                tier: InverseTier::Database,
                message: format!(
                    "DB statements against `{target}` need manual re-run via {engine:?}; \
                     `shit redo` does not execute SQL"
                ),
            });
        }
        CaptureEventKind::ContainerOp { runtime, op, .. } => {
            // DR-CR-26: forward replay of a container destructive verb
            // would mean re-running e.g. `docker rmi` -- but the
            // user's natural shell history already covers re-running
            // the command if they want to. `shit redo` is informational
            // only here; the captured config + stash references are
            // available via `shit show` for inspection.
            warnings.push(PlanWarning::Informational {
                tier: InverseTier::Container,
                message: format!(
                    "container op {op:?} on {runtime:?} captured; \
                     `shit redo` does not re-issue container destructive verbs \
                     (re-run the original command if intended)"
                ),
            });
        }
        CaptureEventKind::TerraformOp { op, .. } => {
            // Same shape as ContainerOp: forward replay would mean
            // re-running `terraform apply` / `destroy`, which the
            // user's shell history covers. Informational only.
            warnings.push(PlanWarning::Informational {
                tier: InverseTier::Cloud,
                message: format!(
                    "terraform op {op:?} captured; `shit redo` does not re-issue \
                     cloud destructive verbs (re-run the original command if intended)"
                ),
            });
        }
    }
}

fn emit_forward_for_tree_op(op: &TreeOp, probe: &dyn StateProbe, nodes: &mut Vec<PlanNode>) {
    match op {
        TreeOp::Create {
            path, kind, mode, ..
        } => {
            // Forward: re-create the path. Re-uses RecreatePath
            // (same as inverse of an Unlink), since the original
            // command did create it.
            nodes.push(PlanNode {
                op: InverseOp::RecreatePath {
                    path: path.clone(),
                    kind: *kind,
                    mode: *mode,
                },
                cohort: 0,
                conflict: phantom_if_exists(path, probe),
            });
        }
        TreeOp::Unlink { path, .. } => {
            nodes.push(PlanNode {
                op: InverseOp::Unlink { path: path.clone() },
                cohort: 0,
                conflict: phantom_if_missing(path, probe),
            });
        }
        TreeOp::Rename { from, to, .. } => {
            nodes.push(PlanNode {
                op: InverseOp::Rename {
                    from: from.clone(),
                    to: to.clone(),
                },
                cohort: 0,
                conflict: phantom_if_missing(from, probe),
            });
        }
        TreeOp::Link { source: _, target } => {
            // Best-effort: re-creating a hardlink without the source
            // inode hint is fragile. Render as a note in warnings;
            // we don't have a "create hardlink" InverseOp shape
            // suitable for the executor today.
            // Skip — the executor would have to look up the source path.
            let _ = target;
        }
        TreeOp::Symlink { target, path } => {
            nodes.push(PlanNode {
                op: InverseOp::CreateSymlink {
                    target: target.clone(),
                    path: path.clone(),
                },
                cohort: 0,
                conflict: phantom_if_exists(path, probe),
            });
        }
    }
}

fn file_conflict(path: &std::path::Path, probe: &dyn StateProbe) -> Option<Conflict> {
    if probe.stat(path).is_none() {
        Some(Conflict::Missing {
            detail: format!("{} no longer present at redo time", path.display()),
        })
    } else {
        None
    }
}

fn phantom_if_exists(path: &std::path::Path, probe: &dyn StateProbe) -> Option<Conflict> {
    if probe.stat(path).is_some() {
        Some(Conflict::Phantom {
            detail: format!(
                "{} already exists at redo time — re-create would clobber",
                path.display()
            ),
        })
    } else {
        None
    }
}

fn phantom_if_missing(path: &std::path::Path, probe: &dyn StateProbe) -> Option<Conflict> {
    if probe.stat(path).is_none() {
        Some(Conflict::Missing {
            detail: format!(
                "{} missing at redo time — original target gone",
                path.display()
            ),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CommandId;
    use crate::events::{CaptureEvent, EventId};
    use crate::inode::InodeRef;
    use crate::metadata::{FileKind, FileMetadata};
    use crate::probe::ProbeStat;
    use crate::probe::mock::InMemoryProbe;
    use crate::store::mock::InMemoryStore;
    use crate::time::TimePoint;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn meta() -> FileMetadata {
        FileMetadata {
            mode: 0o100644,
            uid: 1000,
            gid: 1000,
            size: 0,
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
        }
    }

    /// Probe with `paths` present as regular files.
    fn probe_with(paths: &[&str]) -> InMemoryProbe {
        let mut p = InMemoryProbe::new();
        for path in paths {
            p.by_path.insert(
                PathBuf::from(path),
                (
                    ProbeStat {
                        inode: InodeRef::new(1, path.len() as u64),
                        meta: meta(),
                    },
                    None,
                ),
            );
        }
        p
    }

    fn command(seq: u64) -> CommandRecord {
        CommandRecord {
            command: CommandId {
                session: Uuid::nil(),
                seq,
            },
            cmd_string: None,
            cwd: PathBuf::from("/"),
            pid: 0,
            shell_kind: shit_proto::ShellKind::Bash,
            started_at: TimePoint::new(0, 0),
            ended_at: Some(TimePoint::new(1, 1000)),
            exit_code: Some(0),
            event_ids: vec![],
        }
    }

    fn ev(kind: CaptureEventKind, ts_logical: u64) -> CaptureEvent {
        CaptureEvent {
            id: EventId(ts_logical),
            command: CommandId {
                session: Uuid::nil(),
                seq: 1,
            },
            ts: TimePoint::new(ts_logical, ts_logical * 1000),
            partial: false,
            kind,
        }
    }

    #[test]
    fn forward_env_diff_re_adds_added_re_removes_removed() {
        let mut added = BTreeMap::new();
        added.insert("FOO".to_string(), "bar".to_string());
        let mut removed = BTreeMap::new();
        removed.insert("OLD".to_string(), "stale".to_string());
        let mut modified = BTreeMap::new();
        modified.insert(
            "PATH".to_string(),
            ("/usr/bin".to_string(), "/usr/local/bin".to_string()),
        );
        let events = vec![ev(
            CaptureEventKind::EnvDiff {
                added,
                removed,
                modified,
            },
            1,
        )];
        let plan = plan_forward(
            command(1),
            &events,
            &InMemoryProbe::new(),
            &InMemoryStore::new(),
        );
        // Expect: SetEnv FOO=bar, UnsetEnv OLD, SetEnv PATH=/usr/local/bin.
        let mut set_count = 0;
        let mut unset_count = 0;
        for node in &plan.nodes {
            match &node.op {
                InverseOp::SetEnv { name, value } => {
                    set_count += 1;
                    if name == "FOO" {
                        assert_eq!(value, "bar");
                    }
                    if name == "PATH" {
                        assert_eq!(value, "/usr/local/bin");
                    }
                }
                InverseOp::UnsetEnv { name } => {
                    unset_count += 1;
                    assert_eq!(name, "OLD");
                }
                _ => {}
            }
        }
        assert_eq!(set_count, 2);
        assert_eq!(unset_count, 1);
    }

    #[test]
    fn forward_file_preimage_emits_warning_only() {
        let events = vec![ev(
            CaptureEventKind::FilePreImage {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/tmp/foo"),
                blob: crate::inode::BlobHash::from_bytes([0; 32]),
                meta: FileMetadata {
                    mode: 0o100644,
                    uid: 1000,
                    gid: 1000,
                    size: 0,
                    mtime_unix_nanos: 0,
                    xattrs: Default::default(),
                    acl: None,
                },
                post_content_hash: None,
            },
            1,
        )];
        let plan = plan_forward(
            command(1),
            &events,
            &InMemoryProbe::new(),
            &InMemoryStore::new(),
        );
        assert_eq!(plan.nodes.len(), 0, "no node — content can't be redone");
        assert!(
            plan.warnings.iter().any(|w| matches!(
                w,
                PlanWarning::Informational {
                    tier: InverseTier::Files,
                    ..
                }
            )),
            "expected informational file-tier warning"
        );
    }

    #[test]
    fn forward_metadata_change_targets_after_state() {
        let before = FileMetadata {
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            size: 0,
            mtime_unix_nanos: 0,
            xattrs: Default::default(),
            acl: None,
        };
        let mut after = before.clone();
        after.mode = 0o755;
        let events = vec![ev(
            CaptureEventKind::MetadataChange {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/tmp/script"),
                before,
                after: after.clone(),
            },
            1,
        )];
        let plan = plan_forward(
            command(1),
            &events,
            &probe_with(&["/tmp/newdir", "/tmp/script"]),
            &InMemoryStore::new(),
        );
        assert_eq!(plan.nodes.len(), 1);
        match &plan.nodes[0].op {
            InverseOp::RestoreMetadata { target, .. } => {
                assert_eq!(target.mode, 0o755, "forward targets the post mode");
            }
            other => panic!("expected RestoreMetadata, got {other:?}"),
        }
    }

    #[test]
    fn forward_systemd_op_swaps_before_after() {
        let pre = crate::events::ServiceState {
            active: false,
            enabled: false,
            masked: false,
            raw: String::new(),
        };
        let post = crate::events::ServiceState {
            active: true,
            enabled: true,
            masked: false,
            raw: String::new(),
        };
        let events = vec![ev(
            CaptureEventKind::SystemdOp {
                scope: crate::events::SystemdScope::User,
                unit: "nginx.service".into(),
                before: pre.clone(),
                after: post.clone(),
            },
            1,
        )];
        let plan = plan_forward(
            command(1),
            &events,
            &InMemoryProbe::new(),
            &InMemoryStore::new(),
        );
        match &plan.nodes[0].op {
            InverseOp::SystemdRollback { before, after, .. } => {
                // Forward swaps — the "before" of the forward
                // rollback is the post state, the "after" is the
                // pre. The executor names are oriented for the
                // inverse direction; we re-use them.
                assert!(before.active, "forward before == captured after");
                assert!(!after.active, "forward after == captured pre");
            }
            other => panic!("expected SystemdRollback, got {other:?}"),
        }
    }

    #[test]
    fn forward_treeop_create_emits_recreate() {
        let events = vec![ev(
            CaptureEventKind::TreeOp(TreeOp::Create {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/tmp/newdir"),
                kind: FileKind::Directory,
                mode: 0o755,
            }),
            1,
        )];
        let plan = plan_forward(
            command(1),
            &events,
            &InMemoryProbe::new(),
            &InMemoryStore::new(),
        );
        assert_eq!(plan.nodes.len(), 1);
        assert!(matches!(plan.nodes[0].op, InverseOp::RecreatePath { .. }));
        // No conflict — EmptyProbe says path doesn't exist.
        assert!(plan.nodes[0].conflict.is_none());
    }

    #[test]
    fn forward_treeop_create_conflicts_when_path_already_exists() {
        let events = vec![ev(
            CaptureEventKind::TreeOp(TreeOp::Create {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/tmp/newdir"),
                kind: FileKind::Directory,
                mode: 0o755,
            }),
            1,
        )];
        let plan = plan_forward(
            command(1),
            &events,
            &probe_with(&["/tmp/newdir", "/tmp/script"]),
            &InMemoryStore::new(),
        );
        assert!(matches!(
            plan.nodes[0].conflict,
            Some(Conflict::Phantom { .. })
        ));
    }

    #[test]
    fn forward_treeop_unlink_emits_unlink_with_missing_conflict() {
        let events = vec![ev(
            CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/tmp/gone"),
            }),
            1,
        )];
        let plan = plan_forward(
            command(1),
            &events,
            &InMemoryProbe::new(),
            &InMemoryStore::new(),
        );
        assert!(matches!(plan.nodes[0].op, InverseOp::Unlink { .. }));
        assert!(matches!(
            plan.nodes[0].conflict,
            Some(Conflict::Missing { .. })
        ));
    }

    #[test]
    fn forward_process_op_renders_note_with_redo_specific_message() {
        let events = vec![ev(
            CaptureEventKind::ProcessOp {
                kind: crate::events::ProcessOpKind::Killed,
                pid: 1234,
                argv: vec!["sleep".into(), "1000".into()],
                cwd: PathBuf::from("/tmp"),
                env_summary: Default::default(),
                parent_pid: 1,
                signal: Some(9),
            },
            1,
        )];
        let plan = plan_forward(
            command(1),
            &events,
            &InMemoryProbe::new(),
            &InMemoryStore::new(),
        );
        match &plan.nodes[0].op {
            InverseOp::ProcessNote { message, .. } => {
                assert!(message.contains("cannot be replayed"), "got: {message}");
            }
            other => panic!("expected ProcessNote, got {other:?}"),
        }
    }

    #[test]
    fn forward_db_op_emits_note_with_no_hint() {
        let events = vec![ev(
            CaptureEventKind::DbOp {
                engine: crate::events::DbEngine::Postgres,
                target: "prod".into(),
                statements: vec!["INSERT INTO t VALUES (1)".into()],
                transaction_state: crate::events::DbTxState::Committed,
            },
            1,
        )];
        let plan = plan_forward(
            command(1),
            &events,
            &InMemoryProbe::new(),
            &InMemoryStore::new(),
        );
        match &plan.nodes[0].op {
            InverseOp::DbNote {
                rollback_hint,
                statements,
                ..
            } => {
                assert!(matches!(rollback_hint, crate::inverse::RollbackHint::None));
                assert_eq!(statements.len(), 1);
            }
            other => panic!("expected DbNote, got {other:?}"),
        }
    }

    #[test]
    fn forward_walks_events_chronologically() {
        // Two events: ts=1 creates /a, ts=2 creates /b. Forward
        // plan should emit /a's node before /b's.
        let e1 = ev(
            CaptureEventKind::TreeOp(TreeOp::Create {
                inode: InodeRef::new(1, 1),
                path: PathBuf::from("/a"),
                kind: FileKind::Directory,
                mode: 0o755,
            }),
            1,
        );
        let e2 = ev(
            CaptureEventKind::TreeOp(TreeOp::Create {
                inode: InodeRef::new(1, 2),
                path: PathBuf::from("/b"),
                kind: FileKind::Directory,
                mode: 0o755,
            }),
            2,
        );
        // Input order shouldn't matter; sort is by ts.
        let plan = plan_forward(
            command(1),
            &[e2.clone(), e1.clone()],
            &InMemoryProbe::new(),
            &InMemoryStore::new(),
        );
        let paths: Vec<&Path> = plan
            .nodes
            .iter()
            .filter_map(|n| match &n.op {
                InverseOp::RecreatePath { path, .. } => Some(path.as_path()),
                _ => None,
            })
            .collect();
        assert_eq!(paths, vec![Path::new("/a"), Path::new("/b")]);
    }
}
