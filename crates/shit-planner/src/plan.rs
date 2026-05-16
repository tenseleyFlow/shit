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
//! - Conflict detection is path/inode-only — we don't yet correlate against a
//!   post-image (we don't capture one yet).
//! - Partial events are dropped with a warning; the rest of the plan still
//!   produces actionable output.

use crate::events::{CaptureEvent, CaptureEventKind, CommandRecord, TreeOp};
use crate::inode::InodeRef;
use crate::inverse::{Conflict, InverseOp, PlanNode, PlanWarning, UndoPlan};
use crate::probe::StateProbe;
use crate::store::PlannerStore;
use std::path::Path;

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

    for ev in live {
        emit_for_event(ev, probe, store, &mut nodes, &mut warnings);
    }

    UndoPlan {
        command,
        nodes,
        warnings,
    }
}

fn emit_for_event(
    ev: &CaptureEvent,
    probe: &dyn StateProbe,
    store: &dyn PlannerStore,
    nodes: &mut Vec<PlanNode>,
    warnings: &mut Vec<PlanWarning>,
) {
    match &ev.kind {
        CaptureEventKind::FilePreImage {
            inode,
            path,
            blob,
            meta,
        } => {
            let mut conflict = file_path_conflict(path, *inode, probe);
            if conflict.is_none() && store.blob_size_hint(*blob).is_none() {
                conflict = Some(Conflict::Missing {
                    detail: format!("blob {blob} no longer in store (GC'd or evicted)"),
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
        CaptureEventKind::TreeOp(op) => emit_for_tree_op(op, probe, nodes),
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
            ..
        } => {
            nodes.push(PlanNode {
                op: InverseOp::PackageRollback {
                    manager: *manager,
                    original_op: *op,
                    packages_before: packages_before.clone(),
                    packages_after: packages_after.clone(),
                },
                cohort: 0,
                conflict: None,
            });
        }
        CaptureEventKind::NetworkOp {
            tool,
            before_state,
            inverse_invocations,
            ..
        } => {
            nodes.push(PlanNode {
                op: InverseOp::NetworkRollback {
                    tool: *tool,
                    before_state: before_state.clone(),
                    inverse_invocations: inverse_invocations.clone(),
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
    }
}

fn emit_for_tree_op(op: &TreeOp, probe: &dyn StateProbe, nodes: &mut Vec<PlanNode>) {
    match op {
        TreeOp::Create { path, .. } => {
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
}
