// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end planner scenarios (L3, D-16).
//!
//! Each test builds a pre-state in a tempdir, runs a shell-shaped
//! sequence through [`Sim`] (which performs the real filesystem
//! operation and journals the events the Linux shim + helper would
//! emit for it), plans against the live post-state, executes the plan
//! with the real [`FileExecutor`], and requires the tree to match the
//! pre-state exactly: same entries, kinds, permission bits and bytes.
//!
//! The five shapes are the data-loss cases review found in PR #198's
//! transient-path rules. Any future classifier rule must keep them
//! green.

use crate::events::{
    CaptureEvent, CaptureEventKind, CommandId, CommandRecord, EventId, FilePreImageSource, TreeOp,
};
use crate::executor::{ConflictPolicy, InMemoryBlobReader, OutcomeKind};
use crate::executors::file::FileExecutor;
use crate::inode::{BlobHash, InodeRef};
use crate::metadata::{FileKind, FileMetadata};
use crate::orchestrator::Orchestrator;
use crate::plan::plan;
use crate::probe_live::LiveStateProbe;
use crate::store::mock::InMemoryStore;
use crate::time::TimePoint;
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Source tag the shim's recursive dir-rename walk journals with.
const WALK_SOURCE: FilePreImageSource = FilePreImageSource::ShimRenameSubtree;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Dir { perm: u32 },
    File { perm: u32, bytes: Vec<u8> },
    Symlink { target: PathBuf },
}

/// Recorder for one command's worth of events.
struct Sim {
    root: tempfile::TempDir,
    events: Vec<CaptureEvent>,
    blobs: InMemoryBlobReader,
    store: InMemoryStore,
    next: u64,
    /// Wall clock the command started at; set by the first `snapshot`.
    started_wall_nanos: std::cell::Cell<u64>,
}

impl Sim {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().expect("tempdir"),
            events: Vec::new(),
            blobs: InMemoryBlobReader::new(),
            store: InMemoryStore::new(),
            next: 1,
            started_wall_nanos: std::cell::Cell::new(0),
        }
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.root.path().join(rel)
    }

    // --- pre-state setup (not journaled) ---

    fn seed_dir(&self, rel: &str, perm: u32) {
        let p = self.p(rel);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(perm)).unwrap();
    }

    fn seed_file(&self, rel: &str, bytes: &[u8], perm: u32) {
        let p = self.p(rel);
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(perm)).unwrap();
    }

    // --- journaled operations ---

    fn emit(&mut self, kind: CaptureEventKind) {
        let id = self.next;
        self.next += 1;
        self.events.push(CaptureEvent {
            id: EventId(id),
            command: command_id(),
            ts: TimePoint::new(id, 0),
            partial: false,
            kind,
        });
    }

    fn inode_of(path: &Path) -> InodeRef {
        let m = std::fs::symlink_metadata(path).unwrap();
        InodeRef::new(m.dev(), m.ino())
    }

    fn pre_image(&mut self, path: &Path, source: FilePreImageSource) {
        let m = std::fs::symlink_metadata(path).unwrap();
        let bytes = std::fs::read(path).unwrap();
        let blob = BlobHash::from_bytes(*blake3::hash(&bytes).as_bytes());
        self.store.put_blob(blob, bytes.len() as u64);
        self.blobs.insert(blob, bytes);
        let meta = FileMetadata {
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            size: m.size(),
            mtime_unix_nanos: (m.mtime() as i128) * 1_000_000_000 + m.mtime_nsec() as i128,
            xattrs: BTreeMap::new(),
            acl: None,
            flags: 0,
        };
        self.emit(CaptureEventKind::FilePreImage {
            inode: InodeRef::new(m.dev(), m.ino()),
            path: path.to_path_buf(),
            blob,
            meta,
            post_content_hash: None,
            source,
        });
    }

    /// `echo bytes > rel`: pre-image when the target exists, Create
    /// when it does not.
    fn write(&mut self, rel: &str, bytes: &[u8]) {
        let p = self.p(rel);
        if p.exists() {
            self.pre_image(&p, FilePreImageSource::Other);
            std::fs::write(&p, bytes).unwrap();
        } else {
            std::fs::write(&p, bytes).unwrap();
            let m = std::fs::metadata(&p).unwrap();
            self.emit(CaptureEventKind::TreeOp(TreeOp::Create {
                inode: InodeRef::new(m.dev(), m.ino()),
                path: p,
                kind: FileKind::Regular,
                mode: m.mode(),
            }));
        }
    }

    fn mkdir(&mut self, rel: &str) {
        let p = self.p(rel);
        std::fs::create_dir(&p).unwrap();
        let m = std::fs::metadata(&p).unwrap();
        self.emit(CaptureEventKind::TreeOp(TreeOp::Create {
            inode: InodeRef::new(m.dev(), m.ino()),
            path: p,
            kind: FileKind::Directory,
            mode: m.mode(),
        }));
    }

    /// `mv from to`. A directory `from` gets the shim's recursive
    /// walk (pre-images keyed at the original paths, journaled before
    /// the Rename). A clobbered regular `to` gets the helper's
    /// pre-image + Unlink. A directory `to` means "move into".
    fn mv(&mut self, from: &str, to: &str) {
        self.mv_walk_skipping(from, to, None);
    }

    /// `mv` where the shim's walk misses `skip` (its file or byte
    /// caps tripped).
    fn mv_walk_skipping(&mut self, from: &str, to: &str, skip: Option<&str>) {
        let from_p = self.p(from);
        let mut to_p = self.p(to);
        if to_p.is_dir() {
            to_p = to_p.join(from_p.file_name().unwrap());
        }
        if from_p.is_dir() {
            let mut files = Vec::new();
            walk_files(&from_p, &mut files);
            let skip = skip.map(|s| self.p(s));
            for f in files {
                if Some(&f) != skip.as_ref() {
                    self.pre_image(&f, WALK_SOURCE);
                }
            }
        }
        if to_p.is_file() {
            let m = std::fs::symlink_metadata(&to_p).unwrap();
            self.pre_image(&to_p, FilePreImageSource::Other);
            self.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(m.dev(), m.ino()),
                path: to_p.clone(),
                kind: FileKind::Regular,
                mode: m.mode(),
            }));
        }
        let inode = Self::inode_of(&from_p);
        std::fs::rename(&from_p, &to_p).unwrap();
        self.emit(CaptureEventKind::TreeOp(TreeOp::Rename {
            from: from_p,
            to: to_p,
            inode,
        }));
    }

    /// `rm -rf rel`: post-order, each file pre-imaged then unlinked,
    /// each directory unlinked with its kind and mode.
    fn rm_rf(&mut self, rel: &str) {
        let p = self.p(rel);
        self.rm_rf_path(&p);
    }

    /// `rm -rf rel` as Python's `shutil.rmtree` reaches the shim: the
    /// children go through `unlinkat` (journaled), the top directory
    /// through a plain `rmdir` the shim does not interpose.
    fn rmtree_top_unseen(&mut self, rel: &str) {
        let p = self.p(rel);
        let mut children: Vec<PathBuf> = std::fs::read_dir(&p)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        children.sort();
        for c in children {
            self.rm_rf_path(&c);
        }
        std::fs::remove_dir(&p).unwrap();
    }

    fn mkdir_unseen(&mut self, rel: &str) {
        std::fs::create_dir(self.p(rel)).unwrap();
    }

    /// A write no capture channel journals (the shim's out-of-watch
    /// create path did not fire).
    fn write_unseen(&mut self, rel: &str, bytes: &[u8]) {
        std::fs::write(self.p(rel), bytes).unwrap();
    }

    /// `rm rel` where no pre-image could be captured (unreadable file).
    fn rm_uncaptured(&mut self, rel: &str) {
        let p = self.p(rel);
        let m = std::fs::symlink_metadata(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        self.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
            inode: InodeRef::new(m.dev(), m.ino()),
            path: p,
            kind: FileKind::Regular,
            mode: m.mode(),
        }));
    }

    fn rm_rf_path(&mut self, p: &Path) {
        let m = std::fs::symlink_metadata(p).unwrap();
        if m.is_dir() {
            let mut children: Vec<PathBuf> = std::fs::read_dir(p)
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            children.sort();
            for c in children {
                self.rm_rf_path(&c);
            }
            std::fs::remove_dir(p).unwrap();
            self.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(m.dev(), m.ino()),
                path: p.to_path_buf(),
                kind: FileKind::Directory,
                mode: m.mode(),
            }));
        } else {
            self.pre_image(p, FilePreImageSource::Other);
            std::fs::remove_file(p).unwrap();
            self.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(m.dev(), m.ino()),
                path: p.to_path_buf(),
                kind: FileKind::Regular,
                mode: m.mode(),
            }));
        }
    }

    /// The first call marks the command's start. File mtimes come from
    /// the kernel's coarse clock, so sleep past a tick on both sides:
    /// seeded files are provably older than the start, and files the
    /// command writes are provably not.
    fn snapshot(&self) -> BTreeMap<PathBuf, Entry> {
        if self.started_wall_nanos.get() == 0 {
            std::thread::sleep(std::time::Duration::from_millis(25));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            self.started_wall_nanos.set(now.as_nanos() as u64);
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let mut out = BTreeMap::new();
        snapshot_into(self.root.path(), self.root.path(), &mut out);
        out
    }

    /// Plan against the live post-state and apply with the CLI's
    /// default policy (Abort, serial).
    fn undo(&self) -> Vec<String> {
        let probe = LiveStateProbe::new();
        let record = command_record(self.started_wall_nanos.get());
        let p = plan(record, &self.events, &probe, &self.store);
        let exec = FileExecutor::new(&self.blobs);
        let report = Orchestrator::new(&exec, &probe).run(&p, false, ConflictPolicy::Abort);
        report
            .records
            .iter()
            .map(|r| {
                let mark = match r.outcome_kind {
                    OutcomeKind::Applied => "ok",
                    _ => "!!",
                };
                format!("{mark} {:?} {:?} {:?}", r.outcome_kind, r.op, r.detail)
            })
            .collect()
    }
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for e in entries {
        let m = std::fs::symlink_metadata(&e).unwrap();
        if m.is_dir() {
            walk_files(&e, out);
        } else if m.is_file() {
            out.push(e);
        }
    }
}

fn snapshot_into(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let m = std::fs::symlink_metadata(&p).unwrap();
        let rel = p.strip_prefix(root).unwrap().to_path_buf();
        let perm = m.mode() & 0o7777;
        if m.file_type().is_symlink() {
            let target = std::fs::read_link(&p).unwrap();
            out.insert(rel, Entry::Symlink { target });
        } else if m.is_dir() {
            out.insert(rel, Entry::Dir { perm });
            snapshot_into(root, &p, out);
        } else {
            out.insert(
                rel,
                Entry::File {
                    perm,
                    bytes: std::fs::read(&p).unwrap(),
                },
            );
        }
    }
}

fn command_id() -> CommandId {
    CommandId {
        session: uuid::Uuid::nil(),
        seq: 1,
    }
}

fn command_record(started_wall_nanos: u64) -> CommandRecord {
    CommandRecord {
        command: command_id(),
        cmd_string: Some("scenario".to_string()),
        cwd: PathBuf::from("/"),
        pid: 0,
        shell_kind: shit_proto::ShellKind::Bash,
        started_at: TimePoint::new(0, started_wall_nanos),
        ended_at: Some(TimePoint::new(1_000_000, 0)),
        exit_code: Some(0),
        event_ids: Vec::new(),
    }
}

fn assert_restored(sim: &Sim, before: &BTreeMap<PathBuf, Entry>) {
    let log = sim.undo();
    let after = sim.snapshot();
    assert_eq!(
        &after,
        before,
        "tree after undo differs from pre-state\nexecution:\n  {}\nevents:\n  {}",
        log.join("\n  "),
        sim.events
            .iter()
            .map(|e| format!("{:?}", e.kind))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[test]
fn swap_via_tmp_restores_both_names() {
    // `mv a tmp; mv b a; mv tmp b`
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o644);
    sim.seed_file("b", b"bravo\n", 0o600);
    let before = sim.snapshot();
    sim.mv("a", "tmp");
    sim.mv("b", "a");
    sim.mv("tmp", "b");
    assert_restored(&sim, &before);
}

#[test]
fn write_under_renamed_away_dir_is_restored() {
    // `mv d d.bak; mkdir d; echo x > d.bak/f`
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o750);
    sim.seed_file("d/f", b"original\n", 0o640);
    let before = sim.snapshot();
    sim.mv("d", "d.bak");
    sim.mkdir("d");
    sim.write("d.bak/f", b"x\n");
    assert_restored(&sim, &before);
}

#[test]
fn nested_rm_rf_restores_modes_and_empty_dirs() {
    // `rm -rf top` with top/mid/file and top/mid/empty
    let mut sim = Sim::new();
    sim.seed_dir("top", 0o750);
    sim.seed_dir("top/mid", 0o700);
    sim.seed_dir("top/mid/empty", 0o711);
    sim.seed_file("top/mid/file", b"payload\n", 0o600);
    let before = sim.snapshot();
    sim.rm_rf("top");
    assert_restored(&sim, &before);
}

#[test]
fn move_into_dir_then_rm_rf_dir_restores_file() {
    // `mv important.txt build/; rm -rf build`
    let mut sim = Sim::new();
    sim.seed_file("important.txt", b"keep me\n", 0o644);
    sim.seed_dir("build", 0o755);
    sim.seed_file("build/out.o", b"\x7fELF", 0o644);
    let before = sim.snapshot();
    sim.mv("important.txt", "build/");
    sim.rm_rf("build");
    assert_restored(&sim, &before);
}

#[test]
fn intermediate_write_under_replaced_dir_does_not_survive_undo() {
    // `mv d tmp; mkdir d; echo a > d/f; echo b > d/f`
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/g", b"g\n", 0o644);
    let before = sim.snapshot();
    sim.mv("d", "tmp");
    sim.mkdir("d");
    sim.write("d/f", b"a\n");
    sim.write("d/f", b"b\n");
    assert_restored(&sim, &before);
    assert!(!sim.p("d/f").exists(), "d/f must not exist after undo");
}

#[test]
fn rename_then_rm_with_parent_alive_restores_source_name() {
    // `mv a b; rm b`: the parent survives, so G01.3 used to take the
    // atomic-replace branch and restore `b` instead of `a`.
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    let before = sim.snapshot();
    sim.mv("a", "b");
    sim.rm_rf("b");
    assert_restored(&sim, &before);
}

fn seed_tree(sim: &Sim) {
    sim.seed_dir("d", 0o750);
    sim.seed_file("d/f", b"original\n", 0o640);
    sim.seed_dir("d/empty", 0o700);
    sim.seed_dir("d/sub", 0o711);
    sim.seed_file("d/sub/g", b"g\n", 0o600);
}

#[test]
fn dir_renamed_away_then_removed_is_rebuilt_in_place() {
    // `mv d d.old; rm -rf d.old`
    let mut sim = Sim::new();
    seed_tree(&sim);
    let before = sim.snapshot();
    sim.mv("d", "d.old");
    sim.rm_rf("d.old");
    assert_restored(&sim, &before);
}

#[test]
fn pip_shape_dir_replaced_and_stash_removed() {
    // pip --force-reinstall: `mv d d.old; mkdir d; echo new > d/f;
    // mkdir d/sub; echo new > d/sub/h; rm -rf d.old`
    let mut sim = Sim::new();
    seed_tree(&sim);
    let before = sim.snapshot();
    sim.mv("d", "d.old");
    sim.mkdir("d");
    sim.write("d/f", b"new\n");
    sim.mkdir("d/sub");
    sim.write("d/sub/h", b"new\n");
    sim.rm_rf("d.old");
    assert_restored(&sim, &before);
}

#[test]
fn pip_shape_with_partial_walk_keeps_reverse_rename() {
    // Same, but the walk missed d/sub/g: the subtree rule must not
    // fire, and the per-event inverses still restore everything.
    let mut sim = Sim::new();
    seed_tree(&sim);
    let before = sim.snapshot();
    sim.mv_walk_skipping("d", "d.old", Some("d/sub/g"));
    sim.mkdir("d");
    sim.write("d/f", b"new\n");
    sim.rm_rf("d.old");
    assert_restored(&sim, &before);
}

#[test]
fn pip_shape_as_the_hosted_shim_sees_it() {
    // The journal pip produces on hosted Linux (degraded helper, shim
    // only): no Create for the new tree, no unlink for the stash's top
    // directory. The reverse rename has nothing to move back and the
    // new `d` is in the way; the walk pre-images carry the restore.
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"original\n", 0o640);
    sim.seed_dir("d/empty", 0o700);
    sim.seed_dir("d/sub", 0o711);
    sim.seed_file("d/sub/g", b"g\n", 0o600);
    let before = sim.snapshot();
    sim.mv("d", "d.old");
    sim.mkdir_unseen("d");
    sim.write_unseen("d/f", b"new\n");
    sim.rmtree_top_unseen("d.old");
    assert_restored(&sim, &before);
}

// Review of #205. Each of these failed against the first version of the
// replaced-subtree and moved-data rules.

#[test]
#[ignore = "fails at 04258dd, review of #205: item 1, pre-rename generation dropped"]
fn rm_mv_rm_same_name_restores_both_generations() {
    // `rm -rf t; mv d t; rm -rf t`
    let mut sim = Sim::new();
    sim.seed_dir("t", 0o755);
    sim.seed_file("t/f", b"old t\n", 0o644);
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"old d\n", 0o644);
    let before = sim.snapshot();
    sim.rm_rf("t");
    sim.mv("d", "t");
    sim.rm_rf("t");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 2, moved-in entry taken for a walked copy"]
fn file_moved_over_walked_name_then_rm_rf_restores_its_source() {
    // `mv d t; mv e/f t/f; rm -rf t`
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"from d\n", 0o644);
    sim.seed_dir("e", 0o755);
    sim.seed_file("e/f", b"from e\n", 0o644);
    let before = sim.snapshot();
    sim.mv("d", "t");
    sim.mv("e/f", "t/f");
    sim.rm_rf("t");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 3, destination not gone"]
fn partial_delete_with_empty_dir_keeps_reverse_rename() {
    // `mv d t; rm t/f`, d also holds an empty dir
    let mut sim = Sim::new();
    sim.seed_dir("d/empty", 0o700);
    sim.seed_file("d/f", b"f\n", 0o644);
    let before = sim.snapshot();
    sim.mv("d", "t");
    sim.rm_rf("t/f");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 3, destination not gone"]
fn partial_delete_with_symlink_keeps_reverse_rename() {
    // `mv d t; rm t/f`, d also holds a symlink the walk skips
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"f\n", 0o644);
    std::os::unix::fs::symlink("f", sim.p("d/link")).unwrap();
    let before = sim.snapshot();
    sim.mv("d", "t");
    sim.rm_rf("t/f");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 3, destination not gone"]
fn partial_delete_with_uncaptured_file_keeps_reverse_rename() {
    // `mv d t; rm t/f`, the walk's caps missed d/big
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"f\n", 0o644);
    sim.seed_file("d/big", b"big\n", 0o644);
    let before = sim.snapshot();
    sim.mv_walk_skipping("d", "t", Some("d/big"));
    sim.rm_rf("t/f");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 4, duplicate Create overwrites moved provenance"]
fn bsd_event_order_mv_then_rm_restores_source_name() {
    // `mv a b; rm b` as kqueue reports it: Rename, Create(b), PreImage,
    // Unlink.
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    let before = sim.snapshot();
    sim.mv("a", "b");
    let b = sim.p("b");
    let m = std::fs::symlink_metadata(&b).unwrap();
    sim.emit(CaptureEventKind::TreeOp(TreeOp::Create {
        inode: InodeRef::new(m.dev(), m.ino()),
        path: b,
        kind: FileKind::Regular,
        mode: m.mode(),
    }));
    sim.rm_rf("b");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 5, moved-in empty dir rebuilt at the rename source"]
fn empty_dir_moved_into_renamed_dir_then_rm_rf_restores_its_source() {
    // `mv d t; mv o t/o; rm -rf t`
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"f\n", 0o644);
    sim.seed_dir("o", 0o700);
    let before = sim.snapshot();
    sim.mv("d", "t");
    sim.mv("o", "t/o");
    sim.rm_rf("t");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 6, recreated generation Create inverses dropped"]
fn recreated_generation_at_rename_destination_is_removed() {
    // `mv d t; rm -rf t; mkdir t; echo new > t/f`
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"old\n", 0o644);
    let before = sim.snapshot();
    sim.mv("d", "t");
    sim.rm_rf("t");
    sim.mkdir("t");
    sim.write("t/f", b"new\n");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 7, unjournaled source taken for pre-command data"]
fn unseen_scratch_file_moved_then_removed_leaves_no_stray() {
    // `echo x > tmp; mv tmp x; rm x`, the create not journaled
    let mut sim = Sim::new();
    sim.seed_file("keep", b"k\n", 0o644);
    let before = sim.snapshot();
    sim.write_unseen("tmp", b"x\n");
    sim.mv("tmp", "x");
    sim.rm_rf("x");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 7, read-only variant returns an empty file"]
fn moved_file_unlinked_without_pre_image_refuses() {
    // `mv a b; rm b`, b unreadable so no pre-image exists. The bytes
    // are gone: undo must say so, and must not put an empty `a` back.
    let mut sim = Sim::new();
    sim.seed_file("a", b"secret\n", 0o600);
    sim.seed_file("keep", b"k\n", 0o644);
    sim.snapshot();
    sim.mv("a", "b");
    sim.rm_uncaptured("b");
    let log = sim.undo();
    assert!(
        !sim.p("a").exists(),
        "empty file restored\n{}",
        log.join("\n")
    );
    assert!(!sim.p("b").exists(), "{}", log.join("\n"));
    assert!(
        log.iter().any(|l| l.contains("refused")),
        "no refusal\n{}",
        log.join("\n")
    );
}

#[test]
#[ignore = "fails at 04258dd, review of #205: item 8, source dir mode only taken from a journaled unlink"]
fn source_dir_mode_survives_unjournaled_top_rmdir() {
    // `mv d t; rm -rf t`, rmtree's top rmdir not interposed. A 0700 dir
    // must not come back wider.
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o700);
    sim.seed_file("d/f", b"f\n", 0o600);
    sim.seed_dir("d/empty", 0o711);
    let before = sim.snapshot();
    sim.mv("d", "t");
    sim.rmtree_top_unseen("t");
    assert_restored(&sim, &before);
}

#[test]
#[ignore = "fails at 04258dd, review of #205: walk pre-image dropped by a transient path in the new generation"]
fn walk_pre_image_survives_scratch_file_at_same_path() {
    // `mv d t; mkdir d; echo n > d/f; rm d/f; rm -rf t`
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o750);
    sim.seed_file("d/f", b"original\n", 0o640);
    let before = sim.snapshot();
    sim.mv("d", "t");
    sim.mkdir("d");
    sim.write("d/f", b"n\n");
    sim.rm_rf("d/f");
    sim.rm_rf("t");
    assert_restored(&sim, &before);
}

#[test]
fn file_moved_into_source_before_walk_restores_its_source() {
    // `mv a d/a; mv d t; rm -rf t`
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o644);
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"f\n", 0o644);
    let before = sim.snapshot();
    sim.mv("a", "d/a");
    sim.mv("d", "t");
    sim.rm_rf("t");
    assert_restored(&sim, &before);
}
