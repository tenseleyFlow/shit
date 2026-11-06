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
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Source tag the shim's recursive dir-rename walk journals with.
const WALK_SOURCE: FilePreImageSource = FilePreImageSource::ShimRenameSubtree;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Dir { perm: u32 },
    File { perm: u32, bytes: Vec<u8> },
    Symlink { target: PathBuf },
    Fifo { perm: u32 },
}

/// Recorder for one command's worth of events.
struct Sim {
    root: tempfile::TempDir,
    events: Vec<CaptureEvent>,
    blobs: InMemoryBlobReader,
    store: InMemoryStore,
    next: u64,
    /// Paths under here report this device in journaled events, so a
    /// tempdir can stand in for a second filesystem.
    other_fs: Option<(PathBuf, u64)>,
}

impl Sim {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().expect("tempdir"),
            events: Vec::new(),
            blobs: InMemoryBlobReader::new(),
            store: InMemoryStore::new(),
            next: 1,
            other_fs: None,
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

    /// The device journaled events report for `path`.
    fn dev_of(&self, path: &Path, real: u64) -> u64 {
        match &self.other_fs {
            Some((root, dev)) if path.starts_with(root) => *dev,
            _ => real,
        }
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
        let dev = self.dev_of(path, m.dev());
        self.emit(CaptureEventKind::FilePreImage {
            inode: InodeRef::new(dev, m.ino()),
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

    /// `rm rel` with the shim and the kernel tier both active. Shim:
    /// pre-image (absent above its inline cap) and an Unlink with the
    /// (0, 0) sentinel. Helper: pre-image and an Unlink with the real
    /// inode. `journal_unlink_idempotent` does not merge the two
    /// because the inodes differ.
    fn rm_dual_tier(&mut self, rel: &str, shim_captures: bool, helper_first: bool) {
        let p = self.p(rel);
        let m = std::fs::symlink_metadata(&p).unwrap();
        let shim_unlink = TreeOp::Unlink {
            inode: InodeRef::new(0, 0),
            path: p.clone(),
            kind: FileKind::Regular,
            mode: 0o100644,
        };
        let helper_unlink = TreeOp::Unlink {
            inode: InodeRef::new(m.dev(), m.ino()),
            path: p.clone(),
            kind: FileKind::Regular,
            mode: m.mode(),
        };
        if helper_first {
            self.pre_image(&p, FilePreImageSource::Other);
            self.emit(CaptureEventKind::TreeOp(helper_unlink));
            if shim_captures {
                self.pre_image(&p, FilePreImageSource::Other);
            }
            self.emit(CaptureEventKind::TreeOp(shim_unlink));
        } else {
            if shim_captures {
                self.pre_image(&p, FilePreImageSource::Other);
            }
            self.emit(CaptureEventKind::TreeOp(shim_unlink));
            self.pre_image(&p, FilePreImageSource::Other);
            self.emit(CaptureEventKind::TreeOp(helper_unlink));
        }
        std::fs::remove_file(&p).unwrap();
    }

    /// `mv from to` across filesystems: the shim journals the Rename
    /// before the syscall, rename fails with EXDEV, and mv copies and
    /// unlinks the source. `journal_create` is whether the copy's
    /// create was seen.
    fn mv_exdev(&mut self, from: &str, to: &str, journal_create: bool) {
        let from_p = self.p(from);
        let to_p = self.p(to);
        // The daemon stats `to` for the Rename's inode: its real device.
        let dev = self.other_fs.as_ref().map_or(0, |(_, dev)| *dev);
        self.emit(CaptureEventKind::TreeOp(TreeOp::Rename {
            from: from_p.clone(),
            to: to_p.clone(),
            inode: InodeRef::new(dev, 1),
        }));
        std::fs::copy(&from_p, &to_p).unwrap();
        // mv preserves the source's mtime on the copy.
        std::fs::File::options()
            .write(true)
            .open(&to_p)
            .unwrap()
            .set_modified(std::fs::metadata(&from_p).unwrap().modified().unwrap())
            .unwrap();
        if journal_create {
            let m = std::fs::metadata(&to_p).unwrap();
            self.emit(CaptureEventKind::TreeOp(TreeOp::Create {
                inode: InodeRef::new(m.dev(), m.ino()),
                path: to_p,
                kind: FileKind::Regular,
                mode: m.mode(),
            }));
        }
        self.pre_image(&from_p, FilePreImageSource::Other);
        let m = std::fs::symlink_metadata(&from_p).unwrap();
        std::fs::remove_file(&from_p).unwrap();
        self.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
            inode: InodeRef::new(m.dev(), m.ino()),
            path: from_p,
            kind: FileKind::Regular,
            mode: m.mode(),
        }));
    }

    /// `mv from to` of a directory across filesystems: the walk and
    /// Rename are journaled, rename fails, and mv copies and removes.
    fn mv_exdev_dir(&mut self, from: &str, to: &str) {
        let from_p = self.p(from);
        let to_p = self.p(to);
        let mut files = Vec::new();
        walk_files(&from_p, &mut files);
        for f in &files {
            self.pre_image(f, WALK_SOURCE);
        }
        self.emit(CaptureEventKind::TreeOp(TreeOp::Rename {
            from: from_p.clone(),
            to: to_p.clone(),
            inode: InodeRef::new(0, 0),
        }));
        for f in &files {
            let dst = to_p.join(f.strip_prefix(&from_p).unwrap());
            std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
            std::fs::copy(f, dst).unwrap();
        }
        self.rm_rf_path(&from_p);
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
            let dev = self.dev_of(p, m.dev());
            self.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(dev, m.ino()),
                path: p.to_path_buf(),
                kind: FileKind::Directory,
                mode: m.mode(),
            }));
        } else {
            self.pre_image(p, FilePreImageSource::Other);
            std::fs::remove_file(p).unwrap();
            let dev = self.dev_of(p, m.dev());
            self.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
                inode: InodeRef::new(dev, m.ino()),
                path: p.to_path_buf(),
                kind: FileKind::Regular,
                mode: m.mode(),
            }));
        }
    }

    fn snapshot(&self) -> BTreeMap<PathBuf, Entry> {
        let mut out = BTreeMap::new();
        snapshot_into(self.root.path(), self.root.path(), &mut out);
        out
    }

    fn plan_nodes(&self) -> Vec<crate::inverse::PlanNode> {
        let probe = LiveStateProbe::new();
        plan(command_record(), &self.events, &probe, &self.store).nodes
    }

    fn undo_with_mknod(&self) -> Vec<String> {
        let probe = LiveStateProbe::new();
        let p = plan(command_record(), &self.events, &probe, &self.store);
        let exec = FileExecutor::with_privileged_router(&self.blobs, LocalMknod);
        Orchestrator::new(&exec, &probe)
            .run(&p, false, ConflictPolicy::Abort)
            .records
            .iter()
            .map(|r| match r.outcome_kind {
                OutcomeKind::Applied => format!("ok {:?}", r.op),
                _ => format!("!! {:?} {:?} {:?}", r.outcome_kind, r.op, r.detail),
            })
            .collect()
    }

    /// Plan against the live post-state and apply with the CLI's
    /// default policy (Abort, serial).
    fn undo(&self) -> Vec<String> {
        let probe = LiveStateProbe::new();
        let p = plan(command_record(), &self.events, &probe, &self.store);
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

/// The shim's walk: regular files, recursively.
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
        } else if m.file_type().is_fifo() {
            out.insert(rel, Entry::Fifo { perm });
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

fn command_record() -> CommandRecord {
    CommandRecord {
        command: command_id(),
        cmd_string: Some("scenario".to_string()),
        cwd: PathBuf::from("/"),
        pid: 0,
        shell_kind: shit_proto::ShellKind::Bash,
        started_at: TimePoint::new(0, 0),
        ended_at: Some(TimePoint::new(1_000_000, 0)),
        exit_code: Some(0),
        event_ids: Vec::new(),
    }
}

fn assert_restored(sim: &Sim, before: &BTreeMap<PathBuf, Entry>) {
    let log = sim.undo();
    assert_no_failures(&log);
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
fn pip_shape_as_the_hosted_shim_sees_it_conflicts_with_the_old_tree_intact() {
    // The journal pip produces on hosted Linux (degraded helper, shim
    // only): no Create for the new tree, no unlink for the stash's top
    // directory. The new `d` is in the way of the reverse rename, so undo
    // stops with a loud conflict: the smoke's Outcome B. The old tree is
    // back at the stash name. Sprint L5 tracks getting it back to `d`.
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"original\n", 0o640);
    sim.seed_dir("d/sub", 0o711);
    sim.seed_file("d/sub/g", b"g\n", 0o600);
    sim.snapshot();
    sim.mv("d", "d.old");
    sim.mkdir_unseen("d");
    sim.write_unseen("d/f", b"new\n");
    sim.rmtree_top_unseen("d.old");
    let log = sim.undo();
    assert!(
        log.iter()
            .any(|l| l.starts_with("!! ") && l.contains("Rename")),
        "{}",
        log.join("\n")
    );
    assert_eq!(
        std::fs::read(sim.p("d.old/f")).unwrap(),
        b"original\n",
        "{}",
        log.join("\n")
    );
    assert_eq!(
        std::fs::read(sim.p("d.old/sub/g")).unwrap(),
        b"g\n",
        "{}",
        log.join("\n")
    );
}

// Review of #205. All but the last failed against the first version of
// the replaced-subtree and moved-data rules.

#[test]
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
fn moved_file_with_captured_bytes_is_restored_even_if_it_was_scratch() {
    // `echo x > tmp; mv tmp x; rm x`, the create not journaled. Nothing
    // can tell this from `mv a b; rm b`, so the bytes go back. A stray
    // scratch file is acceptable and data loss is not.
    let mut sim = Sim::new();
    sim.seed_file("keep", b"k\n", 0o644);
    sim.snapshot();
    sim.write_unseen("tmp", b"x\n");
    sim.mv("tmp", "x");
    sim.rm_rf("x");
    let log = sim.undo();
    assert_no_failures(&log);
    assert!(
        !log.iter().any(|l| l.contains("refused")),
        "{}",
        log.join("\n")
    );
    assert_eq!(std::fs::read(sim.p("tmp")).unwrap(), b"x\n");
    assert!(!sim.p("x").exists(), "{}", log.join("\n"));
}

#[test]
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

#[test]
fn clobbering_rename_then_rm_restores_both_names() {
    // `mv a b; rm b` with b existing
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    sim.seed_file("b", b"bravo\n", 0o600);
    let before = sim.snapshot();
    sim.mv("a", "b");
    sim.rm_rf("b");
    assert_restored(&sim, &before);
}

#[test]
fn unseen_scratch_file_over_existing_then_rm_restores_the_existing_file() {
    // `echo x > tmp; mv tmp b; rm b` with b existing, the create not
    // journaled: b comes back, and tmp as a stray.
    let mut sim = Sim::new();
    sim.seed_file("b", b"bravo\n", 0o600);
    sim.snapshot();
    sim.write_unseen("tmp", b"x\n");
    sim.mv("tmp", "b");
    sim.rm_rf("b");
    let log = sim.undo();
    assert_no_failures(&log);
    assert_eq!(
        std::fs::read(sim.p("b")).unwrap(),
        b"bravo\n",
        "{}",
        log.join("\n")
    );
    assert_eq!(
        std::fs::read(sim.p("tmp")).unwrap(),
        b"x\n",
        "{}",
        log.join("\n")
    );
}

#[test]
fn replaced_dir_without_a_complete_walk_stays_a_conflict() {
    // `mv d t; mkdir d; rm -rf t` with a symlink in d, new d unseen: the
    // walk cannot prove the subtree, so the rule stays off and the
    // reverse rename reports the occupied source instead of guessing.
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"f\n", 0o644);
    std::os::unix::fs::symlink("f", sim.p("d/link")).unwrap();
    sim.snapshot();
    sim.mv("d", "t");
    sim.mkdir_unseen("d");
    sim.rm_uncaptured("t/link");
    sim.rmtree_top_unseen("t");
    let log = sim.undo();
    assert!(
        log.iter().any(|l| l.starts_with("!! ")),
        "expected a loud conflict\n{}",
        log.join("\n")
    );
}

#[test]
fn file_written_then_moved_then_removed_restores_the_original() {
    // `echo new > a; mv a b; rm b`: the write's pre-image is the
    // pre-command state; the moved bytes are not.
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    let before = sim.snapshot();
    sim.write("a", b"new\n");
    sim.mv("a", "b");
    sim.rm_rf("b");
    assert_restored(&sim, &before);
}

// Second review of #205.

fn assert_no_failures(log: &[String]) {
    assert!(
        !log.iter()
            .any(|l| l.starts_with("!! ") && !l.contains("refused")),
        "undo hit a conflict\n{}",
        log.join("\n")
    );
}

#[test]
fn dual_tier_mv_then_rm_restores_source_name() {
    // `mv a b; rm b` with shim and helper both reporting the unlink.
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    let before = sim.snapshot();
    sim.mv("a", "b");
    sim.rm_dual_tier("b", true, false);
    assert_restored(&sim, &before);
}

#[test]
fn dual_tier_helper_first_mv_then_rm_restores_source_name() {
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    let before = sim.snapshot();
    sim.mv("a", "b");
    sim.rm_dual_tier("b", true, true);
    assert_restored(&sim, &before);
}

#[test]
fn file_above_shim_cap_moved_then_removed_restores_source_name() {
    // `mv big big2; rm big2`: the shim has no bytes, the helper does,
    // and its pre-image lands after the shim's Unlink.
    let mut sim = Sim::new();
    sim.seed_file("big", b"pretend this is over the cap\n", 0o640);
    let before = sim.snapshot();
    sim.mv("big", "big2");
    sim.rm_dual_tier("big2", false, false);
    let log = sim.undo();
    assert_eq!(sim.snapshot(), before, "{}", log.join("\n"));
    assert!(
        !log.iter().any(|l| l.contains("refused")),
        "false refusal\n{}",
        log.join("\n")
    );
}

#[test]
fn cross_device_mv_then_rm_with_journaled_copy_restores_source() {
    // `mv f other/g; rm other/g`, with the copy's Create seen.
    let mut sim = Sim::new();
    sim.seed_dir("other", 0o755);
    sim.other_fs = Some((sim.p("other"), 4242));
    sim.seed_file("f", b"data\n", 0o640);
    let before = sim.snapshot();
    sim.mv_exdev("f", "other/g", true);
    sim.rm_rf("other/g");
    let log = sim.undo();
    assert_no_failures(&log);
    assert_eq!(sim.snapshot(), before, "{}", log.join("\n"));
}

#[test]
fn cross_device_mv_then_rm_with_unseen_copy_restores_source() {
    // Same with the create unseen: `g` may come back as a stray (its
    // pre-image is all that is known about it), `f` must come back and
    // the undo must not abort.
    let mut sim = Sim::new();
    sim.seed_dir("other", 0o755);
    sim.other_fs = Some((sim.p("other"), 4242));
    sim.seed_file("f", b"data\n", 0o640);
    sim.snapshot();
    sim.mv_exdev("f", "other/g", false);
    sim.rm_rf("other/g");
    let log = sim.undo();
    assert_no_failures(&log);
    assert_eq!(std::fs::read(sim.p("f")).unwrap(), b"data\n");
}

#[test]
fn cross_device_mv_with_copy_still_present_restores_source() {
    // `mv f other/g` alone: the copy is alive, and nothing moves it back.
    let mut sim = Sim::new();
    sim.seed_dir("other", 0o755);
    sim.other_fs = Some((sim.p("other"), 4242));
    sim.seed_file("f", b"data\n", 0o640);
    let before = sim.snapshot();
    sim.mv_exdev("f", "other/g", true);
    let log = sim.undo();
    assert_no_failures(&log);
    assert_eq!(sim.snapshot(), before, "{}", log.join("\n"));
}

#[test]
fn future_dated_file_moved_then_removed_is_restored() {
    // `mv a b; rm b` where a's mtime is ahead of the clock: the bytes
    // were captured, so refusing loses them.
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    let future = std::time::SystemTime::now() + std::time::Duration::from_secs(86_400);
    std::fs::File::options()
        .write(true)
        .open(sim.p("a"))
        .unwrap()
        .set_modified(future)
        .unwrap();
    let before = sim.snapshot();
    sim.mv("a", "b");
    sim.rm_rf("b");
    assert_restored(&sim, &before);
}

#[test]
fn scratch_symlink_moved_then_removed_leaves_nothing_and_no_refusal() {
    // `ln -s x tmp; mv tmp link; rm link`
    let mut sim = Sim::new();
    sim.seed_file("keep", b"k\n", 0o644);
    let before = sim.snapshot();
    std::os::unix::fs::symlink("x", sim.p("tmp")).unwrap();
    sim.emit(CaptureEventKind::TreeOp(TreeOp::Symlink {
        target: "x".to_string(),
        path: sim.p("tmp"),
    }));
    sim.mv("tmp", "link");
    sim.rm_uncaptured("link");
    let log = sim.undo();
    assert_no_failures(&log);
    assert!(
        !log.iter().any(|l| l.contains("refused")),
        "false refusal\n{}",
        log.join("\n")
    );
    assert_eq!(sim.snapshot(), before, "{}", log.join("\n"));
}

#[test]
fn scratch_hard_link_moved_then_removed_leaves_nothing_and_no_refusal() {
    // `ln a tmp; mv tmp link; rm link`, no pre-image at the unlink
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o644);
    let before = sim.snapshot();
    std::fs::hard_link(sim.p("a"), sim.p("tmp")).unwrap();
    let m = std::fs::symlink_metadata(sim.p("tmp")).unwrap();
    sim.emit(CaptureEventKind::TreeOp(TreeOp::Link {
        source: InodeRef::new(m.dev(), m.ino()),
        target: sim.p("tmp"),
    }));
    sim.mv("tmp", "link");
    sim.rm_uncaptured("link");
    let log = sim.undo();
    assert_no_failures(&log);
    assert!(
        !log.iter().any(|l| l.contains("refused")),
        "false refusal\n{}",
        log.join("\n")
    );
    assert_eq!(sim.snapshot(), before, "{}", log.join("\n"));
}

#[test]
fn cross_device_dir_mv_then_rm_restores_source() {
    // `mv d other/t; rm -rf other/t`, the copy's creates unseen: d comes
    // back, and the undo does not abort on the failed rename.
    let mut sim = Sim::new();
    sim.seed_dir("other", 0o755);
    sim.other_fs = Some((sim.p("other"), 4242));
    sim.seed_dir("d/sub", 0o750);
    sim.seed_file("d/f", b"f\n", 0o640);
    sim.seed_file("d/sub/g", b"g\n", 0o600);
    let before = sim.snapshot();
    sim.mv_exdev_dir("d", "other/t");
    sim.rm_rf("other/t");
    let log = sim.undo();
    assert_no_failures(&log);
    let after = sim.snapshot();
    for rel in ["d", "d/f", "d/sub", "d/sub/g"] {
        assert_eq!(
            after.get(Path::new(rel)),
            before.get(Path::new(rel)),
            "{rel}\n{}",
            log.join("\n")
        );
    }
}

#[test]
fn recreated_source_is_not_mistaken_for_a_failed_rename() {
    // `mv a b; echo new > a; rm a`, same device, the recreate unseen. The
    // later events at `a` are a new entry and the Rename stands. Undo
    // restores the new `a` first, so the reverse rename conflicts, loudly,
    // with the original bytes still at `b`. Dropping the Rename would
    // leave nothing saying where they went.
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    sim.snapshot();
    sim.mv("a", "b");
    sim.write_unseen("a", b"new\n");
    sim.rm_rf("a");
    let log = sim.undo();
    assert!(
        log.iter().any(|l| l.contains("Rename")),
        "Rename dropped\n{}",
        log.join("\n")
    );
    assert_eq!(
        std::fs::read(sim.p("b")).unwrap(),
        b"alpha\n",
        "{}",
        log.join("\n")
    );
}

#[test]
fn dual_tier_rename_and_unlink_restores_source_name() {
    // `mv a b; rm b` with both tiers reporting the Rename as well.
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    let before = sim.snapshot();
    sim.mv("a", "b");
    let dup = sim.events.last().unwrap().kind.clone();
    sim.emit(dup);
    sim.rm_dual_tier("b", true, false);
    let log = sim.undo();
    assert_no_failures(&log);
    assert_eq!(sim.snapshot(), before, "{}", log.join("\n"));
}

#[test]
fn dual_tier_rename_alone_restores_source_name() {
    // `mv a b` with both tiers reporting it.
    let mut sim = Sim::new();
    sim.seed_file("a", b"alpha\n", 0o640);
    let before = sim.snapshot();
    sim.mv("a", "b");
    let dup = sim.events.last().unwrap().kind.clone();
    sim.emit(dup);
    let log = sim.undo();
    assert_no_failures(&log);
    assert_eq!(sim.snapshot(), before, "{}", log.join("\n"));
}

// Round 4 review of #205: the dual-tier pip shapes, and the failed rename
// that took the replaced-subtree rule out of this PR.

/// An `rm -rf rel` both tiers report: shim Unlink with the (0, 0)
/// sentinel and helper Unlink with the real inode, per file.
fn rm_rf_dual_tier(sim: &mut Sim, p: &Path) {
    let m = std::fs::symlink_metadata(p).unwrap();
    let kind = if m.is_dir() {
        FileKind::Directory
    } else {
        FileKind::Regular
    };
    if m.is_dir() {
        let mut children: Vec<PathBuf> = std::fs::read_dir(p)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        children.sort();
        for c in children {
            rm_rf_dual_tier(sim, &c);
        }
    } else {
        sim.pre_image(p, FilePreImageSource::Other);
    }
    sim.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
        inode: InodeRef::new(0, 0),
        path: p.to_path_buf(),
        kind,
        mode: m.mode(),
    }));
    if !m.is_dir() {
        sim.pre_image(p, FilePreImageSource::Other);
    }
    sim.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
        inode: InodeRef::new(m.dev(), m.ino()),
        path: p.to_path_buf(),
        kind,
        mode: m.mode(),
    }));
    if m.is_dir() {
        std::fs::remove_dir(p).unwrap();
    } else {
        std::fs::remove_file(p).unwrap();
    }
}

fn seed_pip_tree(sim: &Sim) {
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"v1\n", 0o644);
    sim.seed_dir("d/sub", 0o750);
    sim.seed_file("d/sub/g", b"g1\n", 0o640);
}

#[test]
fn dual_tier_pip_shape_with_journaled_rmdir_restores_the_tree() {
    // pip with the helper's LSM tier and the shim both active: both
    // report the Rename and the unlinks, the helper reports the creates.
    let mut sim = Sim::new();
    seed_pip_tree(&sim);
    let before = sim.snapshot();
    sim.mv("d", "d.old");
    let dup = sim.events.last().unwrap().kind.clone();
    sim.emit(dup);
    sim.mkdir("d");
    sim.write("d/f", b"v2\n");
    let p = sim.p("d.old");
    rm_rf_dual_tier(&mut sim, &p);
    assert_restored(&sim, &before);
}

#[test]
fn dir_diff_pip_shape_restores_names_and_bytes() {
    // pip with BSD's dir-diff: Create events for the rename destination
    // and everything under it, alongside the shim's Rename.
    let mut sim = Sim::new();
    seed_pip_tree(&sim);
    let before = sim.snapshot();
    sim.mv("d", "d.old");
    for rel in ["d.old", "d.old/f", "d.old/sub", "d.old/sub/g"] {
        let p = sim.p(rel);
        let m = std::fs::symlink_metadata(&p).unwrap();
        let kind = if m.is_dir() {
            FileKind::Directory
        } else {
            FileKind::Regular
        };
        sim.emit(CaptureEventKind::TreeOp(TreeOp::Create {
            inode: InodeRef::new(m.dev(), m.ino()),
            path: p,
            kind,
            mode: m.mode(),
        }));
    }
    sim.mkdir("d");
    sim.write("d/f", b"v2\n");
    sim.rm_rf("d.old");
    let log = sim.undo();
    assert_no_failures(&log);
    let after = sim.snapshot();
    // Bytes and names come back. `d/sub`'s mode does not: its unlink is
    // classified transient alongside the dir-diff Create, on trunk too.
    assert_eq!(after.len(), before.len(), "{}", log.join("\n"));
    for rel in ["d/f", "d/sub/g"] {
        assert_eq!(
            after.get(Path::new(rel)),
            before.get(Path::new(rel)),
            "{}",
            log.join("\n")
        );
    }
}

#[test]
fn failed_enotempty_rename_then_rm_rf_restores_destination_bytes() {
    // `d/` and `t/` both hold a and b. os.rename('d', 't') fails with
    // ENOTEMPTY but the walk and Rename are journaled before the syscall.
    // Then `rm -rf t`. Both trees must keep their own bytes. The reverse
    // rename still conflicts at the end (`d` exists): nothing retracts a
    // failed same-device Rename, and sprint L5 needs inode proof for that.
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/a", b"d-a\n", 0o644);
    sim.seed_file("d/b", b"d-b\n", 0o644);
    sim.seed_dir("t", 0o755);
    sim.seed_file("t/a", b"t-a\n", 0o644);
    sim.seed_file("t/b", b"t-b\n", 0o644);
    let before = sim.snapshot();
    let from = sim.p("d");
    let mut files = Vec::new();
    walk_files(&from, &mut files);
    for f in &files {
        sim.pre_image(f, WALK_SOURCE);
    }
    let inode = Sim::inode_of(&from);
    sim.emit(CaptureEventKind::TreeOp(TreeOp::Rename {
        from,
        to: sim.p("t"),
        inode,
    }));
    sim.rm_rf("t");
    let log = sim.undo();
    let after = sim.snapshot();
    assert_eq!(after, before, "bytes lost\n{}", log.join("\n"));
}

fn moved_special_file_plan(kind: FileKind, mode: u32) -> Vec<crate::inverse::PlanNode> {
    // `mv a b; rm b` of a fifo or socket: no content to pre-image.
    let mut sim = Sim::new();
    let (a, b) = (sim.p("a"), sim.p("b"));
    sim.emit(CaptureEventKind::TreeOp(TreeOp::Rename {
        from: a,
        to: b.clone(),
        inode: InodeRef::new(1, 1),
    }));
    sim.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
        inode: InodeRef::new(1, 1),
        path: b,
        kind,
        mode,
    }));
    sim.plan_nodes()
}

fn assert_recreated_then_renamed(nodes: &[crate::inverse::PlanNode], want: FileKind) {
    use crate::inverse::InverseOp;
    assert!(
        matches!(&nodes[0].op, InverseOp::RecreatePath { kind, .. } if *kind == want),
        "{nodes:#?}"
    );
    assert!(
        matches!(&nodes[1].op, InverseOp::Rename { .. }),
        "{nodes:#?}"
    );
    assert_eq!(nodes.len(), 2, "{nodes:#?}");
}

#[test]
fn moved_fifo_with_no_pre_image_is_recreated_and_renamed_back() {
    let nodes = moved_special_file_plan(FileKind::Fifo, 0o010644);
    assert_recreated_then_renamed(&nodes, FileKind::Fifo);
}

#[test]
fn moved_socket_with_no_pre_image_is_recreated_and_renamed_back() {
    let nodes = moved_special_file_plan(FileKind::Socket, 0o140644);
    assert_recreated_then_renamed(&nodes, FileKind::Socket);
}

#[test]
fn dir_rename_over_a_deleted_entry_still_refuses_that_entry() {
    // `mv k t/x; rm t/x` (uncaptured), `mv m d/x; mv d t` with t empty by
    // then. The rename carries d/x onto t/x; k's history must still end
    // in a refusal, with no empty `k` put back.
    let mut sim = Sim::new();
    sim.seed_file("k", b"k\n", 0o644);
    sim.seed_file("m", b"m\n", 0o644);
    sim.seed_dir("t", 0o755);
    sim.seed_dir("d", 0o755);
    sim.snapshot();
    sim.mv("k", "t/x");
    sim.rm_uncaptured("t/x");
    sim.mv("m", "d/x");
    let (d, t) = (sim.p("d"), sim.p("t"));
    let inode = Sim::inode_of(&d);
    std::fs::rename(&d, &t).unwrap();
    sim.emit(CaptureEventKind::TreeOp(TreeOp::Rename {
        from: d,
        to: t,
        inode,
    }));
    let nodes = sim.plan_nodes();
    assert!(
        nodes
            .iter()
            .any(|n| matches!(n.op, crate::inverse::InverseOp::Refuse { .. })),
        "{nodes:#?}"
    );
    let k = sim.p("k");
    assert!(
        !nodes.iter().any(|n| matches!(
            &n.op,
            crate::inverse::InverseOp::Rename { to, .. } if *to == k
        )),
        "{nodes:#?}"
    );
}

#[test]
fn reverse_rename_into_unseen_removed_parent_is_private_and_reported() {
    // `mv d/f x; rmdir d`, the rmdir not interposed: d's mode is unknown.
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o700);
    sim.seed_file("d/f", b"f\n", 0o600);
    sim.snapshot();
    sim.mv("d/f", "x");
    std::fs::remove_dir(sim.p("d")).unwrap();
    let log = sim.undo();
    assert_no_failures(&log);
    assert_eq!(
        std::fs::read(sim.p("d/f")).unwrap(),
        b"f\n",
        "{}",
        log.join("\n")
    );
    let m = std::fs::metadata(sim.p("d")).unwrap();
    assert_eq!(m.mode() & 0o777, 0o700, "{}", log.join("\n"));
    assert!(
        log.iter().any(|l| l.contains("0700")),
        "not reported\n{}",
        log.join("\n")
    );
}

// Re-review of #205 at 6cf28b3.

#[test]
fn dual_tier_moved_empty_dir_then_rm_rf_restores_source() {
    // `mv p build/p; rm -rf build`, p an empty directory, both tiers
    // reporting every unlink.
    let mut sim = Sim::new();
    sim.seed_dir("p", 0o700);
    sim.seed_dir("build", 0o755);
    sim.seed_file("build/out.o", b"o\n", 0o644);
    let before = sim.snapshot();
    sim.mv("p", "build/p");
    let build = sim.p("build");
    rm_rf_dual_tier(&mut sim, &build);
    assert_restored(&sim, &before);
}

fn dual_tier_moved_fifo_plan() -> (Sim, Vec<String>) {
    // `mv p build/p; rm -rf build`, p a fifo, both tiers reporting its
    // unlink with its kind.
    let mut sim = Sim::new();
    sim.seed_dir("build", 0o755);
    let c = std::ffi::CString::new(sim.p("p").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o640) }, 0);
    sim.mv("p", "build/p");
    let fifo = sim.p("build/p");
    let m = std::fs::symlink_metadata(&fifo).unwrap();
    for inode in [InodeRef::new(0, 0), InodeRef::new(m.dev(), m.ino())] {
        sim.emit(CaptureEventKind::TreeOp(TreeOp::Unlink {
            inode,
            path: fifo.clone(),
            kind: FileKind::Fifo,
            mode: m.mode(),
        }));
    }
    std::fs::remove_file(&fifo).unwrap();
    let log = sim.undo_with_mknod();
    (sim, log)
}

/// The helper's mknod, done in-process: fifos need no privilege.
struct LocalMknod;

impl crate::executor::PrivilegedOpRouter for LocalMknod {
    fn chown(&self, _: &Path, _: u32, _: u32, _: bool) -> crate::executor::PrivilegedOpOutcome {
        crate::executor::PrivilegedOpOutcome::Applied
    }

    fn mknod(&self, path: &Path, mode: u32, _: u64) -> crate::executor::PrivilegedOpOutcome {
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), (mode & 0o777) as _) }, 0);
        crate::executor::PrivilegedOpOutcome::Applied
    }
}

#[test]
fn dual_tier_moved_fifo_is_recreated_once() {
    let (sim, log) = dual_tier_moved_fifo_plan();
    assert_no_failures(&log);
    assert!(
        std::fs::symlink_metadata(sim.p("p"))
            .unwrap()
            .file_type()
            .is_fifo(),
        "{}",
        log.join("\n")
    );
}

#[test]
fn file_moved_into_new_dir_then_rm_rf_comes_back_with_a_stray_dir() {
    // `mkdir d; mv existing/f d/; rm -rf d`. The file comes back; `d` is
    // scratch at the planner's level, but restoring and moving f out
    // recreates it, so an empty `d` stays behind. No data is lost.
    let mut sim = Sim::new();
    sim.seed_dir("existing", 0o755);
    sim.seed_file("existing/f", b"f\n", 0o644);
    let before = sim.snapshot();
    sim.mkdir("d");
    sim.mv("existing/f", "d/");
    sim.rm_rf("d");
    let log = sim.undo();
    assert_no_failures(&log);
    let mut after = sim.snapshot();
    assert_eq!(
        after
            .remove(Path::new("d"))
            .map(|e| matches!(e, Entry::Dir { .. })),
        Some(true),
        "{}",
        log.join("\n")
    );
    assert_eq!(after, before, "{}", log.join("\n"));
}
