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
        let dev = match &self.other_fs {
            Some((root, dev)) if path.starts_with(root) => *dev,
            _ => m.dev(),
        };
        self.emit(CaptureEventKind::FilePreImage {
            inode: InodeRef::new(dev, m.ino()),
            path: path.to_path_buf(),
            blob,
            meta,
            post_content_hash: None,
            source,
        });
    }

    fn pre_image_dir(&mut self, path: &Path) {
        let m = std::fs::symlink_metadata(path).unwrap();
        let blob = BlobHash::from_bytes(*blake3::hash(b"").as_bytes());
        self.store.put_blob(blob, 0);
        self.emit(CaptureEventKind::FilePreImage {
            inode: InodeRef::new(m.dev(), m.ino()),
            path: path.to_path_buf(),
            blob,
            meta: FileMetadata {
                mode: m.mode(),
                uid: m.uid(),
                gid: m.gid(),
                size: m.size(),
                mtime_unix_nanos: (m.mtime() as i128) * 1_000_000_000 + m.mtime_nsec() as i128,
                xattrs: BTreeMap::new(),
                acl: None,
                flags: 0,
            },
            post_content_hash: None,
            source: FilePreImageSource::ShimRenameSubtreeDir,
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
            let mut dirs = Vec::new();
            let mut complete = skip.is_none();
            walk_tree(&from_p, &mut files, &mut dirs, &mut complete);
            let skip = skip.map(|s| self.p(s));
            for f in files {
                if Some(&f) != skip.as_ref() {
                    self.pre_image(&f, WALK_SOURCE);
                }
            }
            // As the shim does: directory records only for a complete
            // walk, the rename source itself last.
            if complete {
                for d in dirs {
                    self.pre_image_dir(&d);
                }
                self.pre_image_dir(&from_p);
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
        let mut dirs = Vec::new();
        let mut complete = true;
        walk_tree(&from_p, &mut files, &mut dirs, &mut complete);
        for f in &files {
            self.pre_image(f, WALK_SOURCE);
        }
        for d in &dirs {
            self.pre_image_dir(d);
        }
        self.pre_image_dir(&from_p);
        self.emit(CaptureEventKind::TreeOp(TreeOp::Rename {
            from: from_p.clone(),
            to: to_p.clone(),
            inode: InodeRef::new(0, 0),
        }));
        std::fs::create_dir(&to_p).unwrap();
        for d in &dirs {
            std::fs::create_dir(to_p.join(d.strip_prefix(&from_p).unwrap())).unwrap();
        }
        for f in &files {
            std::fs::copy(f, to_p.join(f.strip_prefix(&from_p).unwrap())).unwrap();
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

    fn snapshot(&self) -> BTreeMap<PathBuf, Entry> {
        let mut out = BTreeMap::new();
        snapshot_into(self.root.path(), self.root.path(), &mut out);
        out
    }

    fn plan_nodes(&self) -> Vec<crate::inverse::PlanNode> {
        let probe = LiveStateProbe::new();
        plan(command_record(), &self.events, &probe, &self.store).nodes
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

/// The shim's walk: regular files and directories; any other entry
/// makes it incomplete.
fn walk_tree(dir: &Path, files: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>, complete: &mut bool) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for e in entries {
        let m = std::fs::symlink_metadata(&e).unwrap();
        if m.is_dir() {
            dirs.push(e.clone());
            walk_tree(&e, files, dirs, complete);
        } else if m.is_file() {
            files.push(e);
        } else {
            *complete = false;
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
fn hosted_pip_shape_restores_a_private_source_dir_mode() {
    // pip_shape_as_the_hosted_shim_sees_it with the new tree already
    // holding the source's name at a wider mode.
    let mut sim = Sim::new();
    sim.seed_dir("d", 0o700);
    sim.seed_file("d/f", b"original\n", 0o600);
    sim.seed_dir("d/sub", 0o711);
    sim.seed_file("d/sub/g", b"g\n", 0o600);
    let before = sim.snapshot();
    sim.mv("d", "d.old");
    sim.mkdir_unseen("d");
    std::fs::set_permissions(sim.p("d"), std::fs::Permissions::from_mode(0o755)).unwrap();
    sim.write_unseen("d/f", b"new\n");
    sim.rmtree_top_unseen("d.old");
    assert_restored(&sim, &before);
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

// macOS refuses rename(2) on a directory without write permission, so
// this shape cannot arise there.
#[cfg(not(target_os = "macos"))]
fn read_only_tree_round_trip(mode: u32) {
    // `chmod -R u+w d` is not interposed: Go's module cache, then
    // `mv d t; chmod -R u+w t; rm -rf t`.
    let mut sim = Sim::new();
    sim.seed_dir("d/sub", 0o755);
    sim.seed_file("d/f", b"f\n", 0o644);
    sim.seed_file("d/sub/g", b"g\n", 0o644);
    sim.seed_dir("d/sub", mode);
    sim.seed_dir("d", mode);
    let before = sim.snapshot();
    sim.mv("d", "t");
    sim.seed_dir("t", 0o755);
    sim.seed_dir("t/sub", 0o755);
    sim.rm_rf("t");
    let log = sim.undo();
    let after = sim.snapshot();
    // Let the tempdir clean itself up, also when the assert fires.
    for p in ["d", "d/sub"] {
        let _ = std::fs::set_permissions(sim.p(p), std::fs::Permissions::from_mode(0o755));
    }
    assert_no_failures(&log);
    assert_eq!(after, before, "{}", log.join("\n"));
}

#[test]
#[cfg(not(target_os = "macos"))]
fn read_only_0555_tree_is_rebuilt() {
    read_only_tree_round_trip(0o555);
}

#[test]
#[cfg(not(target_os = "macos"))]
fn read_only_0500_tree_is_rebuilt() {
    read_only_tree_round_trip(0o500);
}

#[test]
fn rebuilt_directory_gets_its_recorded_metadata_after_its_children() {
    use crate::inverse::InverseOp;
    let mut sim = Sim::new();
    sim.seed_dir("d/sub", 0o750);
    sim.seed_file("d/sub/f", b"f\n", 0o640);
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    for rel in ["d", "d/sub"] {
        std::fs::File::open(sim.p(rel))
            .unwrap()
            .set_modified(old)
            .unwrap();
    }
    sim.snapshot();
    sim.mv("d", "t");
    sim.rm_rf("t");
    let nodes = sim.plan_nodes();
    let pos = |pred: &dyn Fn(&InverseOp) -> bool| nodes.iter().position(|n| pred(&n.op));
    let content = pos(&|op| matches!(op, InverseOp::RestoreContent { .. })).expect("content");
    for rel in ["d", "d/sub"] {
        let p = sim.p(rel);
        let meta = pos(&|op| matches!(op, InverseOp::RestoreMetadata { path, .. } if *path == p));
        let meta = meta.unwrap_or_else(|| panic!("no RestoreMetadata for {rel}: {nodes:#?}"));
        assert!(meta > content, "{rel} metadata before content: {nodes:#?}");
    }
    let log = sim.undo();
    for rel in ["d", "d/sub"] {
        let m = std::fs::metadata(sim.p(rel)).unwrap();
        assert_eq!(m.mtime(), 1_000_000, "{rel}\n{}", log.join("\n"));
    }
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

// Round 4 review of #205.

fn r4_report(name: &str, sim: &Sim, before: &BTreeMap<PathBuf, Entry>) {
    let log = sim.undo();
    let after = sim.snapshot();
    let bad: Vec<&String> = log.iter().filter(|l| !l.starts_with("ok ")).collect();
    let root = sim.root.path().to_string_lossy().to_string();
    eprintln!(
        "R4 {name}: tree_restored={} non_ok_ops={}",
        &after == before,
        bad.len()
    );
    for l in bad {
        eprintln!(
            "R4   {}",
            l.replace(&root, "").chars().take(150).collect::<String>()
        );
    }
    for (k, v) in before {
        if after.get(k) != Some(v) {
            eprintln!("R4   differs/missing: {k:?} after={:?}", after.get(k));
        }
    }
    for k in after.keys() {
        if !before.contains_key(k) {
            eprintln!("R4   extra: {k:?}");
        }
    }
}

/// An `rm -rf rel` both tiers report: shim Unlink with the (0, 0)
/// sentinel and helper Unlink with the real inode, per file.
fn r4_rm_rf_dual(sim: &mut Sim, p: &Path) {
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
            r4_rm_rf_dual(sim, &c);
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

fn r4_seed_pip(sim: &Sim) {
    sim.seed_dir("d", 0o755);
    sim.seed_file("d/f", b"v1\n", 0o644);
    sim.seed_dir("d/sub", 0o750);
    sim.seed_file("d/sub/g", b"g1\n", 0o640);
}

#[test]
fn r4_b_lsm_dual_tier_pip_shape() {
    // pip with the helper's LSM tier and the shim both active: both
    // report the Rename and the unlinks, the helper reports the creates.
    let mut sim = Sim::new();
    r4_seed_pip(&sim);
    let before = sim.snapshot();
    sim.mv("d", "d.old");
    let dup = sim.events.last().unwrap().kind.clone();
    sim.emit(dup);
    sim.mkdir("d");
    sim.write("d/f", b"v2\n");
    let p = sim.p("d.old");
    r4_rm_rf_dual(&mut sim, &p);
    r4_report("B-lsm-dual-tier", &sim, &before);
}

#[test]
fn r4_b_bsd_dir_diff_pip_shape() {
    // pip with BSD's dir-diff: Create events for the rename destination
    // and everything under it, alongside the shim's Rename.
    let mut sim = Sim::new();
    r4_seed_pip(&sim);
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
    r4_report("B-bsd-dir-diff", &sim, &before);
}

#[test]
#[ignore = "fails at fb9f2a6, round 4 review of #205: the replaced-subtree rule matches t by relative name and loses it"]
fn failed_enotempty_rename_then_rm_rf_restores_destination_bytes() {
    // `d/` and `t/` both hold a and b. os.rename('d', 't') fails with
    // ENOTEMPTY but the walk and Rename are journaled before the syscall.
    // Then `rm -rf t`. Both trees must keep their own bytes.
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
    let mut dirs = Vec::new();
    let mut complete = true;
    walk_tree(&from, &mut files, &mut dirs, &mut complete);
    for f in &files {
        sim.pre_image(f, WALK_SOURCE);
    }
    r4_a_dir_records(&mut sim, &dirs, &from);
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

fn r4_a_dir_records(sim: &mut Sim, dirs: &[PathBuf], from: &Path) {
    for d in dirs {
        sim.pre_image_dir(d);
    }
    sim.pre_image_dir(from);
}
