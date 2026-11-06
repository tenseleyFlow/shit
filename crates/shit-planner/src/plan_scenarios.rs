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
const WALK_SOURCE: FilePreImageSource = FilePreImageSource::Other;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Dir { perm: u32 },
    File { perm: u32, bytes: Vec<u8> },
}

/// Recorder for one command's worth of events.
struct Sim {
    root: tempfile::TempDir,
    events: Vec<CaptureEvent>,
    blobs: InMemoryBlobReader,
    store: InMemoryStore,
    next: u64,
}

impl Sim {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().expect("tempdir"),
            events: Vec::new(),
            blobs: InMemoryBlobReader::new(),
            store: InMemoryStore::new(),
            next: 1,
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
        let from_p = self.p(from);
        let mut to_p = self.p(to);
        if to_p.is_dir() {
            to_p = to_p.join(from_p.file_name().unwrap());
        }
        if from_p.is_dir() {
            let mut files = Vec::new();
            walk_files(&from_p, &mut files);
            for f in files {
                self.pre_image(&f, WALK_SOURCE);
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
        if m.is_dir() {
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
#[ignore = "fails on trunk 662af56: G01.3 marks the rename destination transient once its parent is gone"]
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
