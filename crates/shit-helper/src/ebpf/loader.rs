// SPDX-License-Identifier: AGPL-3.0-or-later

//! `EbpfLoader` — userspace BPF loader (S09 stage 3).
//!
//! Stage 3 contract: `probe` is real; `load` loads + attaches a single
//! minimal tracepoint program (`noop_tracepoint.bpf.o`, see
//! `crates/shit-helper/bpf/`). On `drop`, aya detaches every program
//! and frees the BPF map fds — so the load is reversible by the type
//! system.
//!
//! **What stage 3 deliberately does NOT do:**
//!   - No LSM hooks. Tracepoints can't deny syscalls; LSM hooks can.
//!   - No map writes. The tracepoint is purely observational.
//!   - No daemon-side decision plumbing. Stage 4+ wires that.
//!
//! Standing rule (HP-18 in helper-protocol.md): any future addition
//! that loads an LSM hook MUST be reviewed for blast radius and paired
//! with a watchdog. See `crates/shit-helper/examples/bpf_tracepoint_smoke.rs`
//! for the watchdog pattern.

#![cfg(target_os = "linux")]

use crate::priv_linux::{BpfCapState, probe_bpf_caps};
use shit_capture::linux_kernel::{BpfLsmFeatures, probe_bpf_lsm};

use super::error::EbpfError;

/// The BPF program bytes shipped in tree. Compiled from
/// `crates/shit-helper/bpf/src/noop_tracepoint.bpf.c` per the
/// Makefile next to it. Two instructions: `w0 = 0; exit`.
const NOOP_TRACEPOINT_OBJ: &[u8] = include_bytes!("../../bpf/build/noop_tracepoint.bpf.o");

/// Section name inside the .o that aya looks up to find the program.
/// Matches the `__attribute__((section(...)))` in the .c source.
const NOOP_TRACEPOINT_SECTION: &str = "noop_tracepoint";

/// Tracepoint category + name the program attaches to. Read-only —
/// the program fires *after* `sched_process_exec` happens.
const TRACEPOINT_CATEGORY: &str = "sched";
const TRACEPOINT_NAME: &str = "sched_process_exec";

/// L04 — BPF object containing the `lsm/inode_unlink` LSM hook.
/// Built from `crates/shit-helper/bpf/src/inode_unlink.bpf.c`;
/// ringbuf map name = `unlink_events`, program function name =
/// `shit_inode_unlink`, LSM hook = `inode_unlink`.
const INODE_UNLINK_OBJ: &[u8] = include_bytes!("../../bpf/build/inode_unlink.bpf.o");

/// L04 — BPF object containing the `lsm/inode_setattr` LSM hook.
/// Built from `crates/shit-helper/bpf/src/inode_setattr.bpf.c`;
/// ringbuf map name = `setattr_events`, program function name =
/// `shit_inode_setattr`, LSM hook = `inode_setattr`.
const INODE_SETATTR_OBJ: &[u8] = include_bytes!("../../bpf/build/inode_setattr.bpf.o");

/// L04 — BPF object containing the `lsm/inode_mkdir` LSM hook.
const INODE_MKDIR_OBJ: &[u8] = include_bytes!("../../bpf/build/inode_mkdir.bpf.o");

/// L04 — BPF object containing the `lsm/inode_create` LSM hook.
const INODE_CREATE_OBJ: &[u8] = include_bytes!("../../bpf/build/inode_create.bpf.o");

/// L04.1 — BPF object containing the `lsm/file_open` LSM hook.
const FILE_OPEN_OBJ: &[u8] = include_bytes!("../../bpf/build/file_open.bpf.o");

/// L04.1 — BPF object containing the `lsm/inode_rename` LSM hook.
const INODE_RENAME_OBJ: &[u8] = include_bytes!("../../bpf/build/inode_rename.bpf.o");

/// LSM hook name (aya prepends `bpf_lsm_` internally to find the
/// kernel BTF symbol). Matches the SEC("lsm/inode_unlink") in the .c.
const LSM_HOOK_INODE_UNLINK: &str = "inode_unlink";
const LSM_HOOK_INODE_SETATTR: &str = "inode_setattr";
const LSM_HOOK_INODE_MKDIR: &str = "inode_mkdir";
const LSM_HOOK_INODE_CREATE: &str = "inode_create";
const LSM_HOOK_FILE_OPEN: &str = "file_open";
const LSM_HOOK_INODE_RENAME: &str = "inode_rename";

/// Program function name inside the .o. Set by `BPF_PROG(name, ...)`
/// in the .c. aya looks programs up via this name when both the
/// section and the function name agree.
const LSM_PROG_INODE_UNLINK: &str = "shit_inode_unlink";
const LSM_PROG_INODE_SETATTR: &str = "shit_inode_setattr";
const LSM_PROG_INODE_MKDIR: &str = "shit_inode_mkdir";
const LSM_PROG_INODE_CREATE: &str = "shit_inode_create";
const LSM_PROG_FILE_OPEN: &str = "shit_file_open";
const LSM_PROG_INODE_RENAME: &str = "shit_inode_rename";

/// Ringbuf map names. `take_*_ringbuf` methods remove the map from
/// the Ebpf instance and return it as an `aya::maps::RingBuf` for
/// the userspace consumer threads.
const RINGBUF_UNLINK_EVENTS: &str = "unlink_events";
const RINGBUF_SETATTR_EVENTS: &str = "setattr_events";
const RINGBUF_MKDIR_EVENTS: &str = "mkdir_events";
const RINGBUF_CREATE_EVENTS: &str = "create_events";
const RINGBUF_OPEN_EVENTS: &str = "open_events";
const RINGBUF_RENAME_EVENTS: &str = "rename_events";

/// Result of `EbpfLoader::probe` — combined kernel feature + capability
/// view. `should_attempt_load` is the call-site predicate that tells
/// the helper whether it's worth invoking `load`.
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub kernel: BpfLsmFeatures,
    pub caps: BpfCapState,
}

impl ProbeOutcome {
    /// True only when **both** the kernel supports BPF-LSM and we
    /// have the caps to load programs against it. The single
    /// authoritative gate.
    pub fn should_attempt_load(&self) -> bool {
        self.kernel.fully_supported() && self.caps.can_load_lsm()
    }

    /// Reason load would fail or be useless. Empty when load is
    /// safe to attempt.
    pub fn diagnose(&self) -> String {
        if self.should_attempt_load() {
            return "ebpf-lsm load prerequisites met".to_string();
        }
        let mut reasons = Vec::new();
        if !self.kernel.fully_supported() {
            reasons.push(format!("kernel: {}", self.kernel.diagnose()));
        }
        if !self.caps.can_load_lsm() {
            reasons.push("caps: need CAP_BPF+CAP_PERFMON or CAP_SYS_ADMIN".to_string());
        }
        reasons.join("; ")
    }
}

/// The loader. Holds one `aya::Ebpf` instance per loaded program;
/// dropping detaches everything. We never hold a `LinkId` directly —
/// the aya `Ebpf` owns the link lifetime, and drop is our detach.
///
/// `bpf` is the legacy tracepoint slot, also used by `load_lsm_unlink`
/// for the unlink program. `setattr_bpf` is the L04 phase 3 slot for
/// the setattr program. Each .o ships its own ringbuf so they live
/// in separate Ebpf instances.
pub struct EbpfLoader {
    bpf: Option<aya::Ebpf>,
    setattr_bpf: Option<aya::Ebpf>,
    mkdir_bpf: Option<aya::Ebpf>,
    create_bpf: Option<aya::Ebpf>,
    open_bpf: Option<aya::Ebpf>,
    rename_bpf: Option<aya::Ebpf>,
}

impl Default for EbpfLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for EbpfLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EbpfLoader")
            .field("unlink_loaded", &self.bpf.is_some())
            .field("setattr_loaded", &self.setattr_bpf.is_some())
            .field("mkdir_loaded", &self.mkdir_bpf.is_some())
            .finish()
    }
}

impl EbpfLoader {
    pub fn new() -> Self {
        Self {
            bpf: None,
            setattr_bpf: None,
            mkdir_bpf: None,
            create_bpf: None,
            open_bpf: None,
            rename_bpf: None,
        }
    }

    /// Read-only feature + capability probe. Safe to call from any
    /// context; touches no kernel-side state.
    pub fn probe(&self) -> ProbeOutcome {
        ProbeOutcome {
            kernel: probe_bpf_lsm(),
            caps: probe_bpf_caps(),
        }
    }

    /// Whether ANY program is currently loaded + attached.
    pub fn is_loaded(&self) -> bool {
        self.bpf.is_some()
            || self.setattr_bpf.is_some()
            || self.mkdir_bpf.is_some()
            || self.create_bpf.is_some()
            || self.open_bpf.is_some()
            || self.rename_bpf.is_some()
    }

    /// Load + attach the shipped noop tracepoint program. Returns
    /// `Err(PrerequisiteFailed)` when the kernel or our caps say no.
    ///
    /// **Tracepoint-only.** This entry point will never load an LSM
    /// program. A future S09 stage that introduces LSM hooks must
    /// add a separate method (with its own review).
    pub fn load(&mut self) -> Result<(), EbpfError> {
        let outcome = self.probe();
        if !outcome.should_attempt_load() {
            return Err(EbpfError::PrerequisiteFailed(outcome.diagnose()));
        }
        if self.bpf.is_some() {
            tracing::warn!("EbpfLoader::load called while already loaded; ignoring");
            return Ok(());
        }

        // `include_bytes!` returns a `[u8; N]` with alignment 1; the
        // `object` crate's ELF header cast requires 8-byte alignment.
        // Copy through a `Vec` (heap-aligned) before handing to aya.
        let aligned: Vec<u8> = NOOP_TRACEPOINT_OBJ.to_vec();
        let mut bpf =
            aya::Ebpf::load(&aligned).map_err(|e| EbpfError::Aya(format!("load: {e}")))?;

        let prog: &mut aya::programs::TracePoint = bpf
            .program_mut(NOOP_TRACEPOINT_SECTION)
            .ok_or_else(|| {
                EbpfError::Aya(format!(
                    "program `{NOOP_TRACEPOINT_SECTION}` not found in object"
                ))
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                EbpfError::Aya(format!("expected TracePoint: {e}"))
            })?;

        prog.load()
            .map_err(|e| EbpfError::Aya(format!("prog.load: {e}")))?;

        let _link_id = prog
            .attach(TRACEPOINT_CATEGORY, TRACEPOINT_NAME)
            .map_err(|e| EbpfError::Aya(format!("prog.attach: {e}")))?;

        tracing::info!(
            category = TRACEPOINT_CATEGORY,
            name = TRACEPOINT_NAME,
            "ebpf tracepoint loaded and attached"
        );
        self.bpf = Some(bpf);
        Ok(())
    }

    /// Explicit detach. Calling drop is equivalent (aya handles
    /// cleanup), but this lets the caller force it without dropping
    /// the loader (e.g. for graceful shutdown sequencing).
    pub fn detach(&mut self) {
        let unlink_was = self.bpf.take().is_some();
        let setattr_was = self.setattr_bpf.take().is_some();
        let mkdir_was = self.mkdir_bpf.take().is_some();
        let create_was = self.create_bpf.take().is_some();
        let open_was = self.open_bpf.take().is_some();
        let rename_was = self.rename_bpf.take().is_some();
        if unlink_was || setattr_was || mkdir_was || create_was || open_was || rename_was {
            tracing::info!(
                unlink = unlink_was,
                setattr = setattr_was,
                mkdir = mkdir_was,
                create = create_was,
                open = open_was,
                rename = rename_was,
                "ebpf programs detached"
            );
        }
    }

    /// L04 — Load + attach the `lsm/inode_unlink` program. The BPF
    /// program ringbuf's its (dev, inode, pid, comm, ts_ns) records
    /// on every unlinkat(2). The userspace consumer
    /// ([`super::ringbuf_reader`]) takes the ringbuf via
    /// [`Self::take_unlink_ringbuf`] and feeds events into the
    /// [`crate::capture::linux::LinuxCaptureRuntime`].
    ///
    /// One-shot: refuses if an Ebpf instance is already loaded. The
    /// helper boot sequence calls this exactly once after the cap
    /// probe passes.
    ///
    /// **HP-18 sign-off:** This is a Linux Security Module hook.
    /// A verifier rejection on a kernel diff would break every
    /// unlinkat on the box. Mitigation: the program (a) always
    /// returns 0 (allow), (b) uses BPF_CORE_READ for every
    /// kernel-struct field, (c) is straight-line code with no
    /// loops, and (d) drops events silently when the ringbuf
    /// fills rather than returning non-zero. See the .bpf.c
    /// comment block for the full contract.
    pub fn load_lsm_unlink(&mut self) -> Result<(), EbpfError> {
        let outcome = self.probe();
        if !outcome.should_attempt_load() {
            return Err(EbpfError::PrerequisiteFailed(outcome.diagnose()));
        }
        if self.bpf.is_some() {
            return Err(EbpfError::Aya(
                "load_lsm_unlink: another program already loaded".into(),
            ));
        }

        // BTF from /sys/kernel/btf/vmlinux — needed for the LSM
        // hook's attach-by-name resolution.
        let btf = aya::Btf::from_sys_fs()
            .map_err(|e| EbpfError::Aya(format!("Btf::from_sys_fs: {e}")))?;

        // Heap-align (same dance as the tracepoint path).
        let aligned: Vec<u8> = INODE_UNLINK_OBJ.to_vec();
        let mut bpf = aya::Ebpf::load(&aligned)
            .map_err(|e| EbpfError::Aya(format!("Ebpf::load(inode_unlink): {e}")))?;

        let prog: &mut aya::programs::Lsm = bpf
            .program_mut(LSM_PROG_INODE_UNLINK)
            .ok_or_else(|| {
                EbpfError::Aya(format!(
                    "program `{LSM_PROG_INODE_UNLINK}` not found in object"
                ))
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                EbpfError::Aya(format!("expected Lsm program: {e}"))
            })?;

        prog.load(LSM_HOOK_INODE_UNLINK, &btf)
            .map_err(|e| EbpfError::Aya(format!("Lsm.load({LSM_HOOK_INODE_UNLINK}): {e}")))?;

        let _link_id = prog
            .attach()
            .map_err(|e| EbpfError::Aya(format!("Lsm.attach: {e}")))?;

        tracing::info!(
            hook = LSM_HOOK_INODE_UNLINK,
            prog = LSM_PROG_INODE_UNLINK,
            ringbuf = RINGBUF_UNLINK_EVENTS,
            "ebpf-lsm inode_unlink loaded and attached"
        );
        self.bpf = Some(bpf);
        Ok(())
    }

    /// L04 phase 3 — Load + attach the `lsm/inode_setattr` program.
    /// Same contract as [`Self::load_lsm_unlink`]: ringbufs
    /// (dev, inode, old_*, new_*) records on every chmod / chown /
    /// utimes / truncate. Returns 0 (allow) unconditionally.
    ///
    /// One-shot per loader; refuses if already loaded.
    ///
    /// **HP-18 sign-off** identical to the unlink program. Verifier
    /// rejection would break every chmod/chown on the box.
    pub fn load_lsm_setattr(&mut self) -> Result<(), EbpfError> {
        let outcome = self.probe();
        if !outcome.should_attempt_load() {
            return Err(EbpfError::PrerequisiteFailed(outcome.diagnose()));
        }
        if self.setattr_bpf.is_some() {
            return Err(EbpfError::Aya(
                "load_lsm_setattr: setattr program already loaded".into(),
            ));
        }

        let btf = aya::Btf::from_sys_fs()
            .map_err(|e| EbpfError::Aya(format!("Btf::from_sys_fs: {e}")))?;

        let aligned: Vec<u8> = INODE_SETATTR_OBJ.to_vec();
        let mut bpf = aya::Ebpf::load(&aligned)
            .map_err(|e| EbpfError::Aya(format!("Ebpf::load(inode_setattr): {e}")))?;

        let prog: &mut aya::programs::Lsm = bpf
            .program_mut(LSM_PROG_INODE_SETATTR)
            .ok_or_else(|| {
                EbpfError::Aya(format!(
                    "program `{LSM_PROG_INODE_SETATTR}` not found in object"
                ))
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                EbpfError::Aya(format!("expected Lsm program: {e}"))
            })?;

        prog.load(LSM_HOOK_INODE_SETATTR, &btf)
            .map_err(|e| EbpfError::Aya(format!("Lsm.load({LSM_HOOK_INODE_SETATTR}): {e}")))?;

        let _link_id = prog
            .attach()
            .map_err(|e| EbpfError::Aya(format!("Lsm.attach: {e}")))?;

        tracing::info!(
            hook = LSM_HOOK_INODE_SETATTR,
            prog = LSM_PROG_INODE_SETATTR,
            ringbuf = RINGBUF_SETATTR_EVENTS,
            "ebpf-lsm inode_setattr loaded and attached"
        );
        self.setattr_bpf = Some(bpf);
        Ok(())
    }

    /// L04 phase 3 — Take the `setattr_events` ringbuf. Mirror of
    /// [`Self::take_unlink_ringbuf`] for the setattr program.
    pub fn take_setattr_ringbuf(
        &mut self,
    ) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        let bpf = self.setattr_bpf.as_mut()?;
        let map = bpf.take_map(RINGBUF_SETATTR_EVENTS)?;
        aya::maps::RingBuf::try_from(map).ok()
    }

    /// L04 phase 4 — Load + attach the `lsm/inode_mkdir` program.
    /// Same contract as [`Self::load_lsm_unlink`]; ringbufs
    /// `(parent_inode, basename, mode)` for every `mkdir(2)` call.
    pub fn load_lsm_mkdir(&mut self) -> Result<(), EbpfError> {
        let outcome = self.probe();
        if !outcome.should_attempt_load() {
            return Err(EbpfError::PrerequisiteFailed(outcome.diagnose()));
        }
        if self.mkdir_bpf.is_some() {
            return Err(EbpfError::Aya(
                "load_lsm_mkdir: mkdir program already loaded".into(),
            ));
        }

        let btf = aya::Btf::from_sys_fs()
            .map_err(|e| EbpfError::Aya(format!("Btf::from_sys_fs: {e}")))?;

        let aligned: Vec<u8> = INODE_MKDIR_OBJ.to_vec();
        let mut bpf = aya::Ebpf::load(&aligned)
            .map_err(|e| EbpfError::Aya(format!("Ebpf::load(inode_mkdir): {e}")))?;

        let prog: &mut aya::programs::Lsm = bpf
            .program_mut(LSM_PROG_INODE_MKDIR)
            .ok_or_else(|| {
                EbpfError::Aya(format!(
                    "program `{LSM_PROG_INODE_MKDIR}` not found in object"
                ))
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                EbpfError::Aya(format!("expected Lsm program: {e}"))
            })?;

        prog.load(LSM_HOOK_INODE_MKDIR, &btf)
            .map_err(|e| EbpfError::Aya(format!("Lsm.load({LSM_HOOK_INODE_MKDIR}): {e}")))?;

        let _link_id = prog
            .attach()
            .map_err(|e| EbpfError::Aya(format!("Lsm.attach: {e}")))?;

        tracing::info!(
            hook = LSM_HOOK_INODE_MKDIR,
            prog = LSM_PROG_INODE_MKDIR,
            ringbuf = RINGBUF_MKDIR_EVENTS,
            "ebpf-lsm inode_mkdir loaded and attached"
        );
        self.mkdir_bpf = Some(bpf);
        Ok(())
    }

    /// L04 phase 4 — Take the `mkdir_events` ringbuf.
    pub fn take_mkdir_ringbuf(
        &mut self,
    ) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        let bpf = self.mkdir_bpf.as_mut()?;
        let map = bpf.take_map(RINGBUF_MKDIR_EVENTS)?;
        aya::maps::RingBuf::try_from(map).ok()
    }

    /// L04 phase 5 — Load + attach the `lsm/inode_create` program.
    pub fn load_lsm_create(&mut self) -> Result<(), EbpfError> {
        let outcome = self.probe();
        if !outcome.should_attempt_load() {
            return Err(EbpfError::PrerequisiteFailed(outcome.diagnose()));
        }
        if self.create_bpf.is_some() {
            return Err(EbpfError::Aya(
                "load_lsm_create: create program already loaded".into(),
            ));
        }

        let btf = aya::Btf::from_sys_fs()
            .map_err(|e| EbpfError::Aya(format!("Btf::from_sys_fs: {e}")))?;

        let aligned: Vec<u8> = INODE_CREATE_OBJ.to_vec();
        let mut bpf = aya::Ebpf::load(&aligned)
            .map_err(|e| EbpfError::Aya(format!("Ebpf::load(inode_create): {e}")))?;

        let prog: &mut aya::programs::Lsm = bpf
            .program_mut(LSM_PROG_INODE_CREATE)
            .ok_or_else(|| {
                EbpfError::Aya(format!(
                    "program `{LSM_PROG_INODE_CREATE}` not found in object"
                ))
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                EbpfError::Aya(format!("expected Lsm program: {e}"))
            })?;

        prog.load(LSM_HOOK_INODE_CREATE, &btf)
            .map_err(|e| EbpfError::Aya(format!("Lsm.load({LSM_HOOK_INODE_CREATE}): {e}")))?;

        let _link_id = prog
            .attach()
            .map_err(|e| EbpfError::Aya(format!("Lsm.attach: {e}")))?;

        tracing::info!(
            hook = LSM_HOOK_INODE_CREATE,
            prog = LSM_PROG_INODE_CREATE,
            ringbuf = RINGBUF_CREATE_EVENTS,
            "ebpf-lsm inode_create loaded and attached"
        );
        self.create_bpf = Some(bpf);
        Ok(())
    }

    /// L04 phase 5 — Take the `create_events` ringbuf.
    pub fn take_create_ringbuf(
        &mut self,
    ) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        let bpf = self.create_bpf.as_mut()?;
        let map = bpf.take_map(RINGBUF_CREATE_EVENTS)?;
        aya::maps::RingBuf::try_from(map).ok()
    }

    /// L04.1 — Load + attach `lsm/file_open`. Pre-filters to
    /// write-intent in BPF (FMODE_WRITE), so ringbuf traffic stays
    /// manageable under heavy read workloads.
    pub fn load_lsm_open(&mut self) -> Result<(), EbpfError> {
        let outcome = self.probe();
        if !outcome.should_attempt_load() {
            return Err(EbpfError::PrerequisiteFailed(outcome.diagnose()));
        }
        if self.open_bpf.is_some() {
            return Err(EbpfError::Aya(
                "load_lsm_open: open program already loaded".into(),
            ));
        }

        let btf = aya::Btf::from_sys_fs()
            .map_err(|e| EbpfError::Aya(format!("Btf::from_sys_fs: {e}")))?;

        let aligned: Vec<u8> = FILE_OPEN_OBJ.to_vec();
        let mut bpf = aya::Ebpf::load(&aligned)
            .map_err(|e| EbpfError::Aya(format!("Ebpf::load(file_open): {e}")))?;

        let prog: &mut aya::programs::Lsm = bpf
            .program_mut(LSM_PROG_FILE_OPEN)
            .ok_or_else(|| {
                EbpfError::Aya(format!(
                    "program `{LSM_PROG_FILE_OPEN}` not found in object"
                ))
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                EbpfError::Aya(format!("expected Lsm program: {e}"))
            })?;

        prog.load(LSM_HOOK_FILE_OPEN, &btf)
            .map_err(|e| EbpfError::Aya(format!("Lsm.load({LSM_HOOK_FILE_OPEN}): {e}")))?;

        let _link_id = prog
            .attach()
            .map_err(|e| EbpfError::Aya(format!("Lsm.attach: {e}")))?;

        tracing::info!(
            hook = LSM_HOOK_FILE_OPEN,
            prog = LSM_PROG_FILE_OPEN,
            ringbuf = RINGBUF_OPEN_EVENTS,
            "ebpf-lsm file_open loaded and attached"
        );
        self.open_bpf = Some(bpf);
        Ok(())
    }

    /// L04.1 — Take the `open_events` ringbuf.
    pub fn take_open_ringbuf(
        &mut self,
    ) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        let bpf = self.open_bpf.as_mut()?;
        let map = bpf.take_map(RINGBUF_OPEN_EVENTS)?;
        aya::maps::RingBuf::try_from(map).ok()
    }

    /// L04.1 — Load + attach `lsm/inode_rename`.
    pub fn load_lsm_rename(&mut self) -> Result<(), EbpfError> {
        let outcome = self.probe();
        if !outcome.should_attempt_load() {
            return Err(EbpfError::PrerequisiteFailed(outcome.diagnose()));
        }
        if self.rename_bpf.is_some() {
            return Err(EbpfError::Aya(
                "load_lsm_rename: rename program already loaded".into(),
            ));
        }

        let btf = aya::Btf::from_sys_fs()
            .map_err(|e| EbpfError::Aya(format!("Btf::from_sys_fs: {e}")))?;

        let aligned: Vec<u8> = INODE_RENAME_OBJ.to_vec();
        let mut bpf = aya::Ebpf::load(&aligned)
            .map_err(|e| EbpfError::Aya(format!("Ebpf::load(inode_rename): {e}")))?;

        let prog: &mut aya::programs::Lsm = bpf
            .program_mut(LSM_PROG_INODE_RENAME)
            .ok_or_else(|| {
                EbpfError::Aya(format!(
                    "program `{LSM_PROG_INODE_RENAME}` not found in object"
                ))
            })?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| {
                EbpfError::Aya(format!("expected Lsm program: {e}"))
            })?;

        prog.load(LSM_HOOK_INODE_RENAME, &btf)
            .map_err(|e| EbpfError::Aya(format!("Lsm.load({LSM_HOOK_INODE_RENAME}): {e}")))?;

        let _link_id = prog
            .attach()
            .map_err(|e| EbpfError::Aya(format!("Lsm.attach: {e}")))?;

        tracing::info!(
            hook = LSM_HOOK_INODE_RENAME,
            prog = LSM_PROG_INODE_RENAME,
            ringbuf = RINGBUF_RENAME_EVENTS,
            "ebpf-lsm inode_rename loaded and attached"
        );
        self.rename_bpf = Some(bpf);
        Ok(())
    }

    /// L04.1 — Take the `rename_events` ringbuf.
    pub fn take_rename_ringbuf(
        &mut self,
    ) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        let bpf = self.rename_bpf.as_mut()?;
        let map = bpf.take_map(RINGBUF_RENAME_EVENTS)?;
        aya::maps::RingBuf::try_from(map).ok()
    }

    /// L04 — Take the `unlink_events` ringbuf for the userspace
    /// consumer. Returns `None` if the loader isn't loaded yet, or
    /// if the ringbuf has already been taken. The loader retains
    /// ownership of the [`aya::Ebpf`] instance so the program stays
    /// attached for the helper's lifetime; the ringbuf is the only
    /// piece that moves to the reader thread.
    pub fn take_unlink_ringbuf(
        &mut self,
    ) -> Option<aya::maps::RingBuf<aya::maps::MapData>> {
        let bpf = self.bpf.as_mut()?;
        let map = bpf.take_map(RINGBUF_UNLINK_EVENTS)?;
        aya::maps::RingBuf::try_from(map).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_a_view() {
        let l = EbpfLoader::new();
        let _ = l.probe().diagnose();
    }

    #[test]
    fn new_loader_is_not_loaded() {
        let l = EbpfLoader::new();
        assert!(!l.is_loaded());
    }

    #[test]
    fn load_returns_prerequisite_failed_without_caps() {
        // Unit-test environment is unprivileged; load must refuse.
        let mut l = EbpfLoader::new();
        match l.load() {
            Err(EbpfError::PrerequisiteFailed(_)) => {} // expected
            Err(EbpfError::Aya(_)) => {
                // If the test runner is somehow capability-rich we
                // accept this — it means the load actually attempted
                // and aya reported an error (still validates the path).
            }
            Ok(()) => {
                // Surprising: we loaded a real program in a test. Detach
                // immediately to clean up.
                l.detach();
                panic!("load succeeded in unit-test environment — unexpected");
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(!l.is_loaded());
    }

    #[test]
    fn detach_when_not_loaded_is_noop() {
        let mut l = EbpfLoader::new();
        l.detach();
        l.detach();
        assert!(!l.is_loaded());
    }

    #[test]
    fn embedded_object_is_a_valid_elf() {
        // The .o must at least start with the ELF magic. Catches a
        // build-time mistake where the include_bytes! path points at
        // the wrong file.
        assert_eq!(&NOOP_TRACEPOINT_OBJ[..4], b"\x7fELF");
        assert!(NOOP_TRACEPOINT_OBJ.len() > 100);
        assert_eq!(&INODE_UNLINK_OBJ[..4], b"\x7fELF");
        assert!(INODE_UNLINK_OBJ.len() > 100);
        assert_eq!(&INODE_SETATTR_OBJ[..4], b"\x7fELF");
        assert!(INODE_SETATTR_OBJ.len() > 100);
        assert_eq!(&INODE_MKDIR_OBJ[..4], b"\x7fELF");
        assert!(INODE_MKDIR_OBJ.len() > 100);
        assert_eq!(&INODE_CREATE_OBJ[..4], b"\x7fELF");
        assert!(INODE_CREATE_OBJ.len() > 100);
        assert_eq!(&FILE_OPEN_OBJ[..4], b"\x7fELF");
        assert!(FILE_OPEN_OBJ.len() > 100);
        assert_eq!(&INODE_RENAME_OBJ[..4], b"\x7fELF");
        assert!(INODE_RENAME_OBJ.len() > 100);
    }

    #[test]
    fn diagnose_reports_non_empty_reason_when_load_would_fail() {
        let outcome = ProbeOutcome {
            kernel: BpfLsmFeatures::default(),
            caps: BpfCapState::default(),
        };
        assert!(!outcome.should_attempt_load());
        assert!(!outcome.diagnose().is_empty());
    }
}
