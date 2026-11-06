# Windows exploration: WSL first, native Windows gated

**Decision date:** 2026-09-17

**Status:** WSL 2 selected as the first Windows-hosted investigation; native
Windows remains a gated research campaign; no Windows support claim

**Audit baseline:** recovered `resume/integration` tree at `8e71f9a`, including
the in-progress, uncommitted Linux/macOS/BSD resurrection changes. Source-line
references below identify that audit snapshot; names and invariants are the
stable references when later edits move those lines.

**Scope of this lane:** analysis and test design only. This lane changes no
production code and does not enable a Windows build or support label.

## Decision

There are two different Windows-hosted products, and they must not share one
support checkbox:

| Lane | Execution boundary | Reuse | Earliest honest claim |
|---|---|---|---|
| WSL 2 guest | bash/zsh/fish and Linux descendants, operating only on the distro's local ext4 filesystem | Existing Linux helper, event model, planner, executor, and packaging | The already-declared Linux subset, after a dedicated WSL runner passes the WSL0/1/2 gates below |
| Native Windows | PowerShell 7/PSReadLine and Windows descendants, operating on configured local NTFS roots | Framing, command IDs, storage concepts, and pure planning concepts | No magic-undo claim before a minifilter proof and a Windows executor pass WX2 and WX3 |

WSL 2 is the first plausible Windows-hosted deliverable. It uses a real Linux
kernel and an ext4 VHDX, so a new capture backend is not intrinsically needed.
It is **not shippable today**, however: the current Linux path neither
identifies WSL nor enforces the ext4/interop boundary.

Native Windows is a separate platform campaign. A user-mode prototype can
exercise the shell boundary, IPC, storage, and dry-run planner, but it cannot
capture arbitrary pre-images. The only credible primary path found for
transparent native capture is a file-system minifilter. Native support stops
if that driver cannot prove exact, durable, attributed pre-images before the
originating mutation commits.

Windows remains unsupported in the public matrix. `README.md` already says this
and must continue to do so until the relevant gates pass.

The wording audit found no native-Windows support promise: the only other
public matrix mention is the explicit `Windows | Not supported` row in
`docs/macos-security-model.md`. Until a lane reaches its release gate, docs,
installers, `doctor`, release notes, package metadata, and CI job names must use
`experiment`, `audit-only`, or `unsupported` and must not use an unqualified
`Windows support` label. In particular, a passing MSVC compile, a working
PowerShell hook, or a loadable test-signed driver is not a magic-undo claim.

## Current-tree audit

### WSL currently falls through the generic Linux path

The current helper treats WSL as ordinary Linux:

- `crates/shit-helper/src/main.rs:2319-2329` validates a `WatchTree` cwd only by
  checking that the supplied path is absolute, exists, and is a directory.
  `main.rs:2497-2639` then attaches whichever Linux tier started. There is no
  WSL-version, mount-identity, filesystem, or interop check.
- `crates/shit-capture/src/fs_matrix.rs:17-38` has no DrvFS/9P/virtiofs kinds.
  Linux classification uses only `statfs` magic
  (`fs_matrix.rs:225-258`); unknown types become `Other`, and FUSE-like types
  become `Fuse`.
- The matrix explicitly gives network filesystems a streaming tier and gives
  FUSE/unknown filesystems hardlink or streaming fallbacks
  (`fs_matrix.rs:77-146`). Detection failure also becomes `Other("unknown")`
  (`fs_matrix.rs:325-334`). The engine refuses only synthetic proc/sys/dev
  filesystems (`crates/shit-capture/src/cow/engine.rs:27-75`).

Consequently a cwd on `/mnt/c`, DrvFS/9P, virtiofs, SMB, or an unknown mount is
not reliably rejected. It is currently offered a capture fallback.

An ext4-cwd command that reaches another mount is safer under eBPF-LSM than a
command whose cwd starts there, but it is still not an implemented support
boundary. eBPF events are attributed system-wide to the active process tree
(`crates/shit-helper/src/ebpf/ringbuf_reader.rs:470-756`), and several handlers
turn objects missing from the ext4 baseline into `CaptureRefused`; for example,
write-open does so at `crates/shit-helper/src/capture/linux.rs:1628-1663`.
That behavior is incidental rather than an explicit mount allowlist, and every
mutation family has not been proven on WSL filesystems.

The recursive baseline itself stays on the cwd's `st_dev` and withholds
readiness on a cross-filesystem subtree
(`capture/linux.rs:385-469`, `2160-2247`). That is useful, but it does not stop
an active descendant from naming an absolute path outside the baseline.

The current BPF event ABI carries `dev`/`inode` but no mount ID
(`crates/shit-helper/bpf/src/common.h`). WSL0 must therefore decide precisely
whether the allow boundary is the distro-root ext4 *superblock* (for which a
pinned root descriptor plus device/filesystem identity may suffice) or one
specific mount (which needs mount identity). Bind mounts, stacked mounts,
mount namespaces, unmount/remount, and device-number reuse belong in the
negative matrix. A path reconstructed after the event is not authoritative;
if one hook cannot prove the chosen boundary from stable object evidence, that
hook must refuse the command.

### Windows interop is an invisible capture escape

The bash, zsh, and fish hooks send a command line and cwd but perform no WSL or
interop validation (`shell/bash.sh:42-59`, `shell/zsh.sh:32-49`, and
`shell/fish.fish:34-46`). Parsing the command string cannot close this gap: an
alias, script, or generated path can eventually launch a Windows executable.

A Windows `.exe` launched through WSL interop executes outside the Linux
process/capture domain. The Linux helper cannot observe that executable's
Windows filesystem operations and cannot reliably journal a refusal after the
fact. The initial supported profile must therefore disable interop and verify
the effective state; `[interop] appendWindowsPath=false` alone is insufficient.

Microsoft documents that both interop and Windows `PATH` injection default to
true. DrvFS automount and `/etc/fstab` processing also default to true. The
candidate MVP profile should use:

```ini
# /etc/wsl.conf
[interop]
enabled=false
appendWindowsPath=false

[automount]
enabled=false
mountFsTab=false
```

This reduces the escape surface but is not the runtime proof. Doctor/helper
must inspect the effective binfmt/interop state and opened mount identity, and
WSL0 must prove that representative Windows executables cannot launch.

### WSL needs eBPF-LSM, not the current fanotify fallback

The fanotify fallback is not sufficient for the WSL claim:

- Its mark covers the watched directory and direct children, not grandchildren
  (`crates/shit-helper/src/fanotify/mark.rs:120-139`).
- It uses open/access permission events and cannot observe a plain unlink;
  `tests/smoke/rm-undo-linux.sh:14-19` documents why rm requires eBPF-LSM.
- An absolute mutation outside the marked cwd can be entirely invisible.

WSL support must therefore require a successfully loaded and attached
eBPF-LSM tier. Fanotify-only WSL may remain an explicitly unsupported
diagnostic mode until its coverage model changes.

The current Microsoft WSL 6.18 x64 config is promising: it builds BPF-LSM,
BTF, fanotify permission events, ext4 ACLs/security, and virtiofs. Its default
`CONFIG_LSM` list does **not** contain `bpf`. WSL supports additional kernel
command-line arguments through `.wslconfig`, so WSL0 should test the stock
kernel with an explicit `lsm=...bpf` list before considering a custom kernel.
The test must check `/sys/kernel/security/lsm` and a real attach; Kconfig and
`uname` are not runtime evidence.

### The handshake now reports the active Linux tier; doctor still needs proof separation

The old exploration note claimed the existing functional probe reported the
actual tier. That claim was incorrect. The resurrection work has since fixed
the helper handshake, but it has not yet made the doctor surface sufficient for
a WSL support gate:

- `shit-helper probe-ebpf` only evaluates read-only prerequisites; it never
  loads or attaches a program (`crates/shit-helper/src/main.rs:978-988`).
- `shit doctor` labels that prerequisite result `ebpf-lsm`
  (`crates/shit/src/doctor/mod.rs:529-558`).
- The runtime now starts the producer before acknowledging the daemon and
  passes the resolved tier into the handshake. An eBPF attach reports
  `bpf-lsm`; a real fallback reports `fanotify` with the startup failure; a
  producer-start failure cannot be advertised as ready.

The connected helper tier is therefore authoritative at the protocol boundary.
WSL0 must still expose that connected value distinctly in doctor and must not
confuse it with the read-only prerequisite probe. A support gate cannot trust
the current `linux.runtime_capture` field by itself.

Doctor also has no WSL evidence. `HostInfo` contains only OS, release, and arch,
and `LinuxReport` contains tier/capability/systemd/LSM/handshake fields
(`crates/shit/src/doctor/json.rs:96-106`, `170-201`). It does not report WSL
generation, root/cwd mount identity, unsupported mounts, interop, or Windows
`PATH` injection.

### The existing WSL/POSIX hook is availability-first

The shell waits up to five seconds for readiness, but a daemon connection
failure returns success and a reachable not-ready response also lets the
command run (`crates/shit/src/send.rs:504-541`). A reachable daemon records a
command-atomic `CaptureRefused`; an unreachable daemon cannot record anything.

That is acceptable only for an experimental WSL build whose UI does not imply
that an absent journal means a safe empty command. A future protected WSL mode
must either block the command when readiness/refusal durability is unavailable
or durably spool an unprotected-command marker outside the daemon.

### Native reuse is conceptual, not yet a Windows build seam

Static cross-target checks from the recovered tree were repeated on 2026-09-17
with the installed Rust 1.97.1 Windows standard library (the workspace MSRV is
still Rust 1.88) and produced:

```text
cargo check -p shit-proto --target x86_64-pc-windows-msvc --offline
    PASS
cargo check -p shit-shell --target x86_64-pc-windows-msvc --offline
    PASS
cargo check -p shit-planner --target x86_64-pc-windows-msvc \
    --features blake3/pure --offline
    FAIL: 55 errors
```

These are topology checks, not Windows release certification: they do not link
or execute an MSVC binary and they used a newer compiler than the MSRV. Keep
them as a cheap hosted-CI guard, then run the same tests natively with the
pinned project toolchain.

`shit-shell` passing only proves its pure template/state logic compiles; there
is no PowerShell hook. The framing implementation is genuinely portable
(`crates/shit-proto/src/frame.rs:6-37`, `65-129`), but the hook/helper message
catalog remains POSIX-oriented (`crates/shit-proto/src/lib.rs:125-161` and
`crates/shit-proto/src/helper.rs:196-268`, `314-412`).

Planner failures come from Unix fds, metadata, chmod/chown/xattrs, and live
probes in `executors/file.rs`, `executors/xattr.rs`, and `probe_live.rs`.
`crates/shit-planner/src/lib.rs:13-35`, `55`, and `67-70` exports those modules
unconditionally, while `crates/shit-planner/Cargo.toml:18-23` has unconditional
`nix`/`libc` dependencies. `shit-store` depends on the whole planner
(`crates/shit-store/Cargo.toml:10-15`), so the store is not presently an
independently Windows-buildable crate.

The store has a deeper semantic dependency than that Cargo edge. The current
SQLite schema denormalizes identity into signed `dev`/`inode` columns and paths
into `TEXT`; `Index` fills those path columns with `Path::to_string_lossy()`
(`crates/shit-store/migrations/0001-init.sql` and
`crates/shit-store/src/index.rs`). That cannot be the authoritative encoding
for arbitrary native Windows paths, alternate data streams, or a 128-bit file
ID. Likewise, `InodeRef`, `FileMetadata`, `FileKind`, and the existing file
event/inverse variants encode POSIX concepts. A Windows port needs appended,
platform-tagged path/identity/metadata variants plus new lossless index columns;
renaming the existing fields or squeezing a Windows ID into them would break
old postcard journals and make identity comparisons ambiguous.

The process and transport surfaces are also implementation work, not reusable
binaries. The CLI and daemon use Unix datagram/stream sockets, mode-0600 socket
files, Unix peer credentials, signals, and XDG paths. The privileged-helper
channel additionally depends on `SOCK_SEQPACKET`/Unix streams and `SCM_RIGHTS`
staging descriptors (`shitd/src/server.rs`, `ctl.rs`, `shim_listener.rs`, and
`helper_link.rs`). Native named pipes and Filter Manager ports can reuse the
length-bounded frame format, but not those authentication or handle-passing
assumptions.

Useful seams do exist: `StateProbe` and `InverseOpExecutor` are traits
(`crates/shit-planner/src/probe.rs:14-36` and
`crates/shit-planner/src/executor.rs:353-373`). WX0 should expose those seams
behind a platform-neutral planner core without pretending the existing POSIX
file model, store schema, or process/tool executors are portable.

## WSL 2 support contract

The first WSL claim is intentionally narrow:

- WSL 2 only, confirmed by host-side `wsl --list --verbose` evidence as well as
  guest evidence. WSL 1 is rejected.
- One pinned Windows 11, Store WSL, Microsoft-kernel, and Ubuntu matrix first.
- Interactive bash/zsh/fish commands and attributable Linux descendants only.
- Cwd and every captured object must resolve from an opened descriptor to the
  distro root's local ext4 mount. Use `fstatfs` plus mount identity from
  `/proc/self/mountinfo`/`statx`; never trust `/home` or `/mnt` spelling.
- Reject DrvFS/9P, virtiofs/FUSE Windows shares, cross-distro shares, SMB/NFS,
  removable/unknown filesystems, and every untested filesystem.
- Require the active, successfully attached eBPF-LSM tier. Fanotify-only and
  preload-only profiles are unsupported.
- Require effectively disabled Windows interop and no Windows `PATH` injection.
- Host PowerShell, `wsl.exe` launched from Windows, Windows `.exe` descendants,
  PowerShell running inside WSL, host/cross-distro writes, background jobs, and
  non-interactive scripts are outside the initial claim.
- The Linux baseline limits still apply: depth/file/size truncation must
  withhold readiness or poison the whole command, never silently narrow undo.

For an eBPF command that starts on ext4, store the allowed root device/mount
identity in the watch state. Any attributed mutation on another device/mount
must emit one durable command-wide refusal. This must be a central guard shared
by all mutation families, not an assumption that each later path lookup will
fail safely.

Host-side or cross-distro modification through `\\wsl.localhost` is not
attributable to the WSL shell command. If it touches an object whose captured
post-state is later replayed, it must surface as an identity/content conflict.
That behavior is a test requirement, not a current guarantee.

## Smallest concrete WSL0 slice

WSL0 is a feasibility result, not a support patch. Keep it to two reviewable
pieces.

### WSL0-A: truthful observability and candidate policy

1. The actually started Linux tier is now passed from `main.rs` into the helper
   handshake. Finish the observability slice by making doctor distinguish
   `prerequisites_met`, `attach_succeeded`, and the daemon's currently
   connected tier.
2. Add a Linux-only `WslReport` to doctor. Use fixture-testable parsers and
   report evidence rather than guessing:
   - WSL detection/generation hint and raw kernel release;
   - root and current-directory mount ID, fs type, source, and device;
   - active LSMs and actual helper tier;
   - effective WSLInterop binfmt state, `WSL_INTEROP` presence, and Windows
     `PATH` entries;
   - detected DrvFS/9P/virtiofs/network/cross-distro mounts;
   - `candidate_profile: true|false` plus explicit reasons.
3. Add an experimental WSL watch-root validator shared by doctor/helper. It
   accepts only WSL 2 candidate evidence, the distro-root ext4 mount, disabled
   interop, and active eBPF-LSM. It returns a durable readiness refusal for
   everything else.
4. Add one central eBPF event-mount guard so an ext4-cwd command that targets
   another filesystem or disallowed mount poisons the whole command. Compare
   the policy's stable superblock/mount identity, not a path prefix, and do not
   enable a WSL support label.

The handshake portion is implemented in `crates/shit-helper/src/main.rs` and
`crates/shit-helper/src/handshake.rs`. Remaining likely touch points are a new
Linux mount/WSL parser module, `crates/shit-helper/src/capture/linux.rs`, and
`crates/shit/src/doctor/{json.rs,mod.rs,probes/linux.rs}`.

Unit tests should use committed `/proc/self/mountinfo`, osrelease, cmdline, and
binfmt fixtures for:

- distro-root ext4;
- DrvFS/9P, virtiofs, SMB/NFS, and unknown mounts;
- escaped mountinfo paths, bind/stacked mounts, mount namespaces, and
  unmount/remount identity changes;
- interop enabled, disabled, absent, and unreadable;
- WSL 1/2/unknown evidence;
- real eBPF attach, fallback, and disconnected-helper reports;
- cwd accepted only when its opened mount identity matches the allowed root.

### WSL0-B: dedicated host/guest harness

Add a PowerShell host driver and a guest shell driver under `tests/wsl/`. The
host driver records `wsl --version`, `wsl --status`, and
`wsl --list --verbose`, applies each test profile, performs
`wsl.exe --shutdown`, and exports one versioned result bundle. The guest driver
records `uname`, `/proc/cmdline`, active LSMs, mountinfo, doctor JSON, helper
logs, and journal outcomes.

The minimum go/no-go matrix is:

1. **Tier truth:** doctor and handshake report the successfully attached
   eBPF-LSM tier; forced attach failure is never reported as eBPF.
2. **Ext4 positives:** overwrite/append/truncate, create/mkdir, unlink/rmdir,
   rename/atomic replace, mmap write, and a descendant process. Reuse the
   existing LSM smokes, including `rm-undo-linux.sh`, `mv-undo-linux.sh`,
   `mkdir-undo-lsm-tier-linux.sh`, `mmap-write-undo-linux.sh`,
   `sed-i-undo-linux.sh`, and `git-clean-fd-undo-linux.sh`.
3. **Boundary negatives:** cwd on `/mnt/c`; ext4 cwd writing `/mnt/c`; 9p or
   cross-distro share; experimental virtiofs share; SMB/NFS mount; and unknown
   filesystem. Every observed mutation must yield a durable command-wide
   refusal and `undo` must apply zero inverses.
4. **Interop negatives:** with interop enabled, candidate readiness is refused;
   with the supported profile, representative `cmd.exe`/`powershell.exe`
   launches fail. No command may appear safely empty.
5. **Lifecycle:** systemd enabled and disabled, hook-start fallback, distro
   terminate/restart, and `wsl.exe --shutdown` during an in-flight command.
   Recovery must not create a phantom applicable inverse.
6. **Host interference:** mutate a captured ext4 file through
   `\\wsl.localhost` after capture and prove replay reports a conflict rather
   than attributing the host write to the shell command.

**WSL0 gate:** exact ext4 pre-images and truthful loss/refusal behavior match
the Linux eBPF release subset on the pinned stock kernel. Unsupported mounts
and interop never produce an applicable inverse. If the stock kernel cannot
attach the full eBPF tier, or any bypass is silent, stop at an unsupported lab
report; do not require a custom kernel.

## WSL1 and WSL2 gates

### WSL1: bounded guest MVP

- Turn the WSL0 candidate policy into an always-on WSL runtime gate.
- Choose an explicit availability contract: retain experimental fail-open with
  unmistakable unobserved-command UX, or add an opt-in protected hook that
  blocks when readiness/refusal durability is unavailable.
- Make daemon/helper startup and stale endpoint recovery survive distro
  stop/start, with systemd and hook-started modes.
- Run 1,000 interactive commands plus Git/build/package workloads entirely on
  the distro ext4 filesystem.

**WSL1 gate:** no unobserved/refused command is shown as undoable, all supported
mutations round-trip, off-mount events poison the command, and VM shutdown
cannot turn a pending capture into a phantom inverse.

### WSL2: packaging and supported matrix

- Reuse the Linux `.deb`/generic tar inside the distro. Ship no Windows service
  or driver and do not call it native Windows support.
- Test install/upgrade/uninstall on every named Windows/WSL/kernel/distro tuple,
  with and without systemd and after WSL update/export/import/shutdown.
- Any optional PowerShell bootstrap only chooses a distro and invokes its
  verified Linux installer; it never bridges capture domains.
- Publish exclusions beside the install command.

**WSL2 gate:** the dedicated WSL matrix is a release requirement. A normal
Linux CI badge or a successful WSL install is not capture validation.

## Native Windows campaign

### Required architecture

```text
PowerShell 7 + pinned PSReadLine
        | synchronous command boundary and shell state
        v
per-user shitd.exe <--- ACL-scoped named pipes ---> shit.exe/module
        | journal, planner, blob store
        v
restricted Windows service
        | protected staging and privileged replay
        v
file-system minifilter
        | pre-operation callbacks and process lineage
        v
configured local NTFS roots
```

Keep user planning/history out of a machine-wide LocalSystem process. Named
pipes must use explicit user/service SID ACLs, reject remote clients, and
verify client PID, SID, logon session, and command binding. The service and
Filter Manager communication port need separate least-privilege identities and
ACLs.

Treat every arrow in the diagram as a protocol and crash boundary. In
protected mode, the driver cannot interpret a broken pipe, service restart,
full staging volume, timeout, malformed reply, or unknown command token as
permission to continue. The bounded outcome for an in-scope operation is
either `pre-image durable + pending journal durable + allow` or `deny before
commit`. A later user-daemon acknowledgement cannot retroactively make an
already-allowed mutation safe.

Windows file identity is volume serial plus 128-bit file ID, not `(dev,inode)`.
Paths remain native wide paths. Metadata must model attributes/timestamps,
self-relative security descriptors, alternate streams, reparse data, sparse/
compression/encryption state, and hard-link policy. Add Windows event/inverse
variants; do not change existing postcard-serialized POSIX field types in
place.

The authoritative native path representation must round-trip the OS-native
UTF-16 code units and namespace form needed to reopen the object; a normalized
display string may be stored separately for the UI and search. The SQLite
index should include an identity-kind tag, volume serial, 16-byte file ID, and
lossless path key. Migration tests must open every pre-Windows database and
decode every existing postcard fixture unchanged.

USN, ETW, and `ReadDirectoryChangesW` are reconciliation/audit signals, not
pre-image capture. VSS can support explicit coarse checkpoints, not default
per-command magic undo. ReFS block clone is a later optimization, not an NTFS
capture primitive.

### Native failure contract

- **Audit/demo:** may fail open, but never offers applicable file undo.
- **Explicit checkpoint:** restores only a named, fully snapshotted scope and
  is not described as command-attributed magic undo.
- **Protected mode:** PSReadLine does not return the accepted command until the
  daemon/service/driver/staging path is ready. The minifilter denies an
  individual in-scope mutation before commit if its exact pre-image cannot be
  made durable.

Protected mode is not a whole-command transaction. The journal must eventually
distinguish a mutation denied before commit from a capture gap after which the
command is poisoned.

### Decisive native feasibility risks

The native campaign has four independent stop/go questions. A success in one
does not waive another:

1. **Interactive boundary:** PSReadLine exposes command-validation and history
   callbacks, but those are not by themselves a complete pre/post execution
   transaction. WX1 must demonstrate a synchronous pre-boundary before every
   accepted interactive command and exactly one post-boundary after success,
   error, cancellation, multiline input, nested prompts, and profile changes.
   If that requires replacing the Enter key handler, the prototype must prove
   it composes with the pinned PSReadLine modes and restores prior handlers.
2. **Pre-image durability:** ordinary IRP-based operations can be pended, but
   Filter Manager cannot queue every operation shape the same way: documented
   deferred work-item pending excludes paging I/O and non-IRP operations.
   Memory-mapped changes are missed unless paging I/O/section creation is
   handled explicitly. WX2 must therefore prove the strategy for each I/O
   family instead of assuming an `IRP_MJ_WRITE` pre-callback is universal.
3. **Attribution:** a PID alone is reusable and paging or brokered I/O may not
   execute in the original command thread. Bind events to a process-creation
   identity plus logon/session and command token, prove descendant propagation,
   and reject or poison ambiguous handle-transfer, broker, and pre-existing
   writable-mapping cases. Do not attribute by image name or current PID lookup.
4. **Crash-consistent replay material:** the current blob store's Unix
   directory-open/fsync/rename behavior is not a Windows durability proof. The
   service must demonstrate a bounded, ACL-protected staging protocol and a
   recoverable pending-record/publication sequence across service crash,
   reboot, power loss, antivirus/filter interference, and volume exhaustion.

The candidate callback map below is a test inventory, not an implementation
claim:

| Mutation family | Candidate Windows surface to prove | Mandatory negative |
|---|---|---|
| create/supersede/open-for-write | `IRP_MJ_CREATE` disposition/access | reparse, oplock, share-mode, and create race |
| overwrite/append | IRP, fast-I/O, cached, and paging write paths | writable mapping created before command |
| truncate/allocation | `IRP_MJ_SET_INFORMATION` EOF/allocation classes | concurrent extend/truncate and sparse state |
| delete/delete-on-close | disposition information plus cleanup/close lifetime | multiple handles and last-link ambiguity |
| rename/replace/hard link | rename/link information classes | replace target and cross-volume move |
| attributes/timestamps/security | set-information and set-security families | unsupported ACL/reparse/ADS state |

For every row, the proof records the pre-operation object identity from an
opened handle, the exact durable bytes/metadata, the observed post-state used
for conflict checks, and the result under forced service/driver failure.

### WX0: portable seam, no support claim

- **WX0-A, dependency split:** move pure event classification/DAG building
  behind a platform-neutral library boundary. Feature/cfg-gate POSIX live
  probes, executors, process/service adapters, helper IPC, and Unix-only
  dependencies. `shit-proto` and the pure planner tests must compile for MSVC
  without compiling a fake POSIX executor.
- **WX0-B, schema design:** specify `PlatformPath`, `ObjectIdentity`, and
  metadata envelopes with explicit `Posix` and proposed `Windows` forms.
  Preserve the old variants and discriminants; use golden postcard fixtures to
  prove old bytes still decode. Decide the lossless UTF-16-on-disk encoding and
  case/namespace comparison rules before adding production events.
- **WX0-C, store seam:** remove the whole-planner dependency from the blob/index
  layer, add an identity-kind-aware schema migration, and keep display/search
  paths separate from authoritative path bytes. Exercise upgrade, rollback
  refusal, corrupt identity lengths, and old-database reads.
- **WX0-D, hosted CI:** run MSVC compile/tests for framing, pure planner,
  SQLite/blob primitives, and schema fixtures. Keep one Linux/macOS/FreeBSD
  old-journal matrix green on every schema change.

**Gate:** portable Windows tests pass natively and in hosted CI; no lossy path
or identity conversion occurs in authoritative state; all POSIX/old-journal
fixtures remain stable. The CLI, daemon, helper, and executor may still be
absent at this gate.

### WX1: user-mode vertical slice, audit only

- Prototype the PowerShell 7/PSReadLine boundary, per-user daemon, ACL-scoped
  message-mode named pipes, Windows state paths/locking, and a synthetic event.
- Exercise multiline/abort/nested/profile behavior and preserve existing prompt
  customizations.
- Record a state-machine trace for every input: accepted, pre-acknowledged,
  dispatched, completed/cancelled, post-acknowledged, and session-closed. Crash
  the module and daemon at each transition and reconcile open commands on the
  next start.
- Threat-test wrong SID/session/PID, remote clients, oversized/partial frames,
  reconnect, stale command IDs, and daemon crashes.

**Gate:** 1,000 interactive cycles have no lost/duplicate/misordered boundary;
unauthorized clients cannot journal or replay; every boundary failure is shown
as unobserved/audit-only; no artifact claims file undo. Non-interactive
PowerShell remains excluded unless it earns a separate boundary proof.

### WX2: decisive minifilter proof

- Use current WDK C/C++ minifilter samples and one dedicated local NTFS test
  root with a fixed ordinary-file size cap.
- Start with a standalone service/driver harness, not the production journal.
  Give every test mutation a command token and write an independently
  checkable pending-record/pre-image bundle.
- Hold each supported overwrite, append, truncate, create, delete,
  rename/replace, metadata, and security operation until its first pre-image
  and pending record are durable. Prove denial before commit for every capture
  failure; operations that cannot be held safely are exclusions, not degraded
  support.
- Cover cached/non-cached/paging I/O, writable mappings, atomic-save editors,
  delete-on-close, concurrency, and descendant attribution with PID creation
  identity.
- Separately test writable mappings created before the command, paging writes
  whose requestor is not the originating user thread, duplicated/inherited
  handles, and brokered writes. Unless attribution and pre-image timing are
  proven, each case must poison or be rejected before entering protected mode.
- Inject service/driver disconnect, timeout, cancellation, low memory, disk
  full, access denied, sharing/oplock conflicts, PID reuse, rename races,
  reboot, and power loss. Run Filter/Driver Verifier continuously.

**Go gate:** zero silent misses, wrong-user/command captures, phantom inverses,
hangs, corruption, or bugchecks. Every inability to protect either denies the
mutation before commit or, in an explicitly audit-only run, records a gap that
poisons undo. Failure means native magic undo stops here.

### WX3: Windows model and executor

- Add Windows identity/metadata/event variants only after WX2 passes.
- Implement handle-based live probes and replay with no-follow/reparse-aware
  opens, same-volume staging, durable replacement, and identity/post-state
  checks after each operation.
- Round-trip content, ADS, security descriptors, timestamps, attributes,
  supported reparse data, and the declared hard-link/sparse/compression policy.

**Gate:** every field in the narrow NTFS matrix round-trips exactly, every
unsupported field refuses before mutation, and crash/conflict tests remain
conservative. Only then may the project consider a signed limited MVP.

Initial native exclusions include EFS, unknown reparse tags, unproven sparse or
compressed combinations, incomplete hard-link topology, ReFS, network/UNC and
removable filesystems, Registry, services/firewall, background/breakaway jobs,
remoting, alternate PowerShell hosts, `cmd.exe`, Windows Server, and ARM64.

## Workstream ordering

Windows work can run beside the POSIX resurrection, but the gates form two
separate dependency chains:

```text
WSL0-A observability/policy -> WSL0-B real host harness -> WSL1 MVP -> WSL2 support

WX0 portable schema/core --+-> WX1 shell/IPC audit slice
                           +-> WX2 minifilter proof -> WX3 model/executor -> limited native MVP review
```

The parallelism boundary is deliberate. WSL0-A is Linux-only code and can be
reviewed without a Windows kernel developer. WX0 is Rust/schema work and can
run on hosted CI. WX1 needs a Windows/PowerShell owner. WX2 needs a dedicated
WDK/minifilter owner and disposable VM; it must not share a production-code PR
with WX0/WX1. WX3 does not begin until WX2's failure contract passes.

Each lane should publish a versioned evidence bundle containing source commit,
Windows build, WSL/PowerShell/PSReadLine or WDK versions, exact configuration,
test inventory, fault-injection results, and raw logs. A prose summary without
that bundle cannot advance a gate.

## CI and lab topology

- **Existing POSIX CI:** every seam change keeps Linux/macOS/FreeBSD and old
  postcard/SQLite fixtures green.
- **Dedicated WSL 2 runner:** real Store WSL, stock Microsoft kernel, ext4 VHDX,
  interop/mount negatives, host interference, and guest shutdown/restart. Do
  not substitute a Linux VM.
- **Hosted Windows user-mode CI:** MSVC compile, portable fixtures, PowerShell/
  Pester tests, named-pipe security tests, and installer lint. It earns no
  capture badge.
- **Disposable Windows 11 driver VM:** test-signed WX2/WX3 runs, fault
  injection, Filter/Driver Verifier, dumps, performance, reboot, install,
  upgrade, rollback, and uninstall. A hosted runner cannot replace this.

No Windows/WSL workflow exists in `.github/workflows` today. The current Linux
kernel job accepts either eBPF-LSM or fanotify
(`.github/workflows/dr-smoke.yml:2235-2309`), which is too weak for the WSL
contract above.

## Time-sensitive external evidence

These sources were rechecked on 2026-09-17. Pin exact versions in every test
result instead of treating this section as evergreen.

- WSL configuration, including default-on DrvFS automount/fstab processing,
  default-on interop/Windows `PATH`, `kernelCommandLine`, and experimental
  virtiofs:
  <https://learn.microsoft.com/en-us/windows/wsl/wsl-config>
- WSL architecture and ext4 VHDX:
  <https://learn.microsoft.com/en-us/windows/wsl/compare-versions> and
  <https://learn.microsoft.com/en-us/windows/wsl/disk-space>
- Systemd services do not keep a WSL instance alive:
  <https://learn.microsoft.com/en-us/windows/wsl/systemd>
- Current Microsoft WSL 6.18 x64 config. Relevant settings are
  `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`,
  `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`, `CONFIG_EXT4_FS=y`, and a default
  `CONFIG_LSM` string without `bpf`:
  <https://github.com/microsoft/WSL2-Linux-Kernel/blob/linux-msft-wsl-6.18.y/arch/x86/configs/config-wsl>
- Minifilter pre-operation callbacks, pending I/O, generated I/O, mapping
  caveats, section creation, and communication ports:
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-callback-routines>,
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/pending-an-i-o-operation-in-a-preoperation-callback-routine>,
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/i-o-requests-generated-by-the-minifilter-driver>,
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/memory-mapped-files-in-a-file-system-filter-driver>,
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization>, and
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode>
- PSReadLine's command-validation and history callback surfaces (neither is
  documented as a complete pre/post execution lifecycle):
  <https://learn.microsoft.com/en-us/powershell/module/psreadline/set-psreadlineoption?view=powershell-7.5>
- Stable Windows file identity and backup streams:
  <https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info>
  and
  <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupread>
- Named-pipe security and remote-client rejection:
  <https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights>
  and
  <https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew>
- Driver signing and minifilter altitude requirements:
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing>
  and
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request>

## Immediate next action

Implement WSL0-A and WSL0-B in an isolated branch and run them on a dedicated
Windows 11/WSL 2 machine. Do not start a broad native port. In parallel it is
safe to do WX0/WX1 and provision the disposable WDK VM, but every WX1 artifact
remains audit-only. A passing WSL0 unlocks WSL1; only a passing WX2 unlocks
Windows journal variants and WX3.
