# shit

magic undo for the command line

You just made a mistake on the command line — an edit, a botched `mv`, a `rm` that took more than you meant — and you want to undo its *effects*. `shit` watches the right kernel surfaces, captures pre-images cheaply via your filesystem's native copy-on-write, and produces an approvable undo plan.

## Status

Pre-1.0. APIs, wire formats, and on-disk layouts are unstable. The headline claim — "arbitrary command undo" — is honest only for the classes pinned by a green CI smoke today; see [Coverage today](#coverage-today) and [What doesn't work yet](#what-doesnt-work-yet) for the precise picture.

## Install

Coming soon: `brew install tenseleyFlow/tap/shit`, AUR (`shit-bin`), FreeBSD ports, and a signed `curl … | sh`.

## Dev quickstart

```sh
git clone https://github.com/tenseleyFlow/shit
cd shit
make dev    # cargo build --workspace
make test   # cargo test --workspace
make lint   # cargo clippy
make ci     # everything CI runs
```

## How it works

`shit` is three binaries plus shell glue:

- **`shit`** — the CLI: `shit undo`, `shit redo`, `shit list`, `shit show`, `shit pin`, `shit doctor`, …
- **`shitd`** — a per-user daemon that owns the snapshot store, the sqlite index, the IPC sockets, and the undo planner.
- **`shit-helper`** — a privileged helper that drives kernel-level capture: EndpointSecurity on macOS, fanotify-perm + eBPF-LSM on Linux, kqueue + LD_PRELOAD shim on FreeBSD (the shim is the supported default; running without it is reported by `shit doctor` as the degraded `kqueue-only` tier). On un-entitled macOS installs, FSEvents supplies watch readiness and post-hoc diagnostics; actionable default-mode capture comes from the DYLD interposer.
- **shell hooks** (bash, zsh, fish) that bracket each command with metadata events sent over a per-user Unix-domain-socket.

For supported mutations, the capture tier records the pre-image before the mutation: kernel authorization tiers do so before allowing the syscall, while LD_PRELOAD/DYLD interposers capture before calling libc and publish the event only if the call succeeds. Depending on the active tier and filesystem, production capture uses `clonefile` (APFS), `reflink` (btrfs/XFS), hardlink, or bounded streaming copy. Degraded observers such as macOS FSEvents emit partial events for readiness and diagnostics; if one of those observations remains in a command's journal, the planner refuses the whole command and emits no executable inverses. Blobs land in a content-addressed store (blake3 + zstd) under `$XDG_STATE_HOME/shit/`. When you run `shit undo`, the daemon's planner walks the captured events, computes an inverse-op DAG, shows you exactly what it'll do, and applies it on your `y`.

Honesty principle: any command class we cannot mechanically reverse goes in the [refuse-list catalog](#refuse-list-what-we-explicitly-wont-undo) — `shit undo` exits non-zero with a one-line reason rather than silently producing a partial undo.

## Coverage today

Each entry below has a green CI smoke. Where the safe behavior is an explicit refusal rather than an undo, the row says so. The capture mechanism column is named at the kernel surface that fires, not the user-facing tool. "LSM" means the helper's eBPF program is attached to the named hook (`bpf_lsm_<hook>`); "shim" means the LD_PRELOAD shim in `crates/shit-preload-shim/`; "wrapper" means a packaging wrapper script in `packaging/` that brackets the real binary with `shit-helper <tool>-event`.

A handful of smokes (`daemon-boot.sh`, `brew-pkg.sh`, `sqlite3-db.sh`) are **tier-agnostic** — they branch on the runtime platform inside the script and run unchanged on Linux, FreeBSD, and macOS. The smoke-driver auto-buckets them into every available CI runner.

### Linux

**Filesystem mutations** (eBPF-LSM tier — requires `lsm=bpf` in `/sys/kernel/security/lsm` + `cap_bpf,cap_perfmon,cap_sys_admin` on the helper):

| Class | LSM hook | Smoke |
|---|---|---|
| `rm` / `unlink` / `unlinkat` | `inode_unlink` | `rm-undo-linux.sh` |
| `rmdir` / `unlinkat(AT_REMOVEDIR)` | `inode_rmdir`; captures a typed metadata-only marker, then refuses because complete directory metadata cannot yet be replayed | `rmdir-undo-lsm-tier-linux.sh` |
| create a FIFO with `mkfifo` | `inode_create`; inverse removes the newly created path | `mkfifo-undo-linux.sh` |
| delete a pre-existing FIFO | `inode_unlink`; captures a typed metadata-only marker, then refuses because complete FIFO metadata cannot yet be replayed | `mkfifo-restore-undo-linux.sh` |
| `chmod`, `chown`, `chgrp`, `truncate` | `inode_setattr` (v1/v2 BTF-dispatch for kernel ≥7.0 `mnt_idmap` drift) | `chmod-undo-linux.sh`, `chown-undo-linux.sh` |
| `mkdir` / `mkdirat` | `inode_mkdir` | `mkdir-undo-linux.sh` |
| `open(O_CREAT)` / `creat` | `inode_create` | covered via `edit-undo-linux.sh`, `touch-edit-undo-linux.sh` |
| `rename` / `renameat2` (atomic-replace, vim/git/sed dance, dir-rename recursive pre-image) | `inode_rename` (DR-CR-54 recursive subtree capture) | `mv-undo-linux.sh`, `vim-edit-undo-linux.sh`, `sed-i-undo-linux.sh`, `git-commit-undo-linux.sh`, `dir-rename-undo-linux.sh` |
| `symlink` / `symlinkat` (`ln -s`) | `inode_symlink` | `ln-symlink-undo-linux.sh` |
| `link` / `linkat` (hardlink) | `inode_link` | `ln-hardlink-undo-linux.sh` |
| `open(O_TRUNC \| O_WRONLY)` (content overwrites) | `file_open` + live-baseline pre-image | `edit-undo-linux.sh`, `cp-r-undo-linux.sh` |
| `open(O_RDWR) + write/pwrite` (in-place writes, no truncate) | `file_open` + `file_release` content-diff refinement (L04.2, best-effort on kernel ≥7.0) | `write-in-place-undo-linux.sh` |
| `mmap(MAP_SHARED)` writes | same as above; release fires on last unmap+close | `mmap-write-undo-linux.sh` |
| `cmd > existing-file` (shell-pre-stash race) | C06 redirect parser in the bash DEBUG trap → `PreStashRedirects` ctl | `redirect-race-undo-linux.sh`, `dd-of-undo-linux.sh` |

**Destructive git operations** (G01 family — pre-image via the LSM rename/unlink path; the planner's `.git/` smart renderer presents them as single user-readable lines):

| Class | Smoke |
|---|---|
| `git reset --hard <sha>` — HEAD + worktree restore | `git-reset-hard-undo-linux.sh` |
| `git checkout -- <file>` — discard-edit restore | `git-checkout-file-undo-linux.sh` |
| `git checkout <branch>` — branch-switch restore | `git-checkout-branch-undo-linux.sh` |
| `git stash drop` — `.git/refs/stash` rewrite | `git-stash-drop-undo-linux.sh` |
| `git branch -D` (loose ref) | `git-branch-D-undo-linux.sh` |
| `git branch -D` (packed-refs path — `git pack-refs --all` collapsed shape) | `git-branch-D-packed-undo-linux.sh` |
| `git clean -fd` — command-atomic refusal when directory deletion is present; captured file inverses are not partially applied | `git-clean-fd-undo-linux.sh` |

**Shell-state mutations** (DEBUG-trap snapshot via `crates/shit-shell/src/state.rs` → `PreExecShellState` IPC → `ShellStateRestore` inverse, applied via the per-session precmd-queue mechanism — DR-CR-50):

| Class | Smoke |
|---|---|
| `cd <dir>` — pwd restore (bash + zsh + fish parity) | `cd-undo-linux.sh`, `cd-undo-zsh-linux.sh`, `cd-undo-fish-linux.sh` |
| `set -o errexit` / `set -e` — shell-opts restore (bash + zsh) | `set-e-undo-linux.sh`, `set-e-undo-zsh-linux.sh` |
| `alias name=val` — alias-table restore | `alias-undo-linux.sh` |

**Build-install pre-image capture** (LD_PRELOAD shim — works without LSM caps, opt-in via the install-pattern auto-detector in `crates/shit/src/auto_inject.rs`):

| Workload | Smoke |
|---|---|
| `make install PREFIX=…` writing into a non-watched prefix | `make-install-undo-linux.sh` |
| `cargo install --force` overwriting an existing binary | `cargo-install-force-undo-linux.sh` |
| `pip install --user --force-reinstall` overwriting a module | `pip-install-user-undo-linux.sh` (Outcome A via DR-CR-54 recursive pre-image; Outcome B graceful fallback) |

**Native-undo delegation + synthesis fallback** (helper hooks the package manager via apt's `DPkg::Pre-Install-Pkgs` / dnf's plugin / brew's `--json` snapshot):

| Tool | Path | Smoke |
|---|---|---|
| `apt-get install / remove` (≥3.2 with native rollback) | delegates to `apt-get history-rollback <id>` | `apt-history-rollback-linux.sh` |
| `apt-get install / remove` (<3.2) | synthesizes inverse `apt-get` invocation | `refuse-without-native-delegate.sh` (apt 2.8 path) |
| `dnf install / remove` | delegates to `dnf history undo <id>` | `dnf-history-undo-linux.sh` |
| `apt`-tier capture wire (DR-19) | `pkg-event` IPC + journal | `apt-pkg.sh` |

**Container / orchestration** uses an atomic prepare/runtime/finalize protocol. Positive undo coverage currently admits only one explicit, non-pruning image-tag removal against Docker's local `default` context. Route overrides, multiple targets, Podman, and other destructive verbs fail closed before the real runtime executes (exit 125). Installed wrappers enforce the same policy independently with a policy-specific `v3-rmi1` capability, and CLI/daemon startup atomically refreshes stale installed copies after an upgrade.

`PREPARED` and `CONFIRMED` batches protect their archive stashes regardless of age because capture may still be authorizing or the runtime may still be executing. A successful wrapper report advances the batch to durable `FINALIZED`: its inverse stays actionable, while the normal 24-hour stash window starts from the persisted runtime-completion time. `REFUSED` and `FINALIZED` batches return to ordinary command/GC retention, shared archive hashes use the latest referencing finalization time, and new retained container evidence is refused before publication above a 5 GiB hard ceiling.

| Workload | Current policy | Smoke |
|---|---|---|
| `docker rmi --no-prune <tag>` (one tag, local `default` context) | supported: pre-runtime `CONFIRMED` binds a tag-free archive to the immutable image ID; wrapper completion records `FINALIZED`; undo loads and conditionally restores that tag | `docker-rmi-undo-linux.sh` |
| `docker rmi --no-prune <tag> <tag> ...`, route overrides, or Podman `rmi` | refused before runtime; every image remains intact | `docker-rmi-multi-target-undo-linux.sh` |
| `docker rm`, `podman rm` | refused before runtime; the container remains intact | `docker-rm-undo-linux.sh`, `podman-rm-undo-linux.sh` |
| `docker volume rm` | refused before runtime; the volume and its contents remain intact | `docker-volume-rm-undo-linux.sh` |
| `docker network rm` | refused before runtime; the network remains intact | `docker-network-rm-undo-linux.sh` |
| `docker compose down` | refused before runtime; the project remains running | `docker-compose-down-undo-linux.sh` |

**Cloud / IaC** (helper-side `cloud-event` wrapper captures tool state pre-mutation):

| Workload | Capture | Smoke |
|---|---|---|
| `terraform apply` | reverse via `terraform destroy` | `terraform-apply-undo-linux.sh` |
| `terraform destroy` | reverse via state-push + `terraform apply` | `terraform-destroy-undo-linux.sh` |
| `kubectl delete <resource>` | reverse via captured-YAML `apply -f -` (context-drift gated) | `kubectl-delete-undo-linux.sh` (kind cluster) |
| `gh release delete` | reverse via `gh release create` from captured metadata + asset list | `gh-release-delete-undo-linux.sh` |

**Services / networking / processes**:

| Workload | Mechanism | Smoke |
|---|---|---|
| `systemctl stop / start / enable / disable` | wrapper → `svc-event` IPC → planner `SystemdRollback` | `systemctl-stop-undo-linux.sh`, `systemctl-svc.sh` |
| `nft add table / chain / rule` | wrapper → `net-event` IPC | `nft-net.sh` |
| `iptables -N / -A / -D` | wrapper → `net-event` IPC | `iptables-net-linux.sh` |
| `kill / pkill / killall` | wrapper → `proc-event` IPC; informational + restart-hint (no reanimation) | `kill-proc-undo-linux.sh` |
| `sqlite3 file.db "<sql>"` | shim → file pre-image; sqlite WAL-aware | `sqlite3-db.sh` |

### FreeBSD

Capture tier: kqueue (`EVFILT_VNODE` NOTE_WRITE/RENAME/DELETE/ATTRIB) + LD_PRELOAD shim for the cross-watch / install-overwrite race. The shim is the supported default; `shit doctor` reports the `kqueue-only` tier when the shim is missing and surfaces a multi-line WARN block telling you which classes of pre-image you lose. Capsicum sandbox is default-on (B05); set `SHIT_CAPSICUM=0` to opt out.

An experimental per-event ZFS clone engine exists and is validated in isolation by `zfs-clone-primitives-fbsd.sh` and `zfs-clone-engine-fbsd.sh`, but it is not yet called by the production helper or daemon. Current BSD capture uses kqueue plus the preload shim and bounded staging/streaming; the ZFS smokes are engine tests, not a production-tier support claim.

| Class | Smoke |
|---|---|
| `rm`, `mv` (same-dir / cross-dir / dir), `ln` (sym + hard), `cp -r`, `mkdir -p`, `mkfifo` | `rm-undo-fbsd.sh`, `mv-{dir,across-dirs,noop}-undo-fbsd.sh`, `ln-{symlink,hardlink}-undo-fbsd.sh`, etc. |
| `chmod` (regular + recursive + setuid), `chown` (gid) | `chmod-{undo,recursive,setuid}-undo-fbsd.sh`, `chown-undo-fbsd.sh` |
| `cmd > file`, `cmd >> file`, `tee`, `dd of=`, `dd conv=notrunc` (partial writes), `awk -i inplace`, `sort -o`, `sed -i` | `shell-{redirect,append}-undo-fbsd.sh`, `tee-undo-fbsd.sh`, `dd-{large-file,notrunc}-undo-fbsd.sh`, etc. |
| `vim :wq`, `git commit`, atomic-rename save dances | `vim-edit-undo-fbsd.sh`, `git-commit-undo-fbsd.sh` |
| `pkg install` | `pkg-install-undo-fbsd.sh` |
| `pfctl -f`, `pfctl -F all` (firewall add + flush) | `pfctl-{add,flush}-undo-fbsd.sh` |
| `service restart`, `kill` (pattern resolution via sysctl `kern.proc.proc`) | `service-restart-undo-fbsd.sh`, `kill-proc-undo-fbsd.sh` |
| Long-tail: `tar -x`, `cpio -i`, `gzip`, `gunzip`, `patch -p1`, `rsync` (incremental), `xargs rm`, `find -exec rm`, `make install` (intra/cross-watch), backup-and-modify patterns | corresponding `-fbsd.sh` smokes |

### macOS

Capture tier: EndpointSecurity (M03 — entitled installs) or the DYLD interposer for eligible dynamically linked processes (un-entitled default installs). The helper also starts FSEvents in the default tier, but those post-hoc events are marked partial: they establish watch readiness and provide diagnostics, not pre-images. A persisted partial observation makes the command refusal-only; it is never silently dropped while other inverses run. Reconciliation is not yet persistent and order-independent, so this can conservatively refuse a command even when DYLD or ES also supplied authoritative evidence. The DYLD path does not cover SIP/platform or hardened-runtime binaries, statically linked programs, or direct syscalls. `shit doctor` reports the active helper tier.

| Class | Capture | Smoke |
|---|---|---|
| `rm` / `unlink` | ES `AUTH_UNLINK` | `es-unlink-undo-macos.sh` |
| `mv` / `rename` | ES `AUTH_RENAME` | `es-rename-undo-macos.sh` |
| `truncate` / `ftruncate` | ES `AUTH_TRUNCATE` | `es-truncate-undo-macos.sh` |
| content overwrites via `open(O_WRONLY)` | ES `AUTH_OPEN` + clonefile pre-image | `es-open-write-undo-macos.sh` |
| `chmod` / `chown` (metadata) | ES `AUTH_SETMODE` / `AUTH_SETOWNER` observation; explicit refusal until mode/ACL side effects have a lossless inverse | `es-chmod-metadata-macos.sh` |
| xattr round-trip | ES + xattr capture (M03.x.XATTR) | `es-xattr-roundtrip-macos.sh` |
| supported mutations from eligible non-platform processes | DYLD interposer pre-image, journaled only after syscall success | `chmod-undo-dyld-shim-macos.sh`, `make-install-undo-macos.sh`, `xattr-mutate-undo-macos.sh` |
| FSEvents fallback (un-entitled) | partial post-hoc notifications; readiness/diagnostics only, with command-atomic refusal if a partial row remains | `fsevents-fallback-macos.sh` |
| `brew install / uninstall` | brew JSON snapshot wrapper | `brew-pkg.sh` |
| `sqlite3 file.db "<sql>"` | shim pre-image | `sqlite3-db.sh` |

Timestamp setters are an explicit refusal on macOS today. The DYLD `utimes` / `futimes` / `futimens` / `utimensat` interposers and ES `AUTH_UTIMES` refuse rather than offer a lossy inverse because `FileMetadata` does not yet preserve atime. ES `AUTH_SETMODE` and `AUTH_SETOWNER` likewise refuse until ACL and ownership-induced mode changes can be modeled losslessly; eligible DYLD-interposed `chmod`/`chown` calls retain their narrower pre/post capture path.

M03.x follow-ups (`mkfifo`/`mknod` via AUTH_CREATE, `chflags`/extended-ACL via AUTH_SETFLAGS+AUTH_SETACL, hardlink via AUTH_LINK, MAP_SHARED mmap via AUTH_MMAP, AUTH_CLONE/AUTH_COPYFILE for `cp -c`) are tracked in `.docs/sprints/macos/M03.x-followup-roadmap.md` — promote to landed when a real-workload smoke surfaces the gap.

## Refuse-list: what we explicitly won't undo

The planner short-circuits these classes at plan-build time with a one-line reason + optional remediation, surfaced under a `Refused (out of scope for shit undo):` block in `shit undo` output and exposed as `arbitrary_undo_coverage.refused_classes` in `shit doctor --json`. The list is in `crates/shit-planner/src/refuse.rs`.

| Class | Examples | Why |
|---|---|---|
| **remote-push** | `git push`, `docker push`, `podman push`, `npm publish`, `cargo publish`, `gh release upload` | remote replication is outside our capture-tier visibility |
| **history-rewrite** | `git rebase -i`, `git filter-branch`, `git filter-repo` | rewrites ref topology in ways the event journal cannot mechanically reverse; use `git reflog` |
| **identity-generation** | `gpg --gen-key`, `gpg --full-gen-key`, `ssh-keygen` | key material may already be distributed; deleting the file cannot un-publish a public key |
| **power-state** | `shutdown`, `reboot`, `halt`, `poweroff` | no inverse operation exists |
| **sandbox-escape** | `chroot`, `unshare`, `nsenter` | namespace / chroot transitions move execution into a context our capture tier no longer observes |
| **opaque-shell-mutation** | `source script.sh`, `. script.sh` | sourcing mutates the parent shell in arbitrary ways we don't introspect |
| **system-identity** | `useradd`, `userdel`, `usermod`, `groupadd`, `groupdel`, `passwd` | PAM + shadow-file mutations touch state we won't trust ourselves to roll back without per-OS policy |

## What doesn't work yet

These are gaps where coverage is plausible but not yet shipped. Each item is tracked under `.docs/sprints/` (gitignored) with implementation notes.

### Linux

- **`>>` append / `tee -a` Linux smoke** — the append wire + planner + executor are present, and new plans use the inode-bound `InverseOp::FileExtendGuarded { inode, path, truncate_to: pre_size }`; the legacy `FileExtend` variant remains only for persisted-plan compatibility. Pipeline integration tests in `shit-shell::c06_pipeline` are green. The remaining gap is a pinned Linux smoke — FreeBSD has `shell-append-undo-fbsd.sh` covering the round-trip; Linux needs the equivalent (proposed campaign: `AR-append-smoke-linux`).
- **Timestamp updates that change atime** — an LSM event carrying `ATTR_ATIME` is explicitly refused while `FileMetadata` lacks atime; restoring only mtime would be lossy. No broader timestamp-syscall coverage is claimed when that signal is absent.
- **Directory and pre-existing FIFO deletion replay** — the LSM hooks capture authoritative typed metadata-only deletion markers, but the metadata model still omits fields needed for exact reconstruction (including atime and ACL state). The daemon therefore journals `CaptureRefused`, and the planner withholds every other inverse from the same command. The helper-side `mknod` route exists but is deliberately not invoked from incomplete evidence. This does not affect undoing FIFO *creation*: `mkfifo-undo-linux.sh` covers removing a FIFO created by the command.
- **`docker pull <floating-tag>` digest journaling** — DR-CR-51. Post-phase reconciliation reserved but not implemented.
- **Additional destructive container families** — `docker rm`, `podman rm`, `docker volume rm`, `docker network rm`, and `docker compose down` are not admitted by the atomic capture policy yet. Their wrappers deliberately exit 125 before runtime execution; fail-closed smokes verify the resources remain intact and no batch is confirmed.
- **Packaging install hooks** — `apt install shit` → `doctor`-green is the AR09 sprint goal. Today the daemon must be built + setcap'd manually.
- **Socket/block/character-device reconstruction policy** — pathname sockets cannot be recreated with their peer/bind state, while block/character devices need explicit device-number and privilege policy. These deletion shapes refuse rather than guessing; FIFO replay is additionally blocked on the complete-metadata gap above.

### FreeBSD

- **NetBSD / OpenBSD / DragonFly** — explicitly post-v1 stretch (B06). Today the helper compiles only on FreeBSD; the other BSDs have an untested kqueue port.
- **Interposition bypasses** — statically linked or setuid programs and code that issues direct syscalls bypass LD_PRELOAD. Kqueue can still promote a held-fd/baseline pre-image for an already watched target, but it cannot manufacture one for an unbaselined or cross-watch mutation; those bypass cases are not generally claimed as undoable.
- **Perf budgets** — B07 wires a benchmark harness with regression gates. The Linux side is in place; BSD budgets land alongside the perf-bsd-14 CI gate.

### macOS

- **Notarized helper distribution** — M04 sprint. Today the entitled-ES path requires a self-built helper with a developer-signed entitlement. Codesign self-verify infrastructure shipped in M07.C (the daemon refuses helpers whose code signature doesn't validate); the remaining M04 work is the signed-distribution + notarize CI pipeline so a `brew install shit` ships a ready-to-run binary. Un-entitled installs get FSEvents readiness/diagnostics out of the box, but actionable filesystem undo requires the DYLD interposer.
- **DYLD interposer auto-install** — DR-CR-34. The interposer itself shipped via M07.A: the archive/package places `libshit_preload_shim.dylib` in the library directory, while `shit dyld-hooks install` writes shell-rc snippets that point to it. The M07.B.5 smoke validates that path end-to-end against brew's `gchmod`, a non-SIP binary. The remaining work is package-manager auto-install (so `brew install shit` configures DYLD on first run), and coverage for the long tail of interposable libc calls. SIP/platform and hardened-runtime binaries, static binaries, and direct syscalls remain outside this path.
- **Timestamp setters** — `utimes`, `futimes`, `futimens`, `utimensat`, and ES `AUTH_UTIMES` explicitly refuse until the captured metadata model includes atime.
- **M03.x follow-ups** — see `.docs/sprints/macos/M03.x-followup-roadmap.md` for the precise list (AUTH_LINK / AUTH_MMAP / AUTH_SETFLAGS / AUTH_CLONE handlers); each gates on a real-workload smoke surfacing the gap.

## Compatibility expectations

These should work in practice once the underlying mechanism is wired (no architectural blocker discovered), but they don't have a pinned smoke today:

- **`helm install / uninstall`** — same shape as `docker compose`; descriptor candidate in AR08.2.
- **`ufw allow / deny`, `firewall-cmd --add-port`** — both are thin wrappers over iptables/nft; descriptor candidates.
- **`npm install -g`, `gem install`** — same LD_PRELOAD shim path as `pip install --user`. AR08.2.
- **`useradd` (refusal)** — the `system-identity` refuse class catches it at plan-build time today (the refuse-list catalog is shipped in trunk); a pinned smoke would gate that the refusal stays loud.

## OS support matrix

| Capability | Linux (lsm=bpf) | Linux (no LSM) | FreeBSD | macOS (entitled ES) | macOS (default: DYLD + FSEvents) |
|---|---|---|---|---|---|
| filesystem capture | ✅ eBPF-LSM (10 hooks: unlink/rmdir/setattr/mkdir/create/rename/symlink/link/file_open/file_release†; unsafe deletion shapes refuse) | ⚠️ fanotify-perm fallback | ✅ kqueue + Capsicum sandbox | ✅ EndpointSecurity AUTH events for supported families | ✅ DYLD for supported eligible libc calls; FSEvents is diagnostics-only |
| pre-image capture | ✅ regular-file bytes via reflink/btrfs/XFS; directory/FIFO deletion is metadata-only and refused | ✅ same for supported fanotify events | ✅ bounded staged copy from tracked descriptors; experimental ZFS clone engine is not production-wired | ✅ APFS clonefile | ✅ DYLD byte pre-images for supported calls; none from FSEvents |
| userspace interposer | ✅ LD_PRELOAD install-pattern auto-inject | ✅ same | ✅ LD_PRELOAD | ✅ DYLD interposer; platform/static/direct-syscall paths excluded | ✅ same |
| package undo | ✅ apt, dnf | ✅ same | ✅ pkg | ✅ brew | ✅ brew |
| container undo | ✅ Docker `rmi --no-prune` only; other destructive verbs exit 125 | ✅ same | ⚠️ untested | ⚠️ untested | ⚠️ untested |
| cloud undo | ✅ terraform, kubectl, gh | ✅ same | ⚠️ untested | ⚠️ untested | ⚠️ untested |
| services | ✅ systemctl | ✅ same | ✅ service | ⚠️ launchctl untested | ⚠️ launchctl untested |
| firewall | ✅ nft, iptables | ✅ same | ✅ pfctl | ❌ | ❌ |
| shell hook | ✅ bash, zsh, fish | ✅ same | ✅ bash | ⚠️ shell hooks untested | ⚠️ shell hooks untested |

✅ has a green CI smoke today; ⚠️ structurally plausible but unpinned; ❌ not yet built.

Windows is not a supported target. A native Windows port is currently a bounded feasibility experiment; WSL follows the Linux lane rather than constituting a separate native backend.

† `file_release` is the in-place-write capture hook; on Linux ≥ 7.0 the LSM chain entry takes an extra `mnt_idmap` arg and the helper picks the right v1/v2 entry-point at load time via a BTF probe. Older kernels (< 7.0) use the legacy single-arg signature. A verifier-rejected attach on either fork degrades the helper to the fanotify-perm fallback rather than crashing.

## Coverage matrix in JSON

`shit doctor --json` emits `arbitrary_undo_coverage` with three stable class lists, counts, and validation metadata you can pin a CI gate to:

```json
"arbitrary_undo_coverage": {
  "covered_classes": ["container-rmi", "fs-content-restore", "fs-metadata", "fs-post-hash-drift-detection", "fs-rename", "fs-tree", "kubectl-delete", "package-apt", "package-brew", "package-dnf", "preload-install", "process-note", "redirect-truncate", "service-systemctl", "shell-state", "tool-gh", "tool-network", "tool-terraform"],
  "refused_classes": ["remote-push", "history-rewrite", "identity-generation", "power-state", "sandbox-escape", "opaque-shell-mutation", "system-identity"],
  "pending_classes": ["bsd-shim-default", "container-compose", "container-network", "container-rm", "container-volume", "linux-cap-install-verify"],
  "covered_count": 18,
  "refused_count": 7,
  "pending_count": 6,
  "last_validated_at": "",
  "snapshot_workflow_run_url": "",
  "binary_built_at": "..."
}
```

The covered and pending lists come from `shit-planner::coverage_catalog`; the refused list comes from `shit-planner::refuse::CATALOG`. The doctor assembles all three from those code catalogs at runtime so its claims cannot drift from the planner's policy.

## License

AGPLv3. See [LICENSE](./LICENSE).
