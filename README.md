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
- **`shit-helper`** — a privileged helper that drives kernel-level capture: EndpointSecurity on macOS, fanotify-perm + eBPF-LSM on Linux, kqueue + LD_PRELOAD shim on FreeBSD (the shim is the supported default; running without it is reported by `shit doctor` as the degraded `kqueue-only` tier). Falls back to FSEvents-degraded on un-entitled macOS installs.
- **shell hooks** (bash, zsh, fish) that bracket each command with metadata events sent over a per-user Unix-domain-socket.

When a command writes, renames, unlinks, or otherwise mutates a file inside a tracked process subtree, the helper captures the pre-image *before* the kernel allows the syscall to complete — using `clonefile` (APFS), `reflink` (btrfs/XFS), `zfs clone` (ZFS), hardlink, or streaming copy, picking the cheapest tier the underlying filesystem supports. Blobs land in a content-addressed store (blake3 + zstd) under `$XDG_STATE_HOME/shit/`. When you run `shit undo`, the daemon's planner walks the captured events, computes an inverse-op DAG, shows you exactly what it'll do, and applies it on your `y`.

Honesty principle: any command class we cannot mechanically reverse goes in the [refuse-list catalog](#refuse-list-what-we-explicitly-wont-undo) — `shit undo` exits non-zero with a one-line reason rather than silently producing a partial undo.

## Coverage today

Each entry below has a green CI smoke. The capture mechanism column is named at the kernel surface that fires, not the user-facing tool. "LSM" means the helper's eBPF program is attached to the named hook (`bpf_lsm_<hook>`); "shim" means the LD_PRELOAD shim in `crates/shit-preload-shim/`; "wrapper" means a packaging wrapper script in `packaging/` that brackets the real binary with `shit-helper <tool>-event`.

### Linux

**Filesystem mutations** (eBPF-LSM tier — requires `lsm=bpf` in `/sys/kernel/security/lsm` + `cap_bpf,cap_perfmon,cap_sys_admin` on the helper):

| Class | LSM hook | Smoke |
|---|---|---|
| `rm` / `unlink` / `unlinkat` | `inode_unlink` | `rm-undo-linux.sh` |
| `rmdir` / `unlinkat(AT_REMOVEDIR)` (carries dir mode for accurate restore) | `inode_rmdir` (G03) | `git-clean-fd-undo-linux.sh` |
| `chmod`, `chown`, `chgrp`, `utimes`, `truncate` | `inode_setattr` (v1/v2 BTF-dispatch for kernel ≥7.0 `mnt_idmap` drift) | `chmod-undo-linux.sh`, `chown-undo-linux.sh` |
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
| `git clean -fd` (files + directories at captured mode) | `git-clean-fd-undo-linux.sh` |

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

**Container / orchestration** (helper-side `container-event` wrapper captures `docker inspect` JSON pre-mutation; planner walks the JSON to reconstruct a `docker run` argv with ~15 flags):

| Workload | Smoke |
|---|---|
| `docker rm` (full container restore from `docker save` + inspect-JSON argv synthesis) | `docker-rm-undo-linux.sh` |
| `docker rmi` (image tag restore via `docker load`) | `docker-rmi-undo-linux.sh` |
| `docker volume rm` (volume tar stash + restore) | `docker-volume-rm-undo-linux.sh` |
| `docker network rm` (network spec replay) | `docker-network-rm-undo-linux.sh` |
| `docker compose down` (compose project snapshot + `up -d` replay) | `docker-compose-down-undo-linux.sh` |
| `podman rm` (cross-runtime delegation through the same path) | `podman-rm-undo-linux.sh` |

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

Capture tier: EndpointSecurity (M03 — entitled installs) with FSEvents-degraded fallback (M01 — un-entitled, no Apple Developer ID required). The helper auto-selects at boot: ES when the entitlement is granted, FSEvents otherwise. `shit doctor` reports the active tier.

| Class | Capture | Smoke |
|---|---|---|
| `rm` / `unlink` | ES `AUTH_UNLINK` | `es-unlink-undo-macos.sh` |
| `mv` / `rename` | ES `AUTH_RENAME` | `es-rename-undo-macos.sh` |
| `truncate` / `ftruncate` | ES `AUTH_TRUNCATE` | `es-truncate-undo-macos.sh` |
| content overwrites via `open(O_WRONLY)` | ES `AUTH_OPEN` + clonefile pre-image | `es-open-write-undo-macos.sh` |
| `chmod` / `chown` / `utimes` (metadata) | ES `AUTH_SETATTRLIST` | `es-chmod-metadata-macos.sh` |
| xattr round-trip | ES + xattr capture (M03.x.XATTR) | `es-xattr-roundtrip-macos.sh` |
| FSEvents fallback (un-entitled) | post-hoc kqueue-style notifications, no pre-image | `fsevents-fallback-macos.sh` |
| `brew install / uninstall` | brew JSON snapshot wrapper | `brew-pkg.sh` |
| `sqlite3 file.db "<sql>"` | shim pre-image | `sqlite3-db.sh` |

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

- **`>>` append / `tee -a` Linux smoke** — the FileExtend wire + planner + executor all shipped in C06 (`InverseOp::FileExtend { truncate_to: pre_size }`, `FileExecutor::apply_file_extend`); pipeline integration tests in `shit-shell::c06_pipeline` are green. The remaining gap is a pinned Linux smoke — FreeBSD has `shell-append-undo-fbsd.sh` covering the round-trip; Linux needs the equivalent (proposed campaign: `AR-append-smoke-linux`).
- **`docker pull <floating-tag>` digest journaling** — DR-CR-51. Post-phase reconciliation reserved but not implemented.
- **multi-target `docker rmi a b c` batching** — DR-CR-52. Today only the first positional is journaled.
- **Packaging install hooks** — `apt install shit` → `doctor`-green is the AR09 sprint goal. Today the daemon must be built + setcap'd manually.
- **mknod / mkfifo via privileged helper** — `RecreatePath` for fifo/socket/block/char kinds returns `Failed { err: "needs helper-IPC privileged-op routing (DR-15.1)" }`. The chown path is wired; mknod via helper is the remainder.

### FreeBSD

- **NetBSD / OpenBSD / DragonFly** — explicitly post-v1 stretch (B06). Today the helper compiles only on FreeBSD; the other BSDs have an untested kqueue port.
- **Perf budgets** — B07 wires a benchmark harness with regression gates. The Linux side is in place; BSD budgets land alongside the perf-bsd-14 CI gate.

### macOS

- **Notarized helper distribution** — M04 sprint. Today the entitled-ES path requires a self-built helper with a developer-signed entitlement. Codesign self-verify infrastructure shipped in M07.C (the daemon refuses helpers whose code signature doesn't validate); the remaining M04 work is the signed-distribution + notarize CI pipeline so a `brew install shit` ships a ready-to-run binary. Un-entitled installs already get FSEvents-degraded capture out of the box.
- **DYLD interposer auto-install** — DR-CR-34. The interposer itself shipped via M07.A (`shit dyld-hooks install` writes the shim to `/usr/local/lib/libshit_preload_shim.dylib` and the M07.B.5 smoke validates end-to-end against brew's `gchmod`, a non-SIP binary). The remaining work is package-manager auto-install (so `brew install shit` configures DYLD on first run), and the auth-event coverage for the long tail of dyld-strippable syscalls. SIP-protected system binaries are intentionally out of scope — Apple strips `DYLD_INSERT_LIBRARIES` on those by design.
- **M03.x follow-ups** — see `.docs/sprints/macos/M03.x-followup-roadmap.md` for the precise list (AUTH_LINK / AUTH_MMAP / AUTH_SETFLAGS / AUTH_CLONE handlers); each gates on a real-workload smoke surfacing the gap.

## Compatibility expectations

These should work in practice once the underlying mechanism is wired (no architectural blocker discovered), but they don't have a pinned smoke today:

- **`helm install / uninstall`** — same shape as `docker compose`; descriptor candidate in AR08.2.
- **`ufw allow / deny`, `firewall-cmd --add-port`** — both are thin wrappers over iptables/nft; descriptor candidates.
- **`npm install -g`, `gem install`** — same LD_PRELOAD shim path as `pip install --user`. AR08.2.
- **`useradd` (refusal)** — the `system-identity` refuse class catches it at plan-build time today (the refuse-list catalog is shipped in trunk); a pinned smoke would gate that the refusal stays loud.

## OS support matrix

| Capability | Linux (lsm=bpf) | Linux (no LSM) | FreeBSD | macOS (entitled ES) | macOS (FSEvents) |
|---|---|---|---|---|---|
| filesystem capture | ✅ eBPF-LSM (10 hooks: unlink/rmdir/setattr/mkdir/create/rename/symlink/link/file_open/file_release) | ⚠️ fanotify-perm fallback | ✅ kqueue + Capsicum sandbox | ✅ EndpointSecurity AUTH events | ⚠️ post-hoc only, no pre-image |
| pre-image via CoW | ✅ reflink/btrfs/XFS/zfs | ✅ same | ✅ zfs clone / hardlink | ✅ APFS clonefile | ✅ APFS clonefile |
| LD_PRELOAD shim | ✅ install-pattern auto-inject | ✅ same | ✅ | ✅ DYLD interposer (M07.A install + M07.B.5 chmod smoke); SIP binaries excluded by Apple | ✅ same |
| package undo | ✅ apt, dnf | ✅ same | ✅ pkg | ✅ brew | ✅ brew |
| container undo | ✅ docker, podman, compose | ✅ same | ⚠️ untested | ⚠️ untested | ⚠️ untested |
| cloud undo | ✅ terraform, kubectl, gh | ✅ same | ⚠️ untested | ⚠️ untested | ⚠️ untested |
| services | ✅ systemctl | ✅ same | ✅ service | ⚠️ launchctl untested | ⚠️ launchctl untested |
| firewall | ✅ nft, iptables | ✅ same | ✅ pfctl | ❌ | ❌ |
| shell hook | ✅ bash, zsh, fish | ✅ same | ✅ bash | ⚠️ shell hooks untested | ⚠️ shell hooks untested |

✅ has a green CI smoke today; ⚠️ structurally plausible but unpinned; ❌ not yet built.

## Coverage matrix in JSON

`shit doctor --json` emits `arbitrary_undo_coverage` with two stable fields you can pin a CI gate to:

```json
"arbitrary_undo_coverage": {
  "covered_classes": ["container-rm", "container-rmi", "fs-content-restore", "fs-metadata", "fs-rename", "fs-tree", "kubectl-delete", "package-apt", "package-dnf", "package-brew", "preload-install", "process-note", "redirect-truncate", "service-systemctl", "tool-gh", "tool-network", "tool-terraform", "..."],
  "refused_classes": ["remote-push", "history-rewrite", "identity-generation", "power-state", "sandbox-escape", "opaque-shell-mutation", "system-identity"],
  "coverage_pct": 74,
  "last_validated_at": ""
}
```

The `covered_classes` list is hand-curated against the AR08.1 audit; the `refused_classes` list is enumerated from `shit-planner::refuse::CATALOG` at runtime so the two cannot drift.

## License

AGPLv3. See [LICENSE](./LICENSE).
