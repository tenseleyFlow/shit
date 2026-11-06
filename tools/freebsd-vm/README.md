# FreeBSD VM tooling for `shit` development

Scripts in this directory provision a FreeBSD 14 VM under qemu for
validating the BSD capture tier without touching the developer
workstation or a shared host. Two host/guest pairs work:

| Host | Guest | qemu | Root FS | Extra |
|------|-------|------|---------|-------|
| x86_64 Linux (KVM) | amd64 | `qemu-system-x86_64` | UFS (same as CI) | 8 GB second disk as zpool `shitzfs`, dataset `shitzfs/tmp` at `/tmp/zfs` |
| Apple Silicon macOS (HVF) | arm64 | `qemu-system-aarch64` | ZFS | none |

The guest arch follows `uname -m` on the host. Override with
`FBSD_VM_ARCH=amd64|aarch64`.

## Why a local VM and not just CI

CI (`cross-platform-actions/action` on FreeBSD) is the *gating* test
surface, but iteration cadence on it is slow (10-15 min per PR). A
local VM lets us reproduce CI behavior in seconds without burning
GitHub minutes. CI runs FreeBSD 14.2 on UFS; the amd64 VM runs 14.4
on UFS with a ZFS pool beside it, so a smoke can run on either FS.

## Why qemu and not UTM / VirtualBuddy

UTM, VirtualBuddy, and other GUI tools use qemu under the hood. We
go direct so the workflow is scriptable and reproducible. Every boot
is headless; the first one runs nuageinit (FreeBSD's cloud-init) from
the cidata ISO.

## Why FreeBSD only and not also NetBSD / OpenBSD / DragonFly

Per the S10 sprint plan, FreeBSD is the primary BSD; the others are
best-effort and validated only via compile-and-link CI. If a future
sprint promotes one of them to primary, we add another script here.

## Prereqs

x86_64 Linux:

- `qemu-system-x86_64` and `qemu-img`, writable `/dev/kvm`.
- `mkisofs`, `genisoimage` or `xorriso` for the cidata ISO.
- `curl`, `xz`, `rsync`, `ssh-keygen`, `sha512sum`.
- ~15 GB free for the working disks. Put them outside the tree with
  `FBSD_VM_WORK_DIR=/mnt/space/shit-freebsd-vm` if the checkout is on
  a small disk.

Apple Silicon macOS:

- `qemu` from Homebrew (`brew install qemu`), which ships the edk2
  aarch64 firmware.
- ~10 GB free disk.

## Scripts

| Script | Purpose |
|--------|---------|
| `provision.sh` | Download the FreeBSD image into `download/`, verify it against the release `CHECKSUM.SHA512`, build a cidata ISO with an SSH key, boot once. On amd64 it waits for ssh and runs `guest-setup.sh`. |
| `guest-setup.sh` | Runs in the guest: the B04 job's packages plus `bash`, `doas.conf`, rustup 1.88 (amd64), zpool on the second disk. Idempotent. |
| `boot.sh [--wait]` | Boot the provisioned VM headless with SSH forwarded to 127.0.0.1:2225. |
| `ssh.sh` | `ssh -p 2225 freebsd@localhost ...` wrapper with a private known_hosts. |
| `sync.sh` | rsync the checkout into the VM under `~/shit/`. Excludes `target/`, `vendor/`, `.git`, `.docs/`, `.refs/`. |
| `run-smoke.sh <name>` | sync, release build, run one `tests/smoke/<name>`. `SMOKE_TMPDIR=/tmp/zfs` runs it on ZFS. |
| `run-fbsd-smokes.sh [name ...]` | sync, then the B04 job's loop: pf, doctor gate, the `freebsd-vm` bucket under `timeout 300`, per-smoke TSV copied to the work dir. |
| `doctor.sh` | Build `shit` in the VM and print `shit doctor`. |
| `teardown.sh [--stop]` | Power the guest off; without `--stop`, delete the disks. The downloaded image stays cached. |

Typical x86_64 loop:

```
export FBSD_VM_WORK_DIR=/mnt/space/shit-freebsd-vm
tools/freebsd-vm/provision.sh            # first time only
tools/freebsd-vm/boot.sh --wait          # later sessions
tools/freebsd-vm/run-smoke.sh rm-undo-fbsd.sh
tools/freebsd-vm/run-fbsd-smokes.sh                         # UFS, whole bucket
SMOKE_TMPDIR=/tmp/zfs tools/freebsd-vm/run-fbsd-smokes.sh   # same on ZFS
tools/freebsd-vm/teardown.sh --stop
```

The local VM uses rustup 1.88; the B04 CI job still installs pkg
rust, so a lint-only or codegen difference between the two is
possible.

## Working state directory

Everything lives under `tools/freebsd-vm/work/` (gitignored) or
`$FBSD_VM_WORK_DIR`.

```
work/
  download/FreeBSD-*.qcow2.xz   # downloaded base image + CHECKSUM.SHA512
  freebsd14-amd64.qcow2         # working root disk (arm64: freebsd14-arm64.qcow2)
  zpool-disk.qcow2              # amd64 only: second disk for shitzfs
  efivars.fd                    # arm64 only
  cidata.iso                    # cloud-init seed (regenerated each provision)
  id_ed25519, id_ed25519.pub    # local-only SSH key pair
  known_hosts                   # the VM's host key, kept out of ~/.ssh
  vm.log                        # serial console log
  vm.pid                        # running qemu PID when up
  smoke-results-{ufs,zfs}.tsv   # last run-fbsd-smokes.sh results
```

## Standing rule (paired with `DEFERRED-RUNTIME.md` standing rule)

These scripts are the **only** sanctioned way to exercise BSD
runtime-tier code in this project. A future sprint that wants to add
a different mechanism (UTM-based dev loop, Vagrant box, Tart-based,
etc.) must:

1. Pass `shit doctor` runtime check on the existing qemu path first.
2. Add an audit-doc entry explaining the new mechanism's blast radius
   and how it complies with the "VM-first runtime" rule.
3. Get a written go-ahead. Don't add a path that ends in `sudo` on the
   workstation.
