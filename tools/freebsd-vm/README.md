# FreeBSD VM tooling for `shit` development

Scripts in this directory provision a FreeBSD 14 arm64 VM under
qemu-system-aarch64 for the explicit purpose of validating the BSD
capture tier (see `.docs/sprints/S10-bsd-tier.md`) without touching
the developer workstation or a shared host.

## Why a local VM and not just CI

CI (`cross-platform-actions/action` on FreeBSD) is the *gating* test
surface, but iteration cadence on it is slow (10-15 min per PR). A
local VM lets us reproduce CI behavior in seconds without burning
GitHub minutes. Same image, same kernel.

## Why qemu and not UTM / VirtualBuddy

UTM, VirtualBuddy, and other GUI tools use qemu under the hood. We
go direct so the workflow is scriptable and reproducible. The first
boot is interactive (cloud-init runs); subsequent boots are
headless.

## Why FreeBSD only and not also NetBSD / OpenBSD / DragonFly

Per the S10 sprint plan, FreeBSD is the primary BSD; the others are
best-effort and validated only via compile-and-link CI. If a future
sprint promotes one of them to primary, we add another script here.

## Prereqs

- macOS Apple Silicon (this is the only host the script targets — the
  arm64 FreeBSD images we use don't run on Intel Macs without
  emulation).
- `qemu` installed (`brew install qemu`).
- ~10 GB free disk for the VM image + downloaded base ISO.
- ~30 min of wall-clock the first time (image download +
  initial boot + cloud-init).

## Scripts

| Script | Purpose |
|--------|---------|
| `provision.sh` | Download FreeBSD 14 arm64 image, build a cidata ISO with an SSH key + a small first-boot script, boot the VM once to run cloud-init. |
| `boot.sh` | Boot the provisioned VM headless with SSH port-forwarded to localhost:2225. |
| `ssh.sh` | `ssh -p 2225 freebsd@localhost ...` wrapper. |
| `sync.sh` | rsync the codebase into the VM under `~/shit/`. Excludes `target/`, `vendor/` (re-vendored inside the VM), `.docs/`, `.refs/`. |
| `doctor.sh` | Inside the VM: ensure rust is installed, `cargo build --release -p shit`, `./target/release/shit doctor`, return output to the host for inclusion in audit docs. |
| `teardown.sh` | Stop the VM and delete the disk image. The downloaded base ISO stays cached for the next provision. |

## Working state directory

Everything lives under `tools/freebsd-vm/work/` which is `.gitignore`d.

```
tools/freebsd-vm/work/
  freebsd14-arm64.img.xz      # downloaded base image
  freebsd14-arm64.qcow2       # local working disk
  cidata.iso                  # cloud-init seed (one-off, regenerated)
  id_ed25519, id_ed25519.pub  # local-only SSH key pair
  vm.log                      # serial console log
  vm.pid                      # running qemu PID when up
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
