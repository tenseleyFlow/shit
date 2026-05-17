# Linux BPF-LSM VM tooling for `shit` development

Mirrors `tools/freebsd-vm/` for the Linux kernel-tier validation
surface (DR-01..DR-04 in `.docs/sprints/DEFERRED-RUNTIME.md`).

## Why a local VM and not bare metal

Per the project's standing rule (see `CLAUDE.md` and
`.docs/sprints/DEFERRED-RUNTIME.md` § "Standing rule"):

> Before any code path in this project transitions from a
> `NotImplemented` stub to a real syscall that the kernel can refuse
> (LSM verdict, cap mode entry, fanotify mark with non-trivial scope,
> ES allow/deny):
> 1. The blast-radius statement goes in the relevant audit doc.
> 2. The smoke binary uses the HP-18 watchdog pattern.
> 3. The runtime target is a VM, not the developer's workstation,
>    on first attempt. After three clean runs on the VM, workstation
>    runs are allowed but still must be operator-supervised.

The bare-metal `hasu` (NixOS) Linux box is reserved for *workstation*
runs after three clean VM cycles. This tooling provides those VM
cycles.

## Why Ubuntu 24.04 arm64

- **Kernel ≥6.8** ships with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`
  — both required for the aya program loader.
- **Apple Silicon-native** via `qemu-system-aarch64 -accel hvf`. No
  cross-arch emulation; fast iteration.
- **Cloud-init out of the box** — same NoCloud datasource pattern as
  the FreeBSD VM, so the provisioning shape is familiar.
- **`bpftool` and `libbpf-dev` packaged** — installed via apt in
  cloud-init runcmd.

## Why not Fedora / Debian / NixOS

- **Fedora** would also work; we pick Ubuntu LTS for the longer
  support window and the broader user base. The aya code we run
  is distro-agnostic; the chosen distro just needs the kernel
  config and the userspace tools.
- **Debian 13 (trixie)** as an alternative is fine; we'd swap the
  cloud image URL. Not pursued in v1.
- **NixOS** matches the hasu workstation. Reserved for workstation
  runs after the VM cycles succeed; provisioning NixOS under qemu
  is more involved.

## Prereqs

- macOS Apple Silicon (the arm64 cloud image we use doesn't run on
  Intel Macs without slow emulation).
- `qemu` (`brew install qemu`).
- ~5 GB free disk (cloud image + working disk + build artifacts).
- ~10 min of wall-clock the first time (image download + cloud-init
  + apt install + reboot for the LSM stack change).

## Scripts

| Script | Purpose |
|--------|---------|
| `provision.sh` | Download Ubuntu 24.04 arm64 cloud image, build a cidata ISO with cloud-init user-data, boot the VM, install packages, modify the kernel `lsm=` cmdline, schedule the LSM-stack reboot. |
| `boot.sh` | Boot the provisioned VM headless with SSH port-forwarded to `localhost:2226`. |
| `ssh.sh` | `ssh -p 2226 ubuntu@localhost ...` wrapper using the VM-only keypair. |
| `sync.sh` | rsync the codebase into the VM under `~/shit/`. |
| `doctor.sh` | Inside the VM: build `shit`, run `shit doctor`, then a *separate* LSM probe smoke that checks `/sys/kernel/security/lsm` contains `bpf` and `bpftool` is callable. |
| `teardown.sh` | Stop the VM and delete the working disk. Keeps the downloaded cloud image cached. |

## Working state directory

Everything lives under `tools/linux-bpf-vm/work/` which is
`.gitignore`d.

```
tools/linux-bpf-vm/work/
  noble-server-cloudimg-arm64.img    # downloaded base image
  ubuntu-noble-arm64.qcow2           # local working disk (resized)
  cidata.iso                         # cloud-init seed
  id_ed25519, id_ed25519.pub         # local-only SSH keypair
  vm.log                             # serial console log
  vm.pid                             # running qemu PID when up
```

## SSH port collision

This VM uses **port 2226** for SSH (Ubuntu) vs. the FreeBSD VM's
**2225**. Both VMs can run simultaneously on the same host.

## Standing-rule reminder

- This is the **only sanctioned path** for first-attempt exercise of
  the Linux LSM tier (DR-01..DR-04).
- After **three** clean VM runs, workstation (bare-metal hasu)
  runs are allowed but still must be operator-supervised — see
  `.docs/audits/linux-doctor-hasu.md` for the existing read-only
  baseline.
- Never install fanotify marks on filesystems we don't own (see
  HP-18 incident write-up).

## Teardown semantics

`teardown.sh` removes the qcow2 disk but keeps the downloaded base
image. Re-running `provision.sh` after teardown takes ~1 minute
(no re-download) vs. ~5 minutes from a cold start.

If you want a complete wipe (for a known-clean re-provision), delete
the entire `work/` directory by hand. The base image redownloads on
the next `provision.sh` run.
