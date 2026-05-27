# tools/macos-tart-vm — Tart-based macOS dev VM for M03+

Mirror of `tools/freebsd-vm/` and `tools/linux-bpf-vm/` for the
macOS testing tier (M03 EndpointSecurity onwards).

## What this is

A scripted wrapper around [Tart](https://tart.run) that gives the
M03+ helper-side ES dev work a SIP-disabled macOS target, isolated
from the user's primary Mac. Apple-license compliant; runs only on
Apple Silicon hosts.

See `.docs/audits/macos-tart-vm-setup.md` for the full rationale +
manual setup instructions (especially the one-time SIP-disable step
that can't be scripted).

## Quick start

```sh
# One-time (separate from the scripts here):
brew install cirruslabs/cli/tart
tart pull ghcr.io/cirruslabs/macos-sonoma-base:latest

# Boot a fresh VM (clones the base image).
tools/macos-tart-vm/boot.sh

# (Manual: SIP-disable via Recovery — see audit doc.)

# Sync the repo into the VM.
tools/macos-tart-vm/sync.sh

# SSH in.
tools/macos-tart-vm/ssh.sh

# Run the M01 + M02 smoke as a baseline.
tools/macos-tart-vm/run-smoke.sh tests/smoke/fsevents-fallback-macos.sh

# Tear down (idempotent; safe to run anytime).
tools/macos-tart-vm/teardown.sh
```

## VM naming convention

The scripts default to a VM named `shit-m03` cloned from
`ghcr.io/cirruslabs/macos-sonoma-base:latest`. Override via
`SHIT_TART_VM` env var:

```sh
SHIT_TART_VM=shit-m04 tools/macos-tart-vm/boot.sh
```

## Scripts

- **`boot.sh`** — clones the base image (idempotent) and starts the
  VM in headless mode. Prints the assigned IP when ready.
- **`ssh.sh`** — wraps `ssh` with tart-friendly options (skips host-
  key checks since IPs are ephemeral). Pass-through args go to ssh.
- **`sync.sh`** — rsync the repo to the VM. Same exclude list as
  the FreeBSD VM (`target/`, `vendor/`, `.docs/`, `.refs/`, `.git/`,
  the VM tooling's own work dirs).
- **`run-smoke.sh <script>`** — sync + ssh + run the named smoke
  script on the VM. Smoke output streams back to the host stdout.
- **`doctor.sh`** — prints the VM's state: SIP status, sshd up,
  repo synced, last-built binary present.
- **`teardown.sh`** — `tart stop` + `tart delete`. Idempotent.

## Layout

```
tools/macos-tart-vm/
├── README.md                       # this file
├── boot.sh                         # tart clone + tart run --no-graphics &
├── ssh.sh                          # ssh wrapper
├── sync.sh                         # rsync push
├── run-smoke.sh                    # sync + ssh + run
├── doctor.sh                       # VM state snapshot
├── teardown.sh                     # tart stop + tart delete
└── work/                           # gitignored; per-VM ssh-keys + state
    ├── id_ed25519                  # generated on first boot.sh
    ├── id_ed25519.pub
    └── known_hosts                 # per-instance; throwaway
```

## Differences vs the FreeBSD VM tooling

- **No port-forwarding**: tart assigns the VM a real LAN IP via the
  built-in DHCP; we SSH to that IP directly. (`tools/freebsd-vm`
  uses QEMU usermode networking with `hostfwd=tcp:127.0.0.1:2225-:22`.)
- **No `install-tailscale.sh`** by default: Tailscale install on
  the guest is documented in the audit doc but not automated (the
  user does it once via the GUI; subsequent `boot.sh` runs preserve
  the guest's Tailscale state).
- **No `provision.sh`**: Cirrus base images come fully provisioned
  (Xcode CLI tools, Homebrew, Rust toolchain). We don't need our
  own provisioning recipe.
- **First-boot is slower** (~5 min) due to macOS Setup Assistant +
  Spotlight indexing. Subsequent boots are ~30 s.

## Cross-references

- `.docs/audits/macos-tart-vm-setup.md` — full setup + workflow doc
- `.docs/sprints/macos/M03-endpoint-security-client.md` — the M03
  sprint that consumes this tooling
- `tools/freebsd-vm/README.md` — sibling FreeBSD QEMU VM tooling
- `tools/linux-bpf-vm/README.md` — sibling Linux BPF-LSM VM tooling
