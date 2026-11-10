# tools/macos-tart-vm: Tart guest for EndpointSecurity smokes

Sibling of `tools/freebsd-vm/` and `tools/linux-bpf-vm/` for the macOS
EndpointSecurity (ES) tier.

## What this is

On macOS, SIP-protected binaries (`/bin/rm`, `/bin/mv`, `/bin/cp`) do
not load the DYLD shim, so ES is the only way to capture what they do.
An ES client needs the `com.apple.developer.endpoint-security.client`
entitlement. Without an Apple-granted Developer ID profile, the only
way to test the helper is an ad-hoc signature on a macOS guest that has
SIP disabled and AMFI relaxed. These scripts wrap [Tart](https://tart.run)
to run that guest on an Apple Silicon host, so the host's own SIP stays
on.

The reference host is `nomad` (Apple Silicon, macOS 26). The guest
image is `ghcr.io/cirruslabs/macos-sequoia-base:latest` (macOS 15,
25.4 GB compressed, 50 GB disk). The guest must be the same macOS
version as the host or older. The `-base` image is the smallest Cirrus
image; it ships Homebrew and an `admin`/`admin` account with sshd on,
and no Rust toolchain.

## Disk budget

`tart pull` stores the image under `~/.tart/cache` (about 25 GB on
disk). `tart clone` is an APFS copy-on-write clone, so the VM costs
only what the guest writes on top. Check `df -h /` before pulling and
keep at least 15 GB free on the host. `boot.sh` keeps the image's 50
GB disk unless `SHIT_TART_DISK_GB` is set. Remove an unused image with
`tart delete ghcr.io/cirruslabs/<image>:latest`.

## Work directory

The scripts keep the guest's SSH key, a throwaway `known_hosts` and the
last guest IP in a work directory. It defaults to
`tools/macos-tart-vm/work/` (gitignored). Set `SHIT_TART_WORK_DIR` to
put it elsewhere. The `macos-es` workflow uses `$HOME/.shit-tart-vm`
so the key survives `actions/checkout`; use the same value by hand on
the runner host so CI and manual runs share one key:

```sh
export SHIT_TART_WORK_DIR="$HOME/.shit-tart-vm"
```

## One-time setup

```sh
brew install cirruslabs/cli/tart
df -h /
tart pull ghcr.io/cirruslabs/macos-sequoia-base:latest
df -h /

# Clone and start the guest headless. Prints the guest IP.
tools/macos-tart-vm/boot.sh

# Install the per-VM key in the guest (password: admin).
ssh-copy-id -i "$SHIT_TART_WORK_DIR/id_ed25519.pub" admin@"$(tart ip shit-m03)"
```

### Guest provisioning

Install Rust 1.88 in the guest:

```sh
tools/macos-tart-vm/ssh.sh \
  'curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.88'
```

### Disabling SIP in the guest

This step needs the guest's Recovery console, which only opens as a
window on the host's screen. It cannot be done over SSH. Do it at the
host's keyboard (or over Screen Sharing), in Terminal:

1. Stop the guest: `tart stop shit-m03`.
2. Start it in Recovery: `tart run --recovery shit-m03`. A window opens
   showing the Recovery startup screen.
3. Click Options, then Continue. If Recovery asks for a user, pick
   `admin` and enter the password `admin`.
4. In the menu bar, choose Utilities, then Terminal.
5. Run `csrutil disable`. Answer `y`, then give `admin` / `admin`
   when it asks for an administrator.
6. Run `csrutil authenticated-root disable` and answer the same way.
7. Run `nvram boot-args="amfi_get_out_of_my_way=1"`. With this AMFI
   accepts the ES entitlement on an ad-hoc signature.
8. Run `shutdown -h now`. The window closes when the guest stops.
9. Back on the host: `tools/macos-tart-vm/boot.sh`, then
   `tools/macos-tart-vm/doctor.sh`. It should print "SIP disabled" and
   "guest boot-args has amfi_get_out_of_my_way=1".

Leave the host's SIP, boot-args and nvram alone. All of the above runs
inside the guest.

## Running the ES smokes

```sh
# Build, ad-hoc sign the helper with the ES entitlement, and run one
# smoke as root in the guest.
tools/macos-tart-vm/run-es-smoke.sh tests/smoke/es-unlink-undo-macos.sh
```

`run-smoke.sh <script>` runs a smoke without the signing step, as the
guest's `admin` user.

## The macos-es runner

`.github/workflows/macos-es.yml` runs the ES smokes on a self-hosted
runner labelled `macos-es`. The runner executes jobs on the host as the
owner's user, so the workflow has no `pull_request` trigger: fork code
never runs there. It runs on `workflow_dispatch`, and on pushes to
`trunk` once the repo variable `MACOS_ES_ENABLED` is `true`.

## Scripts

- `boot.sh` clones the base image if no VM exists and starts it
  headless. Prints the guest IP when sshd is up.
- `ssh.sh` wraps `ssh` with the per-VM key and a throwaway
  `known_hosts`. Arguments go to ssh.
- `sync.sh` rsyncs the repo to `/Users/admin/shit` in the guest,
  without `target/`, `vendor/`, `.docs/`, `.refs/`, `.git/` and the VM
  tooling work dirs.
- `build-signed.sh` builds `shit-helper` in the guest and ad-hoc signs
  it with `packaging/codesign/macos-entitlements.plist`.
- `run-es-smoke.sh <script>` builds and signs the helper, builds `shit`
  and `shitd`, and runs the smoke as root.
- `run-smoke.sh <script>` syncs, builds and runs a smoke unsigned.
- `doctor.sh` reports VM state, SIP, guest boot-args, Rust, repo sync
  and whether the helper is built.
- `teardown.sh` stops and deletes the VM. The base image stays cached.

## Differences from the FreeBSD VM tooling

Tart gives the guest an address on a host-only network through its
built-in DHCP, and the scripts SSH to that address directly. The
FreeBSD tooling uses QEMU user networking with a port forward. First
boot of a fresh clone takes a few minutes; later boots take about 30
seconds.
