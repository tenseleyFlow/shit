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
image. It ships Homebrew, the Command Line Tools, the Tart guest agent
and an `admin`/`admin` account with sshd on and passwordless sudo. It
has no Rust toolchain. Cirrus builds it with SIP disabled and the boot
policy in Permissive mode, so `csrutil status` already reads
"disabled" on a fresh clone.

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

# Install the per-VM key in the guest through the guest agent.
K="$(cat "$SHIT_TART_WORK_DIR/id_ed25519.pub")"
tart exec shit-m03 /bin/sh -c \
  "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$K' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

`ssh-copy-id -i "$SHIT_TART_WORK_DIR/id_ed25519.pub" admin@"$(tart ip shit-m03)"`
with the password `admin` does the same.

### Guest provisioning

Install Rust 1.88 in the guest:

```sh
tools/macos-tart-vm/ssh.sh \
  'curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.88'
```

### SIP and AMFI in the guest

ES accepts an ad-hoc signed client only when SIP is disabled and AMFI
is relaxed with the boot-arg `amfi_get_out_of_my_way=1`. On the
sequoia-base image SIP is already off, so the boot-arg can be set over
SSH:

```sh
tools/macos-tart-vm/ssh.sh 'sudo nvram boot-args="amfi_get_out_of_my_way=1"'
# Shut down from inside the guest. `tart stop` does not keep NVRAM
# writes made in the running guest.
tools/macos-tart-vm/ssh.sh 'sudo shutdown -h now'
# Wait until `tart list` shows the VM stopped, then:
rm -f "$SHIT_TART_WORK_DIR/vm.ip"
tools/macos-tart-vm/boot.sh
tools/macos-tart-vm/ssh.sh 'sysctl kern.bootargs; csrutil status'
```

`doctor.sh` checks both. Leave the host's SIP, boot-args and nvram
alone; all of this runs inside the guest.

### Recovery fallback

If a guest image ships with SIP enabled, `csrutil` and `nvram
boot-args` can only be changed from the guest's Recovery console. It
opens as a window on the host's screen and cannot be driven over SSH.
At the host's keyboard (or over Screen Sharing), in Terminal:

1. Stop the guest: `tart stop shit-m03`.
2. Start it in Recovery: `tart run --recovery shit-m03`. A window opens
   on the Recovery startup screen.
3. Click Options, then Continue. If Recovery asks for a user, pick
   `admin` and enter the password `admin`.
4. In the menu bar, choose Utilities, then Terminal.
5. Run `csrutil disable`. Answer `y`, then give `admin` / `admin`
   when it asks for an administrator.
6. Run `nvram boot-args="amfi_get_out_of_my_way=1"`.
7. Run `shutdown -h now`. The window closes when the guest stops.
8. Back on the host: `rm -f "$SHIT_TART_WORK_DIR/vm.ip"`, then
   `tools/macos-tart-vm/boot.sh` and `tools/macos-tart-vm/doctor.sh`.
   It should print "SIP disabled" and "guest boot-args has
   amfi_get_out_of_my_way=1".

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
`trunk` once the repo variable `MACOS_ES_ENABLED` is `true`. The
smoke list is `tools/audit/smoke-driver.sh bucket macos-es`: every
smoke with `SMOKE_RUNNER_HINT: macos-es` and no `EXCLUDED_BY`. A smoke
that logs SKIP fails there, because this host meets every ES
precondition.

### Installing the runner

On the host, as the user that owns `~/.tart` and `~/.shit-tart-vm`:

```sh
mkdir -p ~/actions-runner-shit && cd ~/actions-runner-shit
curl -sSfLO https://github.com/actions/runner/releases/download/v2.338.2/actions-runner-osx-arm64-2.338.2.tar.gz
shasum -a 256 actions-runner-osx-arm64-2.338.2.tar.gz
# compare with the SHA in the release notes, then:
tar xzf actions-runner-osx-arm64-2.338.2.tar.gz
# token: gh api -X POST repos/tenseleyFlow/shit/actions/runners/registration-token --jq .token
./config.sh --unattended --url https://github.com/tenseleyFlow/shit \
  --token <token> --name nomad-macos-es --labels macos-es --work _work
./svc.sh install    # writes a launchd user agent in ~/Library/LaunchAgents
./svc.sh start
./svc.sh status
```

Once the runner shows Idle under Settings, Actions, Runners, set the
repo variable `MACOS_ES_ENABLED` to `true`
(`gh variable set MACOS_ES_ENABLED --body true --repo tenseleyFlow/shit`).

### Stopping and removing the runner

```sh
cd ~/actions-runner-shit
./svc.sh stop        # stop it; ./svc.sh start brings it back
./svc.sh uninstall   # remove the launchd agent
# token: gh api -X POST repos/tenseleyFlow/shit/actions/runners/remove-token --jq .token
./config.sh remove --token <token>
gh variable delete MACOS_ES_ENABLED --repo tenseleyFlow/shit
```

Then delete `~/actions-runner-shit`. Stopping the runner leaves the
guest running; `tart stop shit-m03` stops it, and
`tools/macos-tart-vm/teardown.sh` deletes it.

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
