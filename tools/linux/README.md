# tools/linux

Linux-side dev helpers. Most of these are for the bare-metal
validation box (hasu, via Tailscale); a couple bring sanity to the
local cargo loop.

## Files

- **`run-smoke.sh`** — rsync sources to hasu, `cargo build --release`
  remotely, then run one tests/smoke/`<name>`-undo-linux.sh script
  there. Use this in lieu of CI for fast iteration. Sets up
  `sudo -n setcap` opportunistically; falls back loudly to the
  manual command on no-NOPASSWD.
- **`sync.sh`** — rsync-only flavor of run-smoke.sh; useful when you
  want to build but not run.
- **`build-bpf.sh`** — compile the eBPF-LSM programs (vmlinux.h
  generation + clang -target bpf). Run on hasu, not locally.
- **`post-build-setcap.sh`** (AU08) — invoked by `make dev` and
  `make build` to reapply helper file caps after a cargo build
  strips them. See below.

## Dev loop without copy-pasting `sudo setcap`

The problem: every `cargo build` rewrites
`target/{debug,release}/shit-helper`, which strips its `setcap`
file capabilities. The next LSM-tier smoke then fails its
pre-flight ("FAIL: helper lacks cap_bpf"), and the operator has to
paste a `sudo setcap …` line.

AU08 closes the loop in three layers.

### 1. Opt in once: `SHIT_AUTO_SETCAP=1`

Add to your shell rc:

```bash
export SHIT_AUTO_SETCAP=1
```

With this exported, every `make dev` / `make build` invokes
`post-build-setcap.sh`, which runs `sudo -n setcap` on the freshly-
linked helper. Without `SHIT_AUTO_SETCAP=1` the script is a no-op
(no surprise sudo for users who didn't ask).

### 2. Grant NOPASSWD for `setcap` (one paste)

`sudo -n` refuses to prompt. You either configure NOPASSWD for
setcap or the post-build hook logs the manual command and moves on.

To get a paste-ready sudoers snippet covering every plausible
helper path on your machine:

```bash
shit doctor --emit-sudoers-snippet                  # generic
shit doctor --emit-sudoers-snippet --target nixos   # NixOS
```

**Debian / Ubuntu / Fedora / RHEL / Arch**: paste the generic
output into `/etc/sudoers.d/shit-dev` (via `sudo visudo -f`).
**NixOS**: paste the nixos output into `configuration.nix` and run
`sudo nixos-rebuild switch`. The snippet uses the declarative
`security.sudo.extraRules` form so it survives rebuilds.

### 3. Remediate after the fact: `shit doctor --fix`

If you forget to opt in, the doctor can fix things in-place when
NOPASSWD is set up:

```bash
$ shit doctor --fix
shit doctor --fix: helper caps missing; attempting setcap.
  sudo -n setcap cap_sys_admin,cap_bpf,cap_perfmon+ep /path/to/shit-helper
shit doctor --fix: caps applied successfully.
```

When NOPASSWD isn't set up, `--fix` exits non-zero and prints both
the manual command and a pointer back to
`--emit-sudoers-snippet`.

The doctor also distinguishes "first-time setcap" from "caps
existed but a rebuild stripped them" via a sentinel file
(`<helper>.setcap-applied`) that the post-build hook drops on each
successful apply. The probe sets `caps_stale: true` when the
helper's mtime is newer than the sentinel.

## Packaging install path

The dev-loop above covers cargo-built helpers. The .deb / .rpm
packaging is expected to run `setcap` in its postinst, which we
verify (informationally) in the `apt-pkg` smoke via a `getcap` log
line. If the packaging postinst regresses, the cap state shows up
in that smoke's CI log.

Hardening the install-path side is tracked under L06.
