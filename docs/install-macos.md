# Installing `shit` on macOS

`shit` ships in two install modes on macOS. Pick the one that matches what you want.

## TL;DR

| Mode | What you get | Security tradeoff | Who it's for |
|---|---|---|---|
| **Default (DYLD + FSEvents-degraded)** | Undo for tested mutations made by eligible dynamically linked processes. DYLD supplies pre-images; FSEvents supplies readiness and diagnostics only. | No OS security protections are disabled. Eligible child processes load the local shim. | Most users. The recommended path. |
| **Power-user (EndpointSecurity)** | Broader pre-mutation capture, including supported events from Apple platform binaries. Explicit gaps and refusals still apply. | **Significant.** SIP + AuthRoot disabled, AMFI bypassed. You boot into Recovery to enable this. | Developers who need that additional coverage and have read the tradeoffs in full. |

## Default install

```sh
# Homebrew (recommended once the tap package is published)
brew install tenseleyflow/tap/shit
```

The current release workflow produces an arm64 archive named `shit-macos-arm64-<version>.tar.gz`. After downloading it from the matching GitHub release and extracting it, run these commands from the extracted `shit-macos-arm64-<version>/` directory:

```sh
sudo mkdir -p /usr/local/bin /usr/local/lib
sudo install -m 0755 bin/shit bin/shitd bin/shit-helper /usr/local/bin/
sudo install -m 0755 lib/libshit_preload_shim.dylib /usr/local/lib/
```

Install the DYLD hook, then start a new shell so eligible child processes inherit it:

```sh
shit dyld-hooks install
```

The installer currently updates `~/.zshrc` and `~/.bashrc`. Fish's `shit shell-init` support brackets commands but does not install the DYLD export; fish users must arrange for the same environment variable to be inherited before relying on default-mode undo.

In that new shell, start the daemon and source the shell hook:

```sh
shitd &
source <(shit shell-init zsh)   # or bash/fish
```

`shit doctor` will report `kernel_tier: fsevents-degraded`, which is the expected un-entitled helper tier. That label does not mean FSEvents can undo a mutation: its events are partial and carry no pre-image. If a partial observation remains in a command's journal, undo refuses the whole command instead of applying a partial inverse set. Actionable default-mode filesystem undo comes from the DYLD interposer, so run `shit dyld-hooks status` as part of verification. Apple platform/SIP or hardened-runtime binaries, static binaries, and direct syscalls bypass that interposer.

Timestamp setters (`utimes`, `futimes`, `futimens`, and `utimensat`) explicitly refuse for now because the captured metadata model does not preserve atime. A refusal is deliberate: `shit` will not advertise a lossy timestamp undo.

## Power-user install

Read [`macos-power-user-install.md`](./macos-power-user-install.md) **in full** before continuing. It walks through:

1. The exact security tradeoffs you're accepting (and what each toggle weakens).
2. The Recovery-mode steps to disable SIP and AuthRoot — these cannot be scripted, you do them manually.
3. The `shit setup-es-mode --apply` step that codesigns the local helper with the EndpointSecurity entitlement.
4. How to verify the install with `shit doctor`.
5. How to reverse the install if you change your mind.

Apple does not grant the EndpointSecurity entitlement for general distribution of a tool like `shit`. The power-user mode works around that by having you sign the helper locally in an AMFI-bypassed environment that you opted into. There is no path to power-user mode that does not involve disabling SIP — that's the whole reason it's called power-user.

## Which mode should I use?

If you have to ask, use the default. The default mode is what `shit` was designed to be invisible-good at. Power-user mode trades a meaningful chunk of macOS's built-in defenses for broader capture of supported mutations made by Apple platform binaries.

Pick power-user only if:

- You write code on this machine, and you've already accepted SIP-disabled environments (you're a kernel hacker, security researcher, or run a dev VM-equivalent setup).
- You've read [`macos-power-user-install.md`](./macos-power-user-install.md) including the reversal section.
- The machine is not under MDM / enterprise management.

If you're unsure, install the default mode, use `shit` for a week, and decide based on whether you actually hit a case the default mode can't undo.

## Verifying the install

```sh
shit doctor                      # human-readable
shit doctor --json | jq .macos   # full structured report
```

Look for:
- `kernel_tier: "fsevents-degraded"` (default mode — expected) OR `kernel_tier: "endpoint-security"` (power-user mode — expected after `setup-es-mode --apply`).
- `es_capable: false` (default mode, with a populated `es_blockers` array listing what's missing) OR `es_capable: true` (power-user mode).
- `shit dyld-hooks status` reporting the interposer installed when you rely on default-mode filesystem undo.

Both `false` and `true` are correct states. The blockers array only matters if you're trying to be `true` and aren't.

## Uninstalling

```sh
brew uninstall shit               # or: rm /usr/local/bin/{shit,shitd,shit-helper}
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/shit"
```

If you enabled power-user mode and want to fully revert: see the "Reversing the install" section in [`macos-power-user-install.md`](./macos-power-user-install.md).
