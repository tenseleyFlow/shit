# Installing `shit` on macOS

`shit` ships in two install modes on macOS. Pick the one that matches what you want.

## TL;DR

| Mode                            | What you get                                                                 | Security tradeoff                                                                                  | Who it's for                                                                  |
|---------------------------------|------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Default (FSEvents-degraded)** | Reliable undo for most file edits. Post-mutation capture only.               | **None.** Stock macOS. SIP stays on.                                                               | Most users. The recommended path.                                             |
| **Power-user (EndpointSecurity)** | Full pre-mutation undo on every syscall family. Trusted byte-for-byte restore. | **Significant.** SIP + AuthRoot disabled, AMFI bypassed. You boot into Recovery to enable this. | Developers who want maximum coverage and have read the tradeoffs in full.    |

## Default install

```sh
# Homebrew (recommended)
brew install tenseleyflow/tap/shit

# or: direct download
curl -fsSL https://github.com/tenseleyFlow/shit/releases/latest/download/shit-macos-$(uname -m).tar.gz | tar -xz
sudo mv shit shitd shit-helper /usr/local/bin/
```

Then start the daemon and source the shell hook:

```sh
shitd &
source <(shit shell-init zsh)   # or bash/fish
```

That's it. `shit doctor` will report `kernel_tier: fsevents-degraded`, which is the expected default — post-mutation FSEvents captures cover the vast majority of "I just ran the wrong command" cases.

## Power-user install

Read [`macos-power-user-install.md`](./macos-power-user-install.md) **in full** before continuing. It walks through:

1. The exact security tradeoffs you're accepting (and what each toggle weakens).
2. The Recovery-mode steps to disable SIP and AuthRoot — these cannot be scripted, you do them manually.
3. The `shit setup-es-mode --apply` step that codesigns the local helper with the EndpointSecurity entitlement.
4. How to verify the install with `shit doctor`.
5. How to reverse the install if you change your mind.

Apple does not grant the EndpointSecurity entitlement for general distribution of a tool like `shit`. The power-user mode works around that by having you sign the helper locally in an AMFI-bypassed environment that you opted into. There is no path to power-user mode that does not involve disabling SIP — that's the whole reason it's called power-user.

## Which mode should I use?

If you have to ask, use the default. The default mode is what `shit` was designed to be invisible-good at. Power-user mode trades a meaningful chunk of macOS's built-in defenses for a marginal coverage improvement on a class of commands that most users never need to undo.

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

Both `false` and `true` are correct states. The blockers array only matters if you're trying to be `true` and aren't.

## Uninstalling

```sh
brew uninstall shit               # or: rm /usr/local/bin/{shit,shitd,shit-helper}
rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/shit"
```

If you enabled power-user mode and want to fully revert: see the "Reversing the install" section in [`macos-power-user-install.md`](./macos-power-user-install.md).
