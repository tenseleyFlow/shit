# `shit` power-user install on macOS

This is the long-form guide to running `shit` in EndpointSecurity (ES) mode on a stock Mac. **Read it in full** before starting. If you only want the default install, see [`install-macos.md`](./install-macos.md).

**Verified against:** macOS 14.x (Sonoma) and 15.x (Sequoia), Apple Silicon and Intel.

---

## What you're trading

ES mode requires three macOS security mitigations to be relaxed. Each one is independently meaningful — none of them should be touched casually.

### 1. SIP (System Integrity Protection) — disabled

`csrutil disable` removes the kernel's enforcement of code-signing on system binaries, prevents loading of unsigned kernel extensions only by default (you'd still need to opt in), and lifts the restriction on processes attaching to or modifying other processes (most relevantly, Apple-signed ones).

**What this weakens:**
- Malware that gets root can now modify `/System` and `/usr` (outside `/usr/local`).
- Debuggers attach to system processes without restriction. Useful for kernel work; an attack surface for everyone else.
- Loaded executables can be modified or replaced without triggering signature checks.

### 2. Authenticated Root (`csrutil authenticated-root disable`) — disabled

The system volume is normally sealed with a cryptographic snapshot — Apple verifies its integrity at boot. Disabling this lets you (or anyone with root) mount the system volume read-write.

**What this weakens:**
- The "your system files have been tampered with" guarantee is gone. A rootkit can persist in `/System` across reboots.
- macOS auto-updates may refuse to install or may behave unpredictably.

### 3. AMFI bypass (`nvram boot-args="amfi_get_out_of_my_way=0x1"`) — enabled

AMFI (Apple Mobile File Integrity) enforces that entitlements in a binary's code signature are *granted* by Apple. Without this bypass, our ad-hoc-signed helper cannot claim the `com.apple.developer.endpoint-security.client` entitlement — Apple denied us the entitlement for general distribution.

**What this weakens:**
- Any binary on your machine can now claim any entitlement, including extremely powerful ones like `com.apple.private.security.no-sandbox`. This is the AMFI bypass that catches most users off-guard.
- Apple's "this app is signed by who it claims to be signed by" guarantee is gutted.

### Combined

The combined effect is that your Mac, while running, is approximately at the security level of a Linux box running as root with full kernel access. That's a reasonable level for a developer workstation — it is **not** a reasonable level for a primary daily-driver machine if you don't fully understand the consequences.

If you have a machine you only develop on, or you can compartmentalize ES-mode `shit` to a VM, that's a much better fit than your main machine.

---

## Prerequisites

- macOS 14.0 or later (Sonoma or Sequoia).
- Admin password.
- A backup. Recovery-mode flips don't usually break anything, but you're about to weaken multiple integrity mitigations on the boot volume — back up first.
- The machine is **not** managed by MDM. Managed Macs commonly block Recovery boot entirely.

---

## Install

### Step 0 — install `shit` itself

If you haven't already, install the default-mode package per [`install-macos.md`](./install-macos.md). The power-user install **extends** a working default install; it doesn't replace it.

### Step 1 — see what the doctor reports right now

```sh
shit doctor --json | jq '.macos.es_capable, .macos.es_blockers'
```

On a stock Mac this returns `false` and a populated `es_blockers` array. Each blocker has a `component`, a `reason`, and a `fix_command`. Read the full list before continuing — it's the same checklist you're about to walk through.

```sh
shit setup-es-mode --print
```

This prints the exact step-by-step recovery dance + `nvram` invocations tailored to your detected state. Use it as your live cheat sheet alongside this doc.

### Step 2 — disable SIP (Recovery boot)

This step cannot be scripted. `csrutil` only runs from the Recovery shell, by design.

**Apple Silicon:**
1. Shut down the Mac fully (`sudo shutdown -h now`).
2. Press and **hold** the power button until "Loading startup options…" appears.
3. Click **Options** → continue.
4. From the menu bar: **Utilities → Terminal**.
5. Run: `csrutil disable` and confirm with your admin password.
6. Run: `reboot`.

**Intel:**
1. Restart.
2. Hold ⌘+R as soon as you hear the startup chime, until the Apple logo appears.
3. **Utilities → Terminal**.
4. `csrutil disable`, admin password, `reboot`.

After reboot, verify:
```sh
csrutil status
# expected: System Integrity Protection status: disabled.
```

### Step 3 — disable Authenticated Root (Recovery boot, again)

Same Recovery procedure as Step 2. From the Recovery terminal:
```sh
csrutil authenticated-root disable
reboot
```

After reboot:
```sh
csrutil authenticated-root status
# expected: Authenticated Root status: disabled
```

### Step 4 — enable the AMFI bypass

This one *does* run from regular macOS, but it requires the SIP-disable from Step 2 first.

```sh
sudo nvram boot-args="amfi_get_out_of_my_way=0x1"
sudo reboot
```

After reboot:
```sh
nvram boot-args
# expected: boot-args   amfi_get_out_of_my_way=0x1
```

If you already had other `boot-args` (rare), append rather than replace — `boot-args="$(nvram boot-args | awk '{$1=""; print $0}') amfi_get_out_of_my_way=0x1"`.

### Step 5 — codesign the helper with the ES entitlement

```sh
shit setup-es-mode --apply --i-understand-the-tradeoffs
```

This invokes `packaging/codesign/sign-for-power-user.sh` on the installed helper binary, embedding the entitlement plist via ad-hoc signature. The script:

1. Locates the helper (`/usr/local/bin/shit-helper` or `/opt/homebrew/bin/shit-helper`).
2. Locates the entitlement plist shipped in the release tarball.
3. Runs `codesign --force --options runtime --entitlements <plist> --sign - <helper>`.
4. Verifies the entitlement is present in the signed binary.

If you'd rather run the script directly:
```sh
sudo packaging/codesign/sign-for-power-user.sh
```

### Step 6 — restart the daemon + helper

The handshake between `shitd` and `shit-helper` happens at helper spawn time. After re-signing the helper:

```sh
pkill shitd; shitd &
```

### Step 7 — verify

```sh
shit doctor --json | jq '.macos.es_capable'
# expected: true
shit doctor --json | jq '.macos.helper_handshake.kernel_tier'
# expected: "endpoint-security"
```

If either is wrong:
```sh
shit setup-es-mode --check
```
will tell you which specific prereq is failing. The `degraded_reason` field in the handshake report often pinpoints the cause when the kernel_tier comes back wrong.

---

## Reversing the install

If you want to put your Mac back to stock-secure state, the steps unwind in reverse:

### Remove the AMFI bypass
```sh
sudo nvram -d boot-args     # or: sudo nvram boot-args=""
sudo reboot
```

### Re-enable Authenticated Root (Recovery boot)
Boot into Recovery (see Step 2 above), then in the Recovery terminal:
```sh
csrutil authenticated-root enable
reboot
```

### Re-enable SIP (Recovery boot)
```sh
csrutil enable
reboot
```

### What happens to `shit` after reversal?
The helper still runs. Its ES probe will fail (no entitlement enforcement → no ES connection), and the daemon falls back to FSEvents-degraded mode — exactly the same as the default install. No on-disk state needs cleanup. The ad-hoc-signed helper just stops being able to claim ES.

To go further and uninstall `shit` entirely, follow the "Uninstalling" section in [`install-macos.md`](./install-macos.md).

---

## Troubleshooting

### `shit doctor` reports `kernel_tier: fsevents-degraded` after Step 7
Check the handshake's `degraded_reason`:
```sh
shit doctor --json | jq '.macos.helper_handshake.degraded_reason'
```

Common reasons:
- `"NotEntitled"` — the helper was rebuilt or replaced after `setup-es-mode --apply`. Re-run Step 5.
- `"NotPrivileged"` — the helper isn't running as root. Restart `shitd` with `sudo`, or check your launchd setup.
- `"AmfiRejected"` — the AMFI bypass isn't in effect. Verify `nvram boot-args` and that you rebooted after setting it.
- `"SipEnabled"` — SIP got re-enabled (macOS update?). Re-do Step 2.

### `csrutil` says SIP is disabled but the helper still can't get ES
Some macOS updates change the SIP sub-flag layout. Run `csrutil status` and check that `Filesystem Protections: disabled` appears — that's the specific sub-flag ES needs. If it shows enabled while overall SIP is disabled, your macOS rev needs `csrutil disable --no-internal` or similar; check Apple's docs for your version.

### After a macOS update, ES stopped working
macOS major updates frequently revert security toggles. Run `shit doctor` first — it'll tell you exactly which prereq the update flipped, and you can re-apply just that step.

### I'm getting MDM enrollment errors trying to enter Recovery
Your machine is enterprise-managed. You cannot install power-user mode without going through your IT department to first un-manage the machine, and at that point you should be using the default install instead — managed environments are not a good fit for SIP-disabled tooling.

---

## Reference

- Apple, *About System Integrity Protection*: <https://support.apple.com/en-us/HT204899>
- Apple, *About Endpoint Security*: <https://developer.apple.com/documentation/endpointsecurity>
- `shit` audit notes on the entitlement denial: `.docs/audits/apple-entitlement.md` (internal-only).
