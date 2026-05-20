#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Run a Linux smoke script on the bare-metal box (hasu) over
# Tailscale. Builds the workspace binaries (release profile) before
# invoking the script so binaries resolve to
# ${SHIT_SMOKE_BIN_DIR}/{shit,shitd,shit-helper}.
#
# Usage: tools/linux/run-smoke.sh <smoke-script-name>
#   e.g. ./tools/linux/run-smoke.sh rm-undo-linux.sh
#
# Mirrors tools/freebsd-vm/run-smoke.sh. Differences:
#   - No port-forward; ssh directly via Tailscale.
#   - `sudo setcap` on the helper binary post-build so the helper
#     can fanotify_init / load eBPF. Falls back to a loud warning
#     if `sudo -n setcap` requires a password (the smoke then runs
#     in degraded mode and surfaces the missing-caps warning).
#
# Operator setup: configure NOPASSWD for setcap on hasu so this
# script runs unattended. On NixOS:
#   security.sudo.extraRules = [{
#     users = [ "mfwolffe" ];
#     commands = [{ command = "/path/to/setcap"; options = [ "NOPASSWD" ]; }];
#   }];
# Until that's in place, run setcap once manually after each rebuild.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SMOKE_NAME="${1:?usage: run-smoke.sh <smoke-script-name>}"

HASU_HOST="${SHIT_HASU_HOST:-mfwolffe@100.69.85.34}"
REMOTE_DIR="${SHIT_HASU_REMOTE_DIR:-shit}"

log() { printf '[run-smoke %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

# Step 1: sync sources to the box.
log "rsync to ${HASU_HOST}:${REMOTE_DIR}"
bash "${SCRIPT_DIR}/sync.sh" >/dev/null

# Step 2: build release binaries on the box. Non-interactive heredoc.
log "cargo build --release (remote)"
ssh "${HASU_HOST}" "REMOTE_DIR=${REMOTE_DIR} bash -s" <<'REMOTE_BUILD'
set -euo pipefail
cd "$HOME/$REMOTE_DIR"
cargo build --release -p shit -p shitd -p shit-helper --locked 2>&1 | tail -3
REMOTE_BUILD

# Step 3: best-effort sudo -n setcap. If NOPASSWD is configured this
# succeeds silently and the smoke runs unattended. Otherwise it
# returns 1 and we proceed — the smoke's pre-flight will fail fast
# with the exact setcap command for the operator to run manually.
# We do NOT attempt interactive sudo here: this runner is intended
# to work from automation contexts (CI, harnesses) that don't have a
# TTY for the password prompt.
log "setcap (sudo -n; needs NOPASSWD for unattended runs)"
if ssh "${HASU_HOST}" "REMOTE_DIR=${REMOTE_DIR} bash -s" <<'REMOTE_SETCAP' 2>/dev/null
set -euo pipefail
cd "$HOME/$REMOTE_DIR"
SETCAP_BIN="$(command -v setcap || readlink -f /usr/sbin/setcap 2>/dev/null || true)"
[ -n "$SETCAP_BIN" ] && sudo -n "$SETCAP_BIN" cap_sys_admin,cap_bpf,cap_perfmon+ep target/release/shit-helper
REMOTE_SETCAP
then
    log "setcap applied via sudo -n (NOPASSWD)"
else
    log "sudo -n setcap unavailable; the smoke will report the manual command if needed"
fi

# Step 4: run the smoke. Its pre-flight refuses to run in degraded
# mode and surfaces the exact setcap command on missing-caps.
log "running smoke ${SMOKE_NAME}"
ssh "${HASU_HOST}" "SMOKE_NAME=${SMOKE_NAME} REMOTE_DIR=${REMOTE_DIR} bash -s" <<'REMOTE_SMOKE'
set -euo pipefail
cd "$HOME/$REMOTE_DIR"
SMOKE_PATH="tests/smoke/${SMOKE_NAME}"
if [ ! -f "$SMOKE_PATH" ]; then
    echo "[hasu-remote] smoke script missing: $SMOKE_PATH" >&2
    exit 2
fi
bash "$SMOKE_PATH"
REMOTE_SMOKE
