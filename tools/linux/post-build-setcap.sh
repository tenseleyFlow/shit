#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AU08 — post-build setcap hook for the Linux dev loop.
#
# Every `cargo build` rewrites target/{debug,release}/shit-helper,
# which silently strips file capabilities. Without this, the next
# smoke run fails its pre-flight with `FAIL: helper lacks cap_bpf`
# and the operator must copy-paste a `sudo setcap …` line.
#
# This script reapplies the cap set after a build. It is:
#   - Opt-in: only runs when SHIT_AUTO_SETCAP=1.
#   - Idempotent: re-applying the same caps is a no-op.
#   - Non-interactive: uses `sudo -n` so it never prompts. If
#     NOPASSWD isn't configured for setcap, it logs the manual
#     command and exits 0 (does NOT fail the build).
#
# Wire-up:
#   - Makefile `post-build` target invokes this with the binary path.
#   - Developers export SHIT_AUTO_SETCAP=1 in their shell rc.
#   - For seamless ops on dev boxes, generate the sudoers snippet
#     with `shit doctor --emit-sudoers-snippet [--target nixos]`.

set -euo pipefail

BIN="${1:?usage: post-build-setcap.sh <helper-binary-path>}"

log() { printf '[post-build-setcap] %s\n' "$*" >&2; }

if [ "${SHIT_AUTO_SETCAP:-0}" != "1" ]; then
    # No-op when not opted in. Stay silent to keep `cargo build`
    # output clean for users who don't use this hook.
    exit 0
fi

if [ "$(uname -s)" != "Linux" ]; then
    log "skipping: not Linux (uname=$(uname -s))"
    exit 0
fi

if [ ! -x "${BIN}" ]; then
    log "skipping: binary not built yet at ${BIN}"
    exit 0
fi

# Resolve setcap. `setcap` lives in /usr/sbin on most distros, /run/
# current-system/sw/bin on NixOS. `command -v` covers both when the
# user's PATH is sane; readlink falls back for the NixOS /usr/sbin
# symlink case.
SETCAP_BIN="$(command -v setcap 2>/dev/null || readlink -f /usr/sbin/setcap 2>/dev/null || true)"
if [ -z "${SETCAP_BIN}" ] || [ ! -x "${SETCAP_BIN}" ]; then
    log "skipping: setcap not found on PATH or /usr/sbin"
    exit 0
fi

CAPS="cap_sys_admin,cap_bpf,cap_perfmon+ep"

# Already-applied check. `getcap` prints the cap set on success;
# empty when nothing applied. We exit 0 without re-running setcap
# to keep this fast and silent on rebuilds where the cap survives
# (rare today on Linux — most cargo links rewrite the binary — but
# cheap insurance).
if command -v getcap >/dev/null 2>&1; then
    CURRENT="$(getcap "${BIN}" 2>/dev/null | awk '{$1=""; print substr($0,2)}' | tr -d ' ')"
    DESIRED="$(printf '%s\n' "${CAPS}" | tr -d ' ')"
    if [ -n "${CURRENT}" ] && [ "${CURRENT}" = "${DESIRED}" ]; then
        exit 0
    fi
fi

# Attempt the setcap. sudo -n: refuse to prompt; we'd rather log
# the next step than hang a build pipeline.
if sudo -n "${SETCAP_BIN}" "${CAPS}" "${BIN}" 2>/dev/null; then
    # Drop a sentinel so doctor's caps_stale check can tell a
    # subsequent rebuild from a fresh checkout that's never had
    # caps. The sentinel's mtime is set to the helper's mtime at
    # apply time; a later rebuild bumps the helper's mtime past
    # the sentinel → caps_stale = true.
    SENTINEL="${BIN}.setcap-applied"
    : > "${SENTINEL}" 2>/dev/null || true
    touch -r "${BIN}" "${SENTINEL}" 2>/dev/null || true
    log "applied ${CAPS} to ${BIN}"
    exit 0
fi

# NOPASSWD isn't set up. Surface the exact command. Exit 0 — failing
# the build here would be hostile; the smoke pre-flight already
# enforces the cap requirement at smoke run time.
log "sudo -n setcap unavailable; run this once manually:"
log "  sudo ${SETCAP_BIN} ${CAPS} ${BIN}"
log "or generate a sudoers snippet: shit doctor --emit-sudoers-snippet"
exit 0
