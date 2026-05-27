#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# DR-19 smoke — real apt install fires the DPkg::Pre/Post-Invoke
# hook, the daemon journals a PackageOp event.
#
# Prereqs the GH runner provides:
# - apt available (any debian/ubuntu)
# - passwordless sudo
# - python3 (for uuid)
# - sqlite3
#
# Test shape:
#   1. Start shitd under XDG-overridden tempdir.
#   2. SessionOpen + PreExec keyed on $$ — registers the command
#      window. Without this, the daemon drops pkg-events as
#      "not attributable" (per shitd::pkg::handle_post).
#   3. Write /etc/apt/apt.conf.d/99shit-smoke pointing at our
#      release-built shit-helper with an absolute --ctl-sock so
#      sudo's env-stripping doesn't matter.
#   4. sudo apt-get install -y jq — fires Pre+Post.
#   5. Drain, assert PackageOp event for `jq` lands in journal.
#   6. Cleanup: remove jq, drop the apt config.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

APT_CONF="/etc/apt/apt.conf.d/99shit-smoke"
TARGET_PKG="jq"

# Pre-flight: skip cleanly on a non-apt host so the smoke can be
# invoked on a dev workstation without exploding.
if ! command -v apt-get >/dev/null 2>&1; then
    smoke_log "apt-get not present; skipping apt smoke"
    exit 0
fi
if ! command -v sudo >/dev/null 2>&1; then
    smoke_log "sudo not present; skipping apt smoke"
    exit 0
fi

# Ensure the package isn't already installed — otherwise the diff
# would be empty and the daemon would drop the event.
if dpkg-query -W "${TARGET_PKG}" >/dev/null 2>&1; then
    smoke_log "${TARGET_PKG} already installed; removing for clean baseline"
    sudo apt-get remove -y "${TARGET_PKG}" >/dev/null 2>&1 || true
fi

smoke_start_shitd

HELPER="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
if [ ! -x "${HELPER}" ]; then
    smoke_fail "shit-helper binary missing at ${HELPER}"
fi

# Register a command window for $$. Without this the daemon's
# active_commands::resolve_by_descendant walk finds nothing and
# the pkg-event is dropped.
SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

# Install the apt hook config. Absolute paths only — sudo strips
# most of the env including XDG_RUNTIME_DIR.
smoke_log "installing ${APT_CONF}"
sudo tee "${APT_CONF}" >/dev/null <<EOF
// shit DR-19 smoke — auto-installed by tests/smoke/apt-pkg.sh
DPkg::Pre-Invoke   {"${HELPER} pkg-event apt pre  --ctl-sock ${SHIT_CTL_SOCK} || true";};
DPkg::Post-Invoke  {"${HELPER} pkg-event apt post --ctl-sock ${SHIT_CTL_SOCK} || true";};
EOF

# Make the ctl socket readable by root (sudo'd helper).
chmod 0666 "${SHIT_CTL_SOCK}" 2>/dev/null || true

smoke_log "sudo apt-get install -y ${TARGET_PKG}"
sudo apt-get update -qq >/dev/null 2>&1 || true
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    "${TARGET_PKG}" >/dev/null 2>&1

# PostExec — closes the command window.
smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

# Drain so group-commit flushes.
sleep 1.0

# Assert. Look for a PackageOp event in the journal.
n="$(smoke_journal_count "discriminant = 'PackageOp'")"
if [ "${n}" -lt 1 ]; then
    smoke_log "PackageOp event missing. journal dump:"
    smoke_journal_query "SELECT id, discriminant, ts_wall_nanos FROM events;" \
        | sed 's/^/    /' >&2 || true
    smoke_log "daemon log tail:"
    tail -30 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2 || true
    smoke_fail "expected PackageOp event after apt install; saw ${n}"
fi
smoke_log "PackageOp events: ${n}"

# AU08 — informational getcap log on the helper this smoke used.
# apt-pkg itself doesn't require caps (it routes through the
# pkg-event helper subcommand which is unprivileged), so this is a
# log line, not an assertion. The real cap requirement is enforced
# at LSM-tier smokes' own pre-flights. Visibility here helps catch
# packaging regressions where the .deb postinst would have stripped
# or skipped setcap on real installs.
if command -v getcap >/dev/null 2>&1; then
    GETCAP_OUT="$(getcap "${HELPER}" 2>&1 || true)"
    if [ -n "${GETCAP_OUT}" ]; then
        smoke_log "AU08 helper caps: ${GETCAP_OUT}"
    else
        smoke_log "AU08 helper caps: <none>  (no caps applied to ${HELPER})"
    fi
else
    smoke_log "AU08 helper caps: skipped — getcap not on PATH (apt-get install libcap2-bin)"
fi

# Cleanup. Always-run so subsequent smoke runs start clean.
sudo rm -f "${APT_CONF}"
sudo apt-get remove -y "${TARGET_PKG}" >/dev/null 2>&1 || true

smoke_log "PASS: apt-pkg"
