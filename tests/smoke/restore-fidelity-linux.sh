#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: restore-fidelity-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# R7 — undo puts the tree back as it was.
#
# 1. #214: `rm -rf private` of a 0700 directory. Undo brings the
#    directory back 0700, not at the umask, with its file.
# 2. #215: `mkdir d; mv existing/f d/; rm -rf d`. Undo puts f back in
#    existing/ and leaves no empty `d` behind.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: restore-fidelity-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"
export SHIT_FORCE_TIER="${SHIT_FORCE_TIER:-ebpf-lsm}"

WORK="${SHIT_SMOKE_TMP}/work"
mkdir -p "${WORK}/private" "${WORK}/existing"
chmod 0700 "${WORK}/private"
printf 'secret\n' > "${WORK}/private/key"
chmod 0600 "${WORK}/private/key"
printf 'moved\n' > "${WORK}/existing/f"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "$$" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

SEQ=0
run_cmd() {
    local cmdline="$1"
    SEQ=$((SEQ + 1))
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${SESSION}" --seq "${SEQ}" --pid "$$" \
        --cwd "${WORK}" --shell bash --cmdline "${cmdline}" \
        --sock "${SHIT_HOOK_SOCK}"
    (cd "${WORK}" && bash -c "${cmdline}")
    sleep 0.5
    "${SHIT_BIN}" hook-send post-exec \
        --session "${SESSION}" --seq "${SEQ}" --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
}

# --- #214: a private directory keeps its mode ---
run_cmd "rm -rf private"
[ ! -e "${WORK}/private" ] || smoke_fail "rm -rf private did not run"
"${SHIT_BIN}" undo --yes 2>&1 | sed 's/^/    /' >&2
[ -d "${WORK}/private" ] || smoke_fail "undo did not bring private/ back"
MODE="$(stat -c '%a' "${WORK}/private")"
[ "${MODE}" = "700" ] || smoke_fail "private/ came back ${MODE}, want 700"
[ "$(cat "${WORK}/private/key")" = "secret" ] || smoke_fail "private/key has the wrong content"
KMODE="$(stat -c '%a' "${WORK}/private/key")"
[ "${KMODE}" = "600" ] || smoke_fail "private/key came back ${KMODE}, want 600"

# --- #215: no stray born directory ---
run_cmd "mkdir d && mv existing/f d/ && rm -rf d"
[ ! -e "${WORK}/d" ] || smoke_fail "the command left d behind"
"${SHIT_BIN}" undo --yes 2>&1 | sed 's/^/    /' >&2
[ "$(cat "${WORK}/existing/f")" = "moved" ] || smoke_fail "existing/f was not restored"
[ ! -e "${WORK}/d" ] || smoke_fail "undo left a stray ${WORK}/d"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"
smoke_log "PASS: restore-fidelity-linux"
