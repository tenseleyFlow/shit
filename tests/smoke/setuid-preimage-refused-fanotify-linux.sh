#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: setuid-preimage-refused-fanotify-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 120
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# #253: on the fanotify-perm tier the kernel opens each event fd with
# the helper's rights. A watched shell that runs sudo (or any setuid
# program) used to let the helper read a root-only file's pre-image and
# hand it to the user's journal and blob store.
#
# The cwd holds a root:root mode 0600 file. A watched command rewrites it
# through sudo. Under strict capture the helper must not send a
# pre-image for it: no FilePreImage row with a blob names the file, the
# file's bytes are in no file under the state dir, and a CaptureRefused
# row carries the refusal reason.
#
# Needs passwordless sudo; skips without it.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
# shellcheck source=lib-git.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: setuid-preimage-refused-fanotify-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if [ "$(id -u)" = "0" ]; then
    smoke_log "SKIP: running as root; root may read the file, so nothing is refused"
    exit 0
fi
if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true 2>/dev/null; then
    smoke_log "SKIP: no passwordless sudo"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

set +e
smoke_g01_assert_helper_caps "${HELPER_BIN}"
caps_rc=$?
set -e
[ "${caps_rc}" -eq 2 ] && exit 0
[ "${caps_rc}" -eq 0 ] || exit 1
export SHIT_FORCE_TIER=fanotify-perm

SHIT_STRICT_CAPTURE=1 smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
SECRET="${SCRATCH}/root-only.txt"
MARKER="root-only-preimage-$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
printf '%s\n' "${MARKER}" >"${SECRET}"
sudo -n chown root:root "${SECRET}"
sudo -n chmod 0600 "${SECRET}"
if cat "${SECRET}" >/dev/null 2>&1; then
    smoke_fail "setup: ${SECRET} is still readable by $(id -un)"
fi
# The smoke's cleanup removes the scratch dir as the user. The file is
# root's, but the directory is the user's, so the unlink is allowed.
cd "${SCRATCH}"

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
"${SHIT_BIN}" hook-send session-open --session "${SESSION}" --pid "$$" \
    --shell bash --tty "$(tty 2>/dev/null || echo /dev/null)" --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec --session "${SESSION}" --seq 1 --pid "$$" \
    --cwd "${SCRATCH}" --shell bash \
    --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

# The workload: a setuid descendant of the watched shell truncates and
# rewrites the root-only file.
sudo -n sh -c "printf 'replaced\n' > '${SECRET}'"
sleep 0.5

"${SHIT_BIN}" hook-send post-exec --session "${SESSION}" --seq 1 --exit-code 0 \
    --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'CaptureRefused'" 1 10
smoke_dump_refusals

leaked="$(smoke_journal_count "discriminant = 'FilePreImage' AND path = '${SECRET}' AND blob_hash IS NOT NULL")"
if [ "${leaked}" != "0" ]; then
    smoke_journal_query "SELECT id, discriminant, path, hex(blob_hash) FROM events;" \
        | sed 's/^/    /' >&2 || true
    smoke_fail "journaled ${leaked} FilePreImage blob(s) for the root-only file"
fi
if grep -rqsF "${MARKER}" "${XDG_STATE_HOME}"; then
    grep -rlsF "${MARKER}" "${XDG_STATE_HOME}" | sed 's/^/    /' >&2
    smoke_fail "the root-only file's bytes are in the user's state dir"
fi

refusal="$(smoke_journal_query "SELECT hex(payload) FROM events WHERE discriminant = 'CaptureRefused';" \
    | python3 -c 'import sys; print("\n".join(bytes.fromhex(l.strip()).decode("latin-1") for l in sys.stdin if l.strip()))')"
if ! grep -qF "pre-image refused" <<<"${refusal}"; then
    smoke_fail "no CaptureRefused row carries the pre-image refusal"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: setuid-preimage-refused-fanotify-linux (root-only pre-image refused, not captured)"
