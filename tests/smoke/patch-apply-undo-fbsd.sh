#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W09.7.patch smoke — `patch -p1 < diff.patch` modifies an existing
# file (writes a tmpfile then atomic-renames it over the original).
# `shit undo` should restore byte-identical pre-patch content.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: patch-apply-undo-fbsd is FreeBSD-only"
    exit 0
fi

PATCH_BIN="$(command -v patch)"
[ -x "${PATCH_BIN}" ] || smoke_fail "patch not found"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
mkdir -p "${WATCHED}"
SUBJECT="${WATCHED}/script.sh"
{
    printf '#!/bin/sh\n'
    printf 'echo "v1: hello"\n'
    printf 'echo "v1: world"\n'
} > "${SUBJECT}"
PRE_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "pre-patch sha: ${PRE_SHA}"

# Build a unified diff replacing v1 → v2 in both echo lines.
DIFF="${SHIT_SMOKE_TMP}/edit.patch"
cat > "${DIFF}" <<'EOF'
--- script.sh.orig
+++ script.sh
@@ -1,3 +1,3 @@
 #!/bin/sh
-echo "v1: hello"
-echo "v1: world"
+echo "v2: hello"
+echo "v2: world"
EOF

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
cd "${WATCHED}"

"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.5

smoke_log "${PATCH_BIN} script.sh < ${DIFF}"
"${PATCH_BIN}" script.sh < "${DIFF}" > "${SHIT_SMOKE_TMP}/patch.log" 2>&1

POST_PATCH_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "post-patch sha: ${POST_PATCH_SHA}"
[ "${POST_PATCH_SHA}" != "${PRE_SHA}" ] || smoke_fail "patch didn't modify file"

# patch may leave a .orig backup behind on success; that's its own
# backup, not the shit journal's responsibility. Remove it so undo
# doesn't have to deal with it.
rm -f "${SUBJECT}.orig"

sleep 0.5
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
sleep 1.0

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

[ -f "${SUBJECT}" ] || smoke_fail "subject file removed by undo"
POST_UNDO_SHA="$(/sbin/sha256 -q "${SUBJECT}")"
smoke_log "post-undo sha: ${POST_UNDO_SHA}"

if [ "${POST_UNDO_SHA}" = "${PRE_SHA}" ]; then
    smoke_log "PASS: patch-apply-undo-fbsd (script.sh restored byte-identical)"
    exit 0
fi

smoke_fail "byte mismatch: got ${POST_UNDO_SHA}, expected ${PRE_SHA}"
