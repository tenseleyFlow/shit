#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# W06.A.4 smoke — `make install` OVERWRITES an existing file at
# the install destination. The original make-install-undo-fbsd.sh
# covers a CLEAN prefix where install-target/bin/hello doesn't
# exist pre-mutation; W06.A.3's TreeOp::Rename inverse closed that
# (`install` writes a tmpfile then renames over the destination —
# rename inverse restores cleanly when there's no prior file).
#
# This smoke exercises the harder case: the destination already
# holds a different file. `install` first `open(O_TRUNC|O_WRONLY|...)`s
# (or `openat`s) the destination, truncating its content, then writes
# the new bytes. The shim's `open` interposer (W06.A.4) captures the
# OLD content as a pre-image so `shit undo` can restore the prior
# bytes.
#
# Expected outcome (post-W06.A.4): full undo — installed files
# reverted to their pre-existing content, NOT removed. The pre-W06.A.4
# baseline would have either no-op'd the undo (no journal events for
# the overwrite) or removed the dst entirely (if it had a Create event,
# which it shouldn't for an existing dst).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: make-install-overwrite-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

MAKE_BIN="$(command -v make || echo /usr/bin/make)"
[ -x "${MAKE_BIN}" ] || smoke_fail "make not found"
INSTALL_BIN="$(command -v install || echo /usr/bin/install)"
[ -x "${INSTALL_BIN}" ] || smoke_fail "install not found"
smoke_log "make: ${MAKE_BIN}; install: ${INSTALL_BIN}"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

WATCHED="${SHIT_SMOKE_TMP}/watched"
INSTALL_PREFIX="${SHIT_SMOKE_TMP}/install-target"
mkdir -p "${WATCHED}" "${INSTALL_PREFIX}/bin"

cat > "${WATCHED}/Makefile" <<MAK
PREFIX ?= /usr/local
install:
	${INSTALL_BIN} -m 0755 hello \$(PREFIX)/bin/hello
MAK

cat > "${WATCHED}/hello" <<'EOF'
#!/bin/sh
echo "NEW content from shit-installed binary"
EOF
chmod 0755 "${WATCHED}/hello"

# Pre-populate the destination with DIFFERENT bytes. This is the
# critical setup — install will overwrite it via open(O_TRUNC|...).
cat > "${INSTALL_PREFIX}/bin/hello" <<'EOF'
#!/bin/sh
echo "ORIGINAL content predating the install"
EOF
chmod 0755 "${INSTALL_PREFIX}/bin/hello"

PRE_DST_SHA="$(/sbin/sha256 -q "${INSTALL_PREFIX}/bin/hello")"
PRE_SRC_SHA="$(/sbin/sha256 -q "${WATCHED}/hello")"
smoke_log "pre-cmd dst sha: ${PRE_DST_SHA}"
smoke_log "pre-cmd src sha: ${PRE_SRC_SHA}"
[ "${PRE_DST_SHA}" != "${PRE_SRC_SHA}" ] || smoke_fail "pre-state invariant: dst and src content collide"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

cd "${WATCHED}"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID} cwd=${WATCHED}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${WATCHED}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# THE workload — install OVERWRITES an existing dst.
smoke_log "LD_PRELOAD=${SHIM_LIB} make install PREFIX=${INSTALL_PREFIX}"
LD_PRELOAD="${SHIM_LIB}" "${MAKE_BIN}" -C "${WATCHED}" PREFIX="${INSTALL_PREFIX}" install \
    > "${SHIT_SMOKE_TMP}/make.log" 2>&1
MAKE_RC=$?
if [ "${MAKE_RC}" -ne 0 ]; then
    smoke_log "make stderr+stdout:"
    /usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/make.log" >&2 || true
    smoke_fail "make install failed pre-undo (rc=${MAKE_RC})"
fi

POST_INSTALL_DST_SHA="$(/sbin/sha256 -q "${INSTALL_PREFIX}/bin/hello")"
smoke_log "post-install dst sha: ${POST_INSTALL_DST_SHA}"
[ "${POST_INSTALL_DST_SHA}" = "${PRE_SRC_SHA}" ] || \
    smoke_fail "install didn't replace dst with src bytes (got ${POST_INSTALL_DST_SHA}, expected ${PRE_SRC_SHA})"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

sleep 1.0

# Diagnostic: shim notification count.
SHIM_HITS="$(grep -hc 'shim pre-mutation' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
SHIM_HITS="$(printf '%s\n' ${SHIM_HITS} | awk '{s+=$1} END{print s+0}')"
smoke_log "shim notifications observed by daemon: ${SHIM_HITS}"

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "total journal events: ${N_EVENTS}"

# Run undo.
smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

if [ ! -e "${INSTALL_PREFIX}/bin/hello" ]; then
    smoke_fail "post-undo dst MISSING — pre-W06.A.4 behavior (overwrite Unlink'd instead of restored)"
fi

POST_UNDO_DST_SHA="$(/sbin/sha256 -q "${INSTALL_PREFIX}/bin/hello")"
smoke_log "post-undo dst sha: ${POST_UNDO_DST_SHA}"

# Source untouched?
POST_SRC_SHA="$(/sbin/sha256 -q "${WATCHED}/hello")"
if [ "${POST_SRC_SHA}" != "${PRE_SRC_SHA}" ]; then
    smoke_fail "source perturbed (${PRE_SRC_SHA} -> ${POST_SRC_SHA})"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

if [ "${POST_UNDO_DST_SHA}" = "${PRE_DST_SHA}" ]; then
    smoke_log "OUTCOME A — dst restored to pre-install bytes (sha=${PRE_DST_SHA})"
    smoke_log "PASS: make-install-overwrite-undo-fbsd (Outcome A; shim notifications=${SHIM_HITS})"
    exit 0
fi

smoke_fail "dst bytes not restored: got ${POST_UNDO_DST_SHA}, expected ${PRE_DST_SHA}"
