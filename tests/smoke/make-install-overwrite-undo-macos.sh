#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: make-install-overwrite-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M07.B.4 gap-validation smoke — macOS twin of
# make-install-overwrite-undo-fbsd.sh.
#
# The clean-prefix make-install-undo-macos smoke covers a fresh
# install where the destination doesn't exist (TreeOp::Create →
# Unlink inverse). This smoke exercises the harder case: the
# destination ALREADY holds different content. `ginstall`'s
# atomic-replace pattern truncates the destination via
# `open(O_TRUNC|O_WRONLY|O_CREAT)` then writes new bytes. The
# shim's open interposer must capture the OLD content as a
# pre-image BEFORE the truncate takes effect; otherwise `shit
# undo` can only delete (wrong) or no-op (also wrong).
#
# Outcomes:
#   A. Full undo: dst content restored to PRE-install bytes
#      (the M07.B.4 fix landed correctly).
#   B. Loud refusal: undo non-zero, log mentions the
#      destination / pre-image gap.
#   C. (Pre-fix expected) Silent stomp: dst either deleted or
#      left as post-install bytes — fail loudly.
#
# Per feedback-validate-gap-before-building: this smoke is
# EXPECTED TO FAIL on current trunk. If it passes pre-fix the
# gap doesn't exist and the M07.B.4 sprint scope is wrong.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: make-install-overwrite-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

MAKE_BIN="$(command -v gmake 2>/dev/null || true)"
INSTALL_BIN="$(command -v ginstall 2>/dev/null || true)"
if [ -z "${MAKE_BIN}" ] || [ -z "${INSTALL_BIN}" ]; then
    smoke_log "SKIP: macOS DYLD_INSERT smoke requires gmake + ginstall (brew install make coreutils)"
    smoke_log "  detected: gmake=${MAKE_BIN:-MISSING} ginstall=${INSTALL_BIN:-MISSING}"
    exit 0
fi
smoke_log "make: ${MAKE_BIN}; install: ${INSTALL_BIN} (both non-SIP, DYLD survives)"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.dylib"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB} (cargo build -p shit-preload-shim --release)"
export SHIT_HELPER_BIN="${HELPER_BIN}"

sha256_of() {
    shasum -a 256 "$1" | awk '{print $1}'
}

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

# Pre-populate dst with DIFFERENT bytes — the critical setup.
# install will overwrite via open(O_TRUNC|O_WRONLY|O_CREAT).
cat > "${INSTALL_PREFIX}/bin/hello" <<'EOF'
#!/bin/sh
echo "ORIGINAL content predating the install"
EOF
chmod 0755 "${INSTALL_PREFIX}/bin/hello"

PRE_DST_SHA="$(sha256_of "${INSTALL_PREFIX}/bin/hello")"
PRE_SRC_SHA="$(sha256_of "${WATCHED}/hello")"
smoke_log "pre-cmd dst sha: ${PRE_DST_SHA}"
smoke_log "pre-cmd src sha: ${PRE_SRC_SHA}"
[ "${PRE_DST_SHA}" != "${PRE_SRC_SHA}" ] || smoke_fail "pre-state invariant: dst and src collide"

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
sleep 0.7

# THE workload — install OVERWRITES an existing dst.
smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} make install PREFIX=${INSTALL_PREFIX}"
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${MAKE_BIN}" -C "${WATCHED}" PREFIX="${INSTALL_PREFIX}" install \
    > "${SHIT_SMOKE_TMP}/make.log" 2>&1
MAKE_RC=$?
if [ "${MAKE_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/make.log" >&2 || true
    smoke_fail "make install failed pre-undo (rc=${MAKE_RC})"
fi

POST_INSTALL_DST_SHA="$(sha256_of "${INSTALL_PREFIX}/bin/hello")"
smoke_log "post-install dst sha: ${POST_INSTALL_DST_SHA}"
[ "${POST_INSTALL_DST_SHA}" = "${PRE_SRC_SHA}" ] || \
    smoke_fail "install didn't replace dst with src bytes (got ${POST_INSTALL_DST_SHA}, expected ${PRE_SRC_SHA})"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

sleep 1.0

SHIM_HITS="$(grep -hc 'shim pre-mutation' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
SHIM_HITS="$(printf '%s\n' ${SHIM_HITS} | awk '{s+=$1} END{print s+0}')"
smoke_log "shim notifications observed by daemon: ${SHIM_HITS}"

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Pre-fix expectation: post-undo dst is either missing (treated
# as new-create → Unlink'd by mistake) or still holds the
# POST-install bytes (no pre-image was captured). Either way the
# old content is gone.
if [ ! -e "${INSTALL_PREFIX}/bin/hello" ]; then
    smoke_log "post-undo dst MISSING — pre-M07.B.4 behavior (overwrite Unlink'd instead of restored)"
    smoke_log "  shim hits: ${SHIM_HITS}; journal events: ${N_EVENTS}; undo rc: ${UNDO_RC}"
    smoke_fail "M07.B.4 gap confirmed: dst removed, not content-restored"
fi

POST_UNDO_DST_SHA="$(sha256_of "${INSTALL_PREFIX}/bin/hello")"
smoke_log "post-undo dst sha: ${POST_UNDO_DST_SHA}"

POST_SRC_SHA="$(sha256_of "${WATCHED}/hello")"
if [ "${POST_SRC_SHA}" != "${PRE_SRC_SHA}" ]; then
    smoke_fail "source perturbed (${PRE_SRC_SHA} -> ${POST_SRC_SHA})"
fi

if [ "${POST_UNDO_DST_SHA}" = "${PRE_DST_SHA}" ]; then
    smoke_log "OUTCOME A — dst restored to pre-install bytes (sha=${PRE_DST_SHA})"
    smoke_log "PASS: make-install-overwrite-undo-macos (Outcome A; shim hits=${SHIM_HITS})"
    exit 0
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "install-target|out-of-scope|outside|refus|pre.image|hello" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named the gap)"
    smoke_log "PASS: make-install-overwrite-undo-macos (Outcome B)"
    exit 0
fi

smoke_log "OUTCOME C — silent stomp (M07.B.4 gap confirmed)"
smoke_log "  pre dst sha:        ${PRE_DST_SHA}"
smoke_log "  post-install dst:   ${POST_INSTALL_DST_SHA}"
smoke_log "  post-undo dst:      ${POST_UNDO_DST_SHA}"
smoke_log "  undo exit:          ${UNDO_RC}"
smoke_log "  shim hits:          ${SHIM_HITS}"
smoke_log "  journal events:     ${N_EVENTS}"
smoke_fail "dst bytes not restored: got ${POST_UNDO_DST_SHA}, expected ${PRE_DST_SHA}"
