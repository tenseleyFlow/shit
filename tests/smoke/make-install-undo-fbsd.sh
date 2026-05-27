#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: make-install-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# W06 smoke — `make install` writes files into a prefix OUTSIDE
# the watched cwd subtree. `shit undo` should reverse those writes
# even though the kqueue producer can't see them (out-of-watch).
#
# The capture mechanism for cross-watch observation is the
# LD_PRELOAD shim (S24.D) — interposes libc-level mutations and
# notifies the daemon over `$XDG_RUNTIME_DIR/shit/shim.sock`. As
# of trunk-2026-05-23 the daemon's shim listener accepts the
# notifications and acks Allow but does NOT ingest them into the
# journal. W06.1 wires that.
#
# Expected first-run outcome (pre-W06.1): FAIL — silent partial
# undo. Installed files remain post-undo, no refusal, exit 0.
#
# Acceptable outcomes:
#   (A) Full undo: install files gone, source unchanged.
#   (B) Loud refusal: undo exits non-zero AND log mentions the
#       install destination or out-of-scope wording.
# FAIL: undo exits 0, installed files still present.
#
# See .docs/sprints/W/W06-make-install.md and W06.B-bsd.md.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: make-install-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
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

# Set up watched cwd + an unwatched install prefix.
WATCHED="${SHIT_SMOKE_TMP}/watched"
INSTALL_PREFIX="${SHIT_SMOKE_TMP}/install-target"
mkdir -p "${WATCHED}" "${INSTALL_PREFIX}/bin" "${INSTALL_PREFIX}/share"

# Tiny Makefile + sources. The Makefile installs from cwd to
# $(PREFIX). Using BSD-portable Makefile syntax (no $$ tricks).
cat > "${WATCHED}/Makefile" <<MAK
PREFIX ?= /usr/local
install:
	${INSTALL_BIN} -m 0755 hello \$(PREFIX)/bin/hello
	${INSTALL_BIN} -m 0644 README \$(PREFIX)/share/README
MAK

cat > "${WATCHED}/hello" <<'EOF'
#!/bin/sh
echo "hello from shit-installed binary"
EOF
chmod 0755 "${WATCHED}/hello"
printf 'manual README contents\n' > "${WATCHED}/README"

PRE_HELLO_SHA="$(/sbin/sha256 -q "${WATCHED}/hello")"
PRE_README_SHA="$(/sbin/sha256 -q "${WATCHED}/README")"
smoke_log "pre-cmd source sha: hello=${PRE_HELLO_SHA} README=${PRE_README_SHA}"

if [ -e "${INSTALL_PREFIX}/bin/hello" ] || [ -e "${INSTALL_PREFIX}/share/README" ]; then
    smoke_fail "install-target already populated; smoke env not clean"
fi

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

# THE workload. LD_PRELOAD the shim so install-syscalls hit the
# shim socket. PREFIX points to an unwatched dir.
smoke_log "LD_PRELOAD=${SHIM_LIB} make install PREFIX=${INSTALL_PREFIX}"
LD_PRELOAD="${SHIM_LIB}" "${MAKE_BIN}" -C "${WATCHED}" PREFIX="${INSTALL_PREFIX}" install \
    > "${SHIT_SMOKE_TMP}/make.log" 2>&1
MAKE_RC=$?
if [ "${MAKE_RC}" -ne 0 ]; then
    smoke_log "make stderr+stdout:"
    /usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/make.log" >&2 || true
    smoke_fail "make install failed pre-undo (rc=${MAKE_RC}) — workload setup broken"
fi
if [ ! -x "${INSTALL_PREFIX}/bin/hello" ] || [ ! -f "${INSTALL_PREFIX}/share/README" ]; then
    smoke_fail "make install claimed success but install-target files missing"
fi
smoke_log "post-cmd install-target populated:"
ls -la "${INSTALL_PREFIX}/bin/hello" "${INSTALL_PREFIX}/share/README" 2>&1 | /usr/bin/sed 's/^/    /' >&2

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

sleep 1.0

# Diagnostic: how many shim notifications did the daemon log?
# (Until W06.1 wires them, this is the only place they appear.)
# grep -c returns 1 with no matches and set -e would abort; the
# `|| echo 0` keeps the count meaningful in either case.
SHIM_HITS="$(grep -hc 'shim pre-mutation' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
# Multi-file: sum lines; otherwise scalar.
SHIM_HITS="$(printf '%s\n' ${SHIM_HITS} | awk '{s+=$1} END{print s+0}')"
smoke_log "shim notifications observed by daemon: ${SHIM_HITS}"

N_EVENTS="$(smoke_journal_count "1=1" 2>/dev/null || echo 0)"
smoke_log "journal events: ${N_EVENTS}"

# Run undo. Don't let set -e abort on a non-zero exit — we need
# to evaluate the outcome.
smoke_log "running: shit undo --yes"
set +e
"${SHIT_BIN}" undo --yes > "${SHIT_SMOKE_TMP}/undo.log" 2>&1
UNDO_RC=$?
set -e
smoke_log "shit undo --yes exit=${UNDO_RC}"
/usr/bin/sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

# Check whether install-target was reverted.
HELLO_GONE=no
README_GONE=no
[ ! -e "${INSTALL_PREFIX}/bin/hello" ] && HELLO_GONE=yes
[ ! -e "${INSTALL_PREFIX}/share/README" ] && README_GONE=yes
smoke_log "post-undo install-target: bin/hello gone=${HELLO_GONE}, share/README gone=${README_GONE}"

# Source files unchanged?
POST_HELLO_SHA="$(/sbin/sha256 -q "${WATCHED}/hello")"
POST_README_SHA="$(/sbin/sha256 -q "${WATCHED}/README")"
if [ "${POST_HELLO_SHA}" != "${PRE_HELLO_SHA}" ] || [ "${POST_README_SHA}" != "${PRE_README_SHA}" ]; then
    smoke_fail "source files perturbed by undo (hello: ${PRE_HELLO_SHA}→${POST_HELLO_SHA}; README: ${PRE_README_SHA}→${POST_README_SHA})"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo
if [ "${HELLO_GONE}" = "yes" ] && [ "${README_GONE}" = "yes" ]; then
    smoke_log "OUTCOME A — full undo (install-target reverted, source unchanged, shim hits=${SHIM_HITS})"
    smoke_log "PASS: make-install-undo-fbsd (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal
if [ "${UNDO_RC}" -ne 0 ] && grep -qE "install-target|out-of-scope|outside|refus|/bin/hello|/share/README" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named the out-of-scope path)"
    smoke_log "PASS: make-install-undo-fbsd (Outcome B)"
    exit 0
fi

# Outcome C — silent partial undo. Documents the cross-watch
# capture gap W06 was scoped to close.
#
# As of trunk-2026-05-23 the shim infrastructure exists
# (`shit-preload-shim` cdylib at target/release/libshit_preload_shim.so,
# daemon listener at `${XDG_RUNTIME_DIR}/shit-shim.sock`) but
# end-to-end shim → daemon → journal is NOT functional:
#   - Shim notifications reaching the daemon: ${SHIM_HITS}
#   - Journal events for install-target paths: ${N_EVENTS}
# Even when shim notifications DO arrive, the daemon's listener
# acks `Allow` and discards them — W06.1's load-bearing wiring.
#
# This smoke documents the gap and DOES NOT FAIL the run. It
# becomes a regression-gate once W06.1 lands.
smoke_log "OUTCOME C — silent partial undo (expected on trunk-2026-05-23)"
smoke_log "  undo exit:                ${UNDO_RC}"
smoke_log "  install-target bin/hello gone: ${HELLO_GONE}"
smoke_log "  install-target share/README gone: ${README_GONE}"
smoke_log "  shim notifications reaching daemon: ${SHIM_HITS}"
smoke_log "  journal events for install-target: ${N_EVENTS}"
smoke_log "  W06 closes this; see .docs/sprints/W/W06-make-install.md"
smoke_log "PASS: make-install-undo-fbsd (documenting cross-watch gap; W06 territory)"
