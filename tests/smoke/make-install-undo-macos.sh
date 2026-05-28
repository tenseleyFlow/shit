#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: make-install-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M07.A.5 smoke — macOS twin of make-install-undo-linux.sh. `make
# install` writes files into a prefix OUTSIDE the watched cwd
# subtree. `shit undo` should reverse those writes via the
# DYLD_INSERT_LIBRARIES shim capturing libc-level mutations.
#
# Why this is the macOS twin's only viable capture mechanism in
# stock-Mac (FSEvents-degraded) mode: FSEvents fires after the
# mutation lands and can't be filtered to a specific install
# prefix without watching the whole filesystem. The DYLD shim
# notifies the daemon BEFORE each interposed syscall completes,
# carrying the destination path inline. Same architectural shape
# as the Linux smoke's LD_PRELOAD path; same outcomes.
#
# Outcomes (mirroring the FreeBSD / Linux smokes):
#   A. Full undo: install files gone, source unchanged.
#   B. Loud refusal: undo exits non-zero AND log mentions the
#      install destination or out-of-scope wording.
#   C. Silent partial undo (FAIL): install files remain, undo
#      exits 0, no refusal logged.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: make-install-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

# macOS strips DYLD_INSERT_LIBRARIES from any binary in a SIP-
# protected path (`/usr/bin/`, `/bin/`, `/System/`, etc.) by design
# — even when the binary itself isn't hardened-runtime. `/usr/bin/
# make` and `/usr/bin/install` both hit this; if we use them the
# shim never loads and the smoke would observe zero notifications.
#
# Require Homebrew's `gmake` (formula `make`) and `ginstall`
# (formula `coreutils`), both ad-hoc-signed linker output that
# preserves DYLD_INSERT. SKIP loudly when either is missing —
# Outcome C with zero shim hits is uninformative noise.
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

# macOS-specific sha256 helper. `sha256sum` from coreutils may or
# may not be on PATH (Homebrew's `gsha256sum` is the GNU one). The
# Apple-shipped `shasum -a 256` is always present.
sha256_of() {
    shasum -a 256 "$1" | awk '{print $1}'
}

# Set up watched cwd + an unwatched install prefix.
WATCHED="${SHIT_SMOKE_TMP}/watched"
INSTALL_PREFIX="${SHIT_SMOKE_TMP}/install-target"
mkdir -p "${WATCHED}" "${INSTALL_PREFIX}/bin" "${INSTALL_PREFIX}/share"

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

PRE_HELLO_SHA="$(sha256_of "${WATCHED}/hello")"
PRE_README_SHA="$(sha256_of "${WATCHED}/README")"
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

# THE workload. DYLD_INSERT_LIBRARIES the shim so install-syscalls
# hit the shim socket. PREFIX points to an unwatched dir.
#
# gmake + ginstall are both ad-hoc-signed Homebrew binaries; DYLD_INSERT
# survives into both. Validated locally via DYLD_PRINT_INTERPOSING=1 —
# all 8 interposers attach in the gmake process and inherit into ginstall.
smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} make install PREFIX=${INSTALL_PREFIX}"
DYLD_INSERT_LIBRARIES="${SHIM_LIB}" "${MAKE_BIN}" -C "${WATCHED}" PREFIX="${INSTALL_PREFIX}" install \
    > "${SHIT_SMOKE_TMP}/make.log" 2>&1
MAKE_RC=$?
if [ "${MAKE_RC}" -ne 0 ]; then
    smoke_log "make stderr+stdout:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/make.log" >&2 || true
    smoke_fail "make install failed pre-undo (rc=${MAKE_RC}) — workload setup broken"
fi
if [ ! -x "${INSTALL_PREFIX}/bin/hello" ] || [ ! -f "${INSTALL_PREFIX}/share/README" ]; then
    smoke_fail "make install claimed success but install-target files missing"
fi
smoke_log "post-cmd install-target populated:"
ls -la "${INSTALL_PREFIX}/bin/hello" "${INSTALL_PREFIX}/share/README" 2>&1 | sed 's/^/    /' >&2

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

sleep 1.0

# Diagnostic: how many shim notifications reached the daemon?
SHIM_HITS="$(grep -hc 'shim pre-mutation' "${SHIT_SMOKE_TMP}"/state/shit/log/daemon.jsonl.* 2>/dev/null || echo 0)"
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
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

# Check whether install-target was reverted.
HELLO_GONE=no
README_GONE=no
[ ! -e "${INSTALL_PREFIX}/bin/hello" ] && HELLO_GONE=yes
[ ! -e "${INSTALL_PREFIX}/share/README" ] && README_GONE=yes
smoke_log "post-undo install-target: bin/hello gone=${HELLO_GONE}, share/README gone=${README_GONE}"

# Source files unchanged?
POST_HELLO_SHA="$(sha256_of "${WATCHED}/hello")"
POST_README_SHA="$(sha256_of "${WATCHED}/README")"
if [ "${POST_HELLO_SHA}" != "${PRE_HELLO_SHA}" ] || [ "${POST_README_SHA}" != "${PRE_README_SHA}" ]; then
    smoke_fail "source files perturbed by undo (hello: ${PRE_HELLO_SHA}→${POST_HELLO_SHA}; README: ${PRE_README_SHA}→${POST_README_SHA})"
fi

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo
if [ "${HELLO_GONE}" = "yes" ] && [ "${README_GONE}" = "yes" ]; then
    smoke_log "OUTCOME A — full undo (install-target reverted, source unchanged, shim hits=${SHIM_HITS})"
    smoke_log "PASS: make-install-undo-macos (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal
if [ "${UNDO_RC}" -ne 0 ] && grep -qE "install-target|out-of-scope|outside|refus|/bin/hello|/share/README" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named the out-of-scope path)"
    smoke_log "PASS: make-install-undo-macos (Outcome B)"
    exit 0
fi

# Outcome C — silent partial undo. FAIL.
smoke_log "OUTCOME C — silent partial undo (DYLD shim → journal wiring missing)"
smoke_log "  undo exit:                ${UNDO_RC}"
smoke_log "  install-target bin/hello gone: ${HELLO_GONE}"
smoke_log "  install-target share/README gone: ${README_GONE}"
smoke_log "  shim notifications reaching daemon: ${SHIM_HITS}"
smoke_log "  journal events:                    ${N_EVENTS}"
smoke_fail "make install undo did NOT reverse the out-of-watch install (outcome C)"
