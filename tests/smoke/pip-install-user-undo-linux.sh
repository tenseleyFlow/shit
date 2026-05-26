#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR05.3 smoke — `pip install --user` OVERWRITES a script under
# ~/.local/bin. The LD_PRELOAD shim catches the overwrite and
# captures the OLD script's content as a pre-image. `shit undo`
# restores the v1 script.
#
# Same shim path as AR05.2 (cargo install --force) but exercising
# a different runtime (pip's wheel-install path uses Python's
# shutil.move + os.chmod sequence, which lands at libc-level as
# rename + chmod — the rename interposer catches it).
#
# Ubuntu 24.04 PEP 668: system Python is "externally managed".
# pip install --user is blocked unless --break-system-packages
# is passed. We use --break-system-packages in this isolated CI
# smoke; production users running on PEP-668-compliant systems
# typically use venvs. The shim path is identical either way.
#
# Per-run isolation: unique package name + $HOME pointed at the
# smoke tmpdir so ~/.local is per-run.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: pip-install-user-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

if ! command -v pip3 >/dev/null 2>&1 && ! command -v pip >/dev/null 2>&1; then
    smoke_log "SKIP: pip / pip3 not on PATH"
    exit 0
fi
PIP_BIN="$(command -v pip3 2>/dev/null || command -v pip)"
smoke_log "pip: ${PIP_BIN} ($(${PIP_BIN} --version 2>&1 | head -1))"

if ! command -v python3 >/dev/null 2>&1; then
    smoke_log "SKIP: python3 not on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Pin HOME inside the smoke tmpdir so ~/.local is per-run.
SMOKE_HOME="${SHIT_SMOKE_TMP}/home"
mkdir -p "${SMOKE_HOME}/.local/bin"
export HOME="${SMOKE_HOME}"

PKG_NAME="hellopkg_shit_$$"
MOD_NAME="hello_shit_$$"
PKG_DIR="${SHIT_SMOKE_TMP}/${PKG_NAME}"
INSTALLED_BIN="${HOME}/.local/bin/hello-shit-${$}"

mkdir -p "${PKG_DIR}"

cat > "${PKG_DIR}/setup.py" <<EOF
from setuptools import setup
setup(
    name='${PKG_NAME}',
    version='1.0',
    py_modules=['${MOD_NAME}'],
    entry_points={'console_scripts': ['hello-shit-${$}=${MOD_NAME}:main']},
)
EOF

cat > "${PKG_DIR}/${MOD_NAME}.py" <<'EOF'
def main():
    print("hello pip v1")
EOF

PIP_FLAGS="--user --no-build-isolation --quiet"
# PEP 668 (Ubuntu 24.04): system Python is externally managed; pip
# refuses --user without an opt-in. CI smoke uses the opt-in flag.
if "${PIP_BIN}" install --help 2>&1 | grep -q -- "--break-system-packages"; then
    PIP_FLAGS="${PIP_FLAGS} --break-system-packages"
fi

# Pre-state: install v1 (NOT through hooks).
smoke_log "pre-state: pip install ${PIP_FLAGS} (v1)"
( cd "${PKG_DIR}" && "${PIP_BIN}" install ${PIP_FLAGS} . ) \
    >"${SHIT_SMOKE_TMP}/pip-v1.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/pip-v1.log" >&2
        smoke_fail "pre-state pip install (v1) failed"
    }

if [ ! -x "${INSTALLED_BIN}" ]; then
    smoke_log "pip-v1.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/pip-v1.log" >&2
    smoke_fail "v1 script not created at ${INSTALLED_BIN}"
fi

V1_OUTPUT="$("${INSTALLED_BIN}")"
if [ "${V1_OUTPUT}" != "hello pip v1" ]; then
    smoke_fail "pre-state script doesn't print v1 marker: '${V1_OUTPUT}'"
fi
V1_SHA="$(sha256sum "${INSTALLED_BIN}" | awk '{print $1}')"
smoke_log "pre-state: v1 script at ${INSTALLED_BIN}, sha=${V1_SHA:0:16}..."

# v2 source + version bump.
cat > "${PKG_DIR}/${MOD_NAME}.py" <<'EOF'
def main():
    print("hello pip v2")
EOF
sed -i "s/version='1.0'/version='2.0'/" "${PKG_DIR}/setup.py"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID} cwd=${PKG_DIR}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${PKG_DIR}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# THE workload. LD_PRELOAD the shim. pip install --upgrade
# overwrites the v1 script + module at ~/.local.
smoke_log "LD_PRELOAD=${SHIM_LIB} pip install ${PIP_FLAGS} --upgrade (v2)"
( cd "${PKG_DIR}" && LD_PRELOAD="${SHIM_LIB}" "${PIP_BIN}" install ${PIP_FLAGS} --upgrade . ) \
    >"${SHIT_SMOKE_TMP}/pip-v2.log" 2>&1
PIP_RC=$?
if [ "${PIP_RC}" -ne 0 ]; then
    smoke_log "pip-v2.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/pip-v2.log" >&2
    smoke_fail "pip install --upgrade (v2) exited rc=${PIP_RC}"
fi

V2_OUTPUT="$(SHIT_DURING_UNDO=1 "${INSTALLED_BIN}")"
if [ "${V2_OUTPUT}" != "hello pip v2" ]; then
    smoke_fail "post-install script doesn't print v2 marker: '${V2_OUTPUT}'"
fi
V2_SHA="$(sha256sum "${INSTALLED_BIN}" | awk '{print $1}')"
if [ "${V2_SHA}" = "${V1_SHA}" ]; then
    smoke_fail "v2 install didn't actually change the script (sha unchanged)"
fi
smoke_log "post-install: v2 script at ${INSTALLED_BIN}, sha=${V2_SHA:0:16}... (overwrote v1)"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

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

if [ ! -x "${INSTALLED_BIN}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${INSTALLED_BIN} missing post-undo — undo unlinked instead of restoring"
fi

POST_OUTPUT="$(SHIT_DURING_UNDO=1 "${INSTALLED_BIN}")"
POST_SHA="$(sha256sum "${INSTALLED_BIN}" | awk '{print $1}')"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo (v1 restored byte-identical)
if [ "${POST_SHA}" = "${V1_SHA}" ] && [ "${POST_OUTPUT}" = "hello pip v1" ]; then
    smoke_log "OUTCOME A — full undo (script restored to v1 byte-identical, output='${POST_OUTPUT}', shim hits=${SHIM_HITS})"
    smoke_log "PASS: pip-install-user-undo-linux (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal acceptable
if [ "${UNDO_RC}" -ne 0 ] && grep -qE "out-of-scope|outside|refus|local|${PKG_NAME}" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named the out-of-scope path)"
    smoke_log "PASS: pip-install-user-undo-linux (Outcome B)"
    exit 0
fi

# Outcome C — partial / wrong restore
smoke_log "OUTCOME C — partial / wrong restore"
smoke_log "  undo exit:    ${UNDO_RC}"
smoke_log "  output now:   '${POST_OUTPUT}' (expected 'hello pip v1')"
smoke_log "  sha now:      ${POST_SHA:0:16}..."
smoke_log "  sha v1:       ${V1_SHA:0:16}..."
smoke_log "  sha v2:       ${V2_SHA:0:16}..."
smoke_log "  shim hits:    ${SHIM_HITS}"
smoke_log "  journal evts: ${N_EVENTS}"
smoke_fail "pip install --user overwrite undo didn't restore v1 (outcome C)"
