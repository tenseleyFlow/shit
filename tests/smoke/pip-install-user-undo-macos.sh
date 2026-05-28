#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: pip-install-user-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M07.A.5 — macOS twin of pip-install-user-undo-linux.sh. `pip
# install --force-reinstall` overwrites the v1 module under the
# per-run HOME/.local/lib/pythonX.Y/site-packages. The DYLD
# shim catches the overwrite (pip's atomic-rename pattern hits
# the rename interposer; the file write hits open). `shit undo`
# restores the v1 module bytes.
#
# Pre-conditions for the shim to fire on python/pip:
# - python3 must NOT be in a SIP-protected path. Apple's
#   /usr/bin/python3 is a shim that asks you to install Xcode
#   anyway; we explicitly require a Homebrew python3
#   (/opt/homebrew/bin/python3 on arm64, /usr/local/bin on x86).
#
# Per-run isolation: unique package name + $HOME pointed at the
# smoke tmpdir so ~/.local is per-run.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: pip-install-user-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

# Require a non-SIP Python — that's what determines whether DYLD
# survives. Apple's /usr/bin/python3 is SIP-protected (and is a
# shim anyway). The user must have brew install python OR an
# equivalent non-Apple toolchain.
PYTHON_BIN=""
for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3; do
    if [ -x "${candidate}" ]; then
        PYTHON_BIN="${candidate}"
        break
    fi
done
if [ -z "${PYTHON_BIN}" ]; then
    smoke_log "SKIP: no Homebrew python3 found (DYLD_INSERT requires non-SIP python; brew install python)"
    exit 0
fi
case "${PYTHON_BIN}" in
    /usr/bin/* | /bin/* | /System/*)
        smoke_log "SKIP: python at ${PYTHON_BIN} is in a SIP-protected path; DYLD_INSERT would be stripped"
        exit 0
        ;;
esac
PIP_BIN="${PYTHON_BIN} -m pip"
smoke_log "python: ${PYTHON_BIN} ($(${PYTHON_BIN} --version 2>&1))"

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

# Pin HOME inside the smoke tmpdir so ~/.local is per-run.
SMOKE_HOME="${SHIT_SMOKE_TMP}/home"
mkdir -p "${SMOKE_HOME}/.local/bin"
export HOME="${SMOKE_HOME}"

PKG_NAME="hellopkg_shit_$$"
MOD_NAME="hello_shit_$$"
PKG_DIR="${SHIT_SMOKE_TMP}/${PKG_NAME}"
# macOS framework Python's `--user` site differs from Linux: scripts
# land in `~/Library/Python/<X.Y>/bin`, not `~/.local/bin`. Ask the
# interpreter authoritatively.
PY_USER_BASE="$(${PYTHON_BIN} -m site --user-base)"
INSTALLED_BIN="${PY_USER_BASE}/bin/hello-shit-${$}"

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

# Build isolation is ON by default (we don't pass --no-build-isolation
# like the Linux smoke does). On Ubuntu CI, system setuptools is pre-
# installed via apt and --no-build-isolation works without setup; on
# macOS we'd need to bootstrap setuptools into the per-run HOME first.
# Letting pip provision a transient build env is a few seconds slower
# but doesn't introduce a hidden setup dependency.
PIP_FLAGS="--user --quiet"
# Some Homebrew Pythons are PEP-668-enforced; --break-system-packages
# opts in if supported.
if ${PIP_BIN} install --help 2>&1 | grep -q -- "--break-system-packages"; then
    PIP_FLAGS="${PIP_FLAGS} --break-system-packages"
fi

# Pre-state: install v1 (NOT through hooks).
smoke_log "pre-state: pip install ${PIP_FLAGS} (v1)"
( cd "${PKG_DIR}" && ${PIP_BIN} install ${PIP_FLAGS} . ) \
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
# pip's entry-point wrapper script is byte-identical between v1/v2;
# sha the MODULE file instead. See feedback_pip_entry_point memory.
PY_USER_SITE="$(${PIP_BIN} show "${PKG_NAME}" 2>/dev/null | awk '/^Location:/ {print $2}')"
[ -n "${PY_USER_SITE}" ] || smoke_fail "could not resolve user-site location via pip show"
INSTALLED_MOD="${PY_USER_SITE}/${MOD_NAME}.py"
[ -f "${INSTALLED_MOD}" ] || smoke_fail "module file not found at ${INSTALLED_MOD}"
V1_SHA="$(sha256_of "${INSTALLED_MOD}")"
smoke_log "pre-state: v1 module at ${INSTALLED_MOD}, sha=${V1_SHA:0:16}..."

# v2 source + version bump.
cat > "${PKG_DIR}/${MOD_NAME}.py" <<'EOF'
def main():
    print("hello pip v2")
EOF
# macOS sed -i needs empty backup-suffix arg.
sed -i '' "s/version='1.0'/version='2.0'/" "${PKG_DIR}/setup.py"

smoke_start_shitd

SESSION="$(${PYTHON_BIN} -c 'import uuid; print(uuid.uuid4())')"
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

# THE workload. DYLD_INSERT the shim. pip's wheel installer does
# the same rename-into-place pattern as on Linux; same shim
# interposers fire.
smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} pip install ${PIP_FLAGS} --force-reinstall --no-cache-dir (v2)"
( cd "${PKG_DIR}" && DYLD_INSERT_LIBRARIES="${SHIM_LIB}" ${PIP_BIN} install ${PIP_FLAGS} --force-reinstall --no-cache-dir . ) \
    >"${SHIT_SMOKE_TMP}/pip-v2.log" 2>&1
PIP_RC=$?
if [ "${PIP_RC}" -ne 0 ]; then
    smoke_log "pip-v2.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/pip-v2.log" >&2
    smoke_fail "pip install --force-reinstall (v2) exited rc=${PIP_RC}"
fi

V2_OUTPUT="$(SHIT_DURING_UNDO=1 "${INSTALLED_BIN}")"
if [ "${V2_OUTPUT}" != "hello pip v2" ]; then
    smoke_log "pip-v2.log (last 50 lines):"
    tail -50 "${SHIT_SMOKE_TMP}/pip-v2.log" | sed 's/^/    /' >&2
    smoke_log "installed module content:"
    sed 's/^/    /' "${INSTALLED_MOD}" >&2
    smoke_fail "post-install module doesn't print v2 marker: '${V2_OUTPUT}'"
fi
V2_SHA="$(sha256_of "${INSTALLED_MOD}")"
if [ "${V2_SHA}" = "${V1_SHA}" ]; then
    smoke_log "pip-v2.log (last 50 lines):"
    tail -50 "${SHIT_SMOKE_TMP}/pip-v2.log" | sed 's/^/    /' >&2
    smoke_fail "v2 install didn't actually change the module (sha unchanged)"
fi
smoke_log "post-install: v2 module at ${INSTALLED_MOD}, sha=${V2_SHA:0:16}... (overwrote v1)"

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
if [ ! -f "${INSTALLED_MOD}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${INSTALLED_MOD} missing post-undo — undo unlinked instead of restoring"
fi

POST_OUTPUT="$(SHIT_DURING_UNDO=1 "${INSTALLED_BIN}")"
POST_SHA="$(sha256_of "${INSTALLED_MOD}")"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo (v1 module restored byte-identical)
if [ "${POST_SHA}" = "${V1_SHA}" ] && [ "${POST_OUTPUT}" = "hello pip v1" ]; then
    smoke_log "OUTCOME A — full undo (module restored to v1 byte-identical, output='${POST_OUTPUT}', shim hits=${SHIM_HITS})"
    smoke_log "PASS: pip-install-user-undo-macos (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal acceptable (see Linux smoke's rationale
# about pip's transactional rename hitting conflict reports).
if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "out-of-scope|outside|refus|conflict|${PKG_NAME}" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named conflict/out-of-scope)"
    smoke_log "PASS: pip-install-user-undo-macos (Outcome B)"
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
