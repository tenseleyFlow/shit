#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: npm-install-global-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# L8 smoke: `npm install -g` of a newer version over an installed one,
# then `shit undo`. Same LD_PRELOAD shim path as pip-install-user-undo.
# The global prefix is a per-run directory, so no system path is touched.
#
# The package is a local tarball (npm pack), so nothing is fetched from
# the registry. npm replaces the package directory; the pass condition
# is that the v1 module is back byte-identical and still prints v1.
# A loud refusal (non-zero exit naming a conflict) is accepted unless
# SHIT_REQUIRE_OUTCOME_A=1. Undo exits 1 and leaves a temp symlink (#261);
# the smoke gates on the module restore and logs the tree diff.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: npm-install-global-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
for t in npm node python3; do
    if ! command -v "${t}" >/dev/null 2>&1; then
        smoke_log "SKIP: ${t} not on PATH"
        exit 0
    fi
done
smoke_log "npm $(npm --version), node $(node --version)"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

export HOME="${SHIT_SMOKE_TMP}/home"
mkdir -p "${HOME}"
export npm_config_cache="${SHIT_SMOKE_TMP}/npm-cache"
export npm_config_update_notifier=false
export npm_config_audit=false
export npm_config_fund=false
PFX="${SHIT_SMOKE_TMP}/npm-prefix"
mkdir -p "${PFX}"

PKG_NAME="shit-probe-$$"
SRC="${SHIT_SMOKE_TMP}/src"
mkdir -p "${SRC}/v1" "${SRC}/v2"
for v in 1 2; do
    cat > "${SRC}/v${v}/package.json" <<EOF
{ "name": "${PKG_NAME}", "version": "${v}.0.0", "main": "index.js",
  "bin": { "${PKG_NAME}": "index.js" } }
EOF
    cat > "${SRC}/v${v}/index.js" <<EOF
#!/usr/bin/env node
console.log("hello npm v${v}");
EOF
    chmod 0755 "${SRC}/v${v}/index.js"
    ( cd "${SRC}/v${v}" && npm pack --pack-destination "${SRC}" >/dev/null )
done
TGZ1="${SRC}/${PKG_NAME}-1.0.0.tgz"
TGZ2="${SRC}/${PKG_NAME}-2.0.0.tgz"
[ -f "${TGZ1}" ] && [ -f "${TGZ2}" ] || smoke_fail "npm pack did not produce both tarballs"

INSTALLED_DIR="${PFX}/lib/node_modules/${PKG_NAME}"
INSTALLED_MOD="${INSTALLED_DIR}/index.js"
INSTALLED_BIN="${PFX}/bin/${PKG_NAME}"

NPM_FLAGS=(install -g --prefix "${PFX}" --offline --no-audit --no-fund --loglevel=error)

smoke_log "pre-state: npm install -g v1 (not through hooks)"
npm "${NPM_FLAGS[@]}" "${TGZ1}" >"${SHIT_SMOKE_TMP}/npm-v1.log" 2>&1 || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/npm-v1.log" >&2
    smoke_fail "pre-state npm install -g (v1) failed"
}
[ -f "${INSTALLED_MOD}" ] || smoke_fail "v1 module not at ${INSTALLED_MOD}"
V1_OUT="$("${INSTALLED_BIN}")"
[ "${V1_OUT}" = "hello npm v1" ] || smoke_fail "pre-state prints '${V1_OUT}', want 'hello npm v1'"
V1_SHA="$(sha256sum "${INSTALLED_MOD}" | awk '{print $1}')"

tree_snapshot() {
    ( cd "${PFX}" \
        && find . -print0 | sort -z | xargs -0 stat -c '%a %F %n' \
        && find . -type f -print0 | sort -z | xargs -0 sha256sum )
}
tree_snapshot > "${SHIT_SMOKE_TMP}/tree-before.txt"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "" --sock "${SHIT_HOOK_SOCK}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${SRC}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

smoke_log "LD_PRELOAD=${SHIM_LIB} npm install -g (v2)"
set +e
LD_PRELOAD="${SHIM_LIB}" npm "${NPM_FLAGS[@]}" "${TGZ2}" >"${SHIT_SMOKE_TMP}/npm-v2.log" 2>&1
NPM_RC=$?
set -e
if [ "${NPM_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/npm-v2.log" >&2
    smoke_fail "npm install -g (v2) exited rc=${NPM_RC}"
fi
V2_OUT="$("${INSTALLED_BIN}")"
[ "${V2_OUT}" = "hello npm v2" ] || smoke_fail "post-install prints '${V2_OUT}', want 'hello npm v2'"
V2_SHA="$(sha256sum "${INSTALLED_MOD}" | awk '{print $1}')"
[ "${V2_SHA}" != "${V1_SHA}" ] || smoke_fail "v2 install did not change the module"
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
sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

POST_SHA=""
POST_OUT=""
if [ -f "${INSTALLED_MOD}" ]; then
    POST_SHA="$(sha256sum "${INSTALLED_MOD}" | awk '{print $1}')"
    tree_snapshot > "${SHIT_SMOKE_TMP}/tree-after.txt"
    POST_OUT="$(SHIT_DURING_UNDO=1 "${INSTALLED_BIN}" 2>&1 || true)"
fi

TREE_SAME=1
if ! diff "${SHIT_SMOKE_TMP}/tree-before.txt" "${SHIT_SMOKE_TMP}/tree-after.txt" \
    > "${SHIT_SMOKE_TMP}/tree.diff" 2>&1; then
    TREE_SAME=0
    smoke_log "npm prefix differs from the pre-state after undo:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/tree.diff" >&2
fi

if [ "${POST_SHA}" = "${V1_SHA}" ] && [ "${POST_OUT}" = "hello npm v1" ]; then
    # Under SHIT_REQUIRE_OUTCOME_A=1 the only allowed leftover is the
    # temp bin symlink from #261.
    if [ "${SHIT_REQUIRE_OUTCOME_A:-}" = "1" ] && [ "${TREE_SAME}" != "1" ]; then
        if grep -E '^[<>]' "${SHIT_SMOKE_TMP}/tree.diff" \
            | grep -qvE "^> [0-9]+ symbolic link \./bin/\.${PKG_NAME}-[A-Za-z0-9]+$"; then
            smoke_fail "SHIT_REQUIRE_OUTCOME_A=1: prefix tree differs beyond the #261 temp symlink"
        fi
        smoke_log "known gap #261: temp symlink left in bin/ (undo exit=${UNDO_RC})"
    fi
    smoke_log "OUTCOME A: v1 module restored byte-identical (tree_same=${TREE_SAME})"
    smoke_log "PASS: npm-install-global-undo-linux (Outcome A)"
    exit 0
fi

if [ "${SHIT_REQUIRE_OUTCOME_A:-}" = "1" ]; then
    smoke_log "  output now: '${POST_OUT}', sha now: ${POST_SHA:0:16}, v1: ${V1_SHA:0:16}"
    smoke_fail "SHIT_REQUIRE_OUTCOME_A=1: npm -g overwrite not undone"
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "conflict \(|refused|Conflict[A-Za-z]*|out-of-scope" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B: loud refusal (undo non-zero, log names the conflict)"
    smoke_log "PASS: npm-install-global-undo-linux (Outcome B)"
    exit 0
fi

smoke_log "  output now: '${POST_OUT}', sha now: ${POST_SHA:0:16}, v1: ${V1_SHA:0:16}, v2: ${V2_SHA:0:16}"
smoke_fail "npm -g overwrite neither restored nor refused loudly (undo rc=${UNDO_RC})"
