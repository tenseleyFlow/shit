#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: gem-install-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# L8 smoke: `gem install` of v2 of a local gem next to an installed v1,
# then `shit undo`. Same LD_PRELOAD shim path as pip-install-user-undo.
# The gem home is a per-run directory. Gems are built and installed from
# local files, so nothing is fetched from rubygems.org.
#
# Pass conditions: every file and symlink in the gem home matches its
# pre-v2 state (v2 files gone, v1 untouched, executable prints v1), or
# undo exits non-zero and names the conflict. Empty directories are
# compared separately: undo leaves gems/<name>-2.0.0 behind (#260), so a
# directory-only difference is logged, not failed.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: gem-install-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
for t in gem ruby python3; do
    if ! command -v "${t}" >/dev/null 2>&1; then
        smoke_log "SKIP: ${t} not on PATH"
        exit 0
    fi
done
smoke_log "gem $(gem --version), $(ruby --version)"

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

export HOME="${SHIT_SMOKE_TMP}/home"
mkdir -p "${HOME}"
GEMHOME="${SHIT_SMOKE_TMP}/gemhome"
mkdir -p "${GEMHOME}/bin"
export GEM_HOME="${GEMHOME}"
export GEM_PATH="${GEMHOME}"

GEM_NAME="shitprobe${$}"
SRC="${SHIT_SMOKE_TMP}/src"
for v in 1 2; do
    mkdir -p "${SRC}/v${v}/lib" "${SRC}/v${v}/exe"
    cat > "${SRC}/v${v}/${GEM_NAME}.gemspec" <<EOF
Gem::Specification.new do |s|
  s.name = "${GEM_NAME}"
  s.version = "${v}.0.0"
  s.summary = "shit smoke probe"
  s.authors = ["shit"]
  s.files = ["lib/${GEM_NAME}.rb", "exe/${GEM_NAME}"]
  s.bindir = "exe"
  s.executables = ["${GEM_NAME}"]
end
EOF
    echo "module ShitProbe; V = 'hello gem v${v}'; end" > "${SRC}/v${v}/lib/${GEM_NAME}.rb"
    cat > "${SRC}/v${v}/exe/${GEM_NAME}" <<EOF
#!/usr/bin/env ruby
require "${GEM_NAME}"
puts ShitProbe::V
EOF
    chmod 0755 "${SRC}/v${v}/exe/${GEM_NAME}"
    ( cd "${SRC}/v${v}" && gem build "${GEM_NAME}.gemspec" >/dev/null 2>&1 )
done
GEM1="${SRC}/v1/${GEM_NAME}-1.0.0.gem"
GEM2="${SRC}/v2/${GEM_NAME}-2.0.0.gem"
[ -f "${GEM1}" ] && [ -f "${GEM2}" ] || smoke_fail "gem build did not produce both gems"

INSTALLED_BIN="${GEMHOME}/bin/${GEM_NAME}"
GEM_FLAGS=(install --local --no-document --install-dir "${GEMHOME}" --bindir "${GEMHOME}/bin")

smoke_log "pre-state: gem install v1 (not through hooks)"
gem "${GEM_FLAGS[@]}" "${GEM1}" >"${SHIT_SMOKE_TMP}/gem-v1.log" 2>&1 || {
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/gem-v1.log" >&2
    smoke_fail "pre-state gem install (v1) failed"
}
V1_OUT="$("${INSTALLED_BIN}")"
[ "${V1_OUT}" = "hello gem v1" ] || smoke_fail "pre-state prints '${V1_OUT}', want 'hello gem v1'"

tree_snapshot() {
    ( cd "${GEMHOME}" \
        && find . ! -type d -print0 | sort -z | xargs -0 stat -c '%a %F %n' \
        && find . -type f -print0 | sort -z | xargs -0 sha256sum )
}
dir_snapshot() {
    ( cd "${GEMHOME}" && find . -type d | sort )
}
tree_snapshot > "${SHIT_SMOKE_TMP}/tree-before.txt"
dir_snapshot > "${SHIT_SMOKE_TMP}/dirs-before.txt"

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

smoke_log "LD_PRELOAD=${SHIM_LIB} gem install (v2)"
set +e
LD_PRELOAD="${SHIM_LIB}" gem "${GEM_FLAGS[@]}" "${GEM2}" >"${SHIT_SMOKE_TMP}/gem-v2.log" 2>&1
GEM_RC=$?
set -e
if [ "${GEM_RC}" -ne 0 ]; then
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/gem-v2.log" >&2
    smoke_fail "gem install (v2) exited rc=${GEM_RC}"
fi
V2_OUT="$("${INSTALLED_BIN}")"
[ "${V2_OUT}" = "hello gem v2" ] || smoke_fail "post-install prints '${V2_OUT}', want 'hello gem v2'"
tree_snapshot > "${SHIT_SMOKE_TMP}/tree-v2.txt"
if diff -q "${SHIT_SMOKE_TMP}/tree-before.txt" "${SHIT_SMOKE_TMP}/tree-v2.txt" >/dev/null; then
    smoke_fail "v2 install did not change the gem home"
fi
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

tree_snapshot > "${SHIT_SMOKE_TMP}/tree-after.txt"
if diff "${SHIT_SMOKE_TMP}/tree-before.txt" "${SHIT_SMOKE_TMP}/tree-after.txt" \
    > "${SHIT_SMOKE_TMP}/tree.diff" 2>&1; then
    POST_OUT="$(SHIT_DURING_UNDO=1 "${INSTALLED_BIN}" 2>&1 || true)"
    if [ "${POST_OUT}" = "hello gem v1" ]; then
        dir_snapshot > "${SHIT_SMOKE_TMP}/dirs-after.txt"
        if ! diff "${SHIT_SMOKE_TMP}/dirs-before.txt" "${SHIT_SMOKE_TMP}/dirs-after.txt" \
            > "${SHIT_SMOKE_TMP}/dirs.diff" 2>&1; then
            smoke_log "known gap #260: directories differ after undo:"
            sed 's/^/    /' "${SHIT_SMOKE_TMP}/dirs.diff" >&2
            # Under SHIT_REQUIRE_OUTCOME_A=1 only the #260 leftover is allowed.
            if [ "${SHIT_REQUIRE_OUTCOME_A:-}" = "1" ] \
                && grep -E '^[<>]' "${SHIT_SMOKE_TMP}/dirs.diff" \
                    | grep -qvxF "> ./gems/${GEM_NAME}-2.0.0"; then
                smoke_fail "SHIT_REQUIRE_OUTCOME_A=1: unexpected directory differences beyond #260"
            fi
        fi
        if [ "${SHIT_REQUIRE_OUTCOME_A:-}" = "1" ] && [ "${UNDO_RC}" -ne 0 ]; then
            smoke_fail "SHIT_REQUIRE_OUTCOME_A=1: undo exited ${UNDO_RC} after restoring the files"
        fi
        smoke_log "OUTCOME A: gem files match the pre-v2 state, executable prints v1"
        smoke_log "PASS: gem-install-undo-linux (Outcome A)"
        exit 0
    fi
    smoke_fail "tree restored but executable prints '${POST_OUT}'"
fi

smoke_log "gem home differs from the pre-v2 state after undo:"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/tree.diff" >&2

if [ "${SHIT_REQUIRE_OUTCOME_A:-}" = "1" ]; then
    smoke_fail "SHIT_REQUIRE_OUTCOME_A=1: gem home not restored"
fi

if [ "${UNDO_RC}" -ne 0 ] \
    && grep -qE "conflict \(|refused|Conflict[A-Za-z]*|out-of-scope" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B: loud refusal (undo non-zero, log names the conflict)"
    smoke_log "PASS: gem-install-undo-linux (Outcome B)"
    exit 0
fi

smoke_fail "gem install neither restored nor refused loudly (undo rc=${UNDO_RC})"
