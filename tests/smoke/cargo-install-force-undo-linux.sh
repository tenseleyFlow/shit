#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: cargo-install-force-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR05.2 smoke — `cargo install --force` OVERWRITES an existing
# binary at the install root. The LD_PRELOAD shim catches the
# overwrite sequence (cargo build → tempfile → rename over dst)
# and captures the OLD binary's content as a pre-image. `shit undo`
# restores the prior binary bytes.
#
# Contrast with AR05.1:
# - AR05.1 (make-install-undo): FRESH create into out-of-watch
#   prefix. Shim notifies pre-mutation with no pre-image; daemon
#   journals TreeOp::Create; undo unlinks the new file.
# - AR05.2 (this): OVERWRITE of an existing binary. Shim captures
#   bytes via the openat/rename pre-image path; daemon journals
#   FilePreImage; undo restores the captured bytes.
#
# Uses a minimal local Rust crate so we don't pay crates.io fetch
# time. Tag a unique binary name with $$ so concurrent CI runs
# don't collide on /tmp/cargo-test-root/bin/.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: cargo-install-force-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi

if ! command -v cargo >/dev/null 2>&1; then
    smoke_log "SKIP: cargo not on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit binary missing at ${SHIT_BIN}"
[ -f "${SHIM_LIB}" ]   || smoke_fail "shim library missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Per-run isolation: unique crate name + per-run install root.
CRATE_NAME="hello_shit_$$"
CRATE_DIR="${SHIT_SMOKE_TMP}/${CRATE_NAME}"
CARGO_ROOT="${SHIT_SMOKE_TMP}/cargo-root"
INSTALLED_BIN="${CARGO_ROOT}/bin/${CRATE_NAME}"

mkdir -p "${CRATE_DIR}/src" "${CARGO_ROOT}/bin"

cat > "${CRATE_DIR}/Cargo.toml" <<EOF
[package]
name = "${CRATE_NAME}"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "${CRATE_NAME}"
path = "src/main.rs"
EOF

# v1 source.
cat > "${CRATE_DIR}/src/main.rs" <<'EOF'
fn main() {
    println!("hello shit v1");
}
EOF

# Pre-state: install v1 (NOT through hooks). This establishes the
# baseline binary at the install root.
smoke_log "pre-state: cargo install (v1) into ${CARGO_ROOT}"
( cd "${CRATE_DIR}" && cargo install --root "${CARGO_ROOT}" --path . --quiet ) \
    >"${SHIT_SMOKE_TMP}/cargo-v1.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/cargo-v1.log" >&2
        smoke_fail "pre-state cargo install (v1) failed"
    }

if [ ! -x "${INSTALLED_BIN}" ]; then
    smoke_fail "v1 binary not created at ${INSTALLED_BIN}"
fi

# Capture v1's actual output to confirm provenance later.
V1_OUTPUT="$("${INSTALLED_BIN}")"
if [ "${V1_OUTPUT}" != "hello shit v1" ]; then
    smoke_fail "pre-state binary doesn't print v1 marker: '${V1_OUTPUT}'"
fi
V1_SHA="$(sha256sum "${INSTALLED_BIN}" | awk '{print $1}')"
smoke_log "pre-state: v1 binary at ${INSTALLED_BIN}, sha=${V1_SHA:0:16}..."

# Modify source: v2.
cat > "${CRATE_DIR}/src/main.rs" <<'EOF'
fn main() {
    println!("hello shit v2");
}
EOF
# Bump version so cargo install --force has something to install.
sed -i 's/version = "0.1.0"/version = "0.2.0"/' "${CRATE_DIR}/Cargo.toml"

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"

smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID} cwd=${CRATE_DIR}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${CRATE_DIR}" --shell bash --sock "${SHIT_HOOK_SOCK}"
sleep 0.7

# THE workload. cargo install --force OVERWRITES the v1 binary
# at ${INSTALLED_BIN}. The LD_PRELOAD shim catches cargo's
# atomic-rename-over-dst (cargo writes new bin to a tempfile under
# ${CARGO_ROOT}/.crates/ then renames over ${INSTALLED_BIN}). The
# shim's rename interposer captures the OLD binary bytes as a
# pre-image and ships to the daemon.
smoke_log "LD_PRELOAD=${SHIM_LIB} cargo install --force (v2) into ${CARGO_ROOT}"
( cd "${CRATE_DIR}" && LD_PRELOAD="${SHIM_LIB}" cargo install --force --root "${CARGO_ROOT}" --path . --quiet ) \
    >"${SHIT_SMOKE_TMP}/cargo-v2.log" 2>&1
CARGO_RC=$?
if [ "${CARGO_RC}" -ne 0 ]; then
    smoke_log "cargo install --force log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/cargo-v2.log" >&2
    smoke_fail "cargo install --force (v2) exited rc=${CARGO_RC}"
fi

# Confirm the overwrite happened.
V2_OUTPUT="$(SHIT_DURING_UNDO=1 "${INSTALLED_BIN}")"
if [ "${V2_OUTPUT}" != "hello shit v2" ]; then
    smoke_fail "post-install binary doesn't print v2 marker: '${V2_OUTPUT}'"
fi
V2_SHA="$(sha256sum "${INSTALLED_BIN}" | awk '{print $1}')"
if [ "${V2_SHA}" = "${V1_SHA}" ]; then
    smoke_fail "v2 install didn't actually change the binary (sha unchanged)"
fi
smoke_log "post-install: v2 binary at ${INSTALLED_BIN}, sha=${V2_SHA:0:16}... (overwrote v1)"

sleep 0.5

"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"
smoke_log "PostExec seq=1 exit=0"

sleep 1.0

# Diagnostic: shim activity.
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

# Post-undo: ${INSTALLED_BIN} should be back to v1.
if [ ! -x "${INSTALLED_BIN}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "${INSTALLED_BIN} missing post-undo — undo unlinked instead of restoring"
fi

POST_OUTPUT="$(SHIT_DURING_UNDO=1 "${INSTALLED_BIN}")"
POST_SHA="$(sha256sum "${INSTALLED_BIN}" | awk '{print $1}')"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo (v1 restored byte-identical).
if [ "${POST_SHA}" = "${V1_SHA}" ] && [ "${POST_OUTPUT}" = "hello shit v1" ]; then
    smoke_log "OUTCOME A — full undo (binary restored to v1 byte-identical, output='${POST_OUTPUT}', shim hits=${SHIM_HITS})"
    smoke_log "PASS: cargo-install-force-undo-linux (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal acceptable.
if [ "${UNDO_RC}" -ne 0 ] && grep -qE "out-of-scope|outside|refus|cargo-root|${CRATE_NAME}" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named the out-of-scope path)"
    smoke_log "PASS: cargo-install-force-undo-linux (Outcome B)"
    exit 0
fi

# Outcome C — partial / wrong restore. FAIL.
smoke_log "OUTCOME C — partial / wrong restore"
smoke_log "  undo exit:    ${UNDO_RC}"
smoke_log "  output now:   '${POST_OUTPUT}' (expected 'hello shit v1')"
smoke_log "  sha now:      ${POST_SHA:0:16}..."
smoke_log "  sha v1:       ${V1_SHA:0:16}..."
smoke_log "  sha v2:       ${V2_SHA:0:16}..."
smoke_log "  shim hits:    ${SHIM_HITS}"
smoke_log "  journal evts: ${N_EVENTS}"
smoke_fail "cargo install --force undo didn't restore v1 binary (outcome C)"
