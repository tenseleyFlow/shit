#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: cargo-install-force-undo-macos
# SMOKE_PLATFORM: macos
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: macos-14
# SMOKE_TIMEOUT_SEC: 600
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# M07.A.5 — macOS twin of cargo-install-force-undo-linux.sh.
# `cargo install --force` OVERWRITES the existing binary at the
# install root. The DYLD_INSERT_LIBRARIES shim catches cargo's
# atomic-rename-over-dst sequence and captures the OLD binary's
# bytes as a pre-image. `shit undo` restores them.
#
# Pre-conditions for the shim to fire on cargo:
# - cargo from rustup or Homebrew (NOT a SIP-protected /usr/bin path)
# - the temp + rename syscalls cargo issues land in the shim's
#   interposed set (open/openat/rename/renameat)
#
# A Homebrew-installed Rust toolchain is ad-hoc-signed; DYLD_INSERT
# survives. The standard rustup install via curl|sh also works
# (rustup writes to ~/.cargo which it owns).

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Darwin" ]; then
    smoke_log "SKIP: cargo-install-force-undo-macos is macOS-only (uname=$(uname -s))"
    exit 0
fi

if ! command -v cargo >/dev/null 2>&1; then
    smoke_log "SKIP: cargo not on PATH (install rustup or brew install rust)"
    exit 0
fi

CARGO_BIN="$(command -v cargo)"
# Smoke probe: is the cargo binary in a SIP-protected path? If so
# DYLD_INSERT is stripped and the shim can't fire. (Apple doesn't
# ship cargo, but this defends against weird PATH ordering.)
case "${CARGO_BIN}" in
    /usr/bin/* | /bin/* | /System/*)
        smoke_log "SKIP: cargo at ${CARGO_BIN} is in a SIP-protected path; DYLD_INSERT would be stripped"
        exit 0
        ;;
esac
smoke_log "cargo: ${CARGO_BIN}"

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

cat > "${CRATE_DIR}/src/main.rs" <<'EOF'
fn main() {
    println!("hello shit v1");
}
EOF

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

V1_OUTPUT="$("${INSTALLED_BIN}")"
if [ "${V1_OUTPUT}" != "hello shit v1" ]; then
    smoke_fail "pre-state binary doesn't print v1 marker: '${V1_OUTPUT}'"
fi
V1_SHA="$(sha256_of "${INSTALLED_BIN}")"
smoke_log "pre-state: v1 binary at ${INSTALLED_BIN}, sha=${V1_SHA:0:16}..."

# Modify source to v2.
cat > "${CRATE_DIR}/src/main.rs" <<'EOF'
fn main() {
    println!("hello shit v2");
}
EOF
# macOS sed: -i requires a backup-suffix arg. Empty string = no backup.
sed -i '' 's/version = "0.1.0"/version = "0.2.0"/' "${CRATE_DIR}/Cargo.toml"

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

# THE workload. cargo install --force overwrites v1 at INSTALLED_BIN.
# The DYLD shim's rename interposer captures the OLD bytes as a
# pre-image. shitd journals it. undo restores.
smoke_log "DYLD_INSERT_LIBRARIES=${SHIM_LIB} cargo install --force (v2) into ${CARGO_ROOT}"
# `set +e` so a non-zero cargo exit doesn't kill the script before
# we dump the log. (`set -e` from lib.sh is otherwise on; the Linux
# twin has the same latent bug — works only because Linux cargo
# doesn't fail under the shim.)
set +e
( cd "${CRATE_DIR}" && DYLD_INSERT_LIBRARIES="${SHIM_LIB}" cargo install --force --root "${CARGO_ROOT}" --path . --quiet ) \
    >"${SHIT_SMOKE_TMP}/cargo-v2.log" 2>&1
CARGO_RC=$?
set -e
if [ "${CARGO_RC}" -ne 0 ]; then
    smoke_log "cargo install --force log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/cargo-v2.log" >&2
    smoke_fail "cargo install --force (v2) exited rc=${CARGO_RC}"
fi

V2_OUTPUT="$(SHIT_DURING_UNDO=1 "${INSTALLED_BIN}")"
if [ "${V2_OUTPUT}" != "hello shit v2" ]; then
    smoke_fail "post-install binary doesn't print v2 marker: '${V2_OUTPUT}'"
fi
V2_SHA="$(sha256_of "${INSTALLED_BIN}")"
if [ "${V2_SHA}" = "${V1_SHA}" ]; then
    smoke_fail "v2 install didn't actually change the binary (sha unchanged)"
fi
smoke_log "post-install: v2 binary at ${INSTALLED_BIN}, sha=${V2_SHA:0:16}... (overwrote v1)"

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
POST_SHA="$(sha256_of "${INSTALLED_BIN}")"

"${SHIT_BIN}" hook-send session-close --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

# Outcome A — full undo (v1 restored byte-identical).
if [ "${POST_SHA}" = "${V1_SHA}" ] && [ "${POST_OUTPUT}" = "hello shit v1" ]; then
    smoke_log "OUTCOME A — full undo (binary restored to v1 byte-identical, output='${POST_OUTPUT}', shim hits=${SHIM_HITS})"
    smoke_log "PASS: cargo-install-force-undo-macos (Outcome A)"
    exit 0
fi

# Outcome B — loud refusal acceptable.
if [ "${UNDO_RC}" -ne 0 ] && grep -qE "out-of-scope|outside|refus|cargo-root|${CRATE_NAME}" "${SHIT_SMOKE_TMP}/undo.log"; then
    smoke_log "OUTCOME B — loud refusal (undo non-zero, log named the out-of-scope path)"
    smoke_log "PASS: cargo-install-force-undo-macos (Outcome B)"
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
