#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: edit-undo-cross-tier-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: lsm
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 120
#
# AU18 smoke — cross-tier consistency.
#
# Today the same workload (edit file in watched dir) is captured
# by either eBPF-LSM or fanotify-perm depending on
# `pick_linux_tier()`. The 10+ existing smokes that FORCE one
# tier (SHIT_FORCE_TIER=ebpf-lsm) prove that tier WORKS in
# isolation; the implicit-default smokes prove fanotify-perm
# WORKS in isolation. But no smoke runs the SAME workload under
# BOTH tiers and asserts the round-trip is equivalent.
#
# A regression in `pick_linux_tier()` (always picks the wrong
# tier, or picks correctly but the picked tier has a degraded
# code path the OTHER tier wouldn't hit) would not surface on
# existing CI. AU18 is the gate: same edit, both tiers, both
# undo to byte-identical pre-state.
#
# Catches the L04.2 "fallback hides the bug" pattern at the
# smoke layer.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: edit-undo-cross-tier-linux is Linux-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# The known content the workload starts at. Both tier-runs use
# the SAME bytes so the assertion can compare them directly.
KNOWN_CONTENT="cross-tier-baseline 2026-05-28"

# Run the edit-undo workload under a forced tier in an isolated
# state dir. Returns 0 on success; smoke_fail on assertion miss.
#
# Args: $1 = tier (`ebpf-lsm` | `fanotify-perm`)
#
# Side effects:
#   - Mutates XDG_* + SHIT_INDEX_DB + SHIT_CTL_SOCK + SHIT_HOOK_SOCK
#     to point at a per-tier sub-tempdir. Caller restores via
#     `restore_smoke_env` afterwards.
#   - Starts + stops a per-tier shitd.
#   - Logs the post-undo sha so the caller can compare across runs.
run_tier() {
    local tier="$1"
    local subtmp="${SHIT_SMOKE_TMP}/${tier}"
    mkdir -p "${subtmp}/state" "${subtmp}/runtime" "${subtmp}/scratch"
    chmod 0700 "${subtmp}/runtime"

    # Override the env that lib.sh fixed at source time. We
    # restore in the caller after the second run.
    export XDG_STATE_HOME="${subtmp}/state"
    export XDG_RUNTIME_DIR="${subtmp}/runtime"
    export XDG_CONFIG_HOME="${subtmp}/config"
    mkdir -p "${XDG_CONFIG_HOME}"
    SHIT_INDEX_DB="${XDG_STATE_HOME}/shit/index.sqlite"
    SHIT_CTL_SOCK="${XDG_RUNTIME_DIR}/shit-ctl.sock"
    SHIT_HOOK_SOCK="${XDG_RUNTIME_DIR}/shit.sock"
    export SHIT_FORCE_TIER="${tier}"

    local scratch="${subtmp}/scratch"
    local probe="${scratch}/probe.txt"
    printf '%s\n' "${KNOWN_CONTENT}" > "${probe}"
    local pre_sha
    pre_sha="$(sha256sum "${probe}" | cut -d' ' -f1)"
    smoke_log "[tier=${tier}] pre: sha=${pre_sha:0:12}"

    smoke_start_shitd

    local session pid
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    pid="$$"
    cd "${scratch}"

    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "${pid}" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "${pid}" \
        --cwd "${scratch}" --shell bash --depth 1 \
        --sock "${SHIT_HOOK_SOCK}"
    sleep 0.5

    # The workload: bash truncate-write via `tee` (O_TRUNC|O_WRONLY).
    # Same shape both tiers should capture pre-image bytes for.
    printf 'overwritten by cross-tier %s\n' "${tier}" | tee "${probe}" >/dev/null
    local post_cmd_sha
    post_cmd_sha="$(sha256sum "${probe}" | cut -d' ' -f1)"
    [ "${post_cmd_sha}" != "${pre_sha}" ] \
        || smoke_fail "[tier=${tier}] workload no-op: post sha ${post_cmd_sha} == pre"

    sleep 0.5
    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 \
        --sock "${SHIT_HOOK_SOCK}"

    smoke_wait_for_event "discriminant = 'FilePreImage'" 1 10
    local n_events
    n_events="$(smoke_journal_count "discriminant = 'FilePreImage'")"
    smoke_log "[tier=${tier}] FilePreImage events: ${n_events}"

    # Pull the blob_hash hex for the FilePreImage event(s). Both
    # tiers must hash the SAME pre-image bytes — if a tier captures
    # post-write bytes instead, this assertion fails even when the
    # post-undo sha looks OK on a single tier in isolation.
    local blob_hashes
    blob_hashes="$(smoke_journal_query \
        "SELECT hex(blob_hash) FROM events
         WHERE discriminant = 'FilePreImage' AND blob_hash IS NOT NULL
         ORDER BY id;" || true)"
    smoke_log "[tier=${tier}] blob_hashes:"
    printf '%s\n' "${blob_hashes}" | sed 's/^/    /' >&2

    "${SHIT_BIN}" undo --yes > "${subtmp}/undo.log" 2>&1 || {
        sed 's/^/    /' "${subtmp}/undo.log" >&2
        smoke_fail "[tier=${tier}] shit undo exited non-zero"
    }

    local post_undo_sha
    post_undo_sha="$(sha256sum "${probe}" | cut -d' ' -f1)"
    smoke_log "[tier=${tier}] post-undo: sha=${post_undo_sha:0:12}"
    if [ "${post_undo_sha}" != "${pre_sha}" ]; then
        smoke_log "[tier=${tier}] expected sha=${pre_sha}"
        smoke_log "[tier=${tier}] got      sha=${post_undo_sha}"
        sed 's/^/    /' "${subtmp}/undo.log" >&2
        smoke_fail "[tier=${tier}] undo didn't restore byte-identical pre-state"
    fi

    "${SHIT_BIN}" hook-send session-close \
        --session "${session}" --sock "${SHIT_HOOK_SOCK}"

    # Hand the post-undo sha back to the caller via a per-tier file.
    printf '%s\n' "${post_undo_sha}" > "${SHIT_SMOKE_TMP}/${tier}.sha"
    printf '%s\n' "${n_events}"      > "${SHIT_SMOKE_TMP}/${tier}.events"
    printf '%s\n' "${blob_hashes}"   > "${SHIT_SMOKE_TMP}/${tier}.blobs"

    smoke_stop_shitd
    unset SHIT_FORCE_TIER
    cd "${SHIT_SMOKE_TMP}"
}

# Run both tiers. Each populates its own ${SHIT_SMOKE_TMP}/<tier>.sha
# + .events files. We diff after.

if ! command -v getcap >/dev/null 2>&1; then
    smoke_log "SKIP: getcap missing; cross-tier smoke needs to inspect helper caps"
    exit 0
fi
HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
if ! printf '%s' "${HELPER_CAPS}" | grep -q cap_sys_admin; then
    smoke_log "SKIP: helper lacks cap_sys_admin — neither tier will load"
    smoke_log "  sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep ${HELPER_BIN}"
    exit 0
fi

smoke_log "tier 1: ebpf-lsm"
run_tier "ebpf-lsm"
smoke_log "tier 2: fanotify-perm"
run_tier "fanotify-perm"

LSM_SHA="$(cat "${SHIT_SMOKE_TMP}/ebpf-lsm.sha")"
FAN_SHA="$(cat "${SHIT_SMOKE_TMP}/fanotify-perm.sha")"
LSM_EVENTS="$(cat "${SHIT_SMOKE_TMP}/ebpf-lsm.events")"
FAN_EVENTS="$(cat "${SHIT_SMOKE_TMP}/fanotify-perm.events")"
LSM_BLOBS="$(sort -u "${SHIT_SMOKE_TMP}/ebpf-lsm.blobs"      | grep -v '^$' || true)"
FAN_BLOBS="$(sort -u "${SHIT_SMOKE_TMP}/fanotify-perm.blobs" | grep -v '^$' || true)"

smoke_log "cross-tier summary:"
smoke_log "  lsm           sha=${LSM_SHA:0:12} FilePreImage=${LSM_EVENTS}"
smoke_log "  fanotify-perm sha=${FAN_SHA:0:12} FilePreImage=${FAN_EVENTS}"

if [ "${LSM_SHA}" != "${FAN_SHA}" ]; then
    smoke_fail "post-undo sha differs across tiers: lsm=${LSM_SHA} fanotify=${FAN_SHA}"
fi
# Both tiers must have journaled SOMETHING (>=1 FilePreImage).
# Event count can legitimately differ — LSM may emit multiple
# inode_* events for a single write, fanotify emits one
# FAN_OPEN_PERM. We DON'T assert count equality.
if [ "${LSM_EVENTS}" -lt 1 ] || [ "${FAN_EVENTS}" -lt 1 ]; then
    smoke_fail "one or both tiers journaled 0 FilePreImage events: lsm=${LSM_EVENTS} fanotify=${FAN_EVENTS}"
fi

# The captured pre-image MUST have the same blake3 across tiers.
# If a tier captures the wrong bytes (e.g. post-write bytes
# because it raced the syscall), the blob_hash for that tier's
# FilePreImage event will diverge. Belt-and-suspenders next to
# the post-undo sha — covers tiers that store divergent
# pre-images but happen to restore them locally consistently.
if [ -z "${LSM_BLOBS}" ] || [ -z "${FAN_BLOBS}" ]; then
    smoke_fail "missing blob_hashes: lsm='${LSM_BLOBS}' fanotify='${FAN_BLOBS}'"
fi
if [ "${LSM_BLOBS}" != "${FAN_BLOBS}" ]; then
    smoke_log "lsm  blobs:"
    printf '%s\n' "${LSM_BLOBS}" | sed 's/^/    /' >&2
    smoke_log "fanotify blobs:"
    printf '%s\n' "${FAN_BLOBS}" | sed 's/^/    /' >&2
    smoke_fail "FilePreImage blob_hash set differs across tiers"
fi

smoke_log "PASS: edit-undo-cross-tier-linux (both tiers restored byte-identical; same FilePreImage blob_hash)"
