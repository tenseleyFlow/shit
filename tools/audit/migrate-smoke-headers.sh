#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AU14-A — one-shot migration: add SMOKE_* metadata headers to every
# tests/smoke/*.sh that doesn't already have one. Idempotent: skips
# any file that already declares `# SMOKE_NAME:`.
#
# Heuristics (per file):
#   filename suffix → SMOKE_PLATFORM + SMOKE_RUNNER_HINT + SMOKE_TIER_REQUIRED
#     *-fbsd.sh       → freebsd / freebsd-vm / kqueue
#     *-linux.sh      → linux   / ubuntu-24.04 / any (operators promote
#                                                    to lsm/fanotify
#                                                    after migration as
#                                                    needed)
#     *-macos.sh      → macos   / macos-14 / mocked-es
#     other (platform-neutral) → any / ubuntu-24.04 / any
#
#   SMOKE_NAME      = basename without .sh
#   SMOKE_TIMEOUT_SEC = 300 (matches existing freebsd-smoke driver)
#   EXCLUDED_BY     = empty (operator sets this manually for known
#                     deferred smokes — today only
#                     git-branch-D-undo-fbsd.sh has a real deferral)
#   EXCLUDED_REASON = empty
#
# Files explicitly skipped (libraries, not smokes):
#   tests/smoke/lib.sh
#   tests/smoke/lib-git.sh
#
# Run: bash tools/audit/migrate-smoke-headers.sh [--dry-run]

set -euo pipefail

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SMOKE_DIR="${REPO_ROOT}/tests/smoke"

log() { printf '[migrate-smoke-headers] %s\n' "$*" >&2; }

# Skip these — they're libraries sourced by smokes, not smokes themselves.
SKIP_FILES=(
    "lib.sh"
    "lib-git.sh"
)

# Per-smoke deferrals known at AU14-A time. Looked up by basename via
# `excluded_for`; macOS bash 3.x has no associative arrays so we use a
# case statement instead.
excluded_for() {
    case "$1" in
        "git-branch-D-undo-fbsd.sh")
            echo "G01.4-packed|packed-refs branch -D path not yet implemented; deferred"
            ;;
        *) echo "" ;;
    esac
}

guess_platform() {
    local base="$1"
    case "${base}" in
        *-fbsd.sh)  echo freebsd ;;
        *-linux.sh) echo linux ;;
        *-macos.sh) echo macos ;;
        *)          echo any ;;
    esac
}

guess_runner() {
    case "$1" in
        freebsd) echo freebsd-vm ;;
        linux)   echo ubuntu-24.04 ;;
        macos)   echo macos-14 ;;
        any)     echo ubuntu-24.04 ;;
    esac
}

guess_tier() {
    case "$1" in
        freebsd) echo kqueue ;;
        # linux defaults to "any" — LSM/fanotify gating is a follow-up
        # the operator does once the driver is wired. We'd rather
        # under-promise than over-claim a tier requirement.
        linux)   echo any ;;
        macos)   echo mocked-es ;;
        any)     echo any ;;
    esac
}

annotated_count=0
skipped_already=0
skipped_lib=0

for path in "${SMOKE_DIR}"/*.sh; do
    base="$(basename "${path}")"

    skip=0
    for s in "${SKIP_FILES[@]}"; do
        if [ "${base}" = "${s}" ]; then
            skip=1
            break
        fi
    done
    if [ "${skip}" -eq 1 ]; then
        skipped_lib=$((skipped_lib + 1))
        continue
    fi

    if grep -q '^# SMOKE_NAME:' "${path}"; then
        skipped_already=$((skipped_already + 1))
        continue
    fi

    name="${base%.sh}"
    platform="$(guess_platform "${base}")"
    runner="$(guess_runner "${platform}")"
    tier="$(guess_tier "${platform}")"
    excluded_by=""
    excluded_reason=""
    excl_entry="$(excluded_for "${base}")"
    if [ -n "${excl_entry}" ]; then
        excluded_by="${excl_entry%%|*}"
        excluded_reason="${excl_entry#*|}"
    fi

    header_block=$(cat <<EOF
# SMOKE_NAME: ${name}
# SMOKE_PLATFORM: ${platform}
# SMOKE_TIER_REQUIRED: ${tier}
# SMOKE_RUNNER_HINT: ${runner}
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: ${excluded_by}
# EXCLUDED_REASON: ${excluded_reason}
EOF
)

    if [ "${DRY_RUN}" -eq 1 ]; then
        log "would annotate: ${base}"
        echo "${header_block}" | sed 's/^/    /'
        annotated_count=$((annotated_count + 1))
        continue
    fi

    # Insert the header block after the SPDX line (line 2). If the
    # file doesn't have an SPDX line in the expected location, log
    # and skip — manual review required.
    if ! head -2 "${path}" | grep -q 'SPDX-License-Identifier:'; then
        log "WARN: ${base} missing expected SPDX line in first 2 lines; skipping"
        continue
    fi

    tmp="$(mktemp)"
    {
        head -2 "${path}"
        echo "${header_block}"
        tail -n +3 "${path}"
    } > "${tmp}"
    mv "${tmp}" "${path}"
    chmod +x "${path}"
    annotated_count=$((annotated_count + 1))
done

log "annotated: ${annotated_count}"
log "skipped (already annotated): ${skipped_already}"
log "skipped (libraries): ${skipped_lib}"
if [ "${DRY_RUN}" -eq 1 ]; then
    log "DRY RUN — no files modified"
fi
