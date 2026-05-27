#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AU14-A — smoke discovery + bucketing tool.
#
# Reads SMOKE_* metadata headers from every tests/smoke/*.sh, emits a
# JSON matrix describing what each smoke is and where it should run.
# This is the single source of truth that AU14-B's workflow refactor
# will consume; in AU14-A the matrix runs alongside the existing
# hand-curated arrays as informational output.
#
# Subcommands:
#   discover                 — emit smoke-matrix.json to stdout
#   verify                   — fail if any smoke has invalid headers
#                              OR an unaccounted entry (exists but
#                              not gated by any runner bucket)
#   bucket <runner-hint>     — emit just the file paths for one runner
#
# Run from repo root. Bash 4+ is NOT required — POSIX-friendly shell.

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SMOKE_DIR="${REPO_ROOT}/tests/smoke"

log() { printf '[smoke-driver] %s\n' "$*" >&2; }

usage() {
    cat >&2 <<'USAGE'
usage: smoke-driver.sh <subcommand> [args]

Subcommands:
  discover        emit smoke-matrix.json describing every smoke
  verify          fail if any smoke has invalid/missing metadata
  bucket <hint>   list paths of smokes whose SMOKE_RUNNER_HINT == hint
USAGE
    exit 64
}

# Skipped files (libraries, not smokes).
is_library() {
    case "$(basename "$1")" in
        lib.sh|lib-git.sh) return 0 ;;
        *) return 1 ;;
    esac
}

# Extract a single SMOKE_<KEY> value from a smoke header. Trims leading
# whitespace from the value. Empty if the key is absent.
meta_value() {
    local file="$1"
    local key="$2"
    # Header lives in the first 30 lines; bail past that to keep the
    # parser fast and avoid matching the same key inside a comment
    # block later in the file.
    sed -n "1,30p" "${file}" \
        | grep -m1 "^# ${key}:" \
        | sed "s/^# ${key}:[[:space:]]*//" \
        | sed 's/[[:space:]]*$//' \
        || true
}

# Validate one smoke; emit a JSON record on stdout. Exit 1 on schema
# violation. Schema: SMOKE_NAME + SMOKE_PLATFORM + SMOKE_TIER_REQUIRED
# + SMOKE_RUNNER_HINT + SMOKE_TIMEOUT_SEC required; EXCLUDED_BY and
# EXCLUDED_REASON either both empty or both non-empty.
emit_record() {
    local file="$1"
    local base
    base="$(basename "${file}")"

    local name platform tier runner timeout excluded_by excluded_reason
    name="$(meta_value "${file}" SMOKE_NAME)"
    platform="$(meta_value "${file}" SMOKE_PLATFORM)"
    tier="$(meta_value "${file}" SMOKE_TIER_REQUIRED)"
    runner="$(meta_value "${file}" SMOKE_RUNNER_HINT)"
    timeout="$(meta_value "${file}" SMOKE_TIMEOUT_SEC)"
    excluded_by="$(meta_value "${file}" EXCLUDED_BY)"
    excluded_reason="$(meta_value "${file}" EXCLUDED_REASON)"

    # Required keys.
    for kv in "name=${name}" "platform=${platform}" "tier=${tier}" \
              "runner=${runner}" "timeout=${timeout}"; do
        if [ -z "${kv#*=}" ]; then
            log "ERROR: ${base} missing ${kv%=*} header"
            return 1
        fi
    done

    # Timeout must be a positive integer.
    case "${timeout}" in
        ''|*[!0-9]*)
            log "ERROR: ${base} SMOKE_TIMEOUT_SEC must be a positive integer (got '${timeout}')"
            return 1
            ;;
    esac

    # Both EXCLUDED fields together or neither.
    if [ -n "${excluded_by}" ] && [ -z "${excluded_reason}" ]; then
        log "ERROR: ${base} EXCLUDED_BY set but EXCLUDED_REASON empty"
        return 1
    fi
    if [ -z "${excluded_by}" ] && [ -n "${excluded_reason}" ]; then
        log "ERROR: ${base} EXCLUDED_REASON set but EXCLUDED_BY empty"
        return 1
    fi

    # JSON record. Use python3 for safe escaping rather than printf %s.
    python3 -c "
import json, sys
print(json.dumps({
    'file': sys.argv[1],
    'name': sys.argv[2],
    'platform': sys.argv[3],
    'tier': sys.argv[4],
    'runner': sys.argv[5],
    'timeout_sec': int(sys.argv[6]),
    'excluded_by': sys.argv[7],
    'excluded_reason': sys.argv[8],
}))
" "${file#${REPO_ROOT}/}" "${name}" "${platform}" "${tier}" \
   "${runner}" "${timeout}" "${excluded_by}" "${excluded_reason}"
}

# Emit a JSON array of every smoke's record. Validates each on the way.
do_discover() {
    local fail=0
    local first=1
    printf '['
    for f in "${SMOKE_DIR}"/*.sh; do
        if is_library "${f}"; then
            continue
        fi
        rec="$(emit_record "${f}")" || { fail=1; continue; }
        if [ "${first}" -eq 1 ]; then
            first=0
        else
            printf ','
        fi
        printf '\n  %s' "${rec}"
    done
    printf '\n]\n'
    if [ "${fail}" -ne 0 ]; then
        log "ERROR: one or more smokes failed validation; matrix is incomplete"
        return 1
    fi
}

do_verify() {
    local matrix
    matrix="$(do_discover)"
    # Count totals so the verify output is human-useful even when nothing
    # is wrong.
    local total excluded runnable
    total="$(echo "${matrix}" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
    excluded="$(echo "${matrix}" | python3 -c '
import json, sys
data = json.load(sys.stdin)
print(sum(1 for r in data if r["excluded_by"]))')"
    runnable=$((total - excluded))
    log "smoke surface: ${total} total / ${runnable} runnable / ${excluded} excluded"
}

do_bucket() {
    local hint="${1:-}"
    if [ -z "${hint}" ]; then
        log "usage: smoke-driver.sh bucket <runner-hint>"
        exit 64
    fi
    do_discover \
        | python3 -c "
import json, sys
hint = sys.argv[1]
for r in json.load(sys.stdin):
    if r['runner'] == hint and not r['excluded_by']:
        print(r['file'])
" "${hint}"
}

main() {
    local cmd="${1:-}"
    [ -n "${cmd}" ] || usage
    shift
    case "${cmd}" in
        discover) do_discover "$@" ;;
        verify)   do_verify "$@" ;;
        bucket)   do_bucket "$@" ;;
        -h|--help|help) usage ;;
        *) log "unknown subcommand: ${cmd}"; usage ;;
    esac
}

main "$@"
