#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: doctor-coverage-honest
# SMOKE_PLATFORM: any
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 60
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# AU02 smoke — assert `shit doctor --json` carries the honest
# coverage envelope shape introduced in AU02. Specifically:
#
#   - schema_version == 2
#   - coverage_pct field is GONE (was the vanity metric)
#   - covered_count, refused_count, pending_count are populated
#   - binary_built_at is non-empty (vergen sets it)
#   - last_validated_at matches the embedded snapshot's generated_at
#     (empty for the sentinel; non-empty after a CI snapshot lands)
#
# Doesn't require the daemon or capture layer — just builds + runs
# `shit doctor --json` and inspects fields.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
SNAPSHOT="${SHIT_REPO_ROOT}/tools/audit/coverage-snapshot.json"
[ -f "${SNAPSHOT}" ] || smoke_fail "coverage snapshot missing at ${SNAPSHOT}"

smoke_log "shit binary: ${SHIT_BIN}"
smoke_log "snapshot:    ${SNAPSHOT}"

OUT="${SHIT_SMOKE_TMP}/doctor.json"
"${SHIT_BIN}" doctor --json > "${OUT}" 2>/dev/null \
    || smoke_fail "shit doctor --json exited non-zero"

# schema_version
SCHEMA=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['schema_version'])" "${OUT}")
if [ "${SCHEMA}" != "2" ]; then
    smoke_fail "schema_version expected 2, got ${SCHEMA}"
fi
smoke_log "schema_version: ${SCHEMA}"

# coverage_pct must be absent
HAS_PCT=$(python3 -c "
import json, sys
d = json.load(open(sys.argv[1]))
print('coverage_pct' in d.get('arbitrary_undo_coverage', {}))
" "${OUT}")
if [ "${HAS_PCT}" != "False" ]; then
    smoke_fail "coverage_pct field still present (was supposed to drop in AU02)"
fi
smoke_log "coverage_pct: removed (correct)"

# Counts must be present and non-negative; covered + refused both > 0
read -r COV REF PEN BIN_TS SNAP_TS <<<"$(python3 -c "
import json, sys
c = json.load(open(sys.argv[1]))['arbitrary_undo_coverage']
print(c['covered_count'], c['refused_count'], c['pending_count'],
      c['binary_built_at'] or '-', c['last_validated_at'] or '-')
" "${OUT}")"

smoke_log "counts:  covered=${COV} refused=${REF} pending=${PEN}"
smoke_log "binary_built_at:    ${BIN_TS}"
smoke_log "last_validated_at:  ${SNAP_TS}"

if [ "${COV}" -lt 1 ]; then
    smoke_fail "covered_count must be > 0 (got ${COV}); coverage catalog wiring broken"
fi
if [ "${REF}" -lt 1 ]; then
    smoke_fail "refused_count must be > 0 (got ${REF}); refuse catalog wiring broken"
fi
if [ "${BIN_TS}" = "-" ]; then
    smoke_fail "binary_built_at empty; vergen / build.rs wiring broken"
fi

# Cross-check last_validated_at against the embedded snapshot.
SNAP_GEN=$(python3 -c "
import json, sys
print(json.load(open(sys.argv[1])).get('generated_at', ''))
" "${SNAPSHOT}")
EXPECTED_LAST="${SNAP_GEN:--}"
if [ "${SNAP_TS}" != "${EXPECTED_LAST}" ]; then
    smoke_fail "last_validated_at mismatch — doctor=${SNAP_TS} snapshot=${EXPECTED_LAST}"
fi
smoke_log "last_validated_at matches embedded snapshot"

# Catalog cross-reference: every covered_class id in doctor JSON
# must appear in the coverage catalog source.
DOCTOR_CLASSES=$(python3 -c "
import json, sys
for c in json.load(open(sys.argv[1]))['arbitrary_undo_coverage']['covered_classes']:
    print(c)
" "${OUT}" | sort -u)
CATALOG_CLASSES=$(grep -oE 'id: "[a-z][a-z0-9-]*"' "${SHIT_REPO_ROOT}/crates/shit-planner/src/coverage_catalog.rs" \
                 | sed 's/id: "\([^"]*\)"/\1/' | sort -u)
MISSING=$(comm -23 <(echo "${DOCTOR_CLASSES}") <(echo "${CATALOG_CLASSES}"))
if [ -n "${MISSING}" ]; then
    smoke_log "MISSING from catalog source:"
    echo "${MISSING}" | sed 's/^/    /'
    smoke_fail "doctor reports covered classes not in coverage_catalog.rs"
fi
smoke_log "covered_classes cross-reference: ok"

smoke_log "PASS: doctor-coverage-honest (schema v${SCHEMA}, covered=${COV} refused=${REF} pending=${PEN})"
