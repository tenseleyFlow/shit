#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: daemon-boot
# SMOKE_PLATFORM: any
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# DR smoke #1 — daemon boots, ctl socket comes up, status round-trips.
#
# Closes the "does shitd come up under a fresh environment with no
# inherited state?" question. Doesn't touch any tier captures; that's
# what the per-tier smokes do.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

smoke_start_shitd

# Validate the on-disk state dir got initialised. The daemon creates
# index.sqlite on startup so subsequent queries don't race.
if [ ! -f "${SHIT_INDEX_DB}" ]; then
    smoke_fail "index.sqlite missing under ${XDG_STATE_HOME}/shit"
fi
smoke_log "index.sqlite present (size=$(wc -c <"${SHIT_INDEX_DB}") bytes)"

# Validate the schema landed. A fresh DB has all 6 tables.
tables="$(smoke_journal_query "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")"
for required in blobs commands events paths pins sessions; do
    if ! grep -qxF "${required}" <<<"${tables}"; then
        smoke_fail "schema missing table '${required}'; got: ${tables}"
    fi
done
smoke_log "schema OK: ${tables}"

# Validate the events table starts empty — no spurious state.
n="$(smoke_journal_count '1=1')"
if [ "${n}" -ne 0 ]; then
    smoke_fail "fresh journal had ${n} events; expected 0"
fi
smoke_log "events table empty on fresh start"

smoke_log "PASS: daemon-boot"
