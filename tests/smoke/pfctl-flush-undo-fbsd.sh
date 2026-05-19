#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# B01 smoke — `pfctl -F rules; shit undo` restores the prior rules.
#
# Mirrors pfctl-add-undo-fbsd.sh; the difference is the mutation
# verb. -F flushes a subset of pf state (we use -Frules — flush
# rules only, NOT states/nat/table/etc, to keep this surgical).
#
# Safety: we install a labelled 'pass all' ruleset BEFORE running
# the smoke (not the host's baseline). Flushing rules just removes
# our label; the default pass-on-no-match keeps SSH alive. We never
# touch states/nat/queues; we never `pfctl -F all`.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: pfctl-flush-undo-fbsd is FreeBSD-only (uname=$(uname -s))"
    exit 0
fi

PRIV=""
if command -v doas >/dev/null 2>&1; then
    PRIV="doas"
elif command -v sudo >/dev/null 2>&1; then
    PRIV="sudo"
else
    smoke_log "SKIP: neither doas nor sudo on PATH; pfctl smoke needs root"
    exit 0
fi
smoke_log "privilege tool: ${PRIV}"

if [ ! -e /dev/pf ]; then
    smoke_log "SKIP: pf kernel module not loaded (/dev/pf absent)"
    smoke_log "      see pfctl-add-undo-fbsd.sh for one-time setup"
    exit 0
fi

# Same safety guard as the add smoke: only proceed if baseline is
# trivial (pass all or empty).
SAFE_BASELINE=0
if ${PRIV} /sbin/pfctl -sr 2>/dev/null | grep -qE '^pass +all'; then
    SAFE_BASELINE=1
elif [ -z "$(${PRIV} /sbin/pfctl -sr 2>/dev/null)" ]; then
    SAFE_BASELINE=1
fi
if [ "${SAFE_BASELINE}" -ne 1 ]; then
    smoke_log "SKIP: pf has a non-trivial baseline ruleset; refusing to mutate"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper binary missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit binary missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

# Install a known labelled ruleset PRE-smoke so flush has something
# distinctive to remove. This is the "before" state we'll undo to.
PREP_RULESET="${SHIT_SMOKE_TMP}/prep-rules.conf"
cat >"${PREP_RULESET}" <<'EOF'
# B01 flush smoke prep — labelled pass-all (the baseline we undo TO)
pass all label "shit-b01-flush-prep"
EOF
${PRIV} /sbin/pfctl -f "${PREP_RULESET}" || smoke_fail "prep ruleset load failed"
if ! ${PRIV} /sbin/pfctl -sr 2>/dev/null | grep -q 'shit-b01-flush-prep'; then
    smoke_fail "prep ruleset not active"
fi
smoke_log "prep ruleset active: shit-b01-flush-prep"

cleanup() {
    # MUST call smoke_stop_shitd because we're overriding lib.sh's
    # EXIT trap. Without it, shitd is orphaned and the CI action's
    # SSH session waits for its inherited fds to close → 5-min hang.
    smoke_stop_shitd 2>/dev/null || true
    echo 'pass all' | ${PRIV} tee /etc/pf-shit-smoke-restore.conf >/dev/null
    ${PRIV} /sbin/pfctl -f /etc/pf-shit-smoke-restore.conf >/dev/null 2>&1 || true
    ${PRIV} rm -f /etc/pf-shit-smoke-restore.conf 2>/dev/null || true
}
trap cleanup EXIT

smoke_start_shitd

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

chmod 0666 "${SHIT_CTL_SOCK}" 2>/dev/null || true

smoke_log "net-event pre"
"${HELPER_BIN}" net-event pfctl pre --verb=-F --scope-hint="" \
    --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "${PRIV} pfctl -F rules"
${PRIV} /sbin/pfctl -F rules || smoke_fail "pfctl -F rules failed"

# Verify the label is gone post-flush.
if ${PRIV} /sbin/pfctl -sr 2>/dev/null | grep -q 'shit-b01-flush-prep'; then
    smoke_fail "label still present after -F rules — flush didn't apply"
fi

smoke_log "net-event post"
"${HELPER_BIN}" net-event pfctl post --verb=-F --scope-hint="" \
    --ctl-sock "${SHIT_CTL_SOCK}"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'NetworkOp'" 1 10

smoke_log "running: shit undo --yes"
export PATH="/usr/local/sbin:/usr/local/bin:${PATH}"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: the label should be BACK.
sleep 0.5
if ! ${PRIV} /sbin/pfctl -sr 2>/dev/null | grep -q 'shit-b01-flush-prep'; then
    smoke_log "current ruleset:"
    ${PRIV} /sbin/pfctl -sr 2>&1 | head -10 | sed 's/^/    /'
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "label not restored after undo — pf rollback didn't reload prior rules"
fi

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: pfctl-flush-undo-fbsd (rules flushed→undone)"
