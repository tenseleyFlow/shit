#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: helper-privilege-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: self-hosted-lsm
# SMOKE_TIMEOUT_SEC: 120
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# L6 smoke for the helper's privilege posture on a setcap install.
#
# #226: once the helper has set up its kernel tier and served a watched
# command, no thread of it has an effective, inheritable or ambient
# capability, and its permitted set holds at most cap_mknod (plus
# cap_bpf on a kernel before 6.5 with unprivileged_bpf_disabled set).
# no_new_privs is set.
#
# #230: a WatchTree for a process the peer does not own is refused,
# and the refusal is logged. pid 1 is always refused; with passwordless
# sudo a root-owned sleep is refused for its owner.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: helper-privilege-linux is Linux-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ]   || smoke_fail "shit missing"
export SHIT_HELPER_BIN="${HELPER_BIN}"

HELPER_CAPS="$(getcap "${HELPER_BIN}" 2>/dev/null || true)"
for required in cap_sys_admin cap_bpf cap_perfmon; do
    if ! printf '%s' "${HELPER_CAPS}" | grep -q "${required}"; then
        smoke_log "FAIL: helper lacks ${required}; setcap cap_mknod,cap_bpf,cap_perfmon,cap_sys_admin+ep ${HELPER_BIN}"
        exit 1
    fi
done

smoke_start_shitd

SCRATCH="${SHIT_SMOKE_TMP}/scratch"
mkdir -p "${SCRATCH}"
cd "${SCRATCH}"
SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"

# One watched command, so the request loop and the capture threads are
# all up when the sets are read.
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "$$" \
    --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}"
printf 'x\n' > "${SCRATCH}/f"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

HELPER_PID=""
for _ in $(seq 1 50); do
    for pid in $(smoke_descendants "${SHITD_PID}"); do
        comm="$(ps -p "${pid}" -o comm= 2>/dev/null || true)"
        case "${comm##*/}" in
            shit-helper*) HELPER_PID="${pid}" ;;
        esac
    done
    [ -n "${HELPER_PID}" ] && break
    sleep 0.1
done
[ -n "${HELPER_PID}" ] || smoke_fail "no shit-helper child of shitd (pid ${SHITD_PID})"
smoke_log "helper pid ${HELPER_PID}"

# ---- #226: every thread's capability sets ----
ALLOWED=$(( 1 << 27 ))   # CAP_MKNOD
KMAJ="$(uname -r | cut -d. -f1)"
KMIN="$(uname -r | cut -d. -f2 | sed 's/[^0-9].*//')"
UBPF="$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 1)"
if { [ "${KMAJ}" -lt 6 ] || { [ "${KMAJ}" -eq 6 ] && [ "${KMIN}" -lt 5 ]; }; } && [ "${UBPF}" != "0" ]; then
    ALLOWED=$(( ALLOWED | (1 << 39) ))   # CAP_BPF for map reads
fi

field() { awk -v k="$1:" '$1 == k { print $2 }' "$2"; }
THREADS=0
for task in /proc/"${HELPER_PID}"/task/*; do
    st="${task}/status"
    [ -r "${st}" ] || continue
    THREADS=$((THREADS + 1))
    eff="$(field CapEff "${st}")"
    prm="$(field CapPrm "${st}")"
    inh="$(field CapInh "${st}")"
    amb="$(field CapAmb "${st}")"
    tid="${task##*/}"
    [ $((16#${eff})) -eq 0 ] || smoke_fail "thread ${tid}: CapEff ${eff} (want 0)"
    [ $((16#${inh})) -eq 0 ] || smoke_fail "thread ${tid}: CapInh ${inh} (want 0)"
    [ -z "${amb}" ] || [ $((16#${amb})) -eq 0 ] || smoke_fail "thread ${tid}: CapAmb ${amb} (want 0)"
    [ $(( 16#${prm} & ~ALLOWED )) -eq 0 ] \
        || smoke_fail "thread ${tid}: CapPrm ${prm} holds more than $(printf '%x' "${ALLOWED}")"
done
[ "${THREADS}" -gt 1 ] || smoke_fail "read ${THREADS} helper thread(s); expected the reader threads too"
NNP="$(field NoNewPrivs /proc/"${HELPER_PID}"/status)"
[ "${NNP}" = "1" ] || smoke_fail "helper NoNewPrivs=${NNP} (want 1)"
smoke_log "#226: ${THREADS} helper threads, none with an effective capability; permitted within $(printf '%x' "${ALLOWED}")"

# ---- #230: a process the peer does not own is not watched ----
# refuse_watch <seq> <pid> <reason substring>
refuse_watch() {
    "${SHIT_BIN}" hook-send pre-exec \
        --session "$(python3 -c 'import uuid; print(uuid.uuid4())')" --seq "$1" --pid "$2" \
        --cwd "${SCRATCH}" --shell bash --sock "${SHIT_HOOK_SOCK}" || true
    for _ in $(seq 1 50); do
        if sed 's/\x1b\[[0-9;]*m//g' "${SHIT_SMOKE_TMP}/shitd.log" \
            | grep 'WatchTree refused' | grep -q "$3"; then
            smoke_log "#230: pid $2 refused ($3)"
            return 0
        fi
        sleep 0.1
    done
    tail -60 "${SHIT_SMOKE_TMP}/shitd.log" | sed 's/^/    /' >&2
    smoke_fail "no 'WatchTree refused' line with '$3' for pid $2"
}

refuse_watch 2 1 "not a user process"

if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    sudo -n sleep 30 &
    SUDO_PID=$!
    ROOT_SLEEP=""
    for _ in $(seq 1 50); do
        ROOT_SLEEP="$(pgrep -P "${SUDO_PID}" -x sleep 2>/dev/null || true)"
        # sudo may exec sleep in place instead of forking it.
        if [ -z "${ROOT_SLEEP}" ] && [ "$(ps -p "${SUDO_PID}" -o comm= 2>/dev/null)" = "sleep" ]; then
            ROOT_SLEEP="${SUDO_PID}"
        fi
        [ -n "${ROOT_SLEEP}" ] && break
        sleep 0.1
    done
    if [ -n "${ROOT_SLEEP}" ]; then
        refuse_watch 3 "${ROOT_SLEEP}" "not owned by uid"
    else
        smoke_log "#230: no root sleep found; skipped the root-owned process case"
    fi
    sudo -n kill "${ROOT_SLEEP:-${SUDO_PID}}" 2>/dev/null || true
    wait "${SUDO_PID}" 2>/dev/null || true
else
    smoke_log "#230: no passwordless sudo; skipped the root-owned process case"
fi

smoke_log "PASS: helper-privilege-linux (no effective caps in any helper thread; foreign pids not watched)"
