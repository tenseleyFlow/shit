#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Run the freebsd-vm smoke bucket inside the VM the way the
# `freebsd-smoke (B04)` job in .github/workflows/dr-smoke.yml does:
# release build, pf with `pass all`, doctor kqueue gate, then every
# smoke from `smoke-driver.sh bucket freebsd-vm` under
# `timeout --kill-after=10 300` with the job's exit-code accounting.
#
# Usage: run-fbsd-smokes.sh [smoke-name ...]
#   No arguments runs the whole bucket. Results land in the guest at
#   ~/smoke-results.tsv (name, verdict, rc, seconds) and are copied
#   to <work dir>/smoke-results-<tag>.tsv on the host.
#   SMOKE_TMPDIR=/tmp/zfs puts each smoke's scratch tree on ZFS.
#   SMOKE_TAG names the host copy (default: ufs or zfs).

set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

SMOKE_TMPDIR="${SMOKE_TMPDIR:-/tmp}"
case "${SMOKE_TMPDIR}" in
  /tmp/zfs*) DEFAULT_TAG=zfs ;;
  *) DEFAULT_TAG=ufs ;;
esac
SMOKE_TAG="${SMOKE_TAG:-${DEFAULT_TAG}}"

HOST_TSV="${WORK_DIR}/smoke-results-${SMOKE_TAG}.tsv"
# A TSV left from an earlier run must never stand in for this one.
rm -f "${HOST_TSV}"

bash "${FBSD_VM_SCRIPT_DIR}/sync.sh" >/dev/null

set +e
ssh "${SSH_OPTS[@]}" freebsd@127.0.0.1 \
  "SMOKE_TMPDIR=${SMOKE_TMPDIR} SMOKE_ONLY='$*' sh -s" <<'REMOTE_SCRIPT'
set -eu
export PATH="${HOME}/.cargo/bin:/usr/local/bin:${PATH}"
cd ~/shit
RESULTS="${HOME}/smoke-results.tsv"
rm -f "${RESULTS}"

# /bin/sh has no pipefail, so `cargo ... | tail` would hide a failed
# build behind tail's exit status.
echo "===== build release binaries ====="
build_rc=0
cargo build --release \
    -p shit -p shitd -p shit-helper -p shit-preload-shim \
    --locked > /tmp/fbsd-build.log 2>&1 || build_rc=$?
tail -3 /tmp/fbsd-build.log
if [ "$build_rc" -ne 0 ]; then
  echo "build failed rc=$build_rc (full log: /tmp/fbsd-build.log in the guest)"
  exit "$build_rc"
fi

echo "===== load pf with permissive baseline ====="
doas kldload -n pf
echo 'pass all' | doas tee /etc/pf.conf >/dev/null
doas /usr/sbin/service pf onestart >/dev/null 2>&1 || true

echo "===== doctor JSON pre-flight ====="
export SHIT_HELPER_BIN="$(pwd)/target/release/shit-helper"
# Same shape as the B04 job: a crashing doctor (SIGBUS on PR 185,
# rc 138) is reported by its exit code, not as a kqueue verdict.
doctor_rc=0
./target/release/shit doctor --json > /tmp/doctor.json || doctor_rc=$?
if [ "$doctor_rc" -ne 0 ]; then
  echo "doctor preflight: FAILED rc=$doctor_rc"
  exit 1
fi
if ! jq -e '.bsd.kqueue_functional == true' /tmp/doctor.json >/dev/null; then
  echo "doctor preflight: FAILED, kqueue_functional is not true"
  jq '.bsd' /tmp/doctor.json
  exit 1
fi
echo "doctor preflight: ok"
jq -r '.bsd | "  capsicum: \(.capsicum_available)  zfs_datasets: \(.zfs_datasets|length)  runtime_capture: \(.runtime_capture)"' /tmp/doctor.json

if [ -n "${SMOKE_ONLY}" ]; then
  SMOKES="${SMOKE_ONLY}"
else
  SMOKES="$(bash tools/audit/smoke-driver.sh bucket freebsd-vm | xargs -n1 basename)"
fi
echo "  bucket size: $(printf '%s\n' ${SMOKES} | wc -l | tr -d ' ') smokes, TMPDIR=${SMOKE_TMPDIR}"

: > "${RESULTS}"
LOGDIR="${HOME}/smoke-logs"
rm -rf "${LOGDIR}"
mkdir -p "${LOGDIR}"
FAIL_COUNT=0
for smoke in ${SMOKES}; do
  passlog="${LOGDIR}/${smoke}.log"
  rc_file="$(mktemp /tmp/smoke-rc.XXXXXX)"
  start=$(date +%s)
  set +e
  (
    TMPDIR="${SMOKE_TMPDIR}" /usr/bin/timeout --signal=TERM --kill-after=10 300 \
      bash "tests/smoke/$smoke"
    echo $? > "$rc_file"
  ) > "$passlog" 2>&1
  set -e
  secs=$(( $(date +%s) - start ))
  rc=$(cat "$rc_file" 2>/dev/null || echo 1)
  rm -f "$rc_file"
  verdict=FAIL
  case "$rc" in
    0) verdict=PASS ;;
    137) if grep -q "^\[smoke .*\] PASS: " "$passlog"; then verdict=PASS-safety-net; fi ;;
  esac
  # CI counts a clean SKIP exit as PASS; tell them apart here.
  if [ "$rc" = 0 ] && ! grep -q "PASS:" "$passlog" && grep -q "SKIP:" "$passlog"; then
    verdict=SKIP
  fi
  [ "${verdict#PASS}" = "${verdict}" ] && [ "$verdict" != SKIP ] && FAIL_COUNT=$((FAIL_COUNT + 1))
  printf '%s\t%s\t%s\t%s\n' "$smoke" "$verdict" "$rc" "$secs" >> "${RESULTS}"
  printf '  %-48s %-16s rc=%-4s %ss\n' "$smoke" "$verdict" "$rc" "$secs"
  rm -f /tmp/safety-net.*.log /tmp/watchdog.log
done
echo "===== ${FAIL_COUNT} failed ====="
[ "${FAIL_COUNT}" -eq 0 ]
REMOTE_SCRIPT
rc=$?
set -e

if ! scp -q "${SSH_OPTS[@]}" freebsd@127.0.0.1:smoke-results.tsv "${HOST_TSV}" \
  || [[ ! -s "${HOST_TSV}" ]]; then
  rm -f "${HOST_TSV}"
  log "no results TSV from this run (remote rc=${rc}); see the output above"
  [[ "${rc}" -ne 0 ]] || rc=1
  exit "${rc}"
fi
log "results: ${HOST_TSV} (logs in guest ~/smoke-logs/)"
exit "${rc}"
