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
#
# Each invocation writes a fresh run directory in the guest,
# ~/smoke-runs/<UTC stamp>-<tag>-<pid>/, and never deletes an earlier
# one. Per smoke it holds <NNN>-<smoke>/smoke.log, shitd.log, the daemon's
# daemon.jsonl* files, index.sqlite and events.tsv (a dump of the
# journal's events table). ~/smoke-logs is a symlink to the latest run.

set -euo pipefail

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

SMOKE_TMPDIR="${SMOKE_TMPDIR:-/tmp}"
REQUIRE_SNAPSHOT=0
case "${SMOKE_TMPDIR}" in
  /tmp/zfs*) DEFAULT_TAG=zfs REQUIRE_SNAPSHOT=1 ;;
  *) DEFAULT_TAG=ufs ;;
esac
SMOKE_TAG="${SMOKE_TAG:-${DEFAULT_TAG}}"

HOST_TSV="${WORK_DIR}/smoke-results-${SMOKE_TAG}.tsv"
# A TSV left from an earlier run must never stand in for this one.
rm -f "${HOST_TSV}"

bash "${FBSD_VM_SCRIPT_DIR}/sync.sh" >/dev/null

set +e
ssh "${SSH_OPTS[@]}" freebsd@127.0.0.1 \
  "SMOKE_TMPDIR=${SMOKE_TMPDIR} SMOKE_TAG=${SMOKE_TAG} SMOKE_ONLY='$*' SHIT_SMOKE_REQUIRE_ZFS_SNAPSHOT=${REQUIRE_SNAPSHOT} sh -s" <<'REMOTE_SCRIPT'
set -eu
export PATH="${HOME}/.cargo/bin:/usr/local/bin:${PATH}"
export SHIT_SMOKE_REQUIRE_ZFS_SNAPSHOT
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
# A run directory per invocation, never cleared by a later run, so a
# flaky failure keeps its daemon log and journal (#202).
RUNDIR="${HOME}/smoke-runs/$(date -u +%Y%m%dT%H%M%SZ)-${SMOKE_TAG}-$$"
mkdir -p "${RUNDIR}"
# ~/smoke-logs was a real directory before per-run dirs. Keep its
# contents and take the name, or "latest" would silently stay stale.
if [ -e "${HOME}/smoke-logs" ] && [ ! -L "${HOME}/smoke-logs" ]; then
  legacy="${HOME}/smoke-logs.legacy-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  mv "${HOME}/smoke-logs" "${legacy}"
  echo "  moved old ~/smoke-logs to ${legacy}"
fi
ln -sfn "${RUNDIR}" "${HOME}/smoke-logs"
echo "  run dir: ${RUNDIR}"
FAIL_COUNT=0
n=0
for smoke in ${SMOKES}; do
  # Numbered so a smoke named more than once (a flake loop) keeps
  # every iteration.
  n=$((n + 1))
  keep="${RUNDIR}/$(printf '%03d' "$n")-${smoke%.sh}"
  mkdir -p "${keep}"
  passlog="${keep}/smoke.log"
  rc_file="$(mktemp /tmp/smoke-rc.XXXXXX)"
  # A private TMPDIR per smoke lets us find lib.sh's shit-smoke.*
  # scratch dir afterwards; SMOKE_KEEP_TMP=1 stops lib.sh deleting it
  # before the logs and journal are copied out.
  scratch="$(mktemp -d "${SMOKE_TMPDIR}/fbsd-smoke.XXXXXX")"
  start=$(date +%s)
  set +e
  (
    TMPDIR="${scratch}" SMOKE_KEEP_TMP=1 \
      /usr/bin/timeout --signal=TERM --kill-after=10 300 \
      bash "tests/smoke/$smoke"
    echo $? > "$rc_file"
  ) > "$passlog" 2>&1
  set -e
  secs=$(( $(date +%s) - start ))
  for st in "${scratch}"/shit-smoke.*; do
    [ -d "$st" ] || continue
    cp "$st/shitd.log" "${keep}/" 2>/dev/null || true
    cp "$st"/state/shit/log/daemon.jsonl* "${keep}/" 2>/dev/null || true
    if [ -f "$st/state/shit/index.sqlite" ]; then
      sqlite3 "$st/state/shit/index.sqlite" ".backup '${keep}/index.sqlite'" 2>/dev/null || true
      sqlite3 -header -separator "$(printf '\t')" "$st/state/shit/index.sqlite" \
        "SELECT id, seq, ts_logical, discriminant, dev, inode, path,
                hex(blob_hash) AS blob, hex(post_content_hash) AS post
         FROM events ORDER BY id" > "${keep}/events.tsv" 2>/dev/null || true
    fi
  done
  # Bounded: an open helper fd or a stuck FS must not hang the loop.
  if ! /usr/bin/timeout 30 rm -rf "${scratch}" 2>/dev/null \
    && ! /usr/bin/timeout 30 doas rm -rf "${scratch}" 2>/dev/null; then
    echo "  WARN: could not remove ${scratch}; leaving it behind"
  fi
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
cp "${RESULTS}" "${RUNDIR}/results.tsv"
echo "===== ${FAIL_COUNT} failed (run dir ${RUNDIR}) ====="
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
log "results: ${HOST_TSV} (logs in the guest run dir printed above; ~/smoke-logs links the latest)"
exit "${rc}"
