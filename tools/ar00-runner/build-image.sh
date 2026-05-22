#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR00.1 image builder. Provisions a DO droplet from
# ubuntu-24-04-x64 with our cloud-init script, waits for the build
# to finish (cloud-init log heartbeat + a final lsm-bpf assertion),
# snapshots the droplet, then destroys the builder.
#
# The output: a DO snapshot named `shit-runner-image-YYYYMMDD`
# that AR00.2 can spawn runner droplets from.
#
# Pre-reqs:
#   - doctl auth'd (`doctl account get` works).
#   - At least one SSH key registered with DO and listed by
#     `doctl compute ssh-key list`.
#   - About 15 minutes of patience.
#
# Usage:
#   bash tools/ar00-runner/build-image.sh [region]
#
# region defaults to nyc3. Other valid values: sfo3, ams3, sgp1.
#
# Side effects:
#   - Creates one droplet ($1.50/hour while alive; ~15 min total).
#   - Creates one snapshot ($0.06/GB/month). 25GB droplet -> ~$1.50/mo.
#   - Destroys the droplet when done.

set -euo pipefail

REGION="${1:-nyc3}"
SIZE="s-2vcpu-4gb"           # 4GB RAM is the minimum that survives a rustup install + cargo build under load.
BASE_IMAGE="ubuntu-24-04-x64"
TIMESTAMP="$(date -u +%Y%m%d-%H%M)"
DROPLET_NAME="shit-runner-builder-${TIMESTAMP}"
SNAPSHOT_NAME="shit-runner-image-${TIMESTAMP}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_INIT="${SCRIPT_DIR}/cloud-init.yaml"

log() { printf '[ar00-build %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

[ -f "${CLOUD_INIT}" ] || { echo "FAIL: ${CLOUD_INIT} missing" >&2; exit 1; }
command -v doctl >/dev/null || { echo "FAIL: doctl not installed" >&2; exit 1; }

# Pre-flight: cloud-init silently rejects user-data containing any
# non-ASCII byte (it parses as YAML, which 25.x rejects bytes >0x7F
# with `unacceptable character #x0080: special characters are not
# allowed`). Catching this here saves a $0.01 + 15 min round trip.
# Using `tr` (POSIX, BSD- and GNU-compatible) instead of `grep -P`
# (GNU-only) so the check works from macOS too.
nonascii_count=$(LC_ALL=C tr -d '\11\12\15\40-\176' < "${CLOUD_INIT}" | wc -c | tr -d ' ')
if [ "${nonascii_count}" -gt 0 ]; then
  echo "FAIL: ${CLOUD_INIT} contains ${nonascii_count} non-ASCII bytes. cloud-init rejects these." >&2
  echo "  Inspect with:" >&2
  echo "    LC_ALL=C awk 'NR == FNR { for (i = 1; i <= length(\$0); i++) if (substr(\$0,i,1) ~ /[^[:print:][:space:]]/) printf \"%d:%d: byte %02x\\n\", NR, i, substr(\$0,i,1) }' ${CLOUD_INIT}" >&2
  exit 1
fi

# Pick the first SSH key. The operator can change this; we default
# to whatever's first so the script "just works" for a single-user
# account.
SSH_KEY_FP="$(doctl compute ssh-key list --format FingerPrint --no-header | head -1)"
[ -n "${SSH_KEY_FP}" ] || { echo "FAIL: no SSH keys in DO account; add one with 'doctl compute ssh-key import'" >&2; exit 1; }
log "using SSH key fingerprint: ${SSH_KEY_FP}"

log "creating droplet ${DROPLET_NAME} in ${REGION} (${SIZE} ${BASE_IMAGE})"
DROPLET_ID="$(doctl compute droplet create "${DROPLET_NAME}" \
  --image "${BASE_IMAGE}" \
  --size "${SIZE}" \
  --region "${REGION}" \
  --ssh-keys "${SSH_KEY_FP}" \
  --user-data-file "${CLOUD_INIT}" \
  --wait \
  --format ID --no-header)"
log "droplet ${DROPLET_ID} created"

cleanup_droplet() {
  log "destroying droplet ${DROPLET_ID} (cleanup)"
  doctl compute droplet delete "${DROPLET_ID}" --force >/dev/null || true
}

# Wait for cloud-init to complete + reboot. We poll the droplet's
# status (should go active -> off (during reboot) -> active) and then
# wait an extra 60s for the second boot to fully come up.
log "waiting for cloud-init + reboot (up to 15 min)..."
DROPLET_IP="$(doctl compute droplet get "${DROPLET_ID}" --format PublicIPv4 --no-header)"
log "droplet IP: ${DROPLET_IP}"

# SSH polling: cloud-init writes /var/lib/cloud/instance/boot-finished
# at the end of the first boot. Then it reboots. We poll for SSH to
# come back after the reboot AND for /sys/kernel/security/lsm to
# contain 'bpf'.
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR"

# Phase 1: wait for first-boot cloud-init to finish (it'll trigger
# the reboot at the end). Up to 10 min; package install can be slow.
# We poll `cloud-init status`, which reports `done` only when ALL
# datasource parts (vendor-data + user-data) succeeded. A YAML parse
# failure in user-data shows as status=error here even though
# /var/lib/cloud/instance/boot-finished still gets written from
# vendor-data success -- that's the trap we hit on the first attempt.
log "phase 1: waiting for first-boot cloud-init..."
for i in $(seq 1 60); do
  sleep 10
  status=$(ssh ${SSH_OPTS} "root@${DROPLET_IP}" \
    'cloud-init status --long 2>/dev/null | head -2' 2>/dev/null || true)
  state=$(echo "${status}" | grep -E '^status:' | awk '{print $2}')
  case "${state}" in
    done)
      log "phase 1 done (cloud-init status=done)"
      break
      ;;
    error)
      log "FAIL: cloud-init status=error -- user-data was rejected"
      ssh ${SSH_OPTS} "root@${DROPLET_IP}" 'cloud-init status --long' 2>&1 | sed 's/^/  /'
      log "  Inspect with: ssh root@${DROPLET_IP}"
      log "  Or destroy with: doctl compute droplet delete ${DROPLET_ID}"
      exit 1
      ;;
    *)
      log "  cloud-init still running... state=${state:-unknown} (attempt $i/60)"
      ;;
  esac
done

# Phase 1.5: assert our user-data actually deposited its marker.
# Defends against the case where cloud-init reports done but our
# write_files entry was silently dropped (e.g. embedded non-ASCII).
log "phase 1.5: verifying our user-data ran..."
if ! ssh ${SSH_OPTS} "root@${DROPLET_IP}" \
     'test -f /etc/default/grub.d/99-shit-lsm-bpf.cfg' 2>/dev/null; then
  log "FAIL: /etc/default/grub.d/99-shit-lsm-bpf.cfg missing -- user-data did not apply"
  log "  Most likely: cloud-init.yaml contains non-ASCII characters that fail YAML parse."
  log "  Check: LC_ALL=C grep -nP '[^\\x00-\\x7F]' tools/ar00-runner/cloud-init.yaml"
  log "  Inspect: ssh root@${DROPLET_IP} 'tail -50 /var/log/cloud-init.log'"
  log "  Or destroy: doctl compute droplet delete ${DROPLET_ID}"
  exit 1
fi
log "  marker present (OK)"

# Phase 2: cloud-init scheduled a reboot via power_state. Wait for
# the reboot to happen (SSH goes down) and come back.
log "phase 2: waiting for reboot..."
sleep 30  # let the power_state reboot kick in
for i in $(seq 1 30); do
  if ssh ${SSH_OPTS} "root@${DROPLET_IP}" 'uptime' >/dev/null 2>&1; then
    log "phase 2 done (SSH responsive after reboot)"
    break
  fi
  sleep 5
done

# Phase 3: the load-bearing assertion. Without this, the snapshot
# isn't worth taking.
log "phase 3: verifying lsm=bpf in active LSMs..."
LSMS="$(ssh ${SSH_OPTS} "root@${DROPLET_IP}" 'cat /sys/kernel/security/lsm' 2>/dev/null)"
log "  active LSMs: ${LSMS}"
if ! echo "${LSMS}" | grep -q '\bbpf\b'; then
  log "FAIL: bpf NOT in active LSMs after reboot. Aborting snapshot."
  log "  Inspect with: doctl compute ssh ${DROPLET_ID}"
  log "  Or destroy with: doctl compute droplet delete ${DROPLET_ID}"
  exit 1
fi
log "  bpf IS in active LSMs (OK)"

# Optional: also verify BTF + a few tools.
log "phase 4: sanity-check tool availability..."
ssh ${SSH_OPTS} "root@${DROPLET_IP}" '
  ls -la /sys/kernel/btf/vmlinux 2>&1 | head -1
  echo "cargo: $(cargo --version 2>/dev/null || echo missing)"
  echo "docker: $(docker --version 2>/dev/null || echo missing)"
  echo "kubectl: $(kubectl version --client --output=yaml 2>/dev/null | grep -E "gitVersion" | head -1 || echo missing)"
  echo "kind: $(kind --version 2>/dev/null || echo missing)"
  echo "terraform: $(terraform --version 2>/dev/null | head -1 || echo missing)"
  echo "gh: $(gh --version 2>/dev/null | head -1 || echo missing)"
  echo "helm: $(helm version --short 2>/dev/null || echo missing)"
  echo "jq: $(jq --version 2>/dev/null || echo missing)"
' | sed 's/^/  /'

# Strip per-instance state so the snapshot is a clean template, not
# a replay of this builder's first boot. Without this, every droplet
# spawned from the snapshot re-runs the original user-data's apt-get
# install (which then prompts on a kernel-upgrade debconf question
# under whiptail, hanging cloud-init's runcmd that should be running
# our NEW user-data's setup-runner.sh). Also apt clean to shrink
# the snapshot size.
log "phase 4.5: stripping cloud-init state + cleaning apt..."
ssh ${SSH_OPTS} "root@${DROPLET_IP}" '
  cloud-init clean --logs --machine-id 2>&1 | sed "s/^/  cloud-init: /"
  apt-get clean
  rm -rf /var/lib/apt/lists/*
  rm -f /home/runner/.bash_history /root/.bash_history
' 2>&1 | sed 's/^/  /'

# Power off before snapshotting; DO recommends this for consistent
# disk state in the snapshot.
log "phase 5: powering off droplet for clean snapshot..."
doctl compute droplet-action power-off "${DROPLET_ID}" --wait >/dev/null

log "phase 6: taking snapshot ${SNAPSHOT_NAME} (~5 min)..."
doctl compute droplet-action snapshot "${DROPLET_ID}" \
  --snapshot-name "${SNAPSHOT_NAME}" --wait >/dev/null
SNAPSHOT_ID="$(doctl compute snapshot list --resource droplet --format ID,Name --no-header \
  | grep "${SNAPSHOT_NAME}" | awk '{print $1}')"
log "snapshot created: ID=${SNAPSHOT_ID} name=${SNAPSHOT_NAME}"

cleanup_droplet
trap - EXIT

cat <<EOF

=========================================================
AR00.1 image build complete.

Snapshot ID:   ${SNAPSHOT_ID}
Snapshot name: ${SNAPSHOT_NAME}
Region:        ${REGION}

Next: register a runner droplet with this snapshot via
  bash tools/ar00-runner/register-runner.sh ${SNAPSHOT_ID}
=========================================================
EOF
