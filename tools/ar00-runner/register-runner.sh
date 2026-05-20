#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR00.2 runner registration. Spawns a fresh DO droplet from the
# AR00.1 snapshot, installs the GHA actions-runner binary,
# registers it against tenseleyFlow/shit, and configures it as a
# systemd service so it survives reboot.
#
# Usage:
#   bash tools/ar00-runner/register-runner.sh <snapshot-id> [region]
#
# The runner registration token is requested live from the GitHub
# API at runtime; never baked into the snapshot. Token TTL is ~1
# hour from request; the script registers within seconds.
#
# Pre-reqs:
#   - The AR00.1 snapshot exists (see build-image.sh).
#   - `gh auth status` shows you logged into github.com.
#   - The current `gh` user has admin:repo permission on
#     tenseleyFlow/shit (so it can mint runner tokens).
#
# Side effects:
#   - Creates one droplet from the snapshot ($0.036/hour persistent
#     for 4GB; budget ~$25/mo if left running 24/7. Stop the droplet
#     between AR sprints to save money: `doctl compute droplet-
#     action power-off <id>`).
#   - Registers the runner under the `linux-kernel-capture` label.
#   - Returns the droplet ID + IP for sshing in.

set -euo pipefail

SNAPSHOT_ID="${1:-}"
REGION="${2:-nyc3}"
SIZE="s-2vcpu-4gb"
RUNNER_NAME="shit-ar00-runner-$(date -u +%Y%m%d)"
REPO_OWNER="tenseleyFlow"
REPO_NAME="shit"
RUNNER_LABELS="linux-kernel-capture,self-hosted"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

[ -n "${SNAPSHOT_ID}" ] || { echo "Usage: $0 <snapshot-id> [region]" >&2; exit 1; }
command -v doctl >/dev/null || { echo "FAIL: doctl missing" >&2; exit 1; }
command -v gh >/dev/null || { echo "FAIL: gh-cli missing" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "FAIL: gh not logged in; run 'gh auth login'" >&2; exit 1; }

log() { printf '[ar00-register %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# Mint a runner registration token (TTL ~1 hour).
log "minting runner registration token..."
REG_TOKEN="$(gh api -X POST "/repos/${REPO_OWNER}/${REPO_NAME}/actions/runners/registration-token" \
  --jq .token)"
[ -n "${REG_TOKEN}" ] || { echo "FAIL: empty registration token from GitHub" >&2; exit 1; }
log "token minted (TTL ~1h)"

# Pick an SSH key.
SSH_KEY_FP="$(doctl compute ssh-key list --format FingerPrint --no-header | head -1)"
[ -n "${SSH_KEY_FP}" ] || { echo "FAIL: no SSH keys in DO account" >&2; exit 1; }

# user-data script that:
#   1. Creates the actions-runner working dir under the `runner` user.
#   2. Downloads the runner tarball (latest release; pinning would be
#      a hardening follow-up).
#   3. Configures the runner with the minted token.
#   4. Installs it as a systemd service.
USER_DATA="$(cat <<EOF
#cloud-config
write_files:
  - path: /home/runner/setup-runner.sh
    owner: runner:runner
    permissions: '0755'
    content: |
      #!/bin/bash
      set -e
      cd /home/runner
      mkdir -p actions-runner && cd actions-runner
      # Latest stable runner version. Update periodically; pinning is
      # a hardening follow-up.
      RUNNER_VERSION=\$(curl -sSf https://api.github.com/repos/actions/runner/releases/latest | jq -r .tag_name | tr -d v)
      ARCH=\$(uname -m)
      case "\$ARCH" in
        x86_64) RUNNER_ARCH=x64 ;;
        aarch64) RUNNER_ARCH=arm64 ;;
        *) echo "unsupported arch \$ARCH"; exit 1 ;;
      esac
      curl -o actions-runner.tar.gz -L \\
        "https://github.com/actions/runner/releases/download/v\${RUNNER_VERSION}/actions-runner-linux-\${RUNNER_ARCH}-\${RUNNER_VERSION}.tar.gz"
      tar xzf actions-runner.tar.gz
      rm -f actions-runner.tar.gz
      ./config.sh \\
        --url https://github.com/${REPO_OWNER}/${REPO_NAME} \\
        --token "${REG_TOKEN}" \\
        --name "${RUNNER_NAME}" \\
        --labels "${RUNNER_LABELS}" \\
        --unattended \\
        --replace
      sudo ./svc.sh install runner
      sudo ./svc.sh start
runcmd:
  - sudo -u runner bash /home/runner/setup-runner.sh
EOF
)"

log "creating runner droplet from snapshot ${SNAPSHOT_ID}..."
DROPLET_ID="$(doctl compute droplet create "${RUNNER_NAME}" \
  --image "${SNAPSHOT_ID}" \
  --size "${SIZE}" \
  --region "${REGION}" \
  --ssh-keys "${SSH_KEY_FP}" \
  --user-data "${USER_DATA}" \
  --wait \
  --format ID --no-header)"
log "droplet ${DROPLET_ID} created"

DROPLET_IP="$(doctl compute droplet get "${DROPLET_ID}" --format PublicIPv4 --no-header)"
log "droplet IP: ${DROPLET_IP}"

# Wait for the runner registration to complete. The user-data
# script runs config.sh + svc.sh start; we poll the GitHub side
# for the runner to appear with the expected name.
log "waiting for runner to register with GitHub (up to 5 min)..."
for i in $(seq 1 30); do
  sleep 10
  found=$(gh api "/repos/${REPO_OWNER}/${REPO_NAME}/actions/runners" \
    --jq ".runners[] | select(.name==\"${RUNNER_NAME}\") | .status" 2>/dev/null || echo "")
  if [ "${found}" = "online" ]; then
    log "runner registered + online: ${RUNNER_NAME}"
    break
  fi
  log "  not online yet... (attempt $i/30)"
done

if [ "${found}" != "online" ]; then
  echo "FAIL: runner didn't come online within 5 min." >&2
  echo "  SSH in to debug: ssh root@${DROPLET_IP}" >&2
  echo "  Then: sudo -u runner journalctl -u actions.runner.* --no-pager | tail -50" >&2
  exit 1
fi

cat <<EOF

=========================================================
AR00.2 runner registered.

Runner name:  ${RUNNER_NAME}
Droplet ID:   ${DROPLET_ID}
Droplet IP:   ${DROPLET_IP}
Labels:       ${RUNNER_LABELS}

Cost: ~\$0.036/hour while powered on. Stop when not in use:
  doctl compute droplet-action power-off ${DROPLET_ID}
Restart for the next AR sprint:
  doctl compute droplet-action power-on ${DROPLET_ID}

Workflow to target this runner: set
  runs-on: [self-hosted, linux-kernel-capture]
=========================================================
EOF
