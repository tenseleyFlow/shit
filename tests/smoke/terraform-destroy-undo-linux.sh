#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR04.2 smoke — `terraform destroy -auto-approve; shit undo`
# restores the destroyed resources by pushing the captured prior
# state + running `terraform apply -auto-approve` (which sees state-
# says-exists + world-says-no and recreates).
#
# Exercises (DR-CR-06 cloud-event path, destroy direction):
#   1. Pre-state setup (NOT through hooks): init + apply to create
#      the local_file resource so there's something to destroy.
#   2. Helper's prepare_terraform on Destroy: `terraform state pull`
#      captures the post-apply state (1 resource).
#   3. Daemon journals CaptureEvent::TerraformOp { Destroy, prior_state }.
#   4. The real terraform proceeds to destroy — state empty, probe
#      file gone.
#   5. `shit undo --yes` walks captured_state → InverseOp::
#      TerraformReverse { Destroy } → destroy_reverse_via_state_push:
#        a. Stash captured state to tempfile
#        b. terraform state push <tempfile> (restores state)
#        c. terraform apply -auto-approve (sees state-only resources,
#           plans + executes create)
#   6. Post-undo: probe file BACK, state has 1 resource again.
#
# Uses local_file provider; no cloud creds. Reuses HashiCorp apt repo
# install pattern from AR04.1.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: terraform-destroy-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v terraform >/dev/null 2>&1; then
    smoke_log "SKIP: terraform not on PATH"
    exit 0
fi
if ! terraform -version >/dev/null 2>&1; then
    smoke_log "SKIP: 'terraform -version' failed"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

TF_DIR="${SHIT_SMOKE_TMP}/tf-probe"
mkdir -p "${TF_DIR}"
PROBE_FILE="${TF_DIR}/out.txt"
PROBE_CONTENT="hello-from-ar04.2-$(date +%s)"

cat > "${TF_DIR}/main.tf" <<EOF
terraform {
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

resource "local_file" "probe" {
  filename = "${PROBE_FILE}"
  content  = "${PROBE_CONTENT}"
}
EOF

smoke_log "terraform init in ${TF_DIR}"
( cd "${TF_DIR}" && terraform init -no-color ) \
    >"${SHIT_SMOKE_TMP}/tf-init.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/tf-init.log" >&2
        smoke_fail "terraform init failed"
    }

# Pre-state: apply to create the resource. Done BEFORE shit hooks
# are armed so the smoke isolates the destroy → undo path. Hooks
# arming happens after the daemon starts.
smoke_log "pre-state: terraform apply (creates probe file before hooks armed)"
( cd "${TF_DIR}" && terraform apply -auto-approve -no-color ) \
    >"${SHIT_SMOKE_TMP}/tf-preapply.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/tf-preapply.log" >&2
        smoke_fail "pre-state terraform apply failed"
    }

if [ ! -f "${PROBE_FILE}" ]; then
    smoke_fail "pre-state probe file not created by terraform apply"
fi
pre_state_count="$(( cd "${TF_DIR}" && terraform state list 2>/dev/null ) | wc -l | tr -d ' ')"
if [ "${pre_state_count}" -ne 1 ]; then
    smoke_fail "expected 1 resource in pre-state, got ${pre_state_count}"
fi
smoke_log "pre-state: probe file exists, 1 resource in state"

smoke_start_shitd

smoke_log "installing cloud-hooks"
"${SHIT_BIN}" cloud-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/hooks-install.log" >&2
        smoke_fail "cloud-hooks install failed"
    }
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/terraform" ] || smoke_fail "terraform wrapper missing"
export PATH="${HOOKS_BIN}:${PATH}"
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

resolved_tf="$(command -v terraform)"
case "${resolved_tf}" in
    "${HOOKS_BIN}/terraform") smoke_log "terraform resolves to wrapper: ${resolved_tf}" ;;
    *) smoke_fail "expected terraform to resolve to wrapper, got ${resolved_tf}" ;;
esac

SESSION="$(python3 -c 'import uuid; print(uuid.uuid4())')"
PID="$$"
smoke_log "SessionOpen session=${SESSION} pid=${PID}"
"${SHIT_BIN}" hook-send session-open \
    --session "${SESSION}" --pid "${PID}" --shell bash \
    --tty "$(tty 2>/dev/null || echo /dev/null)" \
    --sock "${SHIT_HOOK_SOCK}"

smoke_log "PreExec seq=1 pid=${PID}"
"${SHIT_BIN}" hook-send pre-exec \
    --session "${SESSION}" --seq 1 --pid "${PID}" \
    --cwd "${TF_DIR}" --shell bash --sock "${SHIT_HOOK_SOCK}"

smoke_log "terraform destroy -auto-approve (via wrapper)"
export SHIT_HOOK_DEBUG=1
if ! ( cd "${TF_DIR}" && terraform destroy -auto-approve -no-color ) \
    >"${SHIT_SMOKE_TMP}/tf-destroy.log" 2>&1; then
    smoke_log "tf-destroy.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/tf-destroy.log" >&2
    smoke_fail "terraform destroy exited non-zero"
fi
smoke_log "tf-destroy.log (informational; destroy succeeded):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/tf-destroy.log" >&2

# Confirm the probe file is gone post-destroy.
if [ -f "${PROBE_FILE}" ]; then
    smoke_fail "probe file ${PROBE_FILE} still exists after destroy"
fi
mid_state_count="$(( cd "${TF_DIR}" && terraform state list 2>/dev/null ) | wc -l | tr -d ' ')"
if [ "${mid_state_count}" -ne 0 ]; then
    smoke_fail "expected 0 resources in state after destroy, got ${mid_state_count}"
fi
smoke_log "post-destroy: probe file gone, state empty"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'TerraformOp'" 1 10

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: probe file should be BACK + state should have 1 resource.
if [ ! -f "${PROBE_FILE}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "probe file ${PROBE_FILE} not recreated by undo — destroy-reverse didn't actually run terraform apply"
fi

post_state_count="$(SHIT_DURING_UNDO=1 ( cd "${TF_DIR}" && terraform state list 2>/dev/null ) | wc -l | tr -d ' ')"
if [ "${post_state_count}" -ne 1 ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "state list:"
    SHIT_DURING_UNDO=1 ( cd "${TF_DIR}" && terraform state list 2>/dev/null ) | sed 's/^/    /' >&2
    smoke_fail "expected 1 resource in state post-undo, got ${post_state_count}"
fi
smoke_log "post-undo: probe file recreated + state has 1 resource (destroy→undo round-trip confirmed)"

# Optional content equality check.
post_content="$(cat "${PROBE_FILE}")"
if [ "${post_content}" != "${PROBE_CONTENT}" ]; then
    smoke_fail "probe file content drift: expected '${PROBE_CONTENT}' got '${post_content}'"
fi
smoke_log "probe file content matches pre-destroy"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: terraform-destroy-undo-linux (destroyed → undo recreated)"
