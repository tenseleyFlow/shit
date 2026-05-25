#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AR04.1 smoke — `terraform apply -auto-approve; shit undo` reverts
# the applied module by pushing the captured prior state +
# reconciling via `terraform apply -refresh-only`.
#
# Exercises (DR-CR-06 cloud-event path):
#   1. Helper's prepare_terraform on Apply: `terraform state pull`
#      captures the EMPTY pre-apply state (or whatever existed
#      before).
#   2. Daemon ingests via cloud_track::handle, journals
#      CaptureEvent::TerraformOp.
#   3. The real terraform proceeds to create the local_file.
#   4. `shit undo --yes` walks captured_state → InverseOp::
#      TerraformReverse → DaemonTerraformRunner:
#        a. Stash the pre-apply state to a tempfile under
#           .terraform/shit-tf-prior-<ts>.tfstate
#        b. `terraform state push <tempfile>` (rewinds the state)
#        c. `terraform apply -refresh-only -auto-approve` (reconciles)
#   5. Post-undo: local_file.probe in the captured pre-state is gone
#      (state empty), and the on-disk out.txt should also be removed
#      because the local_file provider deletes the file when its
#      resource is removed from state (note: -refresh-only doesn't
#      destroy resources; the test really validates state revert).
#
# Uses the `local_file` provider — no cloud creds. ubuntu-24.04
# hosted runners don't ship terraform; we install it from HashiCorp's
# apt repo in the CI job.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: terraform-apply-undo-linux is Linux-only (uname=$(uname -s))"
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

# Stage an isolated terraform project so the .terraform/ + state stay
# scoped to this smoke (cwd matters for terraform's implicit module).
TF_DIR="${SHIT_SMOKE_TMP}/tf-probe"
mkdir -p "${TF_DIR}"
PROBE_FILE="${TF_DIR}/out.txt"
PROBE_CONTENT="hello-from-ar04.1-$(date +%s)"

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
    *) smoke_fail "expected terraform to resolve to ${HOOKS_BIN}/terraform, got ${resolved_tf}" ;;
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

smoke_log "terraform apply -auto-approve (via wrapper)"
export SHIT_HOOK_DEBUG=1
if ! ( cd "${TF_DIR}" && terraform apply -auto-approve -no-color ) \
    >"${SHIT_SMOKE_TMP}/tf-apply.log" 2>&1; then
    smoke_log "tf-apply.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/tf-apply.log" >&2
    smoke_fail "terraform apply exited non-zero"
fi
smoke_log "tf-apply.log (informational; apply succeeded):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/tf-apply.log" >&2

# Confirm the probe file was created by terraform.
if [ ! -f "${PROBE_FILE}" ]; then
    smoke_fail "probe file ${PROBE_FILE} was not created by terraform apply"
fi
pre_content="$(cat "${PROBE_FILE}")"
if [ "${pre_content}" != "${PROBE_CONTENT}" ]; then
    smoke_fail "probe file content mismatch pre-undo: got '${pre_content}'"
fi
smoke_log "probe file present with expected content"

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

# Post-undo: apply-reverse runs `terraform destroy`, which BOTH:
#  - empties the state, AND
#  - deletes the resources from the world (for local_file, that
#    means removing out.txt from disk).
# Assert both.
post_state="$(SHIT_DURING_UNDO=1 cd "${TF_DIR}" && terraform state list 2>/dev/null || true)"
if [ -n "${post_state}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_log "terraform state still has resources:"
    printf '  %s\n' "${post_state}" >&2
    smoke_fail "terraform destroy didn't clear state (undo dispatch failed)"
fi
smoke_log "terraform state is empty post-undo"

if [ -f "${PROBE_FILE}" ]; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "probe file ${PROBE_FILE} still exists post-undo — destroy didn't remove it"
fi
smoke_log "probe file removed post-undo (apply→destroy round-trip confirmed)"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: terraform-apply-undo-linux (state rewound; resources back to pre-apply set)"
