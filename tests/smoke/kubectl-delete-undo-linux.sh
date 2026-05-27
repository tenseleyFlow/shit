#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: kubectl-delete-undo-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY: 
# EXCLUDED_REASON: 
#
# AR04.3 smoke — `kubectl delete <kind>/<name>; shit undo` recreates
# the deleted resource by piping the captured YAML to `kubectl apply
# -f -`.
#
# Exercises (DR-CR-06 cloud-event path, kubectl direction):
#   1. Pre-state setup (NOT through hooks): kind create cluster +
#      kubectl apply a small manifest (configmap with a probe value).
#   2. Helper's prepare_kubectl on Delete: `kubectl get -o yaml
#      configmap/shit-probe` captures the YAML.
#   3. Daemon journals CaptureEvent::KubectlOp { Delete, captured_yaml }.
#   4. The real kubectl proceeds to delete the configmap.
#   5. `shit undo --yes` walks captured_yaml → InverseOp::
#      KubectlReverse → DaemonKubectlRunner.run_with_stdin:
#        - Context guard (`kubectl config current-context`) passes
#        - `kubectl apply -f -` with the captured YAML on stdin
#   6. Post-undo: the configmap is back with the same probe value.
#
# Uses `kind` for the cluster (Docker-in-Docker on hosted runner).
# Skips cleanly when docker/kind/kubectl aren't available.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "Linux" ]; then
    smoke_log "SKIP: kubectl-delete-undo-linux is Linux-only (uname=$(uname -s))"
    exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
    smoke_log "SKIP: docker not on PATH (kind needs docker)"
    exit 0
fi
if ! docker version >/dev/null 2>&1; then
    smoke_log "SKIP: 'docker version' failed"
    exit 0
fi
if ! command -v kind >/dev/null 2>&1; then
    smoke_log "SKIP: kind not on PATH"
    exit 0
fi
if ! command -v kubectl >/dev/null 2>&1; then
    smoke_log "SKIP: kubectl not on PATH"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing at ${HELPER_BIN}"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing at ${SHIT_BIN}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

CLUSTER_NAME="shit-ar04-3-$$"
KUBECONFIG="${SHIT_SMOKE_TMP}/kubeconfig"
export KUBECONFIG
CM_NAME="shit-probe"
PROBE_VALUE="hello-from-ar04.3-$(date +%s)"

cleanup_cluster() {
    SHIT_DURING_UNDO=1 kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1 || true
}
trap 'cleanup_cluster' EXIT

smoke_log "kind create cluster ${CLUSTER_NAME}"
kind create cluster --name "${CLUSTER_NAME}" --kubeconfig "${KUBECONFIG}" \
    >"${SHIT_SMOKE_TMP}/kind-create.log" 2>&1 \
    || {
        sed 's/^/    /' "${SHIT_SMOKE_TMP}/kind-create.log" >&2
        smoke_fail "kind create cluster failed"
    }

# Confirm the cluster is reachable.
kubectl cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null 2>&1 \
    || smoke_fail "kubectl cluster-info failed"

# Pre-state: apply a small ConfigMap so there's something to delete.
smoke_log "pre-state: apply ConfigMap ${CM_NAME}"
kubectl --context "kind-${CLUSTER_NAME}" apply -f - <<EOF >/dev/null
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${CM_NAME}
  namespace: default
data:
  probe: "${PROBE_VALUE}"
EOF
if ! kubectl --context "kind-${CLUSTER_NAME}" get configmap "${CM_NAME}" >/dev/null 2>&1; then
    smoke_fail "pre-state ConfigMap was not applied"
fi
smoke_log "pre-state: ConfigMap exists with probe value"

smoke_start_shitd

smoke_log "installing cloud-hooks"
"${SHIT_BIN}" cloud-hooks install >"${SHIT_SMOKE_TMP}/hooks-install.log" 2>&1 \
    || smoke_fail "cloud-hooks install failed"
HOOKS_BIN="${XDG_CONFIG_HOME}/shit/bin"
[ -x "${HOOKS_BIN}/kubectl" ] || smoke_fail "kubectl wrapper missing"
export PATH="${HOOKS_BIN}:${PATH}"
export PATH="${SHIT_SMOKE_BIN_DIR}:${PATH}"

resolved_kctl="$(command -v kubectl)"
case "${resolved_kctl}" in
    "${HOOKS_BIN}/kubectl") smoke_log "kubectl resolves to wrapper: ${resolved_kctl}" ;;
    *) smoke_fail "expected kubectl to resolve to wrapper, got ${resolved_kctl}" ;;
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
    --cwd "$(pwd)" --shell bash --sock "${SHIT_HOOK_SOCK}"

smoke_log "kubectl delete configmap ${CM_NAME} (via wrapper)"
export SHIT_HOOK_DEBUG=1
if ! kubectl --context "kind-${CLUSTER_NAME}" delete configmap "${CM_NAME}" \
    >"${SHIT_SMOKE_TMP}/kctl-delete.log" 2>&1; then
    smoke_log "kctl-delete.log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/kctl-delete.log" >&2
    smoke_fail "kubectl delete exited non-zero"
fi
smoke_log "kctl-delete.log (informational; delete succeeded):"
sed 's/^/    /' "${SHIT_SMOKE_TMP}/kctl-delete.log" >&2

# Confirm gone.
if kubectl --context "kind-${CLUSTER_NAME}" get configmap "${CM_NAME}" >/dev/null 2>&1; then
    smoke_fail "ConfigMap still present after delete"
fi
smoke_log "post-delete: ConfigMap gone"

smoke_log "PostExec seq=1"
"${SHIT_BIN}" hook-send post-exec \
    --session "${SESSION}" --seq 1 --exit-code 0 --sock "${SHIT_HOOK_SOCK}"

smoke_wait_for_event "discriminant = 'KubectlOp'" 1 10

smoke_log "running: shit undo --yes"
"${SHIT_BIN}" undo --yes 2>&1 | tee "${SHIT_SMOKE_TMP}/undo.log" || {
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "shit undo --yes exited non-zero"
}

# Post-undo: ConfigMap should be back with the same probe value.
if ! SHIT_DURING_UNDO=1 kubectl --context "kind-${CLUSTER_NAME}" get configmap "${CM_NAME}" >/dev/null 2>&1; then
    smoke_log "undo log:"
    sed 's/^/    /' "${SHIT_SMOKE_TMP}/undo.log" >&2
    smoke_fail "ConfigMap not recreated by undo — kubectl apply -f - didn't run"
fi

post_value="$(SHIT_DURING_UNDO=1 kubectl --context "kind-${CLUSTER_NAME}" get configmap "${CM_NAME}" -o jsonpath='{.data.probe}' 2>/dev/null)"
if [ "${post_value}" != "${PROBE_VALUE}" ]; then
    smoke_log "post-undo probe value: '${post_value}'"
    smoke_fail "probe value drift: expected '${PROBE_VALUE}' got '${post_value}'"
fi
smoke_log "post-undo: ConfigMap recreated with same probe value (delete→undo round-trip confirmed)"

smoke_log "session close"
"${SHIT_BIN}" hook-send session-close \
    --session "${SESSION}" --sock "${SHIT_HOOK_SOCK}"

smoke_log "PASS: kubectl-delete-undo-linux (ConfigMap deleted → undo recreated with same data)"
