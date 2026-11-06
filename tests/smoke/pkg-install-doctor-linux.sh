#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: pkg-install-doctor-linux
# SMOKE_PLATFORM: linux
# SMOKE_TIER_REQUIRED: any
# SMOKE_RUNNER_HINT: ubuntu-24.04
# SMOKE_TIMEOUT_SEC: 1500
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# P1 smoke — the .deb installs on a clean runner and `shit doctor` is
# green.
#
#   1. Build the release binaries, stage the layout, build the .deb
#      with cargo-deb (`cargo install cargo-deb --locked` beforehand).
#   2. `dpkg -i` it. postinst writes the self-verify baseline and
#      applies cap_bpf,cap_perfmon,cap_sys_admin+ep to the helper.
#   3. Assert the installed files: binaries, shim, systemd user unit,
#      shell hook sources.
#   4. Start shitd through the systemd user unit when a user bus
#      exists, else directly from /usr/bin.
#   5. Assert `shit doctor --json` reports a Linux tier other than
#      `degraded` and that the helper carries all three caps.
#
# Needs sudo. The package is removed on exit unless SHIT_PKG_KEEP=1.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
REAL_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

VIA=direct

pkg_cleanup() {
    local rc=$?
    if [ "${VIA}" = systemd ]; then
        XDG_RUNTIME_DIR="${REAL_RUNTIME_DIR}" systemctl --user disable --now shit 2>/dev/null || true
    fi
    if [ "${SHIT_PKG_KEEP:-0}" != "1" ]; then
        sudo dpkg --purge shit >/dev/null 2>&1 || true
    fi
    (exit "${rc}")
    smoke_cleanup
}
trap pkg_cleanup EXIT

[ "$(uname -s)" = Linux ] || smoke_fail "Linux only"
command -v dpkg >/dev/null || smoke_fail "dpkg not found"
command -v python3 >/dev/null || smoke_fail "python3 not found"
cargo deb --version >/dev/null 2>&1 \
    || smoke_fail "cargo-deb missing; run: cargo install cargo-deb --locked"

cd "${SHIT_REPO_ROOT}" || exit 1

smoke_log "build release binaries"
cargo build --release --workspace
smoke_log "stage layout + build .deb"
packaging/stage.sh target/stage
cargo deb -p shit --no-build
DEB="$(ls -t target/debian/shit_*.deb | head -n1)"
[ -f "${DEB}" ] || smoke_fail "no .deb produced under target/debian"
smoke_log "package: ${DEB}"

smoke_log "dpkg -i"
sudo dpkg -i "${DEB}"

for f in /usr/bin/shit /usr/bin/shitd /usr/bin/shit-helper \
         /usr/lib/shit/libshit_preload_shim.so \
         /usr/lib/systemd/user/shit.service \
         /usr/share/shit/shell/bash.sh /usr/share/shit/shell/zsh.sh \
         /usr/share/shit/shell/fish.fish; do
    [ -e "${f}" ] || smoke_fail "installed file missing: ${f}"
done
smoke_log "installed files present"

CAPS_LINE="$(getcap /usr/bin/shit-helper)"
smoke_log "getcap: ${CAPS_LINE}"
for c in cap_bpf cap_perfmon cap_sys_admin; do
    grep -q "${c}" <<<"${CAPS_LINE}" || smoke_fail "helper lacks ${c} after install"
done
[ -f /var/lib/shit/helper.sha256.baseline ] \
    || smoke_fail "postinst did not write /var/lib/shit/helper.sha256.baseline"

# Daemon: prefer the systemd user unit when the runner has a user bus.
if XDG_RUNTIME_DIR="${REAL_RUNTIME_DIR}" systemctl --user show-environment >/dev/null 2>&1; then
    smoke_log "starting shitd via systemd user unit"
    VIA=systemd
    export XDG_RUNTIME_DIR="${REAL_RUNTIME_DIR}"
    systemctl --user daemon-reload
    systemctl --user enable --now shit
    for _ in $(seq 1 100); do
        [ -S "${REAL_RUNTIME_DIR}/shit-ctl.sock" ] && break
        sleep 0.1
    done
    [ -S "${REAL_RUNTIME_DIR}/shit-ctl.sock" ] \
        || { journalctl --user -u shit --no-pager | tail -30 >&2 || true; smoke_fail "ctl socket never appeared"; }
    systemctl --user is-active shit || smoke_fail "shit.service not active"
else
    smoke_log "no systemd user bus; starting /usr/bin/shitd directly"
    SHIT_SMOKE_BIN_DIR=/usr/bin smoke_start_shitd
fi

OUT="${SHIT_SMOKE_TMP}/doctor.json"
/usr/bin/shit doctor --json > "${OUT}" || smoke_fail "shit doctor --json exited non-zero"
python3 - "${OUT}" <<'PY' || smoke_fail "doctor assertions failed"
import json, sys
d = json.load(open(sys.argv[1]))
lin = d.get("linux")
assert lin, "no linux section in doctor output"
tier = lin["runtime_capture"]
print("runtime_capture:", tier)
print("fanotify_functional:", lin["fanotify_functional"], "ebpf_lsm_functional:", lin["ebpf_lsm_functional"])
print("helper_handshake:", json.dumps(lin["helper_handshake"]))
caps = lin["capabilities"]["helper_binary"]
assert caps["cap_sys_admin"] and caps["cap_bpf"] and caps["cap_perfmon"], f"helper caps: {caps}"
assert tier != "degraded", "linux tier is degraded"
PY

smoke_log "PASS: pkg-install-doctor-linux (daemon via ${VIA})"
