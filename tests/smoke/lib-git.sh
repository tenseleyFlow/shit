# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared hermetic-git harness for the G01 destructive-git smoke
# family. Each smoke sources `lib.sh` first and `lib-git.sh` next:
#
#   source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"
#   source "${SHIT_REPO_ROOT}/tests/smoke/lib-git.sh"
#
# After sourcing, `git_invoke` is available — it wraps the real git
# binary with config-file + HOME redirection and the hermetic flag
# set, so test repos are isolated from the user's ~/.gitconfig and
# pre-commit hooks never fire.
#
# Conventions:
#   - GIT_BIN is exported (probed via `command -v git`).
#   - Caller may skip via `if [ -z "${GIT_BIN}" ]` before sourcing
#     this library if it wants a custom skip message; otherwise the
#     smoke will fail at first `git_invoke` call.

GIT_BIN="$(command -v git || true)"
if [ -n "${GIT_BIN}" ]; then
    export GIT_BIN
fi

# Hermetic identity + hooks-off via in-process `-c` overrides. We
# don't depend on the user's ~/.gitconfig (HOME redirected to
# SHIT_SMOKE_TMP), system config (/dev/null), or pre-commit hooks
# (core.hooksPath = /dev/null).
GIT_HERMETIC=(
    -c "user.email=g01@shit-smoke"
    -c "user.name=shit-smoke"
    -c "core.hooksPath=/dev/null"
    -c "init.defaultBranch=main"
    -c "commit.gpgsign=false"
    -c "tag.gpgsign=false"
)

# Invoke git hermetically. Pass any git args; `-C <dir>` is the
# typical first arg for tests that operate on a scratch repo.
git_invoke() {
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null HOME="${SHIT_SMOKE_TMP}" \
        "${GIT_BIN}" "${GIT_HERMETIC[@]}" "$@"
}

# Helper-cap preflight. Each G01 smoke needs the LSM tier to capture
# .git/* atomic-rename pre-images. Returns 1 + logs FAIL if caps
# are missing — the smoke should `exit 1` to surface the bless
# command.
smoke_g01_assert_helper_caps() {
    local helper_bin="$1"
    if ! command -v getcap >/dev/null 2>&1; then
        smoke_log "SKIP: getcap missing; can't verify helper caps"
        return 2
    fi
    local caps
    caps="$(getcap "${helper_bin}" 2>/dev/null || true)"
    if ! printf '%s' "${caps}" | grep -q cap_sys_admin; then
        smoke_log "FAIL: helper lacks cap_sys_admin (getcap: '${caps}')"
        smoke_log "  Bless: sudo setcap cap_sys_admin,cap_bpf,cap_perfmon+ep ${helper_bin}"
        return 1
    fi
    smoke_log "helper caps: ${caps}"
    return 0
}
