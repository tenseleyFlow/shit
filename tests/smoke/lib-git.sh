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

# FreeBSD ships git under /usr/local/bin after `pkg install git`;
# CI invokes smokes via a minimal PATH so make sure that location
# is reachable before probing.
case "$(uname -s)" in
    FreeBSD|NetBSD|OpenBSD|DragonFly)
        export PATH="/usr/local/sbin:/usr/local/bin:${PATH}"
        ;;
esac
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

# Helper-cap preflight. Linux: each G01 smoke needs the LSM tier
# to capture .git/* atomic-rename pre-images, which requires
# cap_sys_admin on the helper binary. Returns 1 + logs FAIL if
# caps are missing — the smoke should `exit 1` to surface the
# bless command.
#
# FreeBSD: kqueue capture doesn't need elevated caps (capsicum is
# a sandbox the helper enters, not a privilege). Return 0
# (no-op) so the same harness works for the G01.B BSD mirror.
smoke_g01_assert_helper_caps() {
    local helper_bin="$1"
    case "$(uname -s)" in
        FreeBSD|NetBSD|OpenBSD|DragonFly)
            smoke_log "helper caps: n/a (BSD — kqueue tier, no privileged caps required)"
            return 0
            ;;
    esac
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

# R3 slice B — strict git lock-file smoke, shared by the Linux (LSM) and
# FreeBSD (kqueue) wrappers.
#
#   smoke_strict_git_lockfile <name> <hash-fn>
#
# <hash-fn> prints the sha256 of the file given as $1. The caller has
# already passed its tier gate (kernel tier, helper caps, SHIT_FORCE_TIER)
# and set SHIT_BIN. One session under SHIT_STRICT_CAPTURE=1 runs
# `git config`, `git commit` and `git branch -D`, undoing each right after
# it runs, and then requires zero CaptureRefused rows.
smoke_strict_git_lockfile() {
    local name="$1" hash_fn="$2"
    local repo="${SHIT_SMOKE_TMP}/scratch/repo"
    mkdir -p "${repo}"
    git_invoke -C "${repo}" init -q
    echo "initial content" > "${repo}/README.md"
    git_invoke -C "${repo}" add README.md
    git_invoke -C "${repo}" commit -q -m "anchor commit"
    git_invoke -C "${repo}" branch feat
    echo "feature line" >> "${repo}/README.md"
    git_invoke -C "${repo}" commit -q -am "feature commit"
    local feat_sha prior_head config_sha
    feat_sha="$(git_invoke -C "${repo}" rev-parse HEAD)"
    git_invoke -C "${repo}" branch -f feat "${feat_sha}"
    git_invoke -C "${repo}" reset -q --hard HEAD~1
    prior_head="$(git_invoke -C "${repo}" rev-parse HEAD)"
    echo "staged line" >> "${repo}/README.md"
    git_invoke -C "${repo}" add README.md
    config_sha="$("${hash_fn}" "${repo}/.git/config")"
    smoke_log "anchor=${prior_head} feat=${feat_sha} config sha256=${config_sha}"

    SHIT_STRICT_CAPTURE=1 smoke_start_shitd
    local session
    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    cd "${repo}"
    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "$$" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"

    _lockfile_run() {
        local seq="$1" cmdline="$2"
        shift 2
        "${SHIT_BIN}" hook-send pre-exec \
            --session "${session}" --seq "${seq}" --pid "$$" \
            --cwd "${repo}" --shell bash --cmdline "${cmdline}" \
            --sock "${SHIT_HOOK_SOCK}"
        smoke_log "[${seq}] ${cmdline}"
        git_invoke -C "${repo}" "$@"
        "${SHIT_BIN}" hook-send post-exec \
            --session "${session}" --seq "${seq}" --exit-code 0 \
            --sock "${SHIT_HOOK_SOCK}"
    }
    _lockfile_undo() {
        local label="$1"
        local log="${SHIT_SMOKE_TMP}/undo-${label}.log"
        local rc
        set +e
        "${SHIT_BIN}" undo --yes > "${log}" 2>&1
        rc=$?
        set -e
        sed 's/^/    undo: /' "${log}" >&2 || true
        [ "${rc}" -eq 0 ] || smoke_fail "[${label}] shit undo exit=${rc}"
        if grep -q "capture-incomplete" "${log}"; then
            smoke_fail "[${label}] strict undo refused with capture-incomplete"
        fi
    }

    _lockfile_run 1 "git config core.shitprobe yes" config core.shitprobe yes
    [ "$(git_invoke -C "${repo}" config --get core.shitprobe)" = "yes" ] \
        || smoke_fail "[config] git config did not take effect"
    _lockfile_undo config
    if git_invoke -C "${repo}" config --get core.shitprobe >/dev/null 2>&1; then
        smoke_fail "[config] core.shitprobe still set after undo"
    fi
    [ "$("${hash_fn}" "${repo}/.git/config")" = "${config_sha}" ] \
        || smoke_fail "[config] .git/config differs from its pre-command bytes"

    _lockfile_run 2 "git commit -m staged" commit -q -m staged
    _lockfile_undo commit
    [ "$(git_invoke -C "${repo}" rev-parse HEAD)" = "${prior_head}" ] \
        || smoke_fail "[commit] HEAD not restored to ${prior_head}"
    [ "$(git_invoke -C "${repo}" status --porcelain)" = "M  README.md" ] \
        || smoke_fail "[commit] index not restored (status: $(git_invoke -C "${repo}" status --porcelain))"

    _lockfile_run 3 "git branch -D feat" branch -q -D feat
    _lockfile_undo branch
    [ "$(git_invoke -C "${repo}" rev-parse --verify -q feat)" = "${feat_sha}" ] \
        || smoke_fail "[branch] refs/heads/feat not restored to ${feat_sha}"

    "${SHIT_BIN}" hook-send session-close --session "${session}" --sock "${SHIT_HOOK_SOCK}"
    cd "${SHIT_SMOKE_TMP}"

    local refusals
    refusals="$(smoke_journal_count "discriminant = 'CaptureRefused'")"
    if [ "${refusals}" -ne 0 ]; then
        smoke_dump_refusals
        smoke_fail "strict capture journaled ${refusals} CaptureRefused row(s) for born lock files"
    fi
    smoke_log "PASS: ${name} (config, commit and branch -D undone; zero refusals)"
}
