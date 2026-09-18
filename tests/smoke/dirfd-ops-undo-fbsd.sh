#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: dirfd-ops-undo-fbsd
# SMOKE_PLATFORM: freebsd
# SMOKE_TIER_REQUIRED: kqueue
# SMOKE_RUNNER_HINT: freebsd-vm
# SMOKE_TIMEOUT_SEC: 300
# EXCLUDED_BY:
# EXCLUDED_REASON:
#
# Exercise real directory-fd operands end to end on FreeBSD. The command cwd
# is an empty sentinel outside the target tree; a tiny C helper opens each
# target directory by absolute path and then passes relative names to openat,
# unlinkat, renameat, and linkat. Consequently the shim must recover the
# directory path from the live fd (F_KINFO on FreeBSD). Treating an operand as
# cwd-relative either misses the target or creates an artifact in the sentinel.
#
# Each syscall gets its own command/undo cycle. This keeps the expected inverse
# deterministic and ensures an earlier mutation cannot supply a pre-image for
# a later one.

# shellcheck disable=SC2154
SHIT_REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export SHIT_REPO_ROOT
# shellcheck source=lib.sh
source "${SHIT_REPO_ROOT}/tests/smoke/lib.sh"

if [ "$(uname -s)" != "FreeBSD" ]; then
    smoke_log "SKIP: dirfd-ops-undo-fbsd is FreeBSD-only"
    exit 0
fi

HELPER_BIN="${SHIT_SMOKE_BIN_DIR}/shit-helper"
SHIT_BIN="${SHIT_SMOKE_BIN_DIR}/shit"
SHIM_LIB="${SHIT_SMOKE_BIN_DIR}/libshit_preload_shim.so"
[ -x "${HELPER_BIN}" ] || smoke_fail "shit-helper missing"
[ -x "${SHIT_BIN}" ] || smoke_fail "shit missing"
[ -f "${SHIM_LIB}" ] || smoke_fail "preload shim .so missing at ${SHIM_LIB}"
export SHIT_HELPER_BIN="${HELPER_BIN}"

CC_BIN="$(command -v cc 2>/dev/null || true)"
[ -n "${CC_BIN}" ] || smoke_fail "cc not on PATH"

BUILD_DIR="${SHIT_SMOKE_TMP}/dirfd-build"
FIXTURE_DIR="${SHIT_SMOKE_TMP}/dirfd-fixtures"
WATCHED="${SHIT_SMOKE_TMP}/dirfd-targets"
SENTINEL="${SHIT_SMOKE_TMP}/empty-sentinel"
mkdir -p \
    "${BUILD_DIR}" \
    "${FIXTURE_DIR}" \
    "${WATCHED}/openat" \
    "${WATCHED}/unlinkat" \
    "${WATCHED}/renameat" \
    "${WATCHED}/linkat" \
    "${SENTINEL}"

cat > "${BUILD_DIR}/dirfd_ops.c" <<'CSRC'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what) {
    int saved = errno;
    fprintf(stderr, "%s: %s\n", what, strerror(saved));
    return 1;
}

static int replace_via_openat(int dfd) {
    static const char replacement[] = "replacement written through openat\n";
    size_t offset = 0;
    int fd = openat(dfd, "target.txt", O_WRONLY | O_TRUNC, 0);
    if (fd < 0) {
        return fail("openat");
    }
    while (offset < sizeof(replacement) - 1) {
        ssize_t written = write(fd, replacement + offset,
                                sizeof(replacement) - 1 - offset);
        if (written < 0) {
            close(fd);
            return fail("write");
        }
        offset += (size_t)written;
    }
    if (close(fd) != 0) {
        return fail("close target");
    }
    return 0;
}

int main(int argc, char **argv) {
    int dfd;
    int rc;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <openat|unlinkat|renameat|linkat> <dir>\n",
                argv[0]);
        return 2;
    }

    dfd = open(argv[2], O_RDONLY | O_DIRECTORY, 0);
    if (dfd < 0) {
        return fail("open directory");
    }

    if (strcmp(argv[1], "openat") == 0) {
        rc = replace_via_openat(dfd);
    } else if (strcmp(argv[1], "unlinkat") == 0) {
        rc = unlinkat(dfd, "target.txt", 0) == 0 ? 0 : fail("unlinkat");
    } else if (strcmp(argv[1], "renameat") == 0) {
        rc = renameat(dfd, "source.txt", dfd, "destination.txt") == 0
                 ? 0
                 : fail("renameat");
    } else if (strcmp(argv[1], "linkat") == 0) {
        rc = linkat(dfd, "source.txt", dfd, "created.txt", 0) == 0
                 ? 0
                 : fail("linkat");
    } else {
        fprintf(stderr, "unknown operation: %s\n", argv[1]);
        rc = 2;
    }

    if (close(dfd) != 0 && rc == 0) {
        return fail("close directory");
    }
    return rc;
}
CSRC

"${CC_BIN}" -O0 -Wall -Wextra -o "${BUILD_DIR}/dirfd_ops" \
    "${BUILD_DIR}/dirfd_ops.c" 2> "${SHIT_SMOKE_TMP}/cc-dirfd.log"
[ -x "${BUILD_DIR}/dirfd_ops" ] \
    || smoke_fail "cc failed to build dirfd workload"

printf 'original bytes for openat\n' > "${FIXTURE_DIR}/openat.txt"
printf 'original bytes for unlinkat\n' > "${FIXTURE_DIR}/unlinkat.txt"
printf 'original bytes for renameat\n' > "${FIXTURE_DIR}/renameat.txt"
printf 'original bytes for linkat\n' > "${FIXTURE_DIR}/linkat.txt"
printf 'replacement written through openat\n' > "${FIXTURE_DIR}/openat-replacement.txt"

cp "${FIXTURE_DIR}/openat.txt" "${WATCHED}/openat/target.txt"
cp "${FIXTURE_DIR}/unlinkat.txt" "${WATCHED}/unlinkat/target.txt"
cp "${FIXTURE_DIR}/renameat.txt" "${WATCHED}/renameat/source.txt"
cp "${FIXTURE_DIR}/linkat.txt" "${WATCHED}/linkat/source.txt"

EXPECTED_TREE="$(printf '%s\n' \
    linkat \
    linkat/source.txt \
    openat \
    openat/target.txt \
    renameat \
    renameat/source.txt \
    unlinkat \
    unlinkat/target.txt | LC_ALL=C sort)"

assert_sentinel_empty() {
    local phase="$1"
    local residue
    residue="$(find "${SENTINEL}" -mindepth 1 -maxdepth 1 -print)"
    if [ -n "${residue}" ]; then
        smoke_log "unexpected sentinel entries (${phase}):"
        printf '%s\n' "${residue}" | sed 's/^/    /' >&2
        smoke_fail "cwd-relative artifact appeared in empty sentinel (${phase})"
    fi
}

assert_baseline_tree() {
    local phase="$1"
    local actual_tree
    actual_tree="$(find "${WATCHED}" -mindepth 1 -maxdepth 2 -print \
        | sed "s#^${WATCHED}/##" | LC_ALL=C sort)"
    if [ "${actual_tree}" != "${EXPECTED_TREE}" ]; then
        smoke_log "expected tree (${phase}):"
        printf '%s\n' "${EXPECTED_TREE}" | sed 's/^/    /' >&2
        smoke_log "actual tree (${phase}):"
        printf '%s\n' "${actual_tree}" | sed 's/^/    /' >&2
        smoke_fail "target tree mismatch (${phase})"
    fi

    for pair in \
        openat/target.txt:openat.txt \
        unlinkat/target.txt:unlinkat.txt \
        renameat/source.txt:renameat.txt \
        linkat/source.txt:linkat.txt; do
        local relative_path="${pair%%:*}"
        local fixture="${pair#*:}"
        [ -f "${WATCHED}/${relative_path}" ] \
            || smoke_fail "expected regular file missing (${phase}): ${relative_path}"
        [ ! -L "${WATCHED}/${relative_path}" ] \
            || smoke_fail "unexpected symlink (${phase}): ${relative_path}"
        cmp -s "${FIXTURE_DIR}/${fixture}" "${WATCHED}/${relative_path}" \
            || smoke_fail "byte mismatch (${phase}): ${relative_path}"
    done

    local link_count
    link_count="$(stat -f '%l' "${WATCHED}/linkat/source.txt")"
    [ "${link_count}" -eq 1 ] \
        || smoke_fail "linkat source has ${link_count} links after undo (${phase}); want 1"
}

assert_mutated_state() {
    local operation="$1"
    case "${operation}" in
        openat)
            cmp -s "${FIXTURE_DIR}/openat-replacement.txt" \
                "${WATCHED}/openat/target.txt" \
                || smoke_fail "openat did not replace target bytes"
            ;;
        unlinkat)
            [ ! -e "${WATCHED}/unlinkat/target.txt" ] \
                || smoke_fail "unlinkat did not remove target"
            ;;
        renameat)
            [ ! -e "${WATCHED}/renameat/source.txt" ] \
                || smoke_fail "renameat left source in place"
            cmp -s "${FIXTURE_DIR}/renameat.txt" \
                "${WATCHED}/renameat/destination.txt" \
                || smoke_fail "renameat destination bytes differ from source"
            ;;
        linkat)
            cmp -s "${FIXTURE_DIR}/linkat.txt" \
                "${WATCHED}/linkat/created.txt" \
                || smoke_fail "linkat-created path has wrong bytes"
            local source_inode created_inode link_count
            source_inode="$(stat -f '%i' "${WATCHED}/linkat/source.txt")"
            created_inode="$(stat -f '%i' "${WATCHED}/linkat/created.txt")"
            link_count="$(stat -f '%l' "${WATCHED}/linkat/source.txt")"
            [ "${source_inode}" = "${created_inode}" ] \
                || smoke_fail "linkat paths do not share an inode"
            [ "${link_count}" -eq 2 ] \
                || smoke_fail "linkat source has ${link_count} links; want 2"
            ;;
        *)
            smoke_fail "unknown dirfd test operation: ${operation}"
            ;;
    esac
}

smoke_start_shitd

# `smoke_start_shitd` waits for the control socket, which is initialized on a
# separate daemon task from the preload listener. Make the shim transport
# itself the readiness barrier so the first load-bearing openat cannot race
# listener startup and disappear fail-open.
SHIM_SOCK="${XDG_RUNTIME_DIR}/shit-shim.sock"
for _ in $(seq 1 100); do
    [ -S "${SHIM_SOCK}" ] && break
    sleep 0.1
done
[ -S "${SHIM_SOCK}" ] \
    || smoke_fail "shim listener socket never appeared at ${SHIM_SOCK}"
smoke_log "shim listener socket ready: ${SHIM_SOCK}"

run_dirfd_case() {
    local seq="$1"
    local operation="$2"
    local target_dir="${WATCHED}/${operation}"
    local session
    local undo_log="${SHIT_SMOKE_TMP}/undo-dirfd-${operation}.log"
    local undo_rc=0

    session="$(python3 -c 'import uuid; print(uuid.uuid4())')"
    assert_baseline_tree "before ${operation}"
    assert_sentinel_empty "before ${operation}"

    smoke_log "dirfd case ${seq}: ${operation} from cwd=${SENTINEL} against ${target_dir}"
    "${SHIT_BIN}" hook-send session-open \
        --session "${session}" --pid "$$" --shell bash \
        --tty "$(tty 2>/dev/null || echo /dev/null)" \
        --sock "${SHIT_HOOK_SOCK}"
    "${SHIT_BIN}" hook-send pre-exec \
        --session "${session}" --seq 1 --pid "$$" \
        --cwd "${SENTINEL}" --shell bash --depth 1 \
        --cmdline "dirfd_ops ${operation} ${target_dir}" \
        --sock "${SHIT_HOOK_SOCK}"
    sleep 0.7

    (
        cd "${SENTINEL}"
        LD_PRELOAD="${SHIM_LIB}" "${BUILD_DIR}/dirfd_ops" \
            "${operation}" "${target_dir}"
    )
    assert_mutated_state "${operation}"
    assert_sentinel_empty "after ${operation} mutation"

    sleep 0.5
    "${SHIT_BIN}" hook-send post-exec \
        --session "${session}" --seq 1 --exit-code 0 \
        --sock "${SHIT_HOOK_SOCK}"
    sleep 0.8

    smoke_log "dirfd case ${seq}: undo ${operation} from empty sentinel cwd"
    set +e
    (
        cd "${SENTINEL}"
        "${SHIT_BIN}" undo --yes
    ) > "${undo_log}" 2>&1
    undo_rc=$?
    set -e
    smoke_log "dirfd case ${seq}: undo exit=${undo_rc}"
    /usr/bin/sed "s/^/    ${operation}: /" "${undo_log}" >&2

    "${SHIT_BIN}" hook-send session-close \
        --session "${session}" --sock "${SHIT_HOOK_SOCK}"

    [ "${undo_rc}" -eq 0 ] \
        || smoke_fail "${operation} undo exited ${undo_rc}"
    grep -qE 'applied=[1-9][0-9]*' "${undo_log}" \
        || smoke_fail "${operation} undo reported no applied operations"
    assert_sentinel_empty "after ${operation} undo"
    assert_baseline_tree "after ${operation} undo"
}

run_dirfd_case 1 openat
run_dirfd_case 2 unlinkat
run_dirfd_case 3 renameat
run_dirfd_case 4 linkat

smoke_log "PASS: dirfd-ops-undo-fbsd (openat/unlinkat/renameat/linkat restored exact tree; sentinel stayed empty)"
