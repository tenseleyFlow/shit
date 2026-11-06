#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build shit-<version>-<target>.tar.zst plus its .sha256 from target/release.
#
#   packaging/release-tarball.sh <version> <target> <out-dir>
#
# The archive has a single top-level directory shit-<version>-<target>/.
# PREFIX is the install prefix baked into the service files. Tarballs default
# to /usr/local (where users copy them); the deb, rpm and AUR packages stage
# with PREFIX=/usr, and brew renders its own service. `shit service install`
# re-renders the unit from the embedded template with the real binary path.

set -eu

VERSION="${1:?usage: release-tarball.sh <version> <target> <out-dir>}"
TARGET="${2:?missing target}"
OUT="${3:?missing out-dir}"
NAME="shit-$VERSION-$TARGET"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-/usr/local}"
export PREFIX

mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
sh "$ROOT/packaging/stage.sh" "$WORK/$NAME" "${RELEASE_DIR:-$ROOT/target/release}"
tar --zstd -cf "$OUT/$NAME.tar.zst" -C "$WORK" "$NAME"
cd "$OUT"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$NAME.tar.zst" > "$NAME.tar.zst.sha256"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$NAME.tar.zst" > "$NAME.tar.zst.sha256"
else
    sha256 -r "$NAME.tar.zst" | sed 's/^\([0-9a-f]*\) /\1  /' > "$NAME.tar.zst.sha256"
fi
cat "$NAME.tar.zst.sha256"
