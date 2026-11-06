#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build shit-<version>-<target>.tar.zst plus its .sha256 from target/release.
#
#   packaging/release-tarball.sh <version> <target> <out-dir>
#
# The archive has a single top-level directory shit-<version>-<target>/.
# PREFIX is the install prefix baked into the service files; it defaults
# per OS (/usr on Linux, /usr/local on FreeBSD, /opt/homebrew on macOS).

set -eu

VERSION="${1:?usage: release-tarball.sh <version> <target> <out-dir>}"
TARGET="${2:?missing target}"
OUT="${3:?missing out-dir}"
NAME="shit-$VERSION-$TARGET"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -s)" in
    FreeBSD) DEFAULT_PREFIX=/usr/local ;;
    Darwin) DEFAULT_PREFIX=/opt/homebrew ;;
    *) DEFAULT_PREFIX=/usr ;;
esac
PREFIX="${PREFIX:-$DEFAULT_PREFIX}"
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
