#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Stage the install tree for a release tarball or a distro package.
#
#   packaging/stage.sh <stage-dir> [release-dir]
#
# Reads built artifacts from <release-dir> (default target/release) and
# writes:
#
#   bin/{shit,shitd,shit-helper}
#   lib/libshit_preload_shim.{so,dylib}
#   share/shit/shell/             shell hooks (placeholders filled by `shit hooks install`)
#   share/shit/<service file>     systemd/shit.service, launchd/<label>.plist or rc.d/shit
#   share/shit/*-hooks/           command wrappers and package-manager hooks
#   share/shit/descriptors/       builtin and cloud descriptors
#
# PREFIX (default /usr) is substituted into the service files. POSIX sh so it
# also runs on FreeBSD.

set -eu

STAGE="${1:?usage: stage.sh <stage-dir> [release-dir]}"
REL="${2:-target/release}"
PREFIX="${PREFIX:-/usr}"
LOG_PATH="${LOG_PATH:-/tmp/shit-shitd.log}"
LABEL="com.tenseleyflow.shit"
HERE="$(dirname "$0")"
ROOT="$(cd "$HERE/.." && pwd)"
OS="$(uname -s)"

case "$OS" in
    Darwin) EXT=dylib ;;
    *) EXT=so ;;
esac

for b in shit shitd shit-helper; do
    [ -x "$REL/$b" ] || { echo "stage.sh: $REL/$b not built" >&2; exit 1; }
done
[ -f "$REL/libshit_preload_shim.$EXT" ] \
    || { echo "stage.sh: $REL/libshit_preload_shim.$EXT not built" >&2; exit 1; }

rm -rf "$STAGE"
SHARE="$STAGE/share/shit"
mkdir -p "$STAGE/bin" "$STAGE/lib" "$SHARE/shell" "$SHARE/descriptors"

for b in shit shitd shit-helper; do
    install -m 0755 "$REL/$b" "$STAGE/bin/$b"
done
install -m 0644 "$REL/libshit_preload_shim.$EXT" "$STAGE/lib/libshit_preload_shim.$EXT"

cp "$ROOT"/shell/* "$SHARE/shell/"
cp -R "$ROOT"/packaging/descriptors/. "$SHARE/descriptors/"
for d in pkg cloud container db net proc svc; do
    mkdir -p "$SHARE/$d-hooks"
    cp -R "$ROOT/packaging/$d-hooks/." "$SHARE/$d-hooks/"
done
install -m 0644 "$ROOT/LICENSE" "$SHARE/LICENSE"

case "$OS" in
    Linux)
        mkdir -p "$SHARE/systemd"
        # Packaged unit: absolute binary, default config path (shitd treats a
        # missing config file as defaults).
        sed -e "s,@@SHITD_BIN@@,$PREFIX/bin/shitd," \
            -e 's, --config @@CONFIG_PATH@@,,' \
            "$ROOT/packaging/systemd/shit.service" > "$SHARE/systemd/shit.service"
        ;;
    Darwin)
        mkdir -p "$SHARE/launchd"
        sed -e "s,@@LABEL@@,$LABEL," \
            -e "s,@@SHITD_BIN@@,$PREFIX/bin/shitd," \
            -e "s,@@LOG_PATH@@,$LOG_PATH," \
            -e '/<string>--config<\/string>/d' \
            -e '/<string>@@CONFIG_PATH@@<\/string>/d' \
            "$ROOT/packaging/launchd/shit.plist" > "$SHARE/launchd/$LABEL.plist"
        cp "$ROOT/packaging/codesign/sign-for-power-user.sh" \
           "$ROOT/packaging/codesign/macos-entitlements.plist" \
           "$ROOT/packaging/codesign/macos-info.plist" "$SHARE/"
        for f in install-macos.md macos-power-user-install.md; do
            if [ -f "$ROOT/docs/$f" ]; then cp "$ROOT/docs/$f" "$SHARE/"; fi
        done
        ;;
    FreeBSD)
        mkdir -p "$SHARE/rc.d"
        sed -e "s,%%PREFIX%%,$PREFIX," \
            "$ROOT/packaging/freebsd-ports/sysutils/shit/files/shit.in" > "$SHARE/rc.d/shit"
        chmod 0755 "$SHARE/rc.d/shit"
        ;;
esac

echo "staged $STAGE"
