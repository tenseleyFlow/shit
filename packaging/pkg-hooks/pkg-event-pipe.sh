#!/bin/sh
# Companion to pkg-event.conf: pkg(8) feeds us JSON-Lines events on
# stdin. We grep the `type` field and dispatch the matching shit-
# helper pkg-event invocation.
#
# `pkg` writes one JSON object per line; we don't need a real parser
# — the `type` field is always the first key and uses fixed string
# values. A `grep -q` against the line is sufficient.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -u
HELPER="${SHIT_HELPER:-/usr/local/bin/shit-helper}"

while IFS= read -r line; do
    case "$line" in
        *'"type":"INFO_INSTALL_BEGIN"'*|*'"type":"INFO_DEINSTALL_BEGIN"'*|*'"type":"INFO_UPGRADE_BEGIN"'*)
            "$HELPER" pkg-event pkg pre 2>/dev/null || true
            ;;
        *'"type":"INFO_INSTALL_FINISHED"'*|*'"type":"INFO_DEINSTALL_FINISHED"'*|*'"type":"INFO_UPGRADE_FINISHED"'*)
            "$HELPER" pkg-event pkg post 2>/dev/null || true
            ;;
    esac
done
