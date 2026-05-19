#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# RPM %post scriptlet body — DR-65.
#
# Pasted into the .spec under %post. Writes the helper's self-verify
# baseline so the first runtime check returns Match instead of
# BaselineMissing.
#
# %post runs after install/upgrade. The argument distinguishes
# install ($1==1) from upgrade ($1==2) — we treat both the same way
# because re-baselining against a freshly-installed binary is correct
# in either case.

STATE_DIR=/var/lib/shit
HELPER=/usr/libexec/shit/shit-helper

if [ -x "$HELPER" ]; then
    mkdir -p "$STATE_DIR"
    chmod 0755 "$STATE_DIR"
    if ! "$HELPER" self-baseline-write --state-dir "$STATE_DIR"; then
        echo "shit: self-verify baseline write failed (non-fatal)" >&2
    fi
fi

exit 0
