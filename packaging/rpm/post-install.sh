#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# RPM %post scriptlet body — DR-65.
#
# Wired into cargo-generate-rpm as post_install_script. Writes the
# helper's self-verify baseline so the first runtime check returns Match
# instead of BaselineMissing, then applies the helper's file capabilities
# (baseline first: exec of the capped helper fails with EPERM in a
# container whose bounding set lacks the caps).
#
# %post runs after install/upgrade. The argument distinguishes
# install ($1==1) from upgrade ($1==2) — we treat both the same way
# because re-baselining against a freshly-installed binary is correct
# in either case.

STATE_DIR=/var/lib/shit
HELPER=/usr/bin/shit-helper
CAPS=cap_bpf,cap_perfmon,cap_sys_admin+ep

if [ -x "$HELPER" ]; then
    mkdir -p "$STATE_DIR"
    chmod 0755 "$STATE_DIR"
    if ! "$HELPER" self-baseline-write --state-dir "$STATE_DIR"; then
        echo "shit: self-verify baseline write failed (non-fatal)" >&2
    fi
    if ! setcap "$CAPS" "$HELPER"; then
        echo "shit: setcap failed; run: sudo setcap $CAPS $HELPER" >&2
    fi
    echo "shit: start the daemon with: systemctl --user enable --now shit"
fi

exit 0
