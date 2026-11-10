#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# How do the three mechanisms behave with jails? Run as root on the host
# with mac_shitpre loaded and nothing else consuming /dev/shitpre.
#
#  1. A jailed process mutates files while the host helper watches the
#     jail(8) invocation: MAC hooks fire for jailed threads, the event
#     carries the jid, and the pre-image is captured on the host.
#  2. From inside a jail: can root open /dev/shitpre, /dev/auditpipe,
#     /dev/dtrace/dtrace? (The jail shares the host's / and /dev here,
#     the worst case: only privilege checks stand in the way.)
#  3. Capsicum: cap_probe in capability mode.
#
#   jail_probe.sh WORKDIR
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
w=${1:?workdir}
M="$here/helper/mut"
rm -rf "$w"; mkdir -p "$w/t"
jot -b victim 500 > "$w/t/victim"; cp "$w/t/victim" "$w/orig"
jot -b trunc 500 > "$w/t/trunc"; cp "$w/t/trunc" "$w/orig-trunc"

echo "== 1. host helper, jailed mutator"
"$here/helper/shitpre_helper" -m 1 -s "$w/stage" -- \
	jail -c path=/ name=b5probe persist=0 ip4=inherit \
	command=/bin/sh -c "$M unlink $w/t/victim; $M trunc $w/t/trunc"
for f in orig orig-trunc; do
	h=$(sha256 -q "$w/$f")
	if sha256 -q "$w"/stage/* | grep -qx "$h"; then
		echo "ok   pre-image of $f captured from inside the jail"
	else
		echo "FAIL pre-image of $f missing"
	fi
done

echo "== 2. device access from inside a jail (root in jail)"
jail -c path=/ name=b5probe2 persist=0 command=/bin/sh -c '
	for d in /dev/shitpre /dev/auditpipe /dev/dtrace/dtrace; do
		if (exec 3<"$d") 2>/dev/null; then echo "jail: open $d: allowed"
		else echo "jail: open $d: denied"; fi
	done
	dtrace -n "BEGIN { exit(0) }" >/dev/null 2>&1 && echo "jail: dtrace BEGIN: ran" || echo "jail: dtrace BEGIN: failed"
	'"$here"'/audit/auditpipe_reader -q -o /dev/null & p=$!; sleep 1
	if kill -0 $p 2>/dev/null; then echo "jail: auditpipe_reader: running"; kill -INT $p
	else echo "jail: auditpipe_reader: exited (see stderr above)"; fi
	'

echo "== 3. capability mode"
"$here/jail/cap_probe" "$w"
