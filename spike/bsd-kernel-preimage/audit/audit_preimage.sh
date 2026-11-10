#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Is an audit record ever available before the change lands? Runs N
# unlink and N O_TRUNC trials with a static mutator while
# auditpipe_reader lstat()s each record's path on receipt. Run as root.
# Starts auditd only if it is not already running, and stops what it
# started.
#
#   audit_preimage.sh WORKDIR [N]
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
w=${1:?workdir}; n=${2:-20}
M="$here/helper/mut"
[ -x "$M" ] || { echo "build first: $M" >&2; exit 1; }
started=0 rp=
cleanup() {
	[ -n "$rp" ] && kill -INT "$rp" 2>/dev/null && wait "$rp" || true
	rp=
	[ $started = 1 ] && service auditd onestop >/dev/null || true
	started=0
}
trap cleanup EXIT INT TERM
if ! service auditd onestatus >/dev/null 2>&1; then
	service auditd onestart >/dev/null
	started=1
fi
rm -rf "$w"; mkdir -p "$w"
"$here/audit/auditpipe_reader" -o "$w/records.txt" &
rp=$!
sleep 1
for i in $(jot "$n"); do
	jot 1000 > "$w/u$i"; jot 1000 > "$w/t$i"
	"$M" unlink "$w/u$i"
	"$M" trunc "$w/t$i"
done
sleep 1
cleanup
echo "unlink records: $(grep -c "AUE_UNLINK.*$w/u" "$w/records.txt")," \
    "path still present at receipt: $(grep "AUE_UNLINK.*$w/u" "$w/records.txt" | grep -c exists=yes || true)"
echo "open-trunc records: $(grep -c "AUE_OPENAT_WT .*$w/t" "$w/records.txt")," \
    "file still 3893 B at receipt: $(grep "AUE_OPENAT_WT .*$w/t" "$w/records.txt" | grep -c 'size=3893' || true)"
grep "$w/" "$w/records.txt" | head -4
tail -1 "$w/records.txt"
