#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Can DTrace hold a mutating syscall long enough for a userspace copy?
# Runs N unlink and N O_TRUNC trials under stop_test.d, then under
# chill_test.d, and counts how often the copier saw the pre-image.
# Run as root. Loads dtraceall if needed, unloads it if it loaded it, and
# leaves no destructive script running.
#
#   dtrace_preimage.sh WORKDIR [N] [CHILL_NS]
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
w=${1:?workdir}; n=${2:-10}; chill_ns=${3:-200000000}
M="$here/helper/mut"
export DT_TESTDIR="$w"
loaded=0 dp=
cleanup() {
	if [ -n "$dp" ]; then
		kill -TERM "$dp" 2>/dev/null || true
		wait "$dp" 2>/dev/null || true
		dp=
	fi
	if [ $loaded = 1 ]; then
		kldunload dtraceall 2>/dev/null || true
		loaded=0
	fi
}
trap cleanup EXIT INT TERM
if ! kldstat -q -m dtrace; then
	kldload dtraceall
	loaded=1
fi

trial() {
	# $1 = script, $2.. = extra dtrace args
	s=$1; shift
	rm -rf "$w"; mkdir -p "$w"
	dtrace -w -q -s "$here/dtrace/$s" "$@" > "$w/dtrace.out" 2>&1 &
	dp=$!
	sleep 4
	for i in $(jot "$n"); do
		jot 1000 > "$w/u$i"; jot 1000 > "$w/t$i"
		# SIGKILL ends the mutator even if it was left stopped.
		timeout -s KILL 10 "$M" unlink "$w/u$i" || true
		timeout -s KILL 10 "$M" trunc "$w/t$i" || true
		sleep 0.2
	done
	sleep 1
	kill -TERM "$dp"; wait "$dp" || true
	dp=
	echo "== $s $*"
	echo "unlink trials: copier saw file present: $(grep -c "unlink.* present" "$w/copier.log" || true)/$n"
	echo "trunc  trials: copier saw full size (3893 B): $(grep -c "openat present size=3893" "$w/copier.log" || true)/$n"
	echo "trunc  trials: copier saw size 0: $(grep -c "openat present size=0" "$w/copier.log" || true)/$n"
	head -4 "$w/copier.log"
	grep -c "victim=exited" "$w/copier.log" | sed "s/^/copier ran after the mutator exited: /"
}

trial stop_test.d -x switchrate=1000hz "\"$here/dtrace/copier.sh\""
trial chill_test.d -x switchrate=1000hz "\"$here/dtrace/copier.sh\"" "$chill_ns"
