#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Interleaved overhead runs. Run as root from a checkout of the spike.
#
#   run_all.sh BASE PHASE ROUNDS
#
# PHASE mac     per round: plain (module unloaded), plain-loaded (loaded,
#               nothing watched), observe, capture
# PHASE audit   per round: plain, then plain-audit with auditd running and
#               auditpipe_reader preselecting fw,fd,fm,fc
# PHASE dtrace  per round: plain, then plain-dtrace with
#               dtrace/trace_mutators.d running (non-destructive)
#
# Prints raw lines, then the median per condition and workload.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
B=${1:?base}; phase=${2:?phase}; rounds=${3:-11}
KO="$here/mac_shitpre/mac_shitpre.ko"
git -c safe.directory='*' -C "$B/lua" checkout -q v5.4.6
out=$(mktemp)

unload() { kldstat -q -m mac_shitpre && kldunload mac_shitpre || true; }

for r in $(jot "$rounds"); do
	case $phase in
	mac)
		unload
		sh "$here/bench/bench.sh" "$B" plain
		kldload "$KO"
		for c in plain-loaded observe capture; do
			sh "$here/bench/bench.sh" "$B" "$c"
		done
		unload
		;;
	audit)
		sh "$here/bench/bench.sh" "$B" plain
		# auditd only during plain-audit: a running trail turns on
		# per-syscall audit preselection for every process.
		service auditd onestart >/dev/null
		"$here/audit/auditpipe_reader" -q -o "$B/audit-summary.$r" &
		rp=$!
		sleep 1
		sh "$here/bench/bench.sh" "$B" plain-audit
		sleep 1
		kill -INT $rp; wait $rp || true
		service auditd onestop >/dev/null
		;;
	dtrace)
		kldstat -q -m dtrace || kldload dtraceall
		sh "$here/bench/bench.sh" "$B" plain
		dtrace -q -s "$here/dtrace/trace_mutators.d" -o "$B/dtrace-out.$r" &
		dp=$!
		sleep 4
		sh "$here/bench/bench.sh" "$B" plain-dtrace
		# sh ignores SIGINT in background jobs; dtrace needs TERM.
		kill -TERM $dp; wait $dp || true
		[ "$r" = "$rounds" ] && kldunload dtraceall
		;;
	*) echo "unknown phase" >&2; exit 2 ;;
	esac
done | tee "$out"
echo "--- medians over $rounds rounds"
awk '{k=$1" "$2; v[k]=v[k]" "$3} END {for (k in v) print k, v[k]}' "$out" |
while read -r c w vals; do
	m=$(echo $vals | tr ' ' '\n' | sort -n | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')
	echo "$c $w median=$m all:$vals"
done | sort
rm -f "$out"
