#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# One timed run of each file-heavy workload under one condition. Run as
# root. run_all.sh interleaves conditions round by round.
#
#   bench.sh BASE COND
#
# BASE holds src.tar (6942 entries, 218 MB, from /usr/src/sys) and lua/
# (a clone of github.com/lua/lua at v5.4.6).
# COND picks the wrapper:
#   plain*    run the workload directly (also used while an audit or
#             DTrace consumer runs in the background)
#   observe   shitpre_helper -m 0 (events only)
#   capture   shitpre_helper -m 1 (pin + in-kernel copy + helper staging)
# Workloads:
#   untar     tar -xf src.tar into an empty dir
#   checkout  5 round trips git checkout v5.3.6 <-> v5.4.6 (105 files)
# Prints: COND WORKLOAD seconds
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
B=${1:?base}; cond=${2:?cond}
H="$here/helper/shitpre_helper"
case $cond in
plain*) wrap="" ;;
observe*) wrap="$H -m 0 -q --" ;;
capture*) wrap="$H -m 1 -q -s $B/stage --" ;;
*) echo "unknown cond $cond" >&2; exit 2 ;;
esac
g="git -c safe.directory=* -C $B/lua"

timeit() {
	/usr/bin/time -p "$@" 2>&1 >/dev/null | awk '/^real/ {print $2}'
}

rm -rf "$B/x" "$B/stage"; mkdir -p "$B/x"
echo "$cond untar $(timeit $wrap sh -c "tar -xf $B/src.tar -C $B/x")"
rm -rf "$B/stage"
co="for i in 1 2 3 4 5; do $g checkout -q v5.3.6 && $g checkout -q v5.4.6; done"
echo "$cond checkout $(timeit $wrap sh -c "$co")"
rm -rf "$B/x" "$B/stage"
