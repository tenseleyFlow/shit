#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Called by stop_test.d / chill_test.d through system():
#   copier.sh PID PROBEFUNC PATH
# Records whether PATH exists and its size right now, and the time
# relative to the probe. Then, if PID is stop()ped or about to be, waits
# for the stop to land and resumes it; a SIGCONT sent before the stop
# takes effect would leave the process stopped for good.
d=${DT_TESTDIR:?}
v=$3
alive=$(ps -o stat= -p "$1" 2>/dev/null || echo exited)
if [ -e "$v" ]; then
	echo "$1 $2 present size=$(stat -f %z "$v") victim=$alive $v" >> "$d/copier.log"
else
	echo "$1 $2 absent victim=$alive $v" >> "$d/copier.log"
fi
for _ in $(jot 100); do
	st=$(ps -o stat= -p "$1" 2>/dev/null) || exit 0
	case $st in T*) break ;; esac
	sleep 0.01
done
kill -CONT "$1" 2>/dev/null
exit 0
