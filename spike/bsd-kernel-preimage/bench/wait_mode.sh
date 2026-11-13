#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Mode 2: park the syscall in the MAC hook and let a userspace copier
# try to read the file by path. Shows whether a helper-side copy can
# finish while the mutating thread holds the vnode locks.
#
#   wait_mode.sh WORKDIR [wait_ms]
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
w=${1:?workdir}
sysctl security.mac.shitpre.wait_ms=${2:-400} >/dev/null
rm -rf "$w"; mkdir -p "$w/t"
cd "$w/t"
for f in unlinked truncated inplace target chmodded; do
	jot -b "$f line" 2000 > "$f"
done
echo replacement > src
cat > ../ops.sh <<EOF
#!/bin/sh
M=$here/helper/mut
\$M unlink unlinked
\$M trunc truncated
\$M inplace inplace
\$M renameover src target
\$M chmod chmodded 600
EOF
chmod +x ../ops.sh
"$here/helper/shitpre_helper" -m 2 -s "$w/stage" -q -- ../ops.sh
sysctl security.mac.shitpre.waits security.mac.shitpre.wait_timeouts
