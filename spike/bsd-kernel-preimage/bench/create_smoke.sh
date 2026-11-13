#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Regression check for the first prototype's livelock: creating new files
# under a watched subtree (open(O_CREAT) on a vnode the name cache has
# not seen). The vn_fullpath() version spun forever here.
#
#   create_smoke.sh WORKDIR
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
w=${1:?workdir}
rm -rf "$w"; mkdir -p "$w/src" "$w/y"
cd "$w/src"
jot 200 | while read -r i; do echo "file $i" > "f$i"; done
tar -cf ../small.tar .
"$here/helper/shitpre_helper" -m 1 -q -s "$w/stage" -- \
	sh -c "tar -xf $w/small.tar -C $w/y && for i in 1 2 3; do echo x > $w/y/new\$i; done"
ls "$w/y" | wc -l
