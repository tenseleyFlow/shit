#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Functional check for mac_shitpre mode 1: a static binary (no shim)
# mutates files; every pre-image must land in the stage dir byte-equal
# to the original. Run as root with mac_shitpre loaded.
#
#   functional.sh WORKDIR
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
w=${1:?workdir}
rm -rf "$w"; mkdir -p "$w/t" "$w/orig"
cd "$w/t"
i=0
for f in unlinked truncated inplace target mmapped chmodded; do
	i=$((i + 1))
	jot -b "$f line" $((i * 1000)) > "$f"
	cp -p "$f" "../orig/$f"
done
echo "replacement" > src
cat > ../ops.sh <<EOF
#!/bin/sh
M=$here/helper/mut
\$M unlink unlinked
\$M trunc truncated
\$M inplace inplace
\$M renameover src target
\$M mmapw mmapped
\$M chmod chmodded 600
EOF
chmod +x ../ops.sh
"$here/helper/shitpre_helper" -m 1 -s "$w/stage" -- ../ops.sh > ../events.txt
cat ../events.txt
echo "--- verification (sha256 of originals found among staged blobs)"
fail=0
for f in unlinked truncated inplace target mmapped; do
	want=$(sha256 -q "../orig/$f")
	if sha256 -q "$w"/stage/* | grep -qx "$want"; then
		echo "ok   $f pre-image captured"
	else
		echo "FAIL $f pre-image missing"; fail=1
	fi
done
grep -q "setmode .*mode=644.*chmodded" ../events.txt && \
	echo "ok   chmodded old mode 644 reported" || { echo "FAIL chmod"; fail=1; }
exit $fail
