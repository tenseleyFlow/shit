#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Paired per-round ratios for run_all.sh output.

    paired.py evidence/bench-mac.txt

Each round starts at a "plain untar" line. For every other condition,
prints its median time and the median of (condition / plain) taken
within each round, which cancels the drift between rounds caused by
other load on the shared VM.
"""
import re
import statistics as st
import sys

LINE = re.compile(r"^(\S+) (untar|checkout) ([0-9.]+)$")


def main(path):
    rounds, cur = [], None
    for raw in open(path):
        m = LINE.match(raw.strip())
        if not m:
            continue
        cond, work, secs = m.group(1), m.group(2), float(m.group(3))
        if cond == "plain" and work == "untar":
            cur = {}
            rounds.append(cur)
        if cur is not None:
            cur[(cond, work)] = secs
    conds = sorted({c for r in rounds for c, _ in r} - {"plain"})
    for work in ("untar", "checkout"):
        base = [r[("plain", work)] for r in rounds if ("plain", work) in r]
        for cond in conds:
            pairs = [r[(cond, work)] / r[("plain", work)] for r in rounds
                     if (cond, work) in r and ("plain", work) in r]
            vals = [r[(cond, work)] for r in rounds if (cond, work) in r]
            print(f"{work:9} {cond:13} median {st.median(vals):.2f}s "
                  f"plain {st.median(base):.2f}s paired ratio median "
                  f"{st.median(pairs):.2f} (min {min(pairs):.2f}, "
                  f"max {max(pairs):.2f}, n={len(pairs)})")


if __name__ == "__main__":
    main(sys.argv[1])
