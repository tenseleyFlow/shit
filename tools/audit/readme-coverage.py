#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Render the README coverage tables from smoke metadata.

Reads `tools/audit/smoke-driver.sh discover` (the SMOKE_* and EXCLUDED_BY
headers of tests/smoke/*.sh) and rewrites the block between
`<!-- coverage:begin -->` and `<!-- coverage:end -->` in README.md.

  readme-coverage.py            rewrite README.md in place
  readme-coverage.py --check    exit 1 if the block in README.md is stale
  readme-coverage.py --print    write the generated block to stdout

No third-party dependencies.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
README = os.path.join(ROOT, "README.md")
BEGIN = "<!-- coverage:begin -->"
END = "<!-- coverage:end -->"

WORKFLOW = os.path.join(ROOT, ".github", "workflows", "dr-smoke.yml")

# Ordered; the first matching pattern wins. A smoke that matches nothing is
# an error: add a pattern here rather than letting it land in a wrong row.
FAMILIES = [
    ("Strict capture (opt-in loss-aware refusal)", r"^strict-"),
    ("Refuse-list", r"^refuse-"),
    ("Git operations", r"^git-"),
    ("Shell state", r"^(cd|set-e|alias)-"),
    ("Capture tier, sandbox and ZFS engine",
     r"^(capsicum-|shim-default-|preload-shim-|zfs-|es-|fsevents-|ln-hardlink-shim-|setxattr-shim-|"
     r"helper-privilege-)"),
    ("Daemon, doctor and harness",
     r"^(daemon-boot|doctor-|hook-ipc$|shitd-|show-detail-|visibility-|env-oversize-|pkg-install-doctor-)"),
    ("Package managers", r"^(apt-|dnf-|pkg-install-undo|brew-)"),
    ("Containers", r"^(docker-|podman-)"),
    ("Cloud and IaC", r"^(terraform-|kubectl-|gh-)"),
    ("Services, firewall, network and processes",
     r"^(systemctl-|service-|launchctl-|nft-|iptables-|pfctl-|networksetup-|route-|kill-)"),
    ("Databases", r"^sqlite3-"),
    ("Build and install", r"^(make-install-|cargo-|pip-install-|python-venv-)"),
    ("Post-hash drift detection", r"^post-hash-"),
    ("Command shapes (pipelines, wrappers, read-only)",
     r"^(find-exec-|xargs-|and-chain-|bash-c-|background-job-|read-only-cmd-|ssh-keygen-)"),
    ("Filesystem: metadata and attributes",
     r"^(chmod-|chown-|chflags-|xattr-|setxattr-)"),
    ("Filesystem: remove, rename, link, create",
     r"^(rm-|rmdir-|mv-|dir-rename-|renameat-|ln-|link-|hardlink-|symlink-|mkdir-|mkfifo-|mknod-|"
     r"large-file-rm-|non-ascii-|non-utf8-|canonicalize-|restore-fidelity-)"),
    ("Filesystem: content writes and editors",
     r"^(edit-|touch-edit-|vim-|sed-|awk-|sort-|tee-|dd-|shell-|redirect-|write-in-place-|mmap-|cp-|"
     r"large-file-overwrite-|patch-|split-|rotate-|backup-and-modify-|gzip-|tar-|cpio-|rsync-)"),
]
PLATFORMS = [("Linux", "linux"), ("FreeBSD", "freebsd"), ("macOS", "macos"), ("Any OS", "any")]
LSM_RUNNER = "self-hosted LSM runner (runs only when that runner is online)"
BSD_RUNNER = "FreeBSD 14 VM on hosted ubuntu-24.04 (UFS and ZFS legs)"


def die(msg):
    sys.exit("readme-coverage: " + msg)


def family_of(name):
    for label, pat in FAMILIES:
        if re.search(pat, name):
            return label
    die("no surface family for smoke %r; add a pattern to FAMILIES" % name)


def discover():
    out = subprocess.run(
        ["bash", os.path.join(ROOT, "tools/audit/smoke-driver.sh"), "discover"],
        check=True, capture_output=True, text=True, cwd=ROOT,
    ).stdout
    return json.loads(out)


def workflow_runners():
    """Map smoke name -> set of runs-on labels of the dr-smoke.yml jobs naming it."""
    out, job, runs, refs = {}, None, {}, {}
    in_jobs = False
    with open(WORKFLOW, encoding="utf-8") as f:
        for line in f:
            if line.startswith("jobs:"):
                in_jobs = True
                continue
            if not in_jobs:
                continue
            m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
            if m:
                job = m.group(1)
                continue
            m = re.match(r"^    runs-on:\s*(.+?)\s*$", line)
            if m and job:
                runs[job] = m.group(1)
            if job:
                for s in re.findall(r"tests/smoke/([A-Za-z0-9_-]+)\.sh", line):
                    refs.setdefault(s, set()).add(job)
    for s, jobs in refs.items():
        out[s] = {runs[j] for j in jobs if j in runs}
    return out


def location(rec, wf):
    """Where the smoke runs: a label string. Dies if it is wired nowhere."""
    if rec["runner"] == "self-hosted-lsm":
        return LSM_RUNNER
    if rec["runner"] == "freebsd-vm":
        return BSD_RUNNER
    labels = wf.get(rec["name"])
    if not labels:
        die("smoke %r is not referenced by any dr-smoke.yml job" % rec["name"])
    return "hosted " + " and ".join(sorted(labels))


def cell(names):
    return ", ".join("`%s`" % n for n in sorted(names))


def render(records):
    wf = workflow_runners()
    known = {p for _, p in PLATFORMS}
    for r in records:
        if r["platform"] not in known:
            die("smoke %r has unknown SMOKE_PLATFORM %r" % (r["name"], r["platform"]))
    out = [
        BEGIN,
        "<!-- Generated by tools/audit/readme-coverage.py from tests/smoke/*.sh headers and dr-smoke.yml. Do not edit by hand. -->",
        "",
    ]
    order = [label for label, _ in FAMILIES]
    for title, plat in PLATFORMS:
        recs = [r for r in records if r["platform"] == plat]
        live = [r for r in recs if not r["excluded_by"]]
        skipped = [r for r in recs if r["excluded_by"]]
        head = "%d wired into CI" % len(live)
        if skipped:
            head += ", %d excluded" % len(skipped)
        out += ["### %s (%s)" % (title, head), ""]
        where = {}
        for r in live:
            where.setdefault(location(r, wf), []).append(r)
        for loc in sorted(where, key=lambda x: (x != LSM_RUNNER, x)):
            fam = {}
            for r in where[loc]:
                fam.setdefault(family_of(r["name"]), []).append(r["name"])
            out += ["#### %s: %d smoke%s" % (loc, len(where[loc]), "" if len(where[loc]) == 1 else "s"), "",
                    "| Surface family | Smokes |", "|---|---|"]
            for label in order:
                if label in fam:
                    out.append("| %s | %s |" % (label, cell(fam[label])))
            out.append("")
        if skipped:
            out += ["#### Excluded from CI, so not evidence of coverage", "",
                    "| Smoke | Excluded by |", "|---|---|"]
            for r in sorted(skipped, key=lambda r: r["name"]):
                family_of(r["name"])
                out.append("| `%s` | `%s` |" % (r["name"], r["excluded_by"]))
            out.append("")
    out.append(END)
    return "\n".join(out)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in ("", "--check", "--print"):
        sys.exit(__doc__)
    block = render(discover())
    if mode == "--print":
        print(block)
        return
    with open(README, encoding="utf-8") as f:
        text = f.read()
    b, e = text.find(BEGIN), text.find(END)
    if b < 0 or e < b:
        sys.exit("README.md is missing the coverage markers")
    new = text[:b] + block + text[e + len(END):]
    if mode == "--check":
        if new != text:
            sys.stderr.write(
                "README.md coverage block is stale. Run tools/audit/readme-coverage.py and commit.\n")
            sys.exit(1)
        return
    with open(README, "w", encoding="utf-8") as f:
        f.write(new)


if __name__ == "__main__":
    main()
