# Perf-regression baselines

This directory holds per-OS / per-workload baseline JSON files that the
`compare` bin reads in the `.github/workflows/perf.yml` workflow.

## File naming convention

```
<os>-<arch>-<workload>.json
```

- `<os>` — `ubuntu-24.04`, `macos-14`, etc. Match the GitHub Actions
  `runs-on` label.
- `<arch>` — `x86_64` or `aarch64`. The bench binary stamps this into
  the JSON via `std::env::consts::ARCH`.
- `<workload>` — `baseline`, `tight-loop`, `find-workload`,
  `cargo-build`, `git-clone`.

Examples:

- `ubuntu-24.04-x86_64-tight-loop.json`
- `macos-14-aarch64-baseline.json`

## Bootstrapping a new baseline

When the workflow runs on a new OS or for the first time, the
matching baseline file won't exist. The `compare` bin treats that as
a soft pass — absolute-budget gates still apply but relative
regression is skipped.

To promote a freshly-produced run to the canonical baseline:

1. Find the run's artifact in the failing/passing PR's `bench-<os>`
   artifact bundle (`target/bench/<workload>.json`).
2. Inspect it — confirm `median_us` and `p99_us` look healthy for the
   workload's budget.
3. Commit it to this directory under the right name.

The baseline file is **NOT** auto-updated. Plan-perf-budget changes,
infrastructure changes, or substantive code improvements all warrant
an explicit decision to re-baseline; we don't want the gate to drift
silently.

## Rolling baseline (DR-69)

The S21 plan calls for a 14-day rolling baseline computed from recent
trunk runs rather than a static committed file. Static is the v1.0
shape; rolling is tracked under DR-69 alongside the live-daemon
workload provisioning.
