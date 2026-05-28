# tests/smoke — smoke harness contract

Smokes are end-to-end shell scripts that exercise `shit` as a user
would. Each one stands up `shitd`, drives a workload, asserts the
journal + undo behavior, and cleans up. CI runs them across Linux
(ubuntu-24.04 + self-hosted-lsm), FreeBSD (cross-platform-actions),
and macOS (macos-14).

## Metadata contract (AU14)

Every smoke MUST carry a header block immediately after the SPDX
line:

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SMOKE_NAME: <basename-without-extension>
# SMOKE_PLATFORM: <linux|freebsd|macos|any>
# SMOKE_TIER_REQUIRED: <any|lsm|fanotify|kqueue|kqueue+shim|mocked-es>
# SMOKE_RUNNER_HINT: <ubuntu-24.04|self-hosted-lsm|freebsd-vm|macos-14>
# SMOKE_TIMEOUT_SEC: <positive integer>
# EXCLUDED_BY: <empty or sprint-id / issue-id>
# EXCLUDED_REASON: <empty or one-line reason>
#
# <existing comments…>
```

`tools/audit/smoke-driver.sh verify` enforces this schema in CI. A
smoke with a missing or malformed header fails the verify step
loudly — no silent CI drift.

### Field semantics

| Field | Meaning |
|-------|---------|
| `SMOKE_NAME` | Stable identifier — keep equal to filename minus `.sh` |
| `SMOKE_PLATFORM` | Which OS the smoke exercises. `any` for platform-neutral (apt-pkg, hook-ipc, etc.). |
| `SMOKE_TIER_REQUIRED` | What capture tier must be active. `any` if the smoke doesn't depend on kernel-tier capture (e.g., wire-only or executor-only tests). |
| `SMOKE_RUNNER_HINT` | Which CI runner the driver targets. Hand-curated until AU14-B retires the legacy arrays; matters for the matrix output today. |
| `SMOKE_TIMEOUT_SEC` | Hard timeout the driver enforces. Default 300s. |
| `EXCLUDED_BY` | Sprint / issue identifier that owns the deferral. Empty means the smoke is expected to run. |
| `EXCLUDED_REASON` | Human-readable rationale. MUST be set when `EXCLUDED_BY` is set, and vice versa. |

### Exclusion discipline

Marking a smoke `EXCLUDED_BY:` is a serious act — it removes a
runtime invariant from CI's safety net. Use it only when:

1. The smoke surfaces a known gap that has a tracked sprint /
   issue capturing the work, AND
2. Running the smoke today would fail in a way that distracts
   from real signal (e.g. NotImplemented path), AND
3. The exclusion is time-bounded: once the tracked work lands,
   the EXCLUDED fields get cleared in the same PR.

CI today enforces #1 weakly (the field must be non-empty) and #2
not at all (the driver doesn't actually skip excluded smokes —
operators / hand-curated arrays still do). AU14-B will tighten
this: excluded smokes get skipped at the driver level, and the
EXCLUDED_BY value drives a "still excluded?" check at sprint
close.

The current single deferral is `git-branch-D-undo-fbsd.sh` →
`G01.4-packed` (packed-refs branch -D path not yet implemented).

### Hard-assert discipline (AU06)

Inside smoke bodies, every check is either:

1. **Hard**: `smoke_fail "<diagnostic>"` when the expected behavior
   doesn't hold. This is the default.
2. **Carved**: the *whole smoke* gets an `EXCLUDED_BY:` /
   `EXCLUDED_REASON:` header pointing at the sprint that closes
   the gap. The smoke still asserts hard inside; the exclusion
   keeps it out of CI's runner buckets entirely.

There is no soft-assert third option. The two banned legacy
patterns — literal `soft-assert` text and `[FOO-pending]` tags in
`smoke_log` calls — are gated in CI via a grep in the
`smoke-discovery` job. If you find yourself reaching for either,
either tighten the assertion or carve the smoke.

## Authoring a new smoke

1. Copy a peer (e.g. `rm-undo-linux.sh` for a Linux file-op smoke).
2. Update the header block. Keep `SMOKE_NAME` aligned with the
   filename.
3. Write the smoke. Use `lib.sh`'s helpers (`smoke_log`,
   `smoke_fail`, `smoke_start_shitd`, etc.).
4. Validate locally:
   ```
   bash tools/audit/smoke-driver.sh verify
   bash tests/smoke/<your-smoke>.sh
   ```
5. Wire into `.github/workflows/dr-smoke.yml` (hand-curated arrays
   today; AU14-B replaces this with auto-discovery).
6. PR.

## Libraries (NOT smokes)

- `lib.sh` — common helpers (sourced by every smoke).
- `lib-git.sh` — hermetic git fixture helpers.

These are skipped by `smoke-driver.sh` and do not carry the
metadata header.
