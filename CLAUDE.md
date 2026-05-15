# shit — agent guidance

This file is for any AI assistant working in this repo. Read it before making changes.

## What this project is

`shit` is magic undo for the command line. When a user executes a wrong command (an edit, a botched `mv`, a `rm`, a package install), `shit undo` reverses its on-disk and system-state effects. Public-facing details live in `README.md`. The full overview lives in `.docs/overview.md` (gitignored); a sibling `.docs/sprints/` directory contains the 23 sprint specs that define the project end-to-end.

## Architecture (one paragraph)

Three binaries: `shit` (CLI), `shitd` (per-user daemon — owns the snapshot store, sqlite index, undo planner, and IPC sockets), `shit-helper` (privileged helper — runs kernel-level capture: EndpointSecurity on macOS, fanotify-perm + eBPF-LSM on Linux, kqueue + LD_PRELOAD on BSD). Plus shell hooks (bash/zsh/fish) that bracket each command via a persistent UDS fd. Pre-mutation capture is driven by the kernel layer, not the shell; the shell layer only provides command boundaries and metadata. Copy-on-write is lazy and per-event, not at preexec — clonefile / reflink / zfs clone / hardlink / streaming, picked per filesystem.

Wire formats: length-prefixed `postcard`-encoded messages. SOCK_DGRAM for shell→daemon (fire-and-forget). SOCK_SEQPACKET for daemon↔helper (preserves boundaries, supports fd-passing via SCM_RIGHTS). Storage: content-addressed blobs (blake3 + zstd) under `$XDG_STATE_HOME/shit/`, sqlite WAL index, group-commit batching.

## How to work in this repo

### Stages

Development happens in three stages, defined in `.docs/overview.md`:

1. **Planning** — done. Plan lives at `~/.claude/plans/have-a-look-at-reactive-thompson.md`; sprint files at `.docs/sprints/S00.md`–`S22.md`.
2. **Implementation** — you are here. Follow the sprint files in order. Each has Goal / Out-of-scope / Targets / Definition of done / Design notes / Pitfalls / Open questions / Touched files / Dependencies.
3. **Packaging and publishing** — final stage; see S22.

### Working a sprint

- Read the sprint file end-to-end before touching code.
- If you discover a target is too large or needs to be deferred, **stop and discuss**. Do not silently scope-cut. If you do defer a target, punt it to a later sprint file with a thorough explanation.
- If you hit an unanticipated pitfall, pause and record it — append a "Pitfalls encountered" section to the current sprint file, or to a follow-up sprint if it's structural.

### Commits

The user's commit guidelines:

- Commit often. Per-chunk, not multi-file monoliths.
- Avoid `git add -A`; add specific files.
- Imperative, terse subject lines. <250 chars. One line unless an elaboration is genuinely warranted.
- **Never coauthor commits.** Do not add `Co-Authored-By:` lines unless explicitly asked.
- The branch is `trunk`, not `main`.

### Tests

Tests are first-class. Write tests as you go for the sprint's targets. The CI matrix (mac arm64, mac x86_64, linux x86_64, linux arm64, freebsd 14) must stay green; that's a release gate, not a nice-to-have.

### Linting / formatting

- `cargo fmt --all -- --check` (rustfmt config in `rustfmt.toml`; edition 2024, `max_width = 100`).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- `cargo run -p xtask -- license-check` enforces SPDX header `// SPDX-License-Identifier: AGPL-3.0-or-later` on every `.rs` file.
- `make ci` runs the full pipeline.

### Internal docs

- `.docs/` and `.refs/` are intentionally gitignored. They're for plans, sprint specs, audits, and reference material that isn't user-facing.
- `.docs/sprints/SXX-*.md` is the canonical project map. Treat it as authoritative.
- `.docs/audits/` holds running audit notes (started in S06; closes in S20).

### Architectural decisions already locked

- **Rust 2024 edition**, MSRV 1.85.
- **No `notify` crate.** Watcher abstractions are per-platform from day one. Don't introduce a portable wrapper "for convenience" — it'll lose the OS-specific events we need.
- **`thiserror` at library boundaries, `anyhow` only in `main`.**
- **`postcard` for IPC, `serde` JSON only for human-facing config.**
- **`blake3` for hashing, not sha256.**
- **No external snapshot tool integration in v1** (no snapper, no zfs-auto-snapshot, no Time Machine). Roll our own store. Plug-in integrations come in v1.x.
- **Hard-fail by default** when capture can't complete; `--no-protect` per-command escape.
- **Helper is a separate binary.** Privileged code stays in its own address space.

### Don't

- Don't hard-code per-tool integrations (e.g., "if it's nvim, do X"). The whole project's bet is that kernel-tier observation is generic. The only documented exception to this is the `kill`-target pre-snapshot in S18; everything else is generic.
- Don't add features beyond the current sprint's scope. Sprints are the unit of intended progress.
- Don't add comments that re-state what well-named code already does. Comments are for the non-obvious WHY (a hidden constraint, a workaround for a specific OS bug, a TOCTOU defense, etc.).
- Don't introduce backwards-compatibility hacks for a wire format we haven't shipped to anyone yet.
- Don't change the branch name or commit conventions without asking.

## Quick reference

| Command                              | Purpose                                          |
|--------------------------------------|--------------------------------------------------|
| `make dev`                           | `cargo build --workspace`                        |
| `make test`                          | `cargo test --workspace`                         |
| `make lint`                          | `cargo clippy … -D warnings`                     |
| `make fmt-fix`                       | `cargo fmt --all`                                |
| `make license-check`                 | SPDX header check via xtask                       |
| `make ci`                            | full pipeline: fmt + license + lint + test + build |
| `cargo run -p shit -- --version`     | sanity probe                                     |
| `cargo run -p shitd -- --version`    | sanity probe                                     |
| `cargo run -p shit-helper -- --version` | sanity probe                                   |
