// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal library facade exposing the bench-relevant subset of
//! `shit-helper`'s internals.
//!
//! Why this exists: `shit-helper` is primarily a binary, but the
//! B07 perf-regression bench needs to call into the kqueue capture
//! tier's hot path (pre-image read + streaming copy that runs on
//! every NOTE_WRITE / NOTE_DELETE) to measure its per-event cost
//! honestly. Spawning the full helper per iteration would let
//! process-startup dominate the measurement; this facade lets the
//! bench link the functions directly.
//!
//! Deliberately small: only re-declares the leaf modules whose
//! pub surface the bench actually touches. `main.rs` keeps its
//! own `mod` declarations for everything it needs — the modules
//! exposed here are re-compiled into the lib too, but they're
//! pure-logic leaves with no orchestration state, so the cost is
//! a tiny rebuild and no behavioural divergence.
//!
//! Note: the symbol path is `shit_helper::capture::*` rather than
//! mirroring the helper's internal `kqueue::capture::*` because the
//! enclosing `mod kqueue {}` would force `#[path]` resolution into
//! `src/kqueue/kqueue/...`. The shorter path is acceptable for a
//! bench-only surface.
//!
//! If you find yourself needing more of the helper's internals
//! from a non-bin context, prefer factoring the leaf logic into a
//! separate crate over expanding this facade — the dual-target
//! pattern wears thin fast.
//!
//! # Adding a new `#[path]` mount
//!
//! HD-02 made this contract explicit after AU25 burned three CI
//! round-trips to find it:
//!
//! 1. The mounted file MUST be self-contained against
//!    main.rs-tree imports. No `use crate::X` for `X` outside
//!    the file's own definitions; no `use super::X` that
//!    resolves up into the bin's mod tree. External-crate
//!    imports (`shit_proto`, `serde`, `libc`, etc.) are fine —
//!    they resolve through Cargo.toml.
//! 2. Add a `# HD-02 — self-containment contract` section to the
//!    file's `//!` block (see `kqueue/capture.rs` for the
//!    canonical wording).
//! 3. The CI's `helper-lib-bsd-cross-check` job builds this lib
//!    facade for `x86_64-unknown-freebsd` from a Linux runner and
//!    will catch a `crate::` violation in ~30s instead of the 3
//!    minutes the native `freebsd-14` job takes.
//!
//! Symptom of a violation: `error[E0432]: unresolved import
//! 'crate::X'`. macOS / Linux pre-flight CANNOT see it because
//! they don't compile the lib facade for the relevant cfg.

#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
#[path = "kqueue/capture.rs"]
pub mod capture;

// M07.C — re-export the codesign verify facade so integration
// tests in `tests/` (which can only see the lib's public surface)
// can call `verify_path` against a deliberately-corrupted helper
// copy and assert the failure shape end-to-end.
#[cfg(target_os = "macos")]
#[path = "codesign_verify.rs"]
pub mod codesign_verify;
