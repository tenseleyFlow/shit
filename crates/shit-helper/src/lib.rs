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
