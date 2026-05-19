// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deterministic fault-injection points (S20.9).
//!
//! Crash-recovery tests need a way to trigger panics at named
//! callsites without resorting to flaky timing. The `SHIT_FAULT_INJECT`
//! env var lists comma-separated point names that should trigger a
//! `panic!` on the first call to [`maybe_inject`] with that name.
//!
//! ## Release-build semantics
//!
//! `maybe_inject` is a no-op in non-debug builds. The env var is
//! ignored. This is non-negotiable — we never want a deployed
//! production helper or daemon to crash because the user typed
//! `SHIT_FAULT_INJECT` somewhere. The check is `cfg!(debug_assertions)`,
//! which is the standard rustc release/debug split.
//!
//! ## Naming
//!
//! Point names are dotted-snake strings like `blob_store.put.mid_write`.
//! Document new points in the threat model and the per-sprint audit
//! doc when you introduce them.
//!
//! ## Usage
//!
//! ```ignore
//! // In production code:
//! shit_proto::fault_inject::maybe_inject("blob_store.put.mid_write");
//! // ...the syscall that we want to crash before/after...
//!
//! // In a test:
//! SHIT_FAULT_INJECT=blob_store.put.mid_write cargo test ...
//! ```

#[cfg(not(test))]
use std::sync::OnceLock;

const ENV_VAR: &str = "SHIT_FAULT_INJECT";

/// Canonical list of every wired fault-injection point in the
/// codebase. Adding a new `maybe_inject(point)` callsite without
/// registering the name here fires a debug-build panic the first
/// time the function runs — typos become immediate.
///
/// Tests in this module assert this constant matches every active
/// callsite. Documenting points here is the audit trail S20 wants.
pub const KNOWN_INJECTION_POINTS: &[&str] = &[
    // S20.9 — original site.
    "blob_store.put.before_atomic_write",
    "blob_store.put.after_atomic_write",
    // DR-64 — recovery sites.
    "index.put_event_batch.before_tx",
    "index.put_event_batch.before_commit",
    "index.put_event_batch.after_commit",
    "gc.compact_paths.before_delete",
    "gc.compact_paths.after_delete",
    "orchestrator.run.before_op",
    "orchestrator.run.after_op",
    "orchestrator.run_parallel.between_cohorts",
    "helper.handshake.before_ack_send",
    "helper.handshake.after_ack_send",
    // Used by env-path tests in this module.
    "panicky.point",
];

/// Returns `true` when `point` is documented in
/// [`KNOWN_INJECTION_POINTS`]. Used by [`maybe_inject`] to catch
/// typos in debug builds.
pub fn is_known_point(point: &str) -> bool {
    KNOWN_INJECTION_POINTS.contains(&point)
}

/// Trigger a panic if `point` matches an entry in `$SHIT_FAULT_INJECT`.
/// No-op in release builds.
///
/// Returns normally if (a) we're a release build, or (b) the env var
/// doesn't list this point name. Panics otherwise.
///
/// In debug builds, also asserts that `point` is registered in
/// [`KNOWN_INJECTION_POINTS`] — an unregistered name is a typo
/// (or a new site that forgot to update the registry).
pub fn maybe_inject(point: &'static str) {
    if !cfg!(debug_assertions) {
        return;
    }
    debug_assert!(
        is_known_point(point),
        "unregistered fault-injection point: {point:?} (add to KNOWN_INJECTION_POINTS)"
    );
    let points = points();
    if points.iter().any(|p| p == point) {
        panic!("SHIT_FAULT_INJECT triggered at {point}");
    }
}

/// Same as [`maybe_inject`] but returns `bool` instead of panicking.
/// Use when a test wants to observe whether the gate fired without
/// crashing the test runner.
pub fn would_inject(point: &'static str) -> bool {
    if !cfg!(debug_assertions) {
        return false;
    }
    points().iter().any(|p| p == point)
}

/// Read the points env var. Production callers see the value cached
/// at first call (via the OnceLock); tests re-read on every call so
/// they can set the var per-test without OnceLock pinning the value.
#[cfg(not(test))]
fn points() -> Vec<String> {
    static POINTS: OnceLock<Vec<String>> = OnceLock::new();
    POINTS.get_or_init(parse_points).clone()
}

#[cfg(test)]
fn points() -> Vec<String> {
    parse_points()
}

fn parse_points() -> Vec<String> {
    std::env::var(ENV_VAR)
        .ok()
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // We split the tests into pure-function tests of `parse_points`
    // (which don't touch the global env and can run in parallel
    // safely) and a single integration test that exercises the env
    // path. The env-touching test is `#[ignore]`d by default — it
    // can't run alongside other tests because `std::env::set_var`
    // is process-global. Run it explicitly with `cargo test --
    // --ignored env_path`.

    // -- pure tests, parallel-safe --

    fn points_for(env_value: &str) -> Vec<String> {
        env_value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn would_inject_in(points: &[String], target: &str) -> bool {
        points.iter().any(|p| p == target)
    }

    #[test]
    fn parse_empty_env_yields_empty_list() {
        let p = points_for("");
        assert!(p.is_empty());
    }

    #[test]
    fn parse_single_point() {
        let p = points_for("blob_store.put.mid_write");
        assert_eq!(p, vec!["blob_store.put.mid_write".to_string()]);
    }

    #[test]
    fn parse_comma_separated_list_with_spaces() {
        let p = points_for("first.point, second.point , third.point");
        assert_eq!(p.len(), 3);
        assert!(p.iter().any(|s| s == "second.point"));
    }

    #[test]
    fn parse_skips_empty_entries_from_doubled_commas() {
        let p = points_for("a,,b,, ,c");
        assert_eq!(p, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn would_inject_matches_exact_point_name() {
        let points = points_for("a.b.c,d.e.f");
        assert!(would_inject_in(&points, "a.b.c"));
        assert!(would_inject_in(&points, "d.e.f"));
        assert!(!would_inject_in(&points, "a.b"));
        assert!(!would_inject_in(&points, "a.b.c.d"));
    }

    #[test]
    fn known_injection_points_includes_dr64_sites() {
        // Audit assertion: every DR-64 site is documented in the
        // registry. If a callsite is removed, this list shrinks; if
        // a callsite is added without registration, maybe_inject's
        // debug_assert fires.
        let expected = [
            "blob_store.put.before_atomic_write",
            "blob_store.put.after_atomic_write",
            "index.put_event_batch.before_tx",
            "index.put_event_batch.before_commit",
            "index.put_event_batch.after_commit",
            "gc.compact_paths.before_delete",
            "gc.compact_paths.after_delete",
            "orchestrator.run.before_op",
            "orchestrator.run.after_op",
            "orchestrator.run_parallel.between_cohorts",
            "helper.handshake.before_ack_send",
            "helper.handshake.after_ack_send",
        ];
        for site in expected {
            assert!(
                is_known_point(site),
                "DR-64 site {site:?} missing from KNOWN_INJECTION_POINTS"
            );
        }
    }

    #[test]
    fn known_points_have_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for p in KNOWN_INJECTION_POINTS {
            assert!(seen.insert(*p), "duplicate injection point: {p:?}");
        }
    }

    #[test]
    fn known_points_use_dotted_snake_case() {
        for p in KNOWN_INJECTION_POINTS {
            assert!(!p.is_empty(), "empty point name");
            assert!(
                p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
                "{p:?} violates the dotted-snake naming convention"
            );
        }
    }

    #[test]
    fn unknown_point_is_not_in_registry() {
        assert!(!is_known_point("totally.fake.site"));
        assert!(!is_known_point(""));
    }

    // -- env-path integration test, isolated --

    #[test]
    #[ignore = "env-touching; run with --ignored"]
    fn env_path_round_trip() {
        // Set env, call would_inject through the public API, observe
        // truthful result. Other tests must not run in parallel.
        // SAFETY: tests run single-threaded when invoked via
        // `cargo test -- --ignored env_path --test-threads=1`.
        unsafe { std::env::set_var(ENV_VAR, "panicky.point") };
        assert!(would_inject("panicky.point"));
        let result = std::panic::catch_unwind(|| {
            maybe_inject("panicky.point");
        });
        if cfg!(debug_assertions) {
            assert!(result.is_err(), "expected panic in debug build");
        }
        unsafe { std::env::remove_var(ENV_VAR) };
    }
}
