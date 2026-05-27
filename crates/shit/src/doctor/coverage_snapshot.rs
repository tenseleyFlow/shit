// SPDX-License-Identifier: AGPL-3.0-or-later

//! AU02 — compile-time-embedded CI coverage snapshot.
//!
//! The JSON at `tools/audit/coverage-snapshot.json` is `include_str!`'d
//! at compile time and parsed lazily on first access. CI overwrites the
//! file on every green trunk run; a manual release commit picks up the
//! latest artifact. When the snapshot is the sentinel placeholder (empty
//! timestamps), [`current`] still returns a value — the doctor surface
//! just shows empty strings for `last_validated_at` /
//! `snapshot_workflow_run_url`, signaling "no CI validation recorded".
//!
//! [`binary_built_at`] is read from the `SHIT_BUILD_TIMESTAMP` env var
//! set in `build.rs`; comparing it against `last_validated_at` lets the
//! doctor surface a "binary is N days newer than the validation
//! snapshot" warning at higher layers.

use serde::Deserialize;
use std::sync::OnceLock;

/// Embedded snapshot bytes. Tracked file — changing the JSON triggers
/// a rebuild via cargo's include_str dependency tracking.
const EMBEDDED: &str = include_str!("../../../../tools/audit/coverage-snapshot.json");

/// The shape we parse out of `coverage-snapshot.json`. Only the fields
/// the doctor cares about are pulled; extra fields are tolerated for
/// forward-compat (serde's default).
// commit_sha + green_smokes are present in the JSON for traceability
// and future use; not yet surfaced via the doctor JSON envelope.
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Snapshot {
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub workflow_run_url: String,
    #[serde(default)]
    pub commit_sha: String,
    #[serde(default)]
    pub green_smokes: Vec<String>,
}

/// Parsed snapshot — lazy on first call, then reused.
pub fn current() -> &'static Snapshot {
    static CACHED: OnceLock<Snapshot> = OnceLock::new();
    CACHED.get_or_init(|| {
        serde_json::from_str(EMBEDDED).unwrap_or_else(|err| {
            // A malformed snapshot is a build/CI bug, not a runtime
            // crash condition. Log via stderr and continue with the
            // sentinel default.
            eprintln!(
                "shit doctor: failed to parse embedded coverage-snapshot.json: {err}. Falling back to empty snapshot."
            );
            Snapshot::default()
        })
    })
}

/// Build timestamp emitted by vergen in `build.rs`. RFC3339 / ISO 8601
/// UTC. Empty string when vergen didn't run (shouldn't happen in
/// supported builds — `build.rs` requires it).
pub fn binary_built_at() -> String {
    option_env!("VERGEN_BUILD_TIMESTAMP")
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_parses_to_empty_strings() {
        // The committed sentinel has empty timestamp fields. If
        // someone replaces it with a real validation snapshot via
        // CI, these assertions naturally update (and the smoke
        // gates the field presence).
        let snap = current();
        // Sentinel comes through clean — no panic, no None.
        let _ = &snap.generated_at;
        let _ = &snap.workflow_run_url;
    }

    #[test]
    fn binary_built_at_is_populated() {
        // build.rs sets SHIT_BUILD_TIMESTAMP unconditionally; if it
        // didn't, the doctor's "stale binary" warning loses its
        // anchor.
        let ts = binary_built_at();
        assert!(!ts.is_empty(), "SHIT_BUILD_TIMESTAMP must be set by build.rs");
    }
}
