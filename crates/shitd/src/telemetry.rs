// SPDX-License-Identifier: AGPL-3.0-or-later

//! S21.6 OTLP export — PII filter and (gated) collector wiring.
//!
//! The headline guarantee from the threat model is that span fields
//! the workspace deems sensitive MUST never reach the OTLP collector.
//! `tracing-schema.md` enumerates them; the [`is_pii_field`] predicate
//! is the single source of truth in code.
//!
//! Why a pure predicate sits in its own module: the OTel runtime
//! pipeline (`tracing_opentelemetry::layer().with_tracer(...)`) is
//! awkward to unit-test — it depends on a tokio runtime, a tonic
//! channel, and a live collector — but the *filter logic* must be
//! ironclad before any operator turns export on. So the filter is a
//! free function with exhaustive tests; the wiring is a small
//! `init()` that consumes it.
//!
//! The exporter itself is gated behind the `otel` cargo feature so
//! minimal builds don't pay for ~40 transitive crates. See
//! `tracing-schema.md#otlp-export-field-selection` for the contract.
//!
//! ## Runtime wiring status
//!
//! The runtime wiring (init_otlp_layer + integration into log_setup)
//! is tracked as DR-67. This chunk lands the PII filter — the
//! audit-critical part — and the config-surface plumbing. Lighting
//! up the exporter requires a collector test harness that isn't on
//! the S21 path.

// The functions below are scaffolding for DR-67; the runtime layer
// consumes them. Tests cover them fully — the dead-code warning is
// transient.
#![allow(dead_code)]

/// Span/event field names that must be stripped before export.
///
/// Two categories:
///
/// 1. **Forbidden** (from S20.7 leak audit + tracing-schema.md):
///    `value`, `body`, `sql`, `content`, `env_value`,
///    `statement_text`, `raw_block`. These should never appear in
///    workspace tracing events at all; the leak-check gate enforces
///    that — but defense in depth: if one ever sneaks in, strip it
///    before it leaves the process.
///
/// 2. **User-data** (from tracing-schema.md#otlp-export-field-selection):
///    `target`, `unit`, `argv`, `cwd`, `path`. These ARE legitimately
///    used by structured-log consumers (journalctl, vector pipelines)
///    but encode tenant identity and filesystem layout that don't
///    belong in a generic observability backend.
///
/// `argv_*` prefix matches all `argv_0`, `argv_1`, …, `argv_redacted`
/// follow-on fields. Same idea for `path_*` since some emitters use
/// `path_from`/`path_to` for renames.
pub fn is_pii_field(name: &str) -> bool {
    // Exact matches — small enough that a linear scan beats a HashSet
    // and avoids a const-init dependency.
    const EXACT: &[&str] = &[
        // Forbidden — must never appear, but strip if it does.
        "value",
        "body",
        "sql",
        "content",
        "env_value",
        "statement_text",
        "raw_block",
        "password",
        "secret",
        // User-data attributes excluded from OTLP per S21.6 contract.
        "target", // db name / service target, not the tracing `target` macro field
        "unit",   // service unit name
        "argv",
        "cwd",
        "path",
    ];
    if EXACT.contains(&name) {
        return true;
    }
    // Prefix matches for fields that fan out into argv_0..N etc.
    const PREFIXES: &[&str] = &["argv_", "path_", "env_value_"];
    if PREFIXES.iter().any(|p| name.starts_with(p)) {
        return true;
    }
    // `token` as a *field name* is forbidden, but tokens may appear as
    // *values* of a `key_name` field (already redacted upstream). So
    // only the exact field name matches here.
    if name == "token" {
        return true;
    }
    false
}

/// The set of fields the schema requires every event to carry. Kept
/// here next to `is_pii_field` so future schema changes touch one
/// file. Used by the runtime wiring (DR-67) to assert presence on
/// exported spans — a missing required field is a schema bug, not a
/// PII leak, but the OTLP layer is a natural choke point to surface
/// it.
pub fn is_required_base_field(name: &str) -> bool {
    matches!(
        name,
        "component" | "subsystem" | "session_id" | "command_seq" | "pid"
    )
}

/// Classification of a span attribute for the OTLP path. The runtime
/// layer collapses this into a keep/strip decision; tests use the
/// finer-grained enum to spot misclassifications.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AttrDisposition {
    /// Carry through to the collector unchanged.
    Keep,
    /// Strip from the exported span. The structured-log stream still
    /// has it; only OTLP loses it.
    Strip,
}

pub fn classify(name: &str) -> AttrDisposition {
    if is_pii_field(name) {
        AttrDisposition::Strip
    } else {
        AttrDisposition::Keep
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_field_names_are_stripped() {
        for f in [
            "value",
            "body",
            "sql",
            "content",
            "env_value",
            "statement_text",
            "raw_block",
            "password",
            "secret",
            "token",
        ] {
            assert!(is_pii_field(f), "{f} must be classified as PII");
            assert_eq!(classify(f), AttrDisposition::Strip, "{f} must strip");
        }
    }

    #[test]
    fn user_data_attributes_are_stripped() {
        for f in ["target", "unit", "argv", "cwd", "path"] {
            assert!(is_pii_field(f), "{f} must be classified as PII");
        }
    }

    #[test]
    fn argv_prefixed_fields_are_stripped() {
        for f in ["argv_0", "argv_1", "argv_99", "argv_redacted"] {
            assert!(is_pii_field(f), "{f} must be stripped");
        }
    }

    #[test]
    fn path_prefixed_fields_are_stripped() {
        for f in ["path_from", "path_to", "path_orig"] {
            assert!(is_pii_field(f), "{f} must be stripped");
        }
    }

    #[test]
    fn env_value_prefixed_fields_are_stripped() {
        for f in ["env_value_decoded", "env_value_hash"] {
            assert!(is_pii_field(f), "{f} must be stripped");
        }
    }

    #[test]
    fn schema_required_base_fields_are_kept() {
        for f in ["component", "subsystem", "session_id", "command_seq", "pid"] {
            assert!(!is_pii_field(f), "{f} is required, must NOT strip");
            assert_eq!(classify(f), AttrDisposition::Keep);
            assert!(is_required_base_field(f));
        }
    }

    #[test]
    fn schema_hot_path_fields_are_kept() {
        for f in ["tier", "phase", "latency_us"] {
            assert!(!is_pii_field(f), "{f} is a hot-path field, must NOT strip");
            assert_eq!(classify(f), AttrDisposition::Keep);
        }
    }

    #[test]
    fn safe_metadata_fields_are_kept() {
        // Fields that look adjacent to user data but encode no
        // tenant identity — bucket counts, hashes, enum tags, etc.
        for f in [
            "engine",
            "stmts",
            "state",
            "op_kind",
            "version",
            "commit",
            "expected",
            "actual",
            "kernel_tier",
            "message",
        ] {
            assert!(!is_pii_field(f), "{f} should be kept");
        }
    }

    #[test]
    fn case_sensitivity_field_name_match_is_exact() {
        // The tracing convention is snake_case. We don't normalize
        // case — `Target` (capital T) is not a workspace-emitted
        // field name and we'd rather a typo show up than silently
        // strip.
        assert!(!is_pii_field("Target"));
        assert!(!is_pii_field("CWD"));
    }

    #[test]
    fn pii_match_does_not_overreach_on_substrings() {
        // Prefix list requires a trailing underscore — `pathway` does
        // not start with `path_`, so it stays.
        assert!(!is_pii_field("pathway"));
        // Exact-match fields don't extend; `targetable` is fine.
        assert!(!is_pii_field("targetable"));
        // Other near-misses we explicitly want to keep:
        assert!(!is_pii_field("argvictim"));
        assert!(!is_pii_field("cwdrive"));
    }

    #[test]
    fn argv_count_is_stripped_documented_tradeoff() {
        // Documented above: prefix match is broad on purpose to avoid
        // letting a future leak slip through. If we ever need a
        // count-like field, name it `arg_count` (no `argv` prefix).
        assert!(is_pii_field("argv_count"));
    }

    #[test]
    fn empty_field_name_is_not_pii() {
        // Defensive: an empty key would be a malformed event. Don't
        // strip it — let it surface as the schema violation it is.
        assert!(!is_pii_field(""));
    }

    #[test]
    fn pii_predicate_is_deterministic() {
        // Sanity: same input, same answer, every call. (Guards against
        // a future maintainer turning EXACT into a once_cell that
        // grows across calls or something equally cursed.)
        for _ in 0..16 {
            assert!(is_pii_field("argv"));
            assert!(!is_pii_field("session_id"));
        }
    }
}
