// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL-statement classifier (S19.3 — stub).
//!
//! The real classifier lands in S19.3. This stub exists so the
//! [`crate::db`] module compiles after S19.2.

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    ReadOnly,
    Mutating,
    Unknown,
}

/// Stub — will return the real classification in S19.3.
pub fn classify_statement(_sql: &str) -> StatementKind {
    StatementKind::Unknown
}

/// Stub — will split a multi-statement script in S19.3.
pub fn split_statements(_script: &str) -> Vec<String> {
    Vec::new()
}
