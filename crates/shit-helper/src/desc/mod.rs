// SPDX-License-Identifier: AGPL-3.0-or-later

// Stage 1 of C02: schema parser + lint rules land first; later C02
// chunks (matcher, dispatch, snapshot, executor) wire the types into
// the helper's runtime. `dead_code` allowance mirrors the pattern from
// S00-vintage stub modules until the consumers land.
#![allow(dead_code)]

//! Reverse-API descriptor format (C02).
//!
//! A declarative, per-tool TOML file that says "for this argv pattern,
//! snapshot pre-state via this read command, store these fields, and on
//! undo, run this reverse command." It's the long-tail mechanism for
//! cloud / control-plane tools where the reversal is "call the inverse
//! API endpoint" and the only per-tool variation is the endpoint set.
//!
//! Spec: `.docs/audits/descriptor-format.md`.
//! Frozen schema version: `1`.

pub mod interpolate;
pub mod matcher;
pub mod parse;
pub mod schema;

// Re-exports are unused until later C02 chunks wire the loader and
// executor; `#[allow(unused_imports)]` mirrors the same posture as the
// crate-level `dead_code` allow on this module.
#[allow(unused_imports)]
pub use interpolate::{InterpolateError, interpolate_argv, interpolate_token};
#[allow(unused_imports)]
pub use matcher::{MatchOutcome, match_descriptor, match_pattern};
#[allow(unused_imports)]
pub use parse::{ParseError, extract_all};
#[allow(unused_imports)]
pub use schema::{
    Descriptor, DescriptorAuthority, DescriptorMatch, DescriptorReverse, DescriptorSnapshot,
    LintError, MAX_SUPPORTED_VERSION, ParseKind, SchemaError,
};
