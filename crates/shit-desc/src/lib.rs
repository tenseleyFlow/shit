// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reverse-API descriptor format (C02).
//!
//! Split out of `shit-helper` so both the helper (which loads packs +
//! drives capture) and the `shit` CLI (which validates + tests user-
//! authored packs offline) share the same parser + lint + matcher +
//! interpolation surface.
//!
//! Audit doc: `.docs/audits/descriptor-format.md`.
//! Sprint spec: `.docs/sprints/C02-descriptor-and-native-delegation.md`.

pub mod dispatch;
pub mod interpolate;
pub mod matcher;
pub mod parse;
pub mod schema;

pub use dispatch::{LoadError, LoadedDescriptor, Loader};
pub use interpolate::{InterpolateError, interpolate_argv, interpolate_token};
pub use matcher::{MatchOutcome, match_descriptor, match_pattern};
pub use parse::{ParseError, extract_all};
pub use schema::{
    Descriptor, DescriptorAuthority, DescriptorGuard, DescriptorHead, DescriptorMatch,
    DescriptorReverse, DescriptorSnapshot, DescriptorSnapshotPair, LintError,
    MAX_SUPPORTED_VERSION, ParseKind, SchemaError, interpolation_vars,
};
