// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code)]

//! Output formatting infrastructure (S12.2).
//!
//! Subcommands write their human-readable output through this module
//! so behavior is consistent: TTY detection, color resolution,
//! JSON-vs-text dispatch, optional paging.
//!
//! ## Why no top-level `--json` / `--color`
//!
//! The bare-`shit`-is-`shit undo` rule (see memory
//! `shit-cli-undo-default`) means the top-level `Cli` accepts no
//! flags. Each subcommand that needs formatting flags carries its
//! own `--json` / `--color` — same code path, just no risk of
//! `shit --json` parsing as a top-level arg that disturbs the
//! bare-`shit` semantics.

pub mod color;
pub mod env_diff;
pub mod git;
pub mod json;
pub mod pager;

#[allow(unused_imports)]
pub use color::{ColorPref, resolve_color};
#[allow(unused_imports)]
pub use env_diff::{RedactionDisplay, render as render_env_diff};
#[allow(unused_imports)]
pub use git::{GitRestoreGroup, detect_git_restores};
#[allow(unused_imports)]
pub use json::{JsonError, write_json};
#[allow(unused_imports)]
pub use pager::page_if_tty;
