// SPDX-License-Identifier: AGPL-3.0-or-later

//! Concrete [`InverseOpExecutor`](crate::executor::InverseOpExecutor)
//! implementations, one per [`InverseTier`](crate::inverse::InverseTier).
//!
//! S11 ships the file-tier executor (S11.2–S11.5). Future sprints add:
//! - S14 — package-manager tier
//! - S15 — env tier
//! - S16 — systemd / launchd tier
//! - S17 — network/firewall tier
//! - S18 — process tier (note-only)

pub mod env;
pub mod file;
pub mod package;

pub use env::{EnvExecutor, SnippetSink, StringSnippetSink};
pub use file::FileExecutor;
pub use package::{PackageExecutor, PkgRunner, SystemPkgRunner};
