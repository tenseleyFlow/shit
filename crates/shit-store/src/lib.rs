// SPDX-License-Identifier: AGPL-3.0-or-later

//! Content-addressed blob store and sqlite index for `shit`.
//!
//! Spec lives in `.docs/sprints/S04-blob-and-index-store.md`.

pub mod blob;

pub use blob::{BlobError, BlobStat, BlobStore};
