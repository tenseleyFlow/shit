// SPDX-License-Identifier: AGPL-3.0-or-later

//! Content-addressed blob store and sqlite index for `shit`.
//!
//! Spec lives in `.docs/sprints/S04-blob-and-index-store.md`.

pub mod blob;
pub mod index;
pub mod schema;

pub use blob::{BlobError, BlobStat, BlobStore};
pub use index::{Index, IndexError};
pub use schema::SchemaError;
