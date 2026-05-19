// SPDX-License-Identifier: AGPL-3.0-or-later

//! Content-addressed blob store and sqlite index for `shit`.
//!
//! Spec lives in `.docs/sprints/S04-blob-and-index-store.md`.

pub mod blob;
pub mod bookmarks;
pub mod caibx;
pub mod container_stash;
pub mod gc;
pub mod holds;
pub mod importance;
pub mod index;
pub mod large_objects;
pub mod refcount;
pub mod schema;

pub use blob::{BlobError, BlobStat, BlobStore};
pub use bookmarks::Bookmark;
pub use caibx::{CaibxError, ChunkIndex, ChunkRef};
pub use container_stash::{
    CONTAINER_STASH_RETENTION_SECS, ContainerStash, RegisterRequest, StashKind,
};
pub use gc::{GcConfig, GcError, GcReport, SizeCapStatus, check_size_cap, run_pass};
pub use holds::Hold;
pub use importance::{ImportanceConfig, ScoreInputs, bump_for_undo, score_command, set_importance};
pub use index::{Index, IndexError};
pub use large_objects::{ChunkStat, LargeObjectError, LargeObjectStat};
pub use refcount::{ReapBatch, reap_commands};
pub use schema::SchemaError;
