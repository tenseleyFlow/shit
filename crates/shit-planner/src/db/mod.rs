// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database CLI shim pure helpers (S19.2 / S19.3).
//!
//! Pure planner-side logic shared by the helper (`shit-helper db-event`)
//! and the executor/render layers. Two halves:
//!
//! - [`conn`] — connection-string parsing for `psql` / `mysql` /
//!   `sqlite3` argv. Returns a [`ConnInfo`] with the password
//!   *already removed* — passwords never enter the journal.
//! - [`stmt`] — statement classifier. Drops read-only statements
//!   before they cross the wire so `SELECT *` doesn't fill the
//!   blob store.
//!
//! The `db-event` helper sits between `psql` and the daemon. It
//! calls into this module to produce the [`shit_proto::DbEventReq`]
//! payload — no string parsing lives in the helper itself.

pub mod conn;
pub mod stmt;

pub use conn::{ConnInfo, ConnParseError, parse_mysql_argv, parse_psql_argv, parse_sqlite3_argv};
pub use stmt::{StatementKind, classify_statement, split_statements};
