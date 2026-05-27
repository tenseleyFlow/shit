// SPDX-License-Identifier: AGPL-3.0-or-later

//! EndpointSecurity client surface (M03).
//!
//! Apple's `EndpointSecurity` framework lets a properly-entitled
//! userspace process subscribe to kernel-level `ES_EVENT_TYPE_AUTH_*`
//! events and respond ALLOW/DENY before the syscall completes. This
//! is the only macOS path that gives us *pre-mutation* visibility
//! for file content — `rm` / `mv` / `truncate` / `open(O_WRONLY)`
//! all become observable with the original on-disk bytes still
//! recoverable.
//!
//! ## Sprint structure (M03)
//!
//! - `probe.rs` (this PR) — minimal ES client creation probe. Says
//!   "can this binary subscribe?" and returns the kernel's error
//!   code. Used by M02's doctor surface to flip the
//!   `entitlement_present` bool truthful.
//! - `client.rs` (next) — long-lived `EsClient` wrapping the safe
//!   crate's `Client` with our subscription set, ring buffer, and
//!   respond-watchdog.
//! - `subscribe.rs` (next) — the AUTH event-type list from S07/M03
//!   spec (AUTH_OPEN/CREATE/RENAME/UNLINK/TRUNCATE/etc).
//! - `tree.rs` (next) — `HashMap<AuditToken, TreeId>` tracked via
//!   NOTIFY_EXEC/FORK/EXIT.
//! - `respond.rs` (next) — ALLOW/DENY paths + 5-s timeout watchdog.
//! - `ring.rs` (next) — single-producer/single-consumer ring buffer
//!   that decouples the ES callback from the blob-capture worker
//!   so kernel auth deadlines never depend on disk I/O.
//! - `mute_list.rs` (next) — `es_mute_path` calls at startup for
//!   the always-noisy paths (`/dev/null`, our state dir, etc.).
//!
//! ## Dev environment
//!
//! ES requires either:
//! - `com.apple.developer.endpoint-security.client` entitlement on
//!   a signed + notarized binary (production; gated on Apple's
//!   approval — see `.docs/audits/apple-entitlement.md`), OR
//! - A SIP-disabled host (dev). The Tart VM target
//!   (`tools/macos-tart-vm/`, `.docs/audits/macos-tart-vm-setup.md`)
//!   provides this with no Apple paperwork.
//!
//! `probe.rs` reports both states truthfully — `NotEntitled` on
//! stock macOS without the entitlement; `Success` on SIP-disabled
//! VM or on a properly-entitled stock Mac.

pub mod client;
pub mod probe;
pub mod sys;

pub use client::EsClient;
pub use probe::{ProbeResult, probe_client_creation};
