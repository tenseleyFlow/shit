// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime glue between the fanotify kernel-tier modules.
//!
//! S08 contract: the reader thread owns the read+write loop on the
//! fanotify fd. For every permission event it returns `ALLOW`
//! immediately — capture-vs-allow decisions land in S11 once the
//! undo executor and daemon-side AuthDecision logic exist.
//!
//! Architecture:
//!
//! ```text
//!   ┌─────────────────────────────┐
//!   │ reader_thread (blocking)    │
//!   │   poll → read → process →   │
//!   │     ALLOW → writev          │
//!   └─────────────────────────────┘
//!         shares Arc<FanotifyState>
//!   ┌─────────────────────────────┐
//!   │ async loop (S08.14)         │
//!   │   handle WatchTree /        │
//!   │     UnwatchTree → mark fd   │
//!   └─────────────────────────────┘
//! ```

#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::event_loop::{
    Decision, LoopError, RESPONSE_BATCH_MAX, READ_BUF_BYTES, process_batch, read_step,
    wait_readable, write_responses,
};
use super::init::FanotifyFd;
use super::tree::TreeMap;

/// Shared state between the reader thread and the async helper task.
///
/// The fanotify fd is `Arc<FanotifyFd>` so the async side can call
/// `fanotify_mark` (S08.14) concurrent with the reader's poll/read.
/// `mark` and `read` on the same fanotify fd are thread-safe at the
/// kernel level — fanotify's man page documents concurrent access.
pub struct FanotifyState {
    pub fd: Arc<FanotifyFd>,
    pub tree: Arc<Mutex<TreeMap>>,
    pub shutdown: Arc<AtomicBool>,
    /// Telemetry counter. Bumped once per parsed event regardless of
    /// decision. Surfaced via `shit doctor` and the daemon stats path.
    pub events_seen: Arc<AtomicU64>,
    /// Bumped when `process_batch` reports a kernel queue overflow.
    /// Once non-zero the session is degraded; daemon should hard-fail
    /// subsequent preexecs.
    pub overflows: Arc<AtomicU64>,
}

impl FanotifyState {
    pub fn new(fd: FanotifyFd) -> Self {
        Self {
            fd: Arc::new(fd),
            tree: Arc::new(Mutex::new(TreeMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            events_seen: Arc::new(AtomicU64::new(0)),
            overflows: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

impl Clone for FanotifyState {
    fn clone(&self) -> Self {
        Self {
            fd: Arc::clone(&self.fd),
            tree: Arc::clone(&self.tree),
            shutdown: Arc::clone(&self.shutdown),
            events_seen: Arc::clone(&self.events_seen),
            overflows: Arc::clone(&self.overflows),
        }
    }
}

/// Reader thread entry point. Blocks on the fanotify fd via `poll(2)`,
/// reads up to 64 KiB of events at a time, decides ALLOW for each,
/// writes the response batch back atomically.
///
/// Exits when `state.shutdown` is set, when a kernel queue overflow
/// fires (session is degraded — daemon should re-init), or when a
/// non-recoverable read/write error surfaces.
pub fn reader_thread(state: FanotifyState) {
    tracing::info!("fanotify reader thread started");
    let mut buf = vec![0u8; READ_BUF_BYTES];

    loop {
        if state.shutdown.load(Ordering::Acquire) {
            tracing::info!("fanotify reader: shutdown requested");
            break;
        }

        // 250ms poll timeout so we re-check the shutdown flag promptly.
        match wait_readable(&state.fd, Duration::from_millis(250)) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(e) => {
                tracing::error!(err = %e, "fanotify wait_readable failed; exiting reader");
                break;
            }
        }

        let bytes = match read_step(&state.fd, &mut buf) {
            Ok(b) if b.is_empty() => continue,
            Ok(b) => b,
            Err(e) => {
                tracing::error!(err = %e, "fanotify read failed; exiting reader");
                break;
            }
        };

        let events_seen = Arc::clone(&state.events_seen);
        let result = process_batch(
            bytes,
            |_ev| {
                // S08 default: ALLOW everything. S11 swaps this for
                // capture-and-ALLOW once daemon-side decision logic
                // lands. For now we only emit telemetry.
                Some(Decision::Allow)
            },
            |_ev| {
                events_seen.fetch_add(1, Ordering::Relaxed);
            },
        );

        match result {
            Ok(responses) => {
                if !responses.is_empty()
                    && let Err(e) = write_responses(&state.fd, &responses)
                {
                    tracing::error!(err = %e, "fanotify write_responses failed");
                    break;
                }
            }
            Err(LoopError::QueueOverflow) => {
                state.overflows.fetch_add(1, Ordering::Release);
                tracing::warn!(
                    "fanotify kernel queue overflow — session degraded; reader continues"
                );
                // Don't break; subsequent events are still readable.
                // The daemon decides whether to hard-fail subsequent
                // preexecs based on the overflow counter.
            }
            Err(e) => {
                tracing::error!(err = %e, "fanotify process_batch failed; exiting reader");
                break;
            }
        }
    }

    tracing::info!(
        events_seen = state.events_seen.load(Ordering::Relaxed),
        overflows = state.overflows.load(Ordering::Relaxed),
        "fanotify reader thread exiting"
    );
}

// Re-export so callers don't have to reach into event_loop::.
pub use super::event_loop::READ_BUF_BYTES as BUFFER_BYTES;
#[allow(dead_code)]
pub use super::event_loop::RESPONSE_BATCH_MAX as RESPONSE_BATCH;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanotify_state_clone_shares_inner_arcs() {
        // We need a fanotify fd to construct a real FanotifyState.
        // Skip if we can't init (no caps in the test runner).
        let fd = match super::super::init::init_pre_content() {
            Ok(fd) => fd,
            Err(_) => {
                eprintln!("skipping: cannot init fanotify in test env");
                return;
            }
        };
        let s = FanotifyState::new(fd);
        let s2 = s.clone();
        s.events_seen.fetch_add(7, Ordering::Relaxed);
        assert_eq!(s2.events_seen.load(Ordering::Relaxed), 7);
        s.shutdown();
        assert!(s2.shutdown.load(Ordering::Acquire));
    }
}
