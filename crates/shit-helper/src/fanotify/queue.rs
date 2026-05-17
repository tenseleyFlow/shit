// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded ring between the fanotify reader thread and the capture
//! worker. Backpressure policy when full: **hard-fail the session**
//! (deny subsequent perm events with FAN_DENY → kernel returns EACCES
//! to the user's syscall). This is the project-wide hard-fail default;
//! `--no-protect` is not honored at this layer (it's a per-command
//! escape evaluated earlier in the daemon).
//!
//! S05 design note: capture-failure policy is hard-fail by default.
//! This module implements that policy at the kernel-tier boundary.

#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender, TrySendError};
use uuid::Uuid;

use super::parse::Event;

/// Default bounded capacity. 4096 entries × 24 bytes each is ~96 KiB —
/// fits in L1/L2 cache, deep enough to absorb bursty syscall storms
/// without blocking, shallow enough that a stuck worker is detected
/// quickly.
pub const DEFAULT_CAPACITY: usize = 4096;

/// One queued item: the fanotify event plus the session that should
/// own the resulting capture. The fd in `event.fd` is owned by the
/// reader thread until consumed (or until we hard-fail and close it).
#[derive(Debug, Clone)]
pub struct QueuedEvent {
    pub event: Event,
    pub session: Uuid,
    pub command_seq: u64,
}

/// Producer half of the ring. Cloneable so the reader thread can hold
/// it across iterations.
#[derive(Clone)]
pub struct EventTx {
    inner: Sender<QueuedEvent>,
    /// Set once we've ever hit a full-queue overflow. Shared with the
    /// rest of the helper for `shit doctor` and the daemon's status
    /// surface.
    overflowed: Arc<AtomicBool>,
    /// Monotonic counter of dropped events. Useful for telemetry; the
    /// session is hard-failed on first overflow, but later overflows
    /// still increment so we can quantify the storm.
    dropped: Arc<AtomicU64>,
}

/// Consumer half of the ring.
pub struct EventRx {
    inner: Receiver<QueuedEvent>,
}

impl EventTx {
    /// Try to enqueue an event. Returns `Ok(())` on success,
    /// `Err(QueueFull)` when the ring is full and the session must
    /// hard-fail. The caller (the reader thread) must then deny the
    /// event back to the kernel and mark the session as overflowed.
    pub fn try_push(&self, q: QueuedEvent) -> Result<(), QueueError> {
        match self.inner.try_send(q) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.overflowed.store(true, Ordering::Release);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Err(QueueError::Full)
            }
            Err(TrySendError::Disconnected(_)) => Err(QueueError::WorkerGone),
        }
    }

    pub fn has_overflowed(&self) -> bool {
        self.overflowed.load(Ordering::Acquire)
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl EventRx {
    /// Blocking receive — the worker thread sits here waiting for
    /// events. Returns `None` when all `EventTx` clones have been
    /// dropped (helper shutdown).
    pub fn recv(&self) -> Option<QueuedEvent> {
        self.inner.recv().ok()
    }

    /// Non-blocking variant.
    pub fn try_recv(&self) -> Option<QueuedEvent> {
        self.inner.try_recv().ok()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue full — session must hard-fail")]
    Full,
    #[error("capture worker has exited")]
    WorkerGone,
}

/// Build a (tx, rx) pair with the given capacity. Convenience over
/// `crossbeam_channel::bounded` so callers don't have to import it.
pub fn bounded(capacity: usize) -> (EventTx, EventRx) {
    let (tx, rx) = crossbeam_channel::bounded(capacity);
    (
        EventTx {
            inner: tx,
            overflowed: Arc::new(AtomicBool::new(false)),
            dropped: Arc::new(AtomicU64::new(0)),
        },
        EventRx { inner: rx },
    )
}

/// Default-capacity convenience.
pub fn channel() -> (EventTx, EventRx) {
    bounded(DEFAULT_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(fd: i32) -> QueuedEvent {
        QueuedEvent {
            event: Event {
                mask: libc::FAN_OPEN_PERM,
                fd,
                pid: 100,
                event_len: 24,
            },
            session: Uuid::nil(),
            command_seq: 1,
        }
    }

    #[test]
    fn enqueue_dequeue_roundtrips() {
        let (tx, rx) = channel();
        tx.try_push(sample_event(7)).unwrap();
        let got = rx.recv().unwrap();
        assert_eq!(got.event.fd, 7);
    }

    #[test]
    fn full_queue_returns_error_and_marks_overflowed() {
        let (tx, _rx) = bounded(2);
        tx.try_push(sample_event(1)).unwrap();
        tx.try_push(sample_event(2)).unwrap();
        // Third push hits the cap.
        let err = tx.try_push(sample_event(3)).unwrap_err();
        assert!(matches!(err, QueueError::Full));
        assert!(tx.has_overflowed());
        assert_eq!(tx.dropped_count(), 1);
    }

    #[test]
    fn worker_gone_when_rx_dropped() {
        let (tx, rx) = bounded(2);
        drop(rx);
        let err = tx.try_push(sample_event(1)).unwrap_err();
        assert!(matches!(err, QueueError::WorkerGone));
    }

    #[test]
    fn try_recv_returns_none_when_empty() {
        let (_tx, rx) = channel();
        assert!(rx.try_recv().is_none());
    }
}
