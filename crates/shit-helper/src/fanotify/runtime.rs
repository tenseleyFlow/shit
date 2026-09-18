// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime glue between the fanotify kernel-tier modules.
//!
//! S08 contract: the reader thread owns the read+write loop on the
//! fanotify fd. For every permission event it obtains the capture runtime's
//! fail-closed verdict, writes that response, and closes the kernel-provided
//! event descriptor.
//!
//! Architecture:
//!
//! ```text
//!   ┌─────────────────────────────┐
//!   │ reader_thread (blocking)    │
//!   │   poll → read → process →   │
//!   │     verdict → writev        │
//!   └─────────────────────────────┘
//!         shares Arc<FanotifyState>
//!   ┌─────────────────────────────┐
//!   │ async loop (S08.14)         │
//!   │   handle WatchTree /        │
//!   │     UnwatchTree → mark fd   │
//!   └─────────────────────────────┘
//! ```

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::event_loop::{
    Decision, LoopError, READ_BUF_BYTES, process_batch, read_step, wait_readable, write_responses,
};
use super::init::FanotifyFd;
use super::tree::TreeMap;
use crate::capture::linux::{FanotifyCaptureKind, FanotifyEventView, LinuxCaptureRuntime};
use shit_planner::events::CommandId;

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
    /// True while the reader thread is expected to be servicing the
    /// fanotify fd. Cleared on every normal/error exit so WatchTree cannot
    /// claim readiness after the capture loop has died.
    pub reader_alive: Arc<AtomicBool>,
    /// Telemetry counter. Bumped once per parsed event regardless of
    /// decision. Surfaced via `shit doctor` and the daemon stats path.
    pub events_seen: Arc<AtomicU64>,
    /// Bumped when `process_batch` reports a kernel queue overflow.
    /// Once non-zero the session is degraded; daemon should hard-fail
    /// subsequent preexecs.
    pub overflows: Arc<AtomicU64>,
    /// L01 — the capture runtime the reader thread feeds. `None` when
    /// the helper started without an IPC conn to the daemon (test /
    /// degraded paths), in which case the reader still ALLOWs every
    /// perm event but doesn't capture.
    pub capture_runtime: Option<Arc<Mutex<LinuxCaptureRuntime>>>,
    /// L01 — per-CommandId path that was marked at WatchTree time.
    /// Looked up at UnwatchTree to know which path to unmark.
    /// Without this map the helper would leak marks across commands
    /// (slowly accumulating fanotify watches over time).
    pub marked_paths: Arc<Mutex<HashMap<CommandId, PathBuf>>>,
    barrier_tx: mpsc::Sender<FanotifyBarrierRequest>,
    barrier_rx: Arc<Mutex<Option<mpsc::Receiver<FanotifyBarrierRequest>>>>,
}

struct FanotifyBarrierRequest {
    deadline: Instant,
    reply: mpsc::SyncSender<Result<(), String>>,
}

impl FanotifyState {
    pub fn new(fd: FanotifyFd) -> Self {
        let (barrier_tx, barrier_rx) = mpsc::channel();
        Self {
            fd: Arc::new(fd),
            tree: Arc::new(Mutex::new(TreeMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            // The reader flips this only after its thread actually starts.
            // An optimistic initial `true` could let WatchTree advertise
            // readiness in the spawn/scheduling window (or after spawn
            // failure) even though nobody is servicing the fanotify fd.
            reader_alive: Arc::new(AtomicBool::new(false)),
            events_seen: Arc::new(AtomicU64::new(0)),
            overflows: Arc::new(AtomicU64::new(0)),
            capture_runtime: None,
            marked_paths: Arc::new(Mutex::new(HashMap::new())),
            barrier_tx,
            barrier_rx: Arc::new(Mutex::new(Some(barrier_rx))),
        }
    }

    /// Attach a capture runtime so the reader's perm-event handler
    /// emits `CapturedPreImage` upstream. Called once at helper boot
    /// after the conn handshake completes.
    pub fn with_capture_runtime(mut self, rt: Arc<Mutex<LinuxCaptureRuntime>>) -> Self {
        self.capture_runtime = Some(rt);
        self
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    /// Wait until the sole reader has processed everything preceding this
    /// request and drained the fanotify fd to an observed-empty state.
    pub fn flush_until(&self, deadline: Instant) -> Result<(), String> {
        if !self.reader_alive.load(Ordering::Acquire) {
            return Err("fanotify reader is not running".to_string());
        }
        if Instant::now() >= deadline {
            return Err("fanotify reader flush timed out".to_string());
        }
        let (reply, receive) = mpsc::sync_channel(1);
        self.barrier_tx
            .send(FanotifyBarrierRequest { deadline, reply })
            .map_err(|_| "fanotify reader control disconnected".to_string())?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("fanotify reader flush timed out".to_string());
        }
        receive
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => "fanotify reader flush timed out".to_string(),
                mpsc::RecvTimeoutError::Disconnected => {
                    "fanotify reader exited during flush".to_string()
                }
            })?
    }
}

impl Clone for FanotifyState {
    fn clone(&self) -> Self {
        Self {
            fd: Arc::clone(&self.fd),
            tree: Arc::clone(&self.tree),
            shutdown: Arc::clone(&self.shutdown),
            reader_alive: Arc::clone(&self.reader_alive),
            events_seen: Arc::clone(&self.events_seen),
            overflows: Arc::clone(&self.overflows),
            capture_runtime: self.capture_runtime.as_ref().map(Arc::clone),
            marked_paths: Arc::clone(&self.marked_paths),
            barrier_tx: self.barrier_tx.clone(),
            barrier_rx: Arc::clone(&self.barrier_rx),
        }
    }
}

/// Owns the per-event descriptors installed by a fanotify read. They must stay
/// open through capture and the permission response, then be closed exactly
/// once regardless of a later parse/write failure.
#[derive(Default)]
struct EventFdBatch {
    fds: Vec<RawFd>,
}

impl EventFdBatch {
    fn record(&mut self, fd: RawFd) {
        if fd >= 0 {
            self.fds.push(fd);
        }
    }
}

impl Drop for EventFdBatch {
    fn drop(&mut self) {
        for fd in self.fds.drain(..) {
            // SAFETY: every nonnegative descriptor came from exactly one
            // kernel fanotify event and ownership transfers to userspace when
            // that event is read. close(2) errors need no retry: after EINTR,
            // the descriptor's state is unspecified on Linux.
            unsafe { libc::close(fd) };
        }
    }
}

fn process_readable_batch(state: &FanotifyState, buf: &mut [u8]) -> Result<(), LoopError> {
    let bytes = read_step(&state.fd, buf)?;
    if bytes.is_empty() {
        return Ok(());
    }

    let events_seen = Arc::clone(&state.events_seen);
    let tree = Arc::clone(&state.tree);
    let runtime = state.capture_runtime.as_ref().map(Arc::clone);
    let mut event_fds = EventFdBatch::default();
    let outcome = process_batch(
        bytes,
        |ev| {
            // Keep the tree guard until the runtime callback completes. The
            // detach path takes the same tree->runtime order, preventing a
            // resolved event from crossing command-state teardown.
            let mut tg = match tree.lock() {
                Ok(tree) => tree,
                Err(_) => {
                    tracing::error!(
                        pid = ev.pid,
                        "fanotify process-tree lock poisoned; denying permission event"
                    );
                    return Some(Decision::Deny);
                }
            };
            let Some((session, command_seq)) = tg.is_tracked(ev.pid) else {
                return Some(Decision::Allow);
            };
            let decision = if let Some(rt) = runtime.as_ref() {
                let kind = if (ev.mask & libc::FAN_OPEN_EXEC_PERM) != 0 {
                    FanotifyCaptureKind::OpenExec
                } else {
                    FanotifyCaptureKind::OpenWrite
                };
                let view = FanotifyEventView {
                    command: CommandId {
                        session,
                        seq: command_seq,
                    },
                    fd: ev.fd,
                    pid: ev.pid,
                    kind,
                    _life: std::marker::PhantomData,
                };
                match rt.lock() {
                    Ok(mut capture) => capture.handle_event(&view),
                    Err(_) => {
                        tracing::error!(
                            pid = ev.pid,
                            "fanotify capture runtime lock poisoned; denying tracked mutation"
                        );
                        Decision::Deny
                    }
                }
            } else {
                tracing::error!(
                    pid = ev.pid,
                    "fanotify capture runtime unavailable; denying tracked mutation"
                );
                Decision::Deny
            };
            drop(tg);
            Some(decision)
        },
        |ev| {
            events_seen.fetch_add(1, Ordering::Relaxed);
            event_fds.record(ev.fd);
        },
    )?;
    write_responses(&state.fd, &outcome.responses)?;
    if outcome.overflowed {
        return Err(LoopError::QueueOverflow);
    }
    Ok(())
}

fn flush_fanotify_reader(
    state: &FanotifyState,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), String> {
    loop {
        if Instant::now() >= deadline {
            return Err("fanotify reader flush timed out while draining".to_string());
        }
        match wait_readable(&state.fd, Duration::ZERO) {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(error) => return Err(format!("fanotify flush poll failed: {error}")),
        }
        if let Err(error) = process_readable_batch(state, buf) {
            if matches!(error, LoopError::QueueOverflow) {
                state.overflows.fetch_add(1, Ordering::Release);
            }
            return Err(format!("fanotify flush drain failed: {error}"));
        }
    }
}

/// Reader thread entry point. Blocks on the fanotify fd via `poll(2)`,
/// reads up to 64 KiB of events at a time, obtains a verdict for each,
/// and writes every response back before closing the event descriptors.
///
/// Exits when `state.shutdown` is set, when a kernel queue overflow
/// fires (session is degraded — daemon should re-init), or when a
/// non-recoverable read/write error surfaces.
pub fn reader_thread(state: FanotifyState) {
    struct ReaderAliveGuard(Arc<AtomicBool>);
    impl Drop for ReaderAliveGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    state.reader_alive.store(true, Ordering::Release);
    let _alive_guard = ReaderAliveGuard(Arc::clone(&state.reader_alive));
    let barrier_rx = match state.barrier_rx.lock() {
        Ok(mut slot) => match slot.take() {
            Some(receiver) => receiver,
            None => {
                tracing::error!("fanotify barrier receiver already owned; exiting reader");
                return;
            }
        },
        Err(_) => {
            tracing::error!("fanotify barrier receiver lock poisoned; exiting reader");
            return;
        }
    };
    tracing::info!("fanotify reader thread started");
    let mut buf = vec![0u8; READ_BUF_BYTES];

    loop {
        if state.shutdown.load(Ordering::Acquire) {
            tracing::info!("fanotify reader: shutdown requested");
            break;
        }

        while let Ok(request) = barrier_rx.try_recv() {
            let result = flush_fanotify_reader(&state, &mut buf, request.deadline);
            let _ = request.reply.send(result);
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

        match process_readable_batch(&state, &mut buf) {
            Ok(()) => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_fd_batch_closes_every_recorded_descriptor() {
        let mut pipe_fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        {
            let mut batch = EventFdBatch::default();
            batch.record(pipe_fds[0]);
            batch.record(-1);
        }
        assert_eq!(unsafe { libc::fcntl(pipe_fds[0], libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        unsafe { libc::close(pipe_fds[1]) };
    }

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
        s.reader_alive.store(false, Ordering::Release);
        assert!(!s2.reader_alive.load(Ordering::Acquire));
        s.shutdown();
        assert!(s2.shutdown.load(Ordering::Acquire));
    }
}
