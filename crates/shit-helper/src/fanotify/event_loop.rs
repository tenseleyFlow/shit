// SPDX-License-Identifier: AGPL-3.0-or-later

//! fanotify event loop. Single-threaded `epoll` on the fanotify fd:
//! read up to 64 KiB of events at a time, parse, dispatch each to the
//! handler closure, and write every resulting ALLOW/DENY response back
//! in bounded `writev` batches.
//!
//! Architecture choice: `epoll` not `io_uring`. fanotify perm mode
//! requires a synchronous read-write cycle; io_uring offers no benefit
//! and would expand the seccomp surface (see
//! `.docs/audits/seccomp-policy.md`).
//!
//! The loop's `step()` is split out so the main loop is testable in
//! isolation against a controlled buffer; only the syscall-bound parts
//! (`read`, `writev`, `epoll_wait`) need real fanotify to exercise.

#![cfg(target_os = "linux")]

use std::io::{self, IoSlice};
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::time::Duration;

use super::init::FanotifyFd;
use super::parse::{Event, EventIter, ParseError};

/// Read-buffer size. 64 KiB is large enough to hold a healthy batch of
/// 24-byte event records (≈2700 per read) without paying syscall tax
/// on every event.
pub const READ_BUF_BYTES: usize = 64 * 1024;

/// Max responses we batch into a single `writev`. Bounded to keep
/// memory usage flat under bursty workloads.
pub const RESPONSE_BATCH_MAX: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum LoopError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("parse: {0}")]
    Parse(#[from] ParseError),
    #[error("queue overflow — kernel dropped events; session must hard-fail")]
    QueueOverflow,
    #[error("epoll: {0}")]
    Epoll(io::Error),
}

/// Decision the handler returns for a permission event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// All permission responses parsed from one kernel read plus its loss signal.
/// Overflow is data, rather than an early error, so responses that preceded an
/// overflow marker are still returned to the kernel before the runtime marks
/// capture degraded.
#[derive(Debug)]
pub struct BatchOutcome {
    pub responses: Vec<libc::fanotify_response>,
    pub overflowed: bool,
}

impl Decision {
    fn as_kernel_response(self) -> u32 {
        match self {
            Decision::Allow => libc::FAN_ALLOW,
            Decision::Deny => libc::FAN_DENY,
        }
    }
}

/// Parse one full read into events; collect responses for any that
/// `decide` returns a verdict for. Returns the responses to write.
///
/// `decide` returns `None` for events that don't need a permission
/// reply (notification-class records, overflow markers); these events
/// are still surfaced via `observe` for telemetry but no response is
/// emitted.
pub fn process_batch<F, G>(
    buf: &[u8],
    mut decide: F,
    mut observe: G,
) -> Result<BatchOutcome, LoopError>
where
    F: FnMut(&Event) -> Option<Decision>,
    G: FnMut(&Event),
{
    let mut responses = Vec::with_capacity(RESPONSE_BATCH_MAX);
    let mut overflowed = false;
    for ev_res in EventIter::new(buf) {
        let ev = ev_res?;
        observe(&ev);
        if ev.is_overflow() {
            overflowed = true;
            continue;
        }
        if !ev.needs_permission() {
            continue;
        }
        let decision = decide(&ev).unwrap_or(Decision::Allow);
        responses.push(libc::fanotify_response {
            fd: ev.fd,
            response: decision.as_kernel_response(),
        });
    }
    Ok(BatchOutcome {
        responses,
        overflowed,
    })
}

/// Write every response back to the fanotify fd in bounded `writev(2)`
/// groups. Linux currently consumes one response per write syscall (bytes
/// after the first struct are response-info payload), so a successful
/// `writev` normally reports one complete struct even when more iovecs were
/// supplied. Keep retrying from the first unconsumed response so no
/// permission event is stranded.
pub fn write_responses(
    fd: &FanotifyFd,
    responses: &[libc::fanotify_response],
) -> Result<(), LoopError> {
    if responses.is_empty() {
        return Ok(());
    }
    for batch in responses.chunks(RESPONSE_BATCH_MAX) {
        write_response_batch_with(
            batch,
            |remaining| {
                // SAFETY: each `fanotify_response` is POD and every iovec
                // borrows one complete initialized response for the duration
                // of writev.
                let slices: Vec<IoSlice<'_>> = remaining
                    .iter()
                    .map(|response| {
                        let ptr = (response as *const libc::fanotify_response).cast::<u8>();
                        let bytes = unsafe {
                            std::slice::from_raw_parts(ptr, size_of::<libc::fanotify_response>())
                        };
                        IoSlice::new(bytes)
                    })
                    .collect();
                let rc = unsafe {
                    libc::writev(
                        fd.as_raw_fd(),
                        slices.as_ptr().cast::<libc::iovec>(),
                        slices.len() as libc::c_int,
                    )
                };
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(rc as usize)
                }
            },
            // fanotify's poll implementation advertises readable events only,
            // never POLLOUT. Waiting for writable after a hypothetical EAGAIN
            // would therefore deadlock; yield and retry the unchanged slice.
            std::thread::yield_now,
        )?;
    }
    Ok(())
}

fn write_response_batch_with<W, B>(
    batch: &[libc::fanotify_response],
    mut write_once: W,
    mut eagain_backoff: B,
) -> Result<(), LoopError>
where
    W: FnMut(&[libc::fanotify_response]) -> io::Result<usize>,
    B: FnMut(),
{
    let response_size = size_of::<libc::fanotify_response>();
    let mut consumed = 0usize;
    while consumed < batch.len() {
        match write_once(&batch[consumed..]) {
            Ok(0) => {
                return Err(LoopError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "fanotify response write returned zero",
                )));
            }
            Ok(written) => {
                let remaining_bytes = (batch.len() - consumed) * response_size;
                if written > remaining_bytes || written % response_size != 0 {
                    return Err(LoopError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "fanotify response write returned {written} bytes for {remaining_bytes} bytes of complete responses"
                        ),
                    )));
                }
                // Advance only by complete response objects. In particular,
                // never form a byte pointer into the middle of a struct after
                // a short write.
                consumed += written / response_size;
            }
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => {}
            Err(error)
                if error.raw_os_error() == Some(libc::EAGAIN)
                    || error.raw_os_error() == Some(libc::EWOULDBLOCK) =>
            {
                eagain_backoff();
            }
            Err(error) => return Err(LoopError::Io(error)),
        }
    }
    Ok(())
}

/// Block until the fanotify fd has events to read, or `timeout`
/// elapses. Returns `true` if events are ready, `false` on timeout.
pub fn wait_readable(fd: &FanotifyFd, timeout: Duration) -> Result<bool, LoopError> {
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    // poll, not epoll — for a single fd it's strictly simpler and
    // doesn't require an epoll fd we'd have to track separately.
    let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, timeout_ms) };
    if rc < 0 {
        return Err(LoopError::Io(io::Error::last_os_error()));
    }
    Ok(rc > 0 && (pfd.revents & libc::POLLIN) != 0)
}

/// One read step against the fanotify fd into the caller-provided
/// buffer. Returns the slice of `buf` that holds valid event bytes.
pub fn read_step<'a>(fd: &FanotifyFd, buf: &'a mut [u8]) -> Result<&'a [u8], LoopError> {
    let n = unsafe {
        libc::read(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            buf.len(),
        )
    };
    if n < 0 {
        let err = io::Error::last_os_error();
        // EAGAIN on a non-blocking fd means "no events right now" —
        // return empty slice. Other errors surface.
        if err.raw_os_error() == Some(libc::EAGAIN) || err.raw_os_error() == Some(libc::EWOULDBLOCK)
        {
            return Ok(&buf[..0]);
        }
        return Err(LoopError::Io(err));
    }
    Ok(&buf[..n as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_event(mask: u64, fd: i32, pid: i32) -> Vec<u8> {
        let len = size_of::<libc::fanotify_event_metadata>();
        let mut buf = vec![0u8; len];
        let event_len = len as u32;
        buf[0..4].copy_from_slice(&event_len.to_ne_bytes());
        buf[4] = libc::FANOTIFY_METADATA_VERSION;
        buf[6..8].copy_from_slice(&(event_len as u16).to_ne_bytes());
        buf[8..16].copy_from_slice(&mask.to_ne_bytes());
        buf[16..20].copy_from_slice(&fd.to_ne_bytes());
        buf[20..24].copy_from_slice(&pid.to_ne_bytes());
        buf
    }

    #[test]
    fn process_batch_yields_response_per_perm_event() {
        let mut buf = Vec::new();
        buf.extend(build_event(libc::FAN_OPEN_PERM, 7, 100));
        buf.extend(build_event(libc::FAN_ACCESS_PERM, 8, 101));
        let mut seen = 0;
        let outcome = process_batch(
            &buf,
            |_| Some(Decision::Allow),
            |_| {
                seen += 1;
            },
        )
        .unwrap();
        assert_eq!(outcome.responses.len(), 2);
        assert_eq!(seen, 2);
        for r in outcome.responses {
            assert_eq!(r.response, libc::FAN_ALLOW);
        }
    }

    #[test]
    fn process_batch_deny_path() {
        let buf = build_event(libc::FAN_OPEN_PERM, 9, 200);
        let outcome = process_batch(&buf, |_| Some(Decision::Deny), |_| {}).unwrap();
        assert_eq!(outcome.responses.len(), 1);
        assert_eq!(outcome.responses[0].response, libc::FAN_DENY);
        assert_eq!(outcome.responses[0].fd, 9);
    }

    #[test]
    fn process_batch_skips_non_perm_events() {
        // FAN_OPEN is a notification class, not perm.
        let buf = build_event(libc::FAN_OPEN, 9, 200);
        let mut observed = 0;
        let outcome = process_batch(
            &buf,
            |_| Some(Decision::Allow),
            |_| {
                observed += 1;
            },
        )
        .unwrap();
        assert!(outcome.responses.is_empty());
        assert_eq!(observed, 1);
    }

    #[test]
    fn process_batch_surfaces_overflow() {
        let buf = build_event(libc::FAN_Q_OVERFLOW, -1, 0);
        let outcome = process_batch(&buf, |_| Some(Decision::Allow), |_| {}).unwrap();
        assert!(outcome.overflowed);
        assert!(outcome.responses.is_empty());
    }

    #[test]
    fn process_batch_keeps_responses_on_queue_overflow() {
        let mut buf = Vec::new();
        buf.extend(build_event(libc::FAN_OPEN_PERM, 7, 100));
        buf.extend(build_event(libc::FAN_Q_OVERFLOW, -1, 0));
        buf.extend(build_event(libc::FAN_OPEN_PERM, 8, 101));
        let outcome = process_batch(&buf, |_| Some(Decision::Deny), |_| {}).unwrap();
        assert!(outcome.overflowed);
        assert_eq!(
            outcome
                .responses
                .iter()
                .map(|response| response.fd)
                .collect::<Vec<_>>(),
            vec![7, 8]
        );
    }

    #[test]
    fn process_batch_retains_every_permission_event_beyond_write_batch_size() {
        let mut buf = Vec::new();
        for i in 0..(RESPONSE_BATCH_MAX * 2) as i32 {
            buf.extend(build_event(libc::FAN_OPEN_PERM, i, 100 + i));
        }
        let outcome = process_batch(&buf, |_| Some(Decision::Allow), |_| {}).unwrap();
        assert_eq!(outcome.responses.len(), RESPONSE_BATCH_MAX * 2);
        assert_eq!(
            outcome.responses.last().unwrap().fd,
            (RESPONSE_BATCH_MAX * 2 - 1) as i32
        );
    }

    #[test]
    fn process_batch_handler_can_choose_implicit_allow() {
        // None from decide → defaults to Allow.
        let buf = build_event(libc::FAN_OPEN_PERM, 5, 555);
        let outcome = process_batch(&buf, |_| None, |_| {}).unwrap();
        assert_eq!(outcome.responses.len(), 1);
        assert_eq!(outcome.responses[0].response, libc::FAN_ALLOW);
    }

    #[test]
    fn response_writer_retries_interrupt_would_block_and_complete_prefixes() {
        let responses = [
            libc::fanotify_response {
                fd: 10,
                response: libc::FAN_ALLOW,
            },
            libc::fanotify_response {
                fd: 11,
                response: libc::FAN_DENY,
            },
            libc::fanotify_response {
                fd: 12,
                response: libc::FAN_ALLOW,
            },
        ];
        let mut attempts = Vec::new();
        let mut step = 0usize;
        let mut backoffs = 0usize;
        write_response_batch_with(
            &responses,
            |remaining| {
                attempts.push(
                    remaining
                        .iter()
                        .map(|response| response.fd)
                        .collect::<Vec<_>>(),
                );
                step += 1;
                match step {
                    1 => Err(io::Error::from_raw_os_error(libc::EINTR)),
                    2 => Err(io::Error::from_raw_os_error(libc::EAGAIN)),
                    3 => Ok(2 * size_of::<libc::fanotify_response>()),
                    4 => Ok(size_of::<libc::fanotify_response>()),
                    _ => panic!("unexpected write attempt"),
                }
            },
            || backoffs += 1,
        )
        .unwrap();

        assert_eq!(
            attempts,
            vec![
                vec![10, 11, 12],
                vec![10, 11, 12],
                vec![10, 11, 12],
                vec![12]
            ]
        );
        assert_eq!(backoffs, 1);
    }

    #[test]
    fn response_writer_rejects_partial_struct_without_advancing() {
        let responses = [libc::fanotify_response {
            fd: 10,
            response: libc::FAN_ALLOW,
        }];
        let error = write_response_batch_with(
            &responses,
            |_| Ok(size_of::<libc::fanotify_response>() - 1),
            || {},
        )
        .unwrap_err();
        assert!(
            matches!(error, LoopError::Io(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
    }
}
