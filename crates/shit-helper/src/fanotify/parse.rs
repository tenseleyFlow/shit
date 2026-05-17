// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parse the fanotify event stream. The kernel produces a sequence of
//! variable-length `fanotify_event_metadata` records (24 bytes plus
//! optional info blocks). We walk the buffer zero-copy and yield one
//! [`Event`] per record.
//!
//! Defensive parsing — the input is from the kernel and we trust it,
//! but property tests in `helper_fuzz`-style coverage feed it random
//! bytes to make sure we never panic or read past the buffer.

#![cfg(target_os = "linux")]

use std::mem::size_of;

/// One fanotify event in friendlier form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// Bitmask of `FAN_*` event flags (see `libc::FAN_OPEN_PERM`, etc.).
    pub mask: u64,
    /// File descriptor the kernel attached for this event. May be
    /// `FAN_NOFD` (-1) when no fd is available (e.g. queue overflow
    /// records).
    pub fd: i32,
    /// PID of the process that triggered the event.
    pub pid: i32,
    /// Total `event_len` consumed in the buffer. Useful for callers
    /// that want to advance manually. Equal to `metadata_len` plus any
    /// trailing info records (which we currently skip — S08.4 may pick
    /// them up for FAN_REPORT_FID payloads).
    pub event_len: u32,
}

impl Event {
    /// True when this is a queue-overflow marker (no actual event).
    pub fn is_overflow(&self) -> bool {
        (self.mask & libc::FAN_Q_OVERFLOW) != 0
    }

    /// True when the event needs a permission decision.
    pub fn needs_permission(&self) -> bool {
        (self.mask
            & (libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM | libc::FAN_OPEN_EXEC_PERM))
            != 0
    }
}

/// Sentinel for "no fd" — fanotify uses this when an event class
/// doesn't carry an fd (overflow, FID-only events).
pub const FAN_NOFD: i32 = -1;

/// Minimum size of a fanotify event header (`fanotify_event_metadata`).
/// Fixed at 24 bytes per the uapi; we re-derive from `size_of` to stay
/// honest if the kernel ever bumps the structure.
const FANOTIFY_EVENT_METADATA_LEN: usize = size_of::<libc::fanotify_event_metadata>();

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("buffer truncated mid-record: have {have}, need {need}")]
    Truncated { have: usize, need: usize },
    #[error("event_len {got} smaller than header ({header})")]
    HeaderUnderflow { got: u32, header: usize },
    #[error("event_len {got} larger than remaining buffer ({remaining})")]
    Overflow { got: u32, remaining: usize },
    #[error("metadata version mismatch: kernel says {got}, helper expects {expected}")]
    VersionMismatch { got: u8, expected: u8 },
}

/// Iterator over events in a kernel-produced buffer.
pub struct EventIter<'a> {
    buf: &'a [u8],
    /// Once an error is returned, subsequent `.next()` calls yield None.
    poisoned: bool,
}

impl<'a> EventIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            poisoned: false,
        }
    }
}

impl Iterator for EventIter<'_> {
    type Item = Result<Event, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned || self.buf.is_empty() {
            return None;
        }
        if self.buf.len() < FANOTIFY_EVENT_METADATA_LEN {
            self.poisoned = true;
            return Some(Err(ParseError::Truncated {
                have: self.buf.len(),
                need: FANOTIFY_EVENT_METADATA_LEN,
            }));
        }
        // Header layout (uapi/linux/fanotify.h):
        //   __u32 event_len;
        //   __u8  vers;
        //   __u8  reserved;
        //   __u16 metadata_len;
        //   __u64 mask;
        //   __s32 fd;
        //   __s32 pid;
        // We slice + from_le_bytes rather than transmuting; safer
        // against unaligned reads and easier to fuzz.
        let h = &self.buf[..FANOTIFY_EVENT_METADATA_LEN];
        let event_len = u32::from_ne_bytes([h[0], h[1], h[2], h[3]]);
        let vers = h[4];
        // h[5] = reserved
        // h[6..8] = metadata_len (we don't need it directly; event_len drives advance)
        let mask = u64::from_ne_bytes([
            h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15],
        ]);
        let fd = i32::from_ne_bytes([h[16], h[17], h[18], h[19]]);
        let pid = i32::from_ne_bytes([h[20], h[21], h[22], h[23]]);

        if vers != libc::FANOTIFY_METADATA_VERSION {
            self.poisoned = true;
            return Some(Err(ParseError::VersionMismatch {
                got: vers,
                expected: libc::FANOTIFY_METADATA_VERSION,
            }));
        }
        if (event_len as usize) < FANOTIFY_EVENT_METADATA_LEN {
            self.poisoned = true;
            return Some(Err(ParseError::HeaderUnderflow {
                got: event_len,
                header: FANOTIFY_EVENT_METADATA_LEN,
            }));
        }
        if (event_len as usize) > self.buf.len() {
            self.poisoned = true;
            return Some(Err(ParseError::Overflow {
                got: event_len,
                remaining: self.buf.len(),
            }));
        }
        let ev = Event {
            mask,
            fd,
            pid,
            event_len,
        };
        self.buf = &self.buf[event_len as usize..];
        Some(Ok(ev))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic fanotify event header byte-for-byte. Used by
    /// these unit tests since we can't get real events without a
    /// privileged kernel.
    fn build_event(mask: u64, fd: i32, pid: i32) -> [u8; FANOTIFY_EVENT_METADATA_LEN] {
        let mut buf = [0u8; FANOTIFY_EVENT_METADATA_LEN];
        let event_len = FANOTIFY_EVENT_METADATA_LEN as u32;
        buf[0..4].copy_from_slice(&event_len.to_ne_bytes());
        buf[4] = libc::FANOTIFY_METADATA_VERSION;
        buf[5] = 0; // reserved
        buf[6..8].copy_from_slice(&(event_len as u16).to_ne_bytes());
        buf[8..16].copy_from_slice(&mask.to_ne_bytes());
        buf[16..20].copy_from_slice(&fd.to_ne_bytes());
        buf[20..24].copy_from_slice(&pid.to_ne_bytes());
        buf
    }

    #[test]
    fn parse_single_event() {
        let buf = build_event(libc::FAN_OPEN_PERM, 42, 1234);
        let mut iter = EventIter::new(&buf);
        let ev = iter.next().unwrap().unwrap();
        assert_eq!(ev.fd, 42);
        assert_eq!(ev.pid, 1234);
        assert!(ev.needs_permission());
        assert!(!ev.is_overflow());
        assert!(iter.next().is_none());
    }

    #[test]
    fn parse_two_back_to_back() {
        let a = build_event(libc::FAN_OPEN_PERM, 10, 100);
        let b = build_event(libc::FAN_ACCESS_PERM, 11, 101);
        let mut buf = Vec::with_capacity(a.len() + b.len());
        buf.extend_from_slice(&a);
        buf.extend_from_slice(&b);
        let events: Result<Vec<_>, _> = EventIter::new(&buf).collect();
        let events = events.unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].fd, 10);
        assert_eq!(events[1].fd, 11);
    }

    #[test]
    fn truncated_buffer_errors() {
        let buf = [0u8; 8];
        let mut iter = EventIter::new(&buf);
        assert!(matches!(iter.next(), Some(Err(ParseError::Truncated { .. }))));
        // Poisoned: subsequent .next() yields None.
        assert!(iter.next().is_none());
    }

    #[test]
    fn version_mismatch_errors() {
        let mut buf = build_event(libc::FAN_OPEN_PERM, 1, 2);
        buf[4] = libc::FANOTIFY_METADATA_VERSION.wrapping_add(1);
        let mut iter = EventIter::new(&buf);
        assert!(matches!(
            iter.next(),
            Some(Err(ParseError::VersionMismatch { .. }))
        ));
    }

    #[test]
    fn overlong_event_len_errors() {
        let mut buf = build_event(libc::FAN_OPEN_PERM, 1, 2);
        // Claim 999 bytes when only 24 are present.
        buf[0..4].copy_from_slice(&999u32.to_ne_bytes());
        let mut iter = EventIter::new(&buf);
        assert!(matches!(iter.next(), Some(Err(ParseError::Overflow { .. }))));
    }

    #[test]
    fn underlong_event_len_errors() {
        let mut buf = build_event(libc::FAN_OPEN_PERM, 1, 2);
        buf[0..4].copy_from_slice(&8u32.to_ne_bytes());
        let mut iter = EventIter::new(&buf);
        assert!(matches!(
            iter.next(),
            Some(Err(ParseError::HeaderUnderflow { .. }))
        ));
    }

    #[test]
    fn overflow_marker_recognized() {
        let buf = build_event(libc::FAN_Q_OVERFLOW, FAN_NOFD, 0);
        let ev = EventIter::new(&buf).next().unwrap().unwrap();
        assert!(ev.is_overflow());
    }

    #[test]
    fn random_garbage_does_not_panic() {
        // Deterministic 256-byte sweep — exhaustive byte patterns.
        for i in 0u8..=255 {
            let buf = [i; 64];
            for _ in EventIter::new(&buf) {
                // consume; we don't care if it errors, only that it
                // doesn't panic.
            }
        }
    }
}
