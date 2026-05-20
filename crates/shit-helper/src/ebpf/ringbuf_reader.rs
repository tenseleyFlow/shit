// SPDX-License-Identifier: AGPL-3.0-or-later

//! L04 — Userspace consumer of the eBPF-LSM ringbufs.
//!
//! Pops records from `unlink_events` (and future `setattr_events`,
//! `mkdir_events`, `open_events`), decodes the C struct layout
//! defined in `bpf/src/common.h`, and dispatches into the helper's
//! capture runtime.
//!
//! **Status (L04 phase 2 chunk 2):** structure + decoder + stub
//! dispatcher that logs each event. The actual hook into
//! [`crate::capture::linux::LinuxCaptureRuntime::handle_event`]
//! (and the path-resolution + race-to-open work) lands in phase 2
//! chunk 3 via [`super::ringbuf_reader::LsmReader::dispatch_unlink`].
//!
//! Wire layout — must stay byte-identical with `bpf/src/common.h`:
//!
//! ```text
//! shit_event_hdr   (40 bytes)
//!   u8  kind            offset  0
//!   u8  _pad[3]         offset  1
//!   u32 pid             offset  4
//!   u32 tgid            offset  8
//!   u32 _pad2           offset 12
//!   u64 ts_ns           offset 16
//!   u8  comm[16]        offset 24
//! shit_unlink_event (56 bytes total)
//!   shit_event_hdr hdr  offset  0
//!   u64 dev             offset 40
//!   u64 inode           offset 48
//! ```
//!
//! Lifetime model: the reader owns a `RingBuf<MapData>` (taken from
//! the [`EbpfLoader`] via [`crate::ebpf::loader::EbpfLoader::take_unlink_ringbuf`])
//! and runs in its own OS thread. A `JoinHandle` is returned so the
//! helper's shutdown path can join it after closing the BPF Ebpf
//! instance (which closes the ringbuf fd, which makes `next()`
//! return None deterministically).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use aya::maps::{MapData, RingBuf};

/// Header common to every event, mirroring `struct shit_event_hdr`
/// in `bpf/src/common.h`. The `kind` byte indicates the tail layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EventHeader {
    pub kind: u8,
    pub _pad: [u8; 3],
    pub pid: u32,
    pub tgid: u32,
    pub _pad2: u32,
    pub ts_ns: u64,
    pub comm: [u8; 16],
}

const _: () = assert!(std::mem::size_of::<EventHeader>() == 40);

/// `kind` values, matching `enum shit_event_kind` in common.h.
pub mod kind {
    pub const UNLINK: u8 = 1;
    pub const SETATTR: u8 = 2;
    pub const MKDIR: u8 = 3;
    pub const OPEN: u8 = 4;
}

/// `lsm/inode_unlink` event — mirrors `struct shit_unlink_event`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UnlinkEvent {
    pub hdr: EventHeader,
    pub dev: u64,
    pub inode: u64,
}

const _: () = assert!(std::mem::size_of::<UnlinkEvent>() == 56);

/// Sink trait for decoded LSM events. The phase-2-chunk-2 stub
/// implementation just logs; phase-2-chunk-3 wires this into
/// [`crate::capture::linux::LinuxCaptureRuntime`].
///
/// `Send + Sync + 'static` because the reader thread owns its sink.
pub trait LsmEventSink: Send + Sync + 'static {
    fn on_unlink(&self, ev: &UnlinkEvent);
}

/// Stub sink — logs each event at info-level. Useful for the manual
/// smoke (step 4 of the sprint implementation order: "load the
/// program, `rm` a file, see the log line").
pub struct LoggingSink;

impl LsmEventSink for LoggingSink {
    fn on_unlink(&self, ev: &UnlinkEvent) {
        let comm = comm_to_string(&ev.hdr.comm);
        tracing::info!(
            kind = "unlink",
            pid = ev.hdr.pid,
            tgid = ev.hdr.tgid,
            ts_ns = ev.hdr.ts_ns,
            dev = ev.dev,
            inode = ev.inode,
            comm,
            "lsm event"
        );
    }
}

/// Convert a `[u8; 16]` `comm` array (NUL-terminated, like
/// `/proc/<pid>/comm`) into a Rust string. Stops at the first NUL.
fn comm_to_string(buf: &[u8; 16]) -> String {
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

/// Decode a raw ringbuf record as an [`UnlinkEvent`]. Returns `None`
/// when the record is too short (kernel truncation under pressure)
/// or when the `kind` byte mismatches.
///
/// Safety: the C side allocates with `bpf_ringbuf_reserve` which is
/// 8-byte aligned, but the userspace ringbuf surface hands us a
/// `&[u8]` of unspecified alignment. We copy through a `MaybeUninit`
/// rather than transmute to avoid any alignment hazard.
pub fn decode_unlink(bytes: &[u8]) -> Option<UnlinkEvent> {
    if bytes.len() < std::mem::size_of::<UnlinkEvent>() {
        return None;
    }
    if bytes[0] != kind::UNLINK {
        return None;
    }
    let mut out = std::mem::MaybeUninit::<UnlinkEvent>::uninit();
    // SAFETY: `out` is properly sized; we write exactly size_of::<UnlinkEvent>
    // bytes from a slice we've confirmed is at least that long.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            out.as_mut_ptr() as *mut u8,
            std::mem::size_of::<UnlinkEvent>(),
        );
        Some(out.assume_init())
    }
}

/// Userspace consumer of the L04 LSM ringbufs. Owns one OS thread
/// that loops on each ringbuf's `next()`. Dispatches via [`LsmEventSink`].
pub struct LsmReader {
    /// Toggled to false to ask the reader thread to exit. The reader
    /// also exits naturally when the ringbuf returns `None`
    /// forever (i.e. after the loader is dropped and the BPF program
    /// detached).
    alive: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl LsmReader {
    /// Spawn the reader thread. Polls the `unlink_events` ringbuf
    /// with a short sleep between drain passes — aya's blocking
    /// `RingBufItem` iterator requires the AsyncFd wrapper, which
    /// pulls tokio runtime context in. The helper's main loop is
    /// already on a runtime but the BPF detach path needs the reader
    /// to be runtime-agnostic for graceful shutdown.
    ///
    /// `idle_sleep` bounds the latency between an event landing in
    /// the ringbuf and the userspace race-to-open. Default 250 µs
    /// matches the "win the race before vfs_unlink completes
    /// d_drop" budget on idle workloads.
    pub fn spawn(
        unlink_rb: RingBuf<MapData>,
        sink: Arc<dyn LsmEventSink>,
        idle_sleep: Duration,
    ) -> Self {
        let alive = Arc::new(AtomicBool::new(true));
        let alive_t = Arc::clone(&alive);
        let handle = std::thread::Builder::new()
            .name("shit-lsm-rb".into())
            .spawn(move || {
                reader_thread(unlink_rb, sink, alive_t, idle_sleep);
            })
            .expect("spawn shit-lsm-rb");
        LsmReader {
            alive,
            handle: Some(handle),
        }
    }

    /// Ask the reader to exit. Idempotent. The thread sees the flag
    /// flip on its next sleep-tick (≤ `idle_sleep`).
    pub fn stop(&mut self) {
        self.alive.store(false, Ordering::Release);
    }

    /// Block until the reader thread has exited. Calls `stop()`
    /// internally first.
    pub fn join(mut self) {
        self.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for LsmReader {
    fn drop(&mut self) {
        self.stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn reader_thread(
    mut unlink_rb: RingBuf<MapData>,
    sink: Arc<dyn LsmEventSink>,
    alive: Arc<AtomicBool>,
    idle_sleep: Duration,
) {
    while alive.load(Ordering::Acquire) {
        let mut drained_this_pass = 0u32;
        while let Some(rec) = unlink_rb.next() {
            // RingBufItem derefs to &[u8]; explicit slice to dodge
            // inference ambiguity between Deref and AsRef impls.
            let slice: &[u8] = &rec[..];
            if let Some(ev) = decode_unlink(slice) {
                sink.on_unlink(&ev);
                drained_this_pass += 1;
            } else {
                tracing::warn!(
                    bytes = slice.len(),
                    first_byte = slice.first().copied().unwrap_or(0),
                    "ringbuf record could not be decoded as UnlinkEvent"
                );
            }
            if drained_this_pass >= 1024 {
                // Cap per-pass drain so the alive-flag check happens
                // even under pathological event rates.
                break;
            }
        }
        std::thread::sleep(idle_sleep);
    }
    tracing::info!("lsm-rb reader exiting");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn header_layout_is_40_bytes() {
        assert_eq!(std::mem::size_of::<EventHeader>(), 40);
        assert_eq!(std::mem::align_of::<EventHeader>(), 8);
    }

    #[test]
    fn unlink_event_layout_is_56_bytes() {
        assert_eq!(std::mem::size_of::<UnlinkEvent>(), 56);
        assert_eq!(std::mem::align_of::<UnlinkEvent>(), 8);
    }

    #[test]
    fn decode_unlink_round_trips() {
        let original = UnlinkEvent {
            hdr: EventHeader {
                kind: kind::UNLINK,
                _pad: [0; 3],
                pid: 12345,
                tgid: 12345,
                _pad2: 0,
                ts_ns: 0xdead_beef_cafe_babe,
                comm: *b"rm\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            },
            dev: 0x00000801,
            inode: 9_876_543,
        };
        let bytes: [u8; 56] = unsafe { std::mem::transmute(original) };
        let decoded = decode_unlink(&bytes).expect("decode");
        assert_eq!(decoded.hdr.kind, kind::UNLINK);
        assert_eq!(decoded.hdr.pid, 12345);
        assert_eq!(decoded.hdr.ts_ns, 0xdead_beef_cafe_babe);
        assert_eq!(decoded.dev, 0x00000801);
        assert_eq!(decoded.inode, 9_876_543);
        assert_eq!(comm_to_string(&decoded.hdr.comm), "rm");
    }

    #[test]
    fn decode_unlink_rejects_short_record() {
        let bytes = [0u8; 32]; // shorter than the 56-byte struct
        assert!(decode_unlink(&bytes).is_none());
    }

    #[test]
    fn decode_unlink_rejects_wrong_kind() {
        let mut bytes = [0u8; 56];
        bytes[0] = kind::OPEN; // not UNLINK
        assert!(decode_unlink(&bytes).is_none());
    }

    #[test]
    fn comm_to_string_stops_at_nul() {
        let mut buf = [0u8; 16];
        buf[..3].copy_from_slice(b"rm\0");
        // Trailing garbage past the NUL must not appear.
        buf[5] = b'X';
        assert_eq!(comm_to_string(&buf), "rm");
    }

    #[test]
    fn comm_to_string_handles_no_nul() {
        let buf = *b"verylongcommandnm"; // 17 chars compressed to 16
        let buf16: [u8; 16] = buf[..16].try_into().unwrap();
        assert_eq!(comm_to_string(&buf16), "verylongcommandn");
    }

    /// Test that the [`LoggingSink`] doesn't panic and is usable as
    /// `Arc<dyn LsmEventSink>`. The actual log assertion is left for
    /// the integration smoke.
    #[test]
    fn logging_sink_is_object_safe() {
        let sink: Arc<dyn LsmEventSink> = Arc::new(LoggingSink);
        let ev = UnlinkEvent::default();
        sink.on_unlink(&ev);
    }

    /// Capture-into-Vec sink used in tests of higher-layer code that
    /// drives the reader. Not exposed publicly.
    #[allow(dead_code)]
    struct CapturingSink {
        events: Mutex<Vec<UnlinkEvent>>,
    }

    impl LsmEventSink for CapturingSink {
        fn on_unlink(&self, ev: &UnlinkEvent) {
            self.events.lock().unwrap().push(*ev);
        }
    }
}
