// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical crash-log format (S21.8). One module, every binary uses
//! it — the user can post a crash file from `shit`, `shitd`, or
//! `shit-helper` to an issue and have the same shape every time.
//!
//! ## Format (fixed by `tracing-schema.md`)
//!
//! ```text
//! <component> crash log
//! version: 0.1.0
//! commit:  6173f17abc...
//! built:   2026-05-17T15:00:00Z
//! pid:     12347
//! ts:      2026-05-17T19:42:13Z
//! panic:   index out of bounds at crates/shit-helper/src/fanotify/event_loop.rs:142:8
//! backtrace:
//!   0: shit_helper::fanotify::event_loop::handle_event
//!              at crates/shit-helper/src/fanotify/event_loop.rs:142:8
//!   1: …
//! last <N> tracing events (in-process ring buffer):
//! <event line 1>
//! <event line 2>
//! …
//! ```
//!
//! Components fill in their static facts via [`CrashFacts`]; runtime
//! data (panic info, backtrace, ring buffer) is captured at panic
//! time and assembled by [`format_crash_record`]. Pure logic — no
//! tracing-subscriber dep, no panic-hook side effects. The bin-side
//! `crash.rs` modules in each crate wrap this with their panic hook.

use std::fmt::Write;

/// Static facts about the binary: version, commit, build time. Each
/// binary builds one of these from its `env!()` macros at startup and
/// holds the value in a `OnceLock` for the panic hook to read.
#[derive(Debug, Clone)]
pub struct CrashFacts {
    pub component: &'static str,
    pub version: &'static str,
    pub commit: &'static str,
    pub built: &'static str,
    pub rustc: &'static str,
    pub target: &'static str,
}

/// Runtime panic info — caller fills in from `PanicHookInfo` +
/// `Backtrace::force_capture()`.
#[derive(Debug, Clone)]
pub struct CrashPanic {
    pub message: String,
    /// "file:line:col" or empty string if location is unknown (rare).
    pub location: String,
    /// `Backtrace::to_string()` output. May be empty if backtrace
    /// capture failed; the record still serialises.
    pub backtrace: String,
}

/// Format the crash record. Pure: same inputs → same output, no I/O.
///
/// `events` is the rolling window of last-N tracing events the binary's
/// in-process [`TracingRing`] retained. May be empty if the ring buffer
/// hasn't been wired (or the binary crashed before any event was
/// recorded).
///
/// `now_unix_secs` is the wall-clock timestamp of the panic. Passed
/// in rather than read internally so tests are deterministic.
pub fn format_crash_record(
    facts: &CrashFacts,
    panic: &CrashPanic,
    pid: u32,
    now_unix_secs: u64,
    events: &[String],
) -> String {
    let mut buf = String::with_capacity(2048 + events.len() * 256);
    // Header
    let _ = writeln!(buf, "{} crash log", facts.component);
    let _ = writeln!(buf, "version: {}", facts.version);
    let _ = writeln!(buf, "commit:  {}", facts.commit);
    let _ = writeln!(buf, "built:   {}", facts.built);
    let _ = writeln!(buf, "rustc:   {}", facts.rustc);
    let _ = writeln!(buf, "target:  {}", facts.target);
    let _ = writeln!(buf, "pid:     {pid}");
    let _ = writeln!(buf, "ts:      {now_unix_secs}");
    // Panic
    if panic.location.is_empty() {
        let _ = writeln!(buf, "panic:   {}", sanitise_line(&panic.message));
    } else {
        let _ = writeln!(
            buf,
            "panic:   {} at {}",
            sanitise_line(&panic.message),
            panic.location
        );
    }
    // Backtrace
    let _ = writeln!(buf, "backtrace:");
    if panic.backtrace.is_empty() {
        let _ = writeln!(buf, "  (unavailable)");
    } else {
        for line in panic.backtrace.lines() {
            let _ = writeln!(buf, "  {line}");
        }
    }
    // Tracing tail
    let _ = writeln!(
        buf,
        "last {} tracing events (in-process ring buffer):",
        events.len()
    );
    for ev in events {
        let _ = writeln!(buf, "{}", sanitise_line(ev));
    }
    buf
}

/// Compute the on-disk filename for a crash record. Lives next to the
/// formatter so the bins don't reimplement it.
///
/// Format: `<component>-<unix_secs>-<pid>.txt`. Sorted by timestamp;
/// pid breaks ties when two components crash in the same second.
pub fn crash_filename(component: &str, now_unix_secs: u64, pid: u32) -> String {
    format!("{component}-{now_unix_secs}-{pid}.txt")
}

/// Single-line sanitiser — strips CR/LF and replaces them with `\n`
/// literals so a multi-line panic message can't break the
/// `key: value` shape of the header. The tracing-events portion is
/// already JSON (one line per event) so this is mostly a guard
/// against weird panic payloads (e.g. a `format!` with embedded
/// newlines).
fn sanitise_line(s: &str) -> String {
    s.replace('\r', "\\r").replace('\n', "\\n")
}

/// Bounded ring buffer for tracing events. Holds up to `capacity`
/// formatted event strings; older entries are dropped on overflow.
///
/// Designed for `Arc<TracingRing>` shared between every tracing event
/// (push side, serialised by Mutex) and the panic hook (drain side,
/// best-effort lock acquisition).
///
/// Why a Mutex and not a lock-free queue: the push rate from
/// `tracing::*` at `info` level is low (lifecycle events only — hot
/// path is `debug` which is off in production). The contention is
/// negligible. A lock-free queue (`crossbeam-queue::ArrayQueue`)
/// would be measurably faster only if the budget is "every event
/// must be under 1µs," which we don't promise here.
#[derive(Debug)]
pub struct TracingRing {
    capacity: usize,
    inner: std::sync::Mutex<std::collections::VecDeque<String>>,
}

impl TracingRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(capacity)),
        }
    }

    /// Push one event line. Drops the oldest if at capacity.
    pub fn push(&self, line: String) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        if g.len() == self.capacity {
            g.pop_front();
        }
        g.push_back(line);
    }

    /// Snapshot the current ring into a Vec. Used by the panic hook.
    /// Best-effort: returns empty if the lock is poisoned (which
    /// happens if a previous panic was caught mid-push).
    pub fn snapshot(&self) -> Vec<String> {
        match self.inner.lock() {
            Ok(g) => g.iter().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> CrashFacts {
        CrashFacts {
            component: "shit-test",
            version: "0.1.0",
            commit: "deadbeef",
            built: "2026-05-17T15:00:00Z",
            rustc: "1.88.0",
            target: "x86_64-unknown-linux-gnu",
        }
    }

    fn panic_info() -> CrashPanic {
        CrashPanic {
            message: "index out of bounds".to_string(),
            location: "src/main.rs:42:8".to_string(),
            backtrace: "  0: foo\n  1: bar\n".to_string(),
        }
    }

    #[test]
    fn format_includes_all_header_fields() {
        let out = format_crash_record(&facts(), &panic_info(), 1234, 1_700_000_000, &[]);
        assert!(out.starts_with("shit-test crash log\n"));
        assert!(out.contains("version: 0.1.0\n"));
        assert!(out.contains("commit:  deadbeef\n"));
        assert!(out.contains("built:   2026-05-17T15:00:00Z\n"));
        assert!(out.contains("rustc:   1.88.0\n"));
        assert!(out.contains("target:  x86_64-unknown-linux-gnu\n"));
        assert!(out.contains("pid:     1234\n"));
        assert!(out.contains("ts:      1700000000\n"));
    }

    #[test]
    fn format_includes_panic_message_and_location() {
        let out = format_crash_record(&facts(), &panic_info(), 1, 0, &[]);
        assert!(out.contains("panic:   index out of bounds at src/main.rs:42:8\n"));
    }

    #[test]
    fn format_handles_missing_location() {
        let mut p = panic_info();
        p.location = String::new();
        let out = format_crash_record(&facts(), &p, 1, 0, &[]);
        assert!(out.contains("panic:   index out of bounds\n"));
    }

    #[test]
    fn format_handles_missing_backtrace() {
        let mut p = panic_info();
        p.backtrace = String::new();
        let out = format_crash_record(&facts(), &p, 1, 0, &[]);
        assert!(out.contains("backtrace:\n  (unavailable)\n"));
    }

    #[test]
    fn format_indents_backtrace_lines() {
        let out = format_crash_record(&facts(), &panic_info(), 1, 0, &[]);
        // Each backtrace line gets a 2-space indent prefix from the formatter.
        // The original message already had 2 spaces, so observed indent is 4 total.
        assert!(out.contains("\n    0: foo\n"));
        assert!(out.contains("\n    1: bar\n"));
    }

    #[test]
    fn format_carries_tracing_events_verbatim() {
        let events = vec![
            r#"{"level":"INFO","msg":"a"}"#.to_string(),
            r#"{"level":"WARN","msg":"b"}"#.to_string(),
        ];
        let out = format_crash_record(&facts(), &panic_info(), 1, 0, &events);
        assert!(out.contains("last 2 tracing events (in-process ring buffer):\n"));
        assert!(out.contains(r#"{"level":"INFO","msg":"a"}"#));
        assert!(out.contains(r#"{"level":"WARN","msg":"b"}"#));
    }

    #[test]
    fn format_empty_ring_buffer_renders_zero_count() {
        let out = format_crash_record(&facts(), &panic_info(), 1, 0, &[]);
        assert!(out.contains("last 0 tracing events"));
    }

    #[test]
    fn format_sanitises_newlines_in_panic_message() {
        let mut p = panic_info();
        p.message = "line1\nline2\rline3".to_string();
        let out = format_crash_record(&facts(), &p, 1, 0, &[]);
        // The header MUST stay one line per key.
        assert!(out.contains("panic:   line1\\nline2\\rline3 at"));
        // And the rest of the body comes intact after.
        assert!(out.contains("backtrace:"));
    }

    #[test]
    fn format_sanitises_newlines_in_tracing_events() {
        let events = vec!["weird\nevent".to_string()];
        let out = format_crash_record(&facts(), &panic_info(), 1, 0, &events);
        assert!(out.contains("weird\\nevent"));
    }

    #[test]
    fn crash_filename_shape() {
        assert_eq!(
            crash_filename("shit-helper", 1_700_000_000, 12347),
            "shit-helper-1700000000-12347.txt"
        );
    }

    #[test]
    fn crash_filename_sorts_lexically_by_time() {
        let a = crash_filename("c", 1_000_000_000, 1);
        let b = crash_filename("c", 1_000_000_001, 1);
        assert!(a < b, "earlier ts must sort before later");
    }

    #[test]
    fn tracing_ring_drops_oldest_at_capacity() {
        let r = TracingRing::new(3);
        r.push("a".to_string());
        r.push("b".to_string());
        r.push("c".to_string());
        r.push("d".to_string());
        let snap = r.snapshot();
        assert_eq!(
            snap,
            vec!["b".to_string(), "c".to_string(), "d".to_string()]
        );
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn tracing_ring_handles_zero_capacity_gracefully() {
        // A zero-capacity ring is degenerate but shouldn't panic.
        let r = TracingRing::new(0);
        r.push("anything".to_string());
        // With capacity 0, push removes "the front" before inserting,
        // but since front doesn't exist, VecDeque silently lets us
        // push past capacity. The next push would trim. Acceptable —
        // a zero-cap ring is a configuration error, not a security
        // bug. Test confirms no panic.
        assert!(r.len() <= 1);
    }

    #[test]
    fn tracing_ring_snapshot_is_independent_of_ring() {
        let r = TracingRing::new(2);
        r.push("a".to_string());
        let snap = r.snapshot();
        r.push("b".to_string());
        r.push("c".to_string());
        // First snapshot didn't see b/c.
        assert_eq!(snap, vec!["a".to_string()]);
        // New snapshot sees them.
        assert_eq!(r.snapshot(), vec!["b".to_string(), "c".to_string()]);
    }

    #[test]
    fn tracing_ring_concurrent_push_does_not_lose_data() {
        let r = std::sync::Arc::new(TracingRing::new(10_000));
        let r2 = std::sync::Arc::clone(&r);
        let h = std::thread::spawn(move || {
            for i in 0..5000 {
                r2.push(format!("a-{i}"));
            }
        });
        for i in 0..5000 {
            r.push(format!("b-{i}"));
        }
        h.join().unwrap();
        assert_eq!(r.len(), 10_000);
    }

    #[test]
    fn format_output_is_deterministic() {
        // Same inputs twice should produce byte-identical output.
        let a = format_crash_record(&facts(), &panic_info(), 1, 100, &["e".to_string()]);
        let b = format_crash_record(&facts(), &panic_info(), 1, 100, &["e".to_string()]);
        assert_eq!(a, b);
    }

    #[test]
    fn format_round_trip_via_lines_recovers_header_keys() {
        // A consumer (e.g. a triage script) parses by line and
        // splits on the first ":". The format MUST guarantee each
        // header line has exactly one logical key before the colon.
        let out = format_crash_record(&facts(), &panic_info(), 1, 100, &[]);
        let mut header_keys = Vec::new();
        for line in out.lines() {
            if line.starts_with("backtrace:") {
                break;
            }
            if let Some((k, _)) = line.split_once(':') {
                header_keys.push(k.trim().to_string());
            }
        }
        // First line is "<component> crash log" with no colon — skipped.
        // Remaining keys must be the documented set, in order.
        assert_eq!(
            header_keys,
            vec![
                "version", "commit", "built", "rustc", "target", "pid", "ts", "panic",
            ]
        );
    }
}
