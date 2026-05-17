// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit metrics` — query the daemon's perf-counter snapshot (S21.5).
//!
//! ## Formats
//!
//! - **`--format text` (default)** — human-readable single-page
//!   summary, same column-aligned style as `shit status`.
//! - **`--format prometheus`** — Prometheus text-exposition format
//!   for scraping by an external collector. Every counter gets a
//!   `# HELP` and `# TYPE` line per the [exposition spec][1].
//! - **`--format json`** — raw `MetricsSnapshot` serialized via
//!   serde. Useful for ad-hoc piping into `jq`.
//!
//! [1]: https://prometheus.io/docs/instrumenting/exposition_formats/
//!
//! ## Watch mode
//!
//! `--watch <duration>` polls the daemon on a fixed cadence and
//! re-renders. The text formatter clears the screen between
//! frames (via ANSI `\x1b[2J\x1b[H`); prometheus and json render
//! a fresh full document per poll without clearing — the consumer
//! is assumed to be a pipe.

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};
use shit_proto::{CtlRequest, CtlResponse, MetricsSnapshot, decode_frame, encode_frame};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Args)]
pub struct MetricsArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = MetricsFormat::Text)]
    pub format: MetricsFormat,

    /// Re-poll on this interval (e.g. `1s`, `5s`, `30s`). When set,
    /// the command runs indefinitely until Ctrl-C.
    #[arg(long, value_parser = parse_duration)]
    pub watch: Option<Duration>,

    /// Override the ctl-socket path.
    #[arg(long)]
    pub ctl_sock: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum MetricsFormat {
    Text,
    Prometheus,
    Json,
}

pub fn run(args: MetricsArgs) -> Result<()> {
    let path = args
        .ctl_sock
        .unwrap_or_else(crate::paths::default_ctl_socket_path);
    match args.watch {
        Some(interval) => loop {
            match query(&path) {
                Ok(s) => render_and_print(&s, args.format, /* clear */ true)?,
                Err(e) => {
                    // Print errors and keep polling — daemon might
                    // come back. Don't bail in watch mode.
                    eprintln!("metrics: {e}");
                }
            }
            std::thread::sleep(interval);
        },
        None => {
            let snap = query(&path).with_context(|| "query metrics")?;
            render_and_print(&snap, args.format, false)
        }
    }
}

fn render_and_print(snap: &MetricsSnapshot, format: MetricsFormat, clear: bool) -> Result<()> {
    if clear && format == MetricsFormat::Text {
        // ANSI clear + cursor home. Honored by every terminal we
        // target; ignored when stdout isn't a tty.
        print!("\x1b[2J\x1b[H");
    }
    let out = match format {
        MetricsFormat::Text => render_text(snap),
        MetricsFormat::Prometheus => render_prometheus(snap),
        MetricsFormat::Json => render_json(snap)?,
    };
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(out.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn query(path: &Path) -> Result<MetricsSnapshot> {
    let mut stream = UnixStream::connect(path)
        .with_context(|| format!("connect ctl socket {}", path.display()))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let req = encode_frame(&CtlRequest::Metrics).context("encode")?;
    stream.write_all(&req).context("write")?;
    // MetricsSnapshot fits comfortably in MAX_FRAME_SIZE; read once.
    let mut buf = vec![0u8; shit_proto::MAX_FRAME_SIZE];
    let n = stream.read(&mut buf).context("read")?;
    let resp: CtlResponse = decode_frame(&buf[..n]).context("decode")?;
    match resp {
        CtlResponse::Metrics(s) => Ok(s),
        CtlResponse::Error(e) => bail!("daemon error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
}

pub fn render_text(s: &MetricsSnapshot) -> String {
    let mut out = String::new();
    out.push_str("daemon\n");
    out.push_str(&format!("  pid                  {}\n", s.pid));
    out.push_str(&format!(
        "  uptime               {}\n",
        fmt_secs(s.uptime_secs)
    ));
    if !s.kernel_tier.is_empty() {
        out.push_str(&format!("  kernel tier          {}\n", s.kernel_tier));
    }
    out.push_str("hook ingest\n");
    out.push_str(&format!(
        "  messages received    {}\n",
        s.hook_messages_received
    ));
    out.push_str(&format!(
        "  decode errors        {}\n",
        s.hook_decode_errors
    ));
    if s.hook_latency_samples > 0 {
        out.push_str(&format!(
            "  latency p50          {} us\n",
            s.hook_latency_us_p50
        ));
        out.push_str(&format!(
            "  latency p99          {} us\n",
            s.hook_latency_us_p99
        ));
        out.push_str(&format!(
            "  latency samples      {}\n",
            s.hook_latency_samples
        ));
    } else {
        out.push_str("  latency              (no samples yet)\n");
    }
    out.push_str("store\n");
    out.push_str(&format!(
        "  size                 {}\n",
        fmt_bytes(s.store_size_bytes)
    ));
    out.push_str(&format!("  blob count           {}\n", s.store_blob_count));
    out.push_str(&format!(
        "  command count        {}\n",
        s.store_command_count
    ));
    out.push_str("gc\n");
    if s.last_gc_at_unix_secs > 0 {
        out.push_str(&format!(
            "  last pass duration   {} ms\n",
            s.last_gc_duration_ms
        ));
        out.push_str(&format!(
            "  last pass reclaimed  {}\n",
            fmt_bytes(s.last_gc_bytes_reclaimed)
        ));
        out.push_str(&format!(
            "  last pass at         {} (unix)\n",
            s.last_gc_at_unix_secs
        ));
    } else {
        out.push_str("  (no GC pass completed yet)\n");
    }
    out
}

pub fn render_prometheus(s: &MetricsSnapshot) -> String {
    let mut out = String::new();
    // One stanza per metric. HELP + TYPE + sample lines, per the
    // Prometheus exposition format spec.
    out.push_str("# HELP shit_uptime_seconds Daemon uptime in seconds.\n");
    out.push_str("# TYPE shit_uptime_seconds counter\n");
    out.push_str(&format!("shit_uptime_seconds {}\n", s.uptime_secs));

    out.push_str("# HELP shit_hook_messages_total Hook messages received from shells.\n");
    out.push_str("# TYPE shit_hook_messages_total counter\n");
    out.push_str(&format!(
        "shit_hook_messages_total {}\n",
        s.hook_messages_received
    ));

    out.push_str("# HELP shit_hook_decode_errors_total Hook frames that failed to decode.\n");
    out.push_str("# TYPE shit_hook_decode_errors_total counter\n");
    out.push_str(&format!(
        "shit_hook_decode_errors_total {}\n",
        s.hook_decode_errors
    ));

    out.push_str("# HELP shit_hook_latency_microseconds Hook-handling latency percentiles (us).\n");
    out.push_str("# TYPE shit_hook_latency_microseconds summary\n");
    out.push_str(&format!(
        "shit_hook_latency_microseconds{{quantile=\"0.5\"}} {}\n",
        s.hook_latency_us_p50
    ));
    out.push_str(&format!(
        "shit_hook_latency_microseconds{{quantile=\"0.99\"}} {}\n",
        s.hook_latency_us_p99
    ));
    out.push_str(&format!(
        "shit_hook_latency_microseconds_count {}\n",
        s.hook_latency_samples
    ));

    out.push_str("# HELP shit_store_size_bytes Total compressed blob bytes on disk.\n");
    out.push_str("# TYPE shit_store_size_bytes gauge\n");
    out.push_str(&format!("shit_store_size_bytes {}\n", s.store_size_bytes));

    out.push_str("# HELP shit_store_blob_count Distinct blob count.\n");
    out.push_str("# TYPE shit_store_blob_count gauge\n");
    out.push_str(&format!("shit_store_blob_count {}\n", s.store_blob_count));

    out.push_str("# HELP shit_store_command_count Recorded command count.\n");
    out.push_str("# TYPE shit_store_command_count gauge\n");
    out.push_str(&format!(
        "shit_store_command_count {}\n",
        s.store_command_count
    ));

    out.push_str("# HELP shit_gc_last_duration_ms Wall-clock duration of the last GC pass.\n");
    out.push_str("# TYPE shit_gc_last_duration_ms gauge\n");
    out.push_str(&format!(
        "shit_gc_last_duration_ms {}\n",
        s.last_gc_duration_ms
    ));

    out.push_str("# HELP shit_gc_last_bytes_reclaimed Bytes reclaimed by the last GC pass.\n");
    out.push_str("# TYPE shit_gc_last_bytes_reclaimed gauge\n");
    out.push_str(&format!(
        "shit_gc_last_bytes_reclaimed {}\n",
        s.last_gc_bytes_reclaimed
    ));

    out
}

fn render_json(s: &MetricsSnapshot) -> Result<String> {
    let mut out = serde_json::to_string_pretty(s).context("serialize MetricsSnapshot")?;
    out.push('\n');
    Ok(out)
}

fn fmt_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if b >= GB {
        format!("{:.2} GiB", b as f64 / GB as f64)
    } else if b >= MB {
        format!("{:.2} MiB", b as f64 / MB as f64)
    } else if b >= KB {
        format!("{:.2} KiB", b as f64 / KB as f64)
    } else {
        format!("{b} B")
    }
}

/// Parse durations like `1s`, `500ms`, `2m`, `1h`. We only accept
/// the simple `<N><unit>` form to keep the surface small; for
/// fancier needs the user pipes from `cron`/`watch`.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    // Find the first non-digit position.
    let split = s
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| format!("missing unit in {s:?}"))?;
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|e| format!("invalid number {num:?}: {e}"))?;
    let dur = match unit {
        "ms" => Duration::from_millis(n),
        "s" => Duration::from_secs(n),
        "m" => Duration::from_secs(n * 60),
        "h" => Duration::from_secs(n * 3600),
        other => return Err(format!("unknown unit {other:?}; want ms/s/m/h")),
    };
    Ok(dur)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_snap() -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: 3661,
            pid: 12345,
            hook_messages_received: 1234,
            hook_decode_errors: 2,
            hook_latency_us_p50: 850,
            hook_latency_us_p99: 9100,
            hook_latency_samples: 1234,
            store_size_bytes: 17 * 1024 * 1024,
            store_blob_count: 100,
            store_command_count: 50,
            last_gc_duration_ms: 142,
            last_gc_bytes_reclaimed: 1024 * 1024,
            last_gc_at_unix_secs: 1_700_000_000,
            kernel_tier: "fanotify".into(),
        }
    }

    #[test]
    fn render_text_includes_all_sections_when_populated() {
        let out = render_text(&sample_snap());
        assert!(out.contains("daemon"));
        assert!(out.contains("pid                  12345"));
        assert!(out.contains("uptime               1h1m"));
        assert!(out.contains("kernel tier          fanotify"));
        assert!(out.contains("hook ingest"));
        assert!(out.contains("messages received    1234"));
        assert!(out.contains("latency p50          850 us"));
        assert!(out.contains("latency p99          9100 us"));
        assert!(out.contains("latency samples      1234"));
        assert!(out.contains("store"));
        assert!(out.contains("size                 17.00 MiB"));
        assert!(out.contains("blob count           100"));
        assert!(out.contains("command count        50"));
        assert!(out.contains("gc"));
        assert!(out.contains("last pass duration   142 ms"));
        assert!(out.contains("last pass reclaimed  1.00 MiB"));
        assert!(out.contains("last pass at         1700000000"));
    }

    #[test]
    fn render_text_no_samples_says_no_samples_yet() {
        let mut snap = sample_snap();
        snap.hook_latency_samples = 0;
        snap.hook_latency_us_p50 = 0;
        snap.hook_latency_us_p99 = 0;
        let out = render_text(&snap);
        assert!(out.contains("latency              (no samples yet)"));
        assert!(!out.contains("latency p50"));
    }

    #[test]
    fn render_text_no_gc_says_no_pass_yet() {
        let mut snap = sample_snap();
        snap.last_gc_at_unix_secs = 0;
        let out = render_text(&snap);
        assert!(out.contains("(no GC pass completed yet)"));
        assert!(!out.contains("last pass duration"));
    }

    #[test]
    fn render_text_omits_kernel_tier_when_empty() {
        let mut snap = sample_snap();
        snap.kernel_tier = String::new();
        let out = render_text(&snap);
        assert!(!out.contains("kernel tier"));
    }

    #[test]
    fn render_prometheus_has_help_and_type_per_metric() {
        let out = render_prometheus(&sample_snap());
        // Spot-check the required exposition shape.
        for prefix in [
            "shit_uptime_seconds",
            "shit_hook_messages_total",
            "shit_hook_decode_errors_total",
            "shit_hook_latency_microseconds",
            "shit_store_size_bytes",
            "shit_store_blob_count",
            "shit_store_command_count",
            "shit_gc_last_duration_ms",
            "shit_gc_last_bytes_reclaimed",
        ] {
            assert!(
                out.contains(&format!("# HELP {prefix}")),
                "missing HELP for {prefix}: {out}"
            );
            assert!(
                out.contains(&format!("# TYPE {prefix}")),
                "missing TYPE for {prefix}: {out}"
            );
        }
    }

    #[test]
    fn render_prometheus_emits_summary_quantiles() {
        let out = render_prometheus(&sample_snap());
        assert!(out.contains("shit_hook_latency_microseconds{quantile=\"0.5\"} 850"));
        assert!(out.contains("shit_hook_latency_microseconds{quantile=\"0.99\"} 9100"));
        assert!(out.contains("shit_hook_latency_microseconds_count 1234"));
    }

    #[test]
    fn render_json_round_trips_via_serde() {
        let snap = sample_snap();
        let out = render_json(&snap).unwrap();
        let back: MetricsSnapshot = serde_json::from_str(&out).unwrap();
        assert_eq!(back, snap);
    }

    #[test]
    fn parse_duration_accepts_all_units() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("3s").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    }

    #[test]
    fn parse_duration_rejects_malformed() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("5x").is_err());
        assert!(parse_duration("5").is_err()); // missing unit
    }

    #[test]
    fn fmt_bytes_renders_units() {
        assert_eq!(fmt_bytes(500), "500 B");
        assert_eq!(fmt_bytes(1500), "1.46 KiB");
        assert_eq!(fmt_bytes(2 * 1024 * 1024), "2.00 MiB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn fmt_secs_renders_h_m_s() {
        assert_eq!(fmt_secs(45), "45s");
        assert_eq!(fmt_secs(125), "2m5s");
        assert_eq!(fmt_secs(3725), "1h2m");
    }
}
