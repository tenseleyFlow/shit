// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result, bail};
use shit_proto::{CtlRequest, CtlResponse, DaemonStatus, decode_frame, encode_frame};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);

pub fn run(ctl_sock: Option<PathBuf>) -> Result<()> {
    let path = ctl_sock.unwrap_or_else(crate::paths::default_ctl_socket_path);
    match query_status(&path) {
        Ok(s) => {
            render(&s);
            Ok(())
        }
        Err(e) => {
            // Distinguish "no daemon" from other failures.
            if let Some(io) = e.downcast_ref::<std::io::Error>()
                && matches!(
                    io.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                )
            {
                println!("daemon: not running (no ctl socket at {})", path.display());
                return Ok(());
            }
            Err(e)
        }
    }
}

fn query_status(path: &Path) -> Result<DaemonStatus> {
    let mut stream = UnixStream::connect(path)
        .with_context(|| format!("connect ctl socket {}", path.display()))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let req = encode_frame(&CtlRequest::Status).context("encode CtlRequest::Status")?;
    stream.write_all(&req).context("write request")?;
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).context("read response")?;
    let resp: CtlResponse =
        decode_frame(&buf[..n]).with_context(|| format!("decode response ({n} bytes)"))?;
    match resp {
        CtlResponse::Status(s) => Ok(s),
        CtlResponse::Error(e) => bail!("daemon error: {e}"),
        other => bail!("unexpected response: {other:?}"),
    }
}

fn render(s: &DaemonStatus) {
    println!("daemon");
    println!("  version            {} (commit {})", s.version, s.commit);
    println!("  pid                {}", s.pid);
    println!("  uptime             {}", fmt_secs(s.uptime_secs));
    println!(
        "  idle for           {} (timeout {})",
        fmt_secs(s.idle_for_secs),
        fmt_secs(s.idle_timeout_secs)
    );
    println!("  hook socket        {}", s.hook_socket_path);
    println!("  ctl socket         {}", s.ctl_socket_path);
    println!("  hook messages      {}", s.hook_messages_received);
    println!("  hook decode errors {}", s.hook_decode_errors);
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
