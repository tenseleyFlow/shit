// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result};
use clap::Subcommand;
use shit_proto::{CtlRequest, CtlResponse, HookMessage, ShellKind, decode_frame, encode_frame};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Subcommand)]
pub enum HookSendKind {
    SessionOpen {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        pid: u32,
        #[arg(long, value_parser = parse_shell)]
        shell: ShellKind,
        #[arg(long)]
        tty: String,
        #[arg(long)]
        sock: PathBuf,
    },
    PreExec {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        pid: u32,
        #[arg(long)]
        cwd: PathBuf,
        #[arg(long, value_parser = parse_shell)]
        shell: ShellKind,
        #[arg(long, default_value_t = 1)]
        depth: u8,
        #[arg(long)]
        sock: PathBuf,
        /// Task #105 — after sending the PreExec datagram, BLOCK
        /// until the helper signals capture-is-ready for this
        /// (session, seq) via `CtlRequest::WaitWatchReady`. Defaults
        /// to the sibling `shit-ctl.sock` of `--sock`. Pass an empty
        /// string to disable the wait (only safe in degraded mode or
        /// for testing -- the user's command will race the helper's
        /// WatchTree handling otherwise).
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
        /// Maximum time to wait for capture readiness. 0 disables
        /// the wait entirely (same as no ctl_sock). Default 5s --
        /// large enough for cold-start BPF load (~1 s) with margin,
        /// small enough that a hung helper doesn't hang the shell.
        #[arg(long, default_value_t = 5000)]
        wait_ready_ms: u32,
    },
    PostExec {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        exit_code: i32,
        #[arg(long)]
        sock: PathBuf,
    },
    SessionClose {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        sock: PathBuf,
    },
    /// S15 — env tracking. The shell hook pipes the env block on
    /// stdin as `KEY=VALUE\0KEY=VALUE\0...` (the output of
    /// `env -0 | sort -z` on Linux/macOS). We hash it via the
    /// planner's canonicalizer and emit `HookMessage::PreExecEnv`.
    ///
    /// Cheap on the hot path: only the 32-byte hash crosses the
    /// wire here; the full block is sent in [`PostExecEnv`] only
    /// when the hash changes (Stage 1 always sends — the "only on
    /// change" optimization is gated on the daemon's pre-stash, see
    /// S15.4).
    #[command(name = "pre-exec-env")]
    PreExecEnv {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        sock: PathBuf,
    },
    /// Companion to `PreExecEnv`. Same stdin format. The full
    /// block crosses the wire; the daemon diffs against the pre-hash
    /// it cached and emits a `CaptureEvent::EnvDiff` only when
    /// non-empty.
    #[command(name = "post-exec-env")]
    PostExecEnv {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        sock: PathBuf,
    },
}

fn parse_shell(s: &str) -> Result<ShellKind, String> {
    ShellKind::from_str(s).map_err(|e| e.to_string())
}

fn ts_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// What to do after the datagram lands. Only PreExec needs the
/// post-send WaitWatchReady ctl round-trip (task #105); everything
/// else returns immediately.
struct PostSend {
    /// Ctl socket to call. Derived from the hook sock's parent dir
    /// when the caller didn't pass `--ctl-sock` explicitly.
    ctl_sock: PathBuf,
    session: Uuid,
    command_seq: u64,
    timeout_ms: u32,
}

pub fn run(kind: HookSendKind) -> Result<()> {
    let (msg, sock, post): (HookMessage, PathBuf, Option<PostSend>) = match kind {
        HookSendKind::SessionOpen {
            session,
            pid,
            shell,
            tty,
            sock,
        } => (
            HookMessage::SessionOpen {
                session,
                shell_kind: shell,
                parent_pid: pid,
                tty,
                ts_unix_nanos: ts_now(),
            },
            sock,
            None,
        ),
        HookSendKind::PreExec {
            session,
            seq,
            pid,
            cwd,
            shell,
            depth,
            sock,
            ctl_sock,
            wait_ready_ms,
        } => {
            let (cwd_dev, cwd_inode) = stat_cwd(&cwd).unwrap_or((0, 0));
            let cwd_path = cwd.to_string_lossy().into_owned();
            // Task #105 — derive ctl_sock from hook sock's parent
            // dir when not explicitly given. Convention:
            // `<runtime>/shit.sock` -> `<runtime>/shit-ctl.sock`.
            let post = if wait_ready_ms == 0 {
                None
            } else {
                let derived_ctl = ctl_sock.clone().unwrap_or_else(|| {
                    sock.parent()
                        .map(|p| p.join("shit-ctl.sock"))
                        .unwrap_or_else(|| PathBuf::from("shit-ctl.sock"))
                });
                Some(PostSend {
                    ctl_sock: derived_ctl,
                    session,
                    command_seq: seq,
                    timeout_ms: wait_ready_ms,
                })
            };
            (
                HookMessage::PreExec {
                    session,
                    seq,
                    pid,
                    cwd_inode,
                    cwd_dev,
                    cwd_path,
                    ts_unix_nanos: ts_now(),
                    shell_kind: shell,
                    depth,
                },
                sock,
                post,
            )
        }
        HookSendKind::PostExec {
            session,
            seq,
            exit_code,
            sock,
        } => (
            HookMessage::PostExec {
                session,
                seq,
                exit_code,
                ts_unix_nanos: ts_now(),
            },
            sock,
            None,
        ),
        HookSendKind::SessionClose { session, sock } => (
            HookMessage::SessionClose {
                session,
                ts_unix_nanos: ts_now(),
            },
            sock,
            None,
        ),
        HookSendKind::PreExecEnv { session, seq, sock } => {
            let env_block = read_env_block_from_stdin()?;
            (
                HookMessage::PreExecEnv {
                    session,
                    seq,
                    env_block,
                    ts_unix_nanos: ts_now(),
                },
                sock,
                None,
            )
        }
        HookSendKind::PostExecEnv { session, seq, sock } => {
            let env_block = read_env_block_from_stdin()?;
            (
                HookMessage::PostExecEnv {
                    session,
                    seq,
                    env_block,
                    ts_unix_nanos: ts_now(),
                },
                sock,
                None,
            )
        }
    };
    send_message(&sock, &msg)?;
    if let Some(p) = post {
        wait_watch_ready(&p)?;
    }
    Ok(())
}

/// Block until the daemon confirms helper-side capture readiness for
/// (session, command_seq), or the timeout fires. Connection failures
/// degrade silently: a fresh shell with no daemon yet shouldn't fail
/// PreExec at the hook layer (the user's command would have run
/// without capture anyway -- we're not making it worse). The hook
/// has already journaled the PreExec via the datagram path.
fn wait_watch_ready(p: &PostSend) -> Result<()> {
    let req = CtlRequest::WaitWatchReady {
        session: p.session,
        command_seq: p.command_seq,
        timeout_ms: p.timeout_ms,
    };
    let resp = match call_ctl(&p.ctl_sock, &req, p.timeout_ms) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };
    match resp {
        CtlResponse::WatchReady { ready: true, .. } => Ok(()),
        CtlResponse::WatchReady {
            ready: false,
            reason,
        } => {
            // Don't fail the hook -- the command will run with
            // possibly-degraded capture. The daemon will have logged
            // why; the shell user doesn't need a scary error here.
            // (`reason` ends up in our stderr for debug visibility.)
            eprintln!(
                "shit: PreExec wait-watch-ready returned not-ready (reason: {})",
                reason.as_deref().unwrap_or("?")
            );
            Ok(())
        }
        other => {
            eprintln!("shit: PreExec wait-watch-ready got unexpected response {other:?}");
            Ok(())
        }
    }
}

fn call_ctl(path: &Path, req: &CtlRequest, timeout_ms: u32) -> Result<CtlResponse> {
    use std::io::Write;
    let mut stream =
        UnixStream::connect(path).with_context(|| format!("connect ctl {}", path.display()))?;
    // Match the timeout on read/write so a stuck daemon doesn't hang
    // the hook past the caller's intended budget. +250 ms slack to
    // let the daemon respond `timeout` itself rather than us
    // half-closing under it.
    let dur = Duration::from_millis(u64::from(timeout_ms) + 250);
    stream.set_read_timeout(Some(dur))?;
    stream.set_write_timeout(Some(dur))?;
    let bytes = encode_frame(req).context("encode ctl request")?;
    stream.write_all(&bytes).context("write ctl request")?;
    let mut buf = vec![0u8; 8 * 1024];
    let n = stream.read(&mut buf).context("read ctl response")?;
    let resp: CtlResponse = decode_frame(&buf[..n]).context("decode ctl response")?;
    Ok(resp)
}

/// Read the shell's env block from stdin. Capped at 1 MiB — way over
/// even the noisiest systems but cheap to enforce.
const MAX_ENV_BLOCK: usize = 1 << 20;

fn read_env_block_from_stdin() -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(8192);
    std::io::stdin()
        .take(MAX_ENV_BLOCK as u64 + 1)
        .read_to_end(&mut buf)
        .context("read env block from stdin")?;
    if buf.len() > MAX_ENV_BLOCK {
        anyhow::bail!(
            "env block exceeds {MAX_ENV_BLOCK} bytes; refusing to send (raise the cap if this is genuine)"
        );
    }
    Ok(buf)
}

fn stat_cwd(cwd: &std::path::Path) -> Option<(u64, u64)> {
    let md = std::fs::metadata(cwd).ok()?;
    Some((md.dev(), md.ino()))
}

fn send_message(sock_path: &std::path::Path, msg: &HookMessage) -> Result<()> {
    let frame = encode_frame(msg).context("encode frame")?;
    let client = UnixDatagram::unbound().context("UnixDatagram::unbound")?;
    client
        .send_to(&frame, sock_path)
        .with_context(|| format!("send_to {}", sock_path.display()))?;
    Ok(())
}
