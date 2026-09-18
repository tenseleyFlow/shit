// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result};
use clap::Subcommand;
use shit_proto::{
    CtlRequest, CtlResponse, HookMessage, MAX_FRAME_SIZE, RedirectOpWire, RedirectTargetWire,
    ShellKind, decode_frame, encode_frame,
};
use shit_shell::redirect::{RedirectOp, parse_redirects};
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
        /// AU26: the literal command-line string the shell is about
        /// to run. Bash passes `$BASH_COMMAND`, zsh passes `$1` from
        /// `preexec`, fish passes `$argv` from `--on-event
        /// fish_preexec`. Plumbed into `CommandRecord.cmd_string` so
        /// the planner's refuse-list match can fire at undo time.
        /// Optional + `allow_hyphen_values` because real commands
        /// frequently start with `--` flags.
        #[arg(long, allow_hyphen_values = true)]
        cmdline: Option<String>,
        /// Task #105 — after sending the PreExec datagram, BLOCK
        /// until the helper signals capture-is-ready for this
        /// (session, seq) via `CtlRequest::WaitWatchReady`. Defaults
        /// from `--sock` using the daemon's XDG/TMPDIR naming convention.
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
    /// AR06.1/.2/.3 — pre-command shell-state snapshot. Carries
    /// pwd + (AR06.2) set-opts + (AR06.3) aliases. The bash hook
    /// collects all three; opts and aliases are passed via stdin
    /// as NUL-separated records (one record per `\0`, fields
    /// tab-separated). `--from-stdin` toggles reading those extra
    /// dimensions; without it, only `--pwd` is shipped (back-compat
    /// with the AR06.1-era hook shape).
    ///
    /// Why stdin and not flags: a busy shell can have hundreds of
    /// aliases, and alias expansions can contain literal newlines.
    /// NUL-separation handles arbitrary bytes without an encoding
    /// step.
    #[command(name = "pre-exec-shell-state")]
    PreExecShellState {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        pwd: String,
        #[arg(long)]
        sock: PathBuf,
        /// AR06.2/.3 — read opts + aliases from stdin. Format:
        /// `OPT\tname\tvalue\0` and `ALIAS\tname\tvalue\0` records,
        /// mixed. Other prefixes are ignored (forward-compat for
        /// AR06.4 functions).
        #[arg(long, action = clap::ArgAction::SetTrue)]
        from_stdin: bool,
    },
    /// Companion to `PreExecShellState`. Same field set; bash
    /// hook calls after the user's command. Daemon pairs with the
    /// matching `PreExecShellState` by `(session, seq)` and emits
    /// a `ShellStateDiff` event only when at least one dimension
    /// differs.
    #[command(name = "post-exec-shell-state")]
    PostExecShellState {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        pwd: String,
        #[arg(long)]
        sock: PathBuf,
        #[arg(long, action = clap::ArgAction::SetTrue)]
        from_stdin: bool,
    },
    /// AR06.5 — synchronous pre-stash for shell stream redirects.
    /// The shell hook calls this BEFORE the about-to-run command's
    /// `open(O_TRUNC)` fires; we parse the command line for redirect
    /// destinations and ship them via a `PreStashRedirects` ctl
    /// request. The hook blocks on the ack so the redirect doesn't
    /// race the pre-stash. Daemon-side per-target failures are
    /// returned only after the daemon has durably refused command-wide
    /// undo. This subcommand exits non-zero unless it receives that safe
    /// acknowledgement; the shell still runs the user's command but leaves
    /// its journal row open rather than publishing a false-complete capture.
    ///
    /// `--cmdline` carries the literal command-line string (the
    /// bash hook passes `$BASH_COMMAND`, zsh passes `$1` from
    /// preexec, fish passes `$argv` from `--on-event fish_preexec`).
    /// `--ctl-sock` defaults from the hook socket using the daemon's
    /// XDG/TMPDIR naming convention, matching the PreExec path.
    #[command(name = "pre-exec-redirects")]
    PreExecRedirects {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        /// The literal command-line string the shell is about to
        /// execute. Quoted whole — the parser does the tokenization.
        #[arg(long, allow_hyphen_values = true)]
        cmdline: String,
        /// Hook UDS — used to derive the ctl socket if `--ctl-sock`
        /// isn't given. Optional because the parse-and-skip fast
        /// path doesn't need a daemon at all.
        #[arg(long)]
        sock: Option<PathBuf>,
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
        /// Cap the round-trip. Default 1500 ms — large enough to
        /// hash a few-MB log file, small enough not to wedge the
        /// shell if the daemon is unhealthy. 0 rejects redirect-bearing
        /// command lines because no safe acknowledgement can be obtained.
        #[arg(long, default_value_t = 1500)]
        timeout_ms: u32,
    },
    /// Durably refuse command-wide undo after a shell companion capture
    /// failure, then wait for the daemon's normal PostExec lifecycle owner to
    /// drain capture and close the command row. Safe to retry.
    #[command(name = "refuse-and-close")]
    RefuseAndClose {
        #[arg(long)]
        session: Uuid,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        exit_code: i32,
        #[arg(long, allow_hyphen_values = true)]
        detail: String,
        /// Hook UDS, used to derive the matching ctl socket.
        #[arg(long)]
        sock: Option<PathBuf>,
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
        #[arg(long, default_value_t = 7500)]
        timeout_ms: u32,
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
    // The synchronous ctl-backed variants do not ship a HookMessage. Handle
    // them first so the datagram match below stays linear.
    let kind = match kind {
        HookSendKind::PreExecRedirects {
            session,
            seq,
            cmdline,
            sock,
            ctl_sock,
            timeout_ms,
        } => {
            return run_pre_exec_redirects(session, seq, cmdline, sock, ctl_sock, timeout_ms);
        }
        HookSendKind::RefuseAndClose {
            session,
            seq,
            exit_code,
            detail,
            sock,
            ctl_sock,
            timeout_ms,
        } => {
            return run_refuse_and_close(
                session, seq, exit_code, detail, sock, ctl_sock, timeout_ms,
            );
        }
        other => other,
    };
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
            cmdline,
            ctl_sock,
            wait_ready_ms,
        } => {
            let (cwd_dev, cwd_inode) = stat_cwd(&cwd).unwrap_or((0, 0));
            let cwd_path = cwd.to_string_lossy().into_owned();
            // Task #105 — derive ctl_sock from the hook socket when not
            // explicitly given. This preserves both supported conventions:
            // `shit.sock` -> `shit-ctl.sock` under XDG_RUNTIME_DIR and
            // `shit-<uid>.sock` -> `shit-ctl-<uid>.sock` in TMPDIR.
            let post = if wait_ready_ms == 0 {
                None
            } else {
                let derived_ctl = ctl_sock
                    .clone()
                    .unwrap_or_else(|| ctl_socket_for_hook(Some(&sock)));
                Some(PostSend {
                    ctl_sock: derived_ctl,
                    session,
                    command_seq: seq,
                    timeout_ms: wait_ready_ms,
                })
            };
            // AU26: truncate to PRE_EXEC_CMDLINE_MAX_BYTES at the
            // nearest UTF-8 char boundary at or below the cap. The
            // bash hook ships $BASH_COMMAND verbatim; pathological
            // macros / aliased pipelines can exceed 4 KiB but
            // truncation can't hide a refuse-list pattern (every
            // catalog pattern is <40 bytes).
            let cmd_string = cmdline.map(shit_proto::truncate_cmd_string);
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
                    cmd_string,
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
        HookSendKind::PreExecShellState {
            session,
            seq,
            pwd,
            sock,
            from_stdin,
        } => {
            let (opts, aliases) = if from_stdin {
                read_shell_state_from_stdin()?
            } else {
                (Vec::new(), Vec::new())
            };
            (
                HookMessage::PreExecShellState {
                    session,
                    seq,
                    pwd,
                    opts,
                    aliases,
                    ts_unix_nanos: ts_now(),
                },
                sock,
                None,
            )
        }
        HookSendKind::PostExecShellState {
            session,
            seq,
            pwd,
            sock,
            from_stdin,
        } => {
            let (opts, aliases) = if from_stdin {
                read_shell_state_from_stdin()?
            } else {
                (Vec::new(), Vec::new())
            };
            (
                HookMessage::PostExecShellState {
                    session,
                    seq,
                    pwd,
                    opts,
                    aliases,
                    ts_unix_nanos: ts_now(),
                },
                sock,
                None,
            )
        }
        HookSendKind::PreExecRedirects { .. } => {
            // Handled by the early-return above; matched here only
            // to keep the match exhaustive without an unreachable!().
            return Ok(());
        }
        HookSendKind::RefuseAndClose { .. } => return Ok(()),
    };
    send_message(&sock, &msg)?;
    if let Some(p) = post {
        wait_watch_ready(&p)?;
    }
    Ok(())
}

fn run_refuse_and_close(
    session: Uuid,
    command_seq: u64,
    exit_code: i32,
    detail: String,
    sock: Option<PathBuf>,
    ctl_sock: Option<PathBuf>,
    timeout_ms: u32,
) -> Result<()> {
    if timeout_ms == 0 {
        anyhow::bail!("refuse-and-close requires a non-zero acknowledgement timeout");
    }
    let ctl_path = ctl_sock.unwrap_or_else(|| ctl_socket_for_hook(sock.as_deref()));
    let request = CtlRequest::RefuseAndCloseCommand {
        session,
        command_seq,
        exit_code,
        detail,
        timeout_ms,
    };
    match call_ctl(&ctl_path, &request, timeout_ms) {
        Ok(CtlResponse::RefuseAndCloseAck) => Ok(()),
        Ok(CtlResponse::Error(detail)) => anyhow::bail!("refuse-and-close failed: {detail}"),
        Ok(other) => anyhow::bail!("refuse-and-close got unexpected response {other:?}"),
        Err(error) => Err(error.context("refuse-and-close was not durably acknowledged")),
    }
}

/// AR06.5 — parse the command line for stream-redirect destinations
/// and synchronously ship them to the daemon for pre-stash. Returns
/// `Ok(())` means either there were no redirect targets or the daemon returned
/// a safe acknowledgement. Per-target failures are safe inside that ACK
/// because the daemon first journals a command-scoped `CaptureRefused`.
/// Transport failures and top-level daemon errors propagate so the shell hook
/// can leave the command unprepared/unfinalized without suppressing execution.
fn run_pre_exec_redirects(
    session: Uuid,
    command_seq: u64,
    cmdline: String,
    sock: Option<PathBuf>,
    ctl_sock: Option<PathBuf>,
    timeout_ms: u32,
) -> Result<()> {
    let cwd = std::env::current_dir().context("resolve shell working directory")?;
    run_pre_exec_redirects_from_cwd(
        session,
        command_seq,
        cmdline,
        sock,
        ctl_sock,
        timeout_ms,
        &cwd,
    )
}

fn run_pre_exec_redirects_from_cwd(
    session: Uuid,
    command_seq: u64,
    cmdline: String,
    sock: Option<PathBuf>,
    ctl_sock: Option<PathBuf>,
    timeout_ms: u32,
    cwd: &Path,
) -> Result<()> {
    let analysis = parse_redirects(&cmdline);
    if analysis.is_empty() {
        return Ok(());
    }
    if timeout_ms == 0 {
        anyhow::bail!("redirect pre-stash requires a non-zero acknowledgement timeout");
    }
    let mut targets: Vec<RedirectTargetWire> = Vec::new();
    for target in analysis.targets {
        let path = normalize_redirect_target(&target.path, cwd).with_context(|| {
            format!("redirect target {:?} is not safely resolvable", target.path)
        })?;
        let op = to_op_wire(target.op);
        if let Some(existing) = targets.iter_mut().find(|item| item.path == path) {
            // A path mentioned more than once needs only one pre-state. Prefer
            // full content capture if any operator can truncate it.
            if is_truncate_wire(op) {
                existing.op = op;
            }
        } else {
            targets.push(RedirectTargetWire { op, path });
        }
    }
    if targets.len() > MAX_REDIRECT_TARGETS {
        anyhow::bail!(
            "redirect command has {} targets, above the {MAX_REDIRECT_TARGETS}-target safety limit",
            targets.len()
        );
    }
    let ctl_path = ctl_sock.unwrap_or_else(|| ctl_socket_for_hook(sock.as_deref()));
    let req = CtlRequest::PreStashRedirects {
        session,
        command_seq,
        targets,
    };
    match call_ctl(&ctl_path, &req, timeout_ms) {
        Ok(CtlResponse::PreStashRedirectsAck(r)) => {
            for err in &r.errors {
                eprintln!("shit: pre-exec-redirects: {}: {}", err.path, err.reason);
            }
            Ok(())
        }
        Ok(CtlResponse::Error(detail)) => {
            anyhow::bail!("redirect pre-stash was not safely acknowledged: {detail}")
        }
        Ok(other) => anyhow::bail!("redirect pre-stash got unexpected response {other:?}"),
        Err(error) => {
            Err(error.context("redirect pre-stash did not receive a safe acknowledgement"))
        }
    }
}

const MAX_REDIRECT_TARGETS: usize = 16;
const MAX_REDIRECT_PATH_BYTES: usize = 4096;

fn ctl_socket_for_hook(hook_socket: Option<&Path>) -> PathBuf {
    let Some(hook_socket) = hook_socket else {
        return PathBuf::from("shit-ctl.sock");
    };
    let Some(file_name) = hook_socket.file_name().and_then(|name| name.to_str()) else {
        return hook_socket.with_file_name("shit-ctl.sock");
    };
    if file_name == "shit.sock" {
        return hook_socket.with_file_name("shit-ctl.sock");
    }
    if let Some(suffix) = file_name
        .strip_prefix("shit-")
        .and_then(|name| name.strip_suffix(".sock"))
        .filter(|suffix| !suffix.is_empty())
    {
        return hook_socket.with_file_name(format!("shit-ctl-{suffix}.sock"));
    }
    hook_socket.with_file_name("shit-ctl.sock")
}

fn normalize_redirect_target(raw: &str, cwd: &Path) -> Result<String> {
    if raw.is_empty() {
        anyhow::bail!("empty path");
    }
    if raw.as_bytes().contains(&0) {
        anyhow::bail!("NUL byte in path");
    }
    if raw.starts_with('~')
        || raw.chars().any(|ch| {
            matches!(
                ch,
                '$' | '`' | '*' | '?' | '[' | ']' | '{' | '}' | '\\' | '(' | ')'
            )
        })
    {
        anyhow::bail!("shell expansion cannot be reproduced safely");
    }
    if !cwd.is_absolute() {
        anyhow::bail!("shell working directory is not absolute");
    }

    let raw_path = Path::new(raw);
    let joined = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        cwd.join(raw_path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        use std::path::Component;
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) => anyhow::bail!("unsupported path prefix"),
        }
    }
    if !normalized.is_absolute() {
        anyhow::bail!("normalized target is not absolute");
    }
    let encoded = normalized
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("path is not valid UTF-8 for the control protocol"))?;
    if encoded.len() > MAX_REDIRECT_PATH_BYTES {
        anyhow::bail!("path exceeds {MAX_REDIRECT_PATH_BYTES}-byte safety limit");
    }
    Ok(encoded.to_owned())
}

fn is_truncate_wire(op: RedirectOpWire) -> bool {
    matches!(
        op,
        RedirectOpWire::Truncate | RedirectOpWire::TeeTruncate | RedirectOpWire::DdOf
    )
}

fn to_op_wire(op: RedirectOp) -> RedirectOpWire {
    match op {
        RedirectOp::Truncate => RedirectOpWire::Truncate,
        RedirectOp::Append => RedirectOpWire::Append,
        RedirectOp::TeeTruncate => RedirectOpWire::TeeTruncate,
        RedirectOp::TeeAppend => RedirectOpWire::TeeAppend,
        RedirectOp::DdOf => RedirectOpWire::DdOf,
    }
}

/// Block until the daemon confirms helper-side capture readiness for
/// (session, command_seq), or the timeout fires. Connection failures
/// remain fail-open at the shell boundary: a fresh shell with no daemon yet
/// must not prevent the user's command from running. When the daemon is
/// reachable, every not-ready outcome is durably recorded as a command-atomic
/// capture refusal before this call returns. If the daemon itself is
/// unreachable, no process is available to persist that refusal; this is an
/// explicit availability-over-capture limitation of the current hook model.
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
            // Don't fail the hook -- the command still runs, but the daemon
            // has made this command non-undoable by journaling CaptureRefused.
            // Surface the reason for immediate operator visibility.
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
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .context("read ctl response header")?;
    let body_len = u32::from_be_bytes(header) as usize;
    let total_len = body_len
        .checked_add(header.len())
        .ok_or_else(|| anyhow::anyhow!("ctl response length overflow"))?;
    if total_len > MAX_FRAME_SIZE {
        anyhow::bail!("ctl response exceeds {MAX_FRAME_SIZE}-byte frame limit");
    }
    let mut frame = vec![0_u8; total_len];
    frame[..4].copy_from_slice(&header);
    stream
        .read_exact(&mut frame[4..])
        .context("read ctl response body")?;
    let resp: CtlResponse = decode_frame(&frame).context("decode ctl response")?;
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

/// AR06.2/.3 — parse a shell-state stdin block. Each record is
/// NUL-terminated; within a record, fields are tab-separated:
///   `OPT\t<name>\t<value>\0`
///   `ALIAS\t<name>\t<value>\0`
/// NUL separates records so embedded newlines / tabs in alias
/// values round-trip without escaping. Unknown record prefixes
/// (e.g. `FUNC` once AR06.4 lands) are silently ignored —
/// forward-compat with newer hooks talking to older daemons.
#[allow(clippy::type_complexity)]
fn read_shell_state_from_stdin() -> Result<(Vec<(String, String)>, Vec<(String, String)>)> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .context("read shell-state stdin")?;
    let mut opts: Vec<(String, String)> = Vec::new();
    let mut aliases: Vec<(String, String)> = Vec::new();
    for record_bytes in buf.split(|&b| b == 0) {
        if record_bytes.is_empty() {
            continue;
        }
        // Records are utf-8 by construction (bash text). On the
        // rare chance of non-utf-8 in an alias value, lossy-decode
        // — we'd rather get something than refuse the whole batch.
        let record = String::from_utf8_lossy(record_bytes);
        let mut parts = record.splitn(3, '\t');
        let kind = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("").to_string();
        let value = parts.next().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        match kind {
            "OPT" => opts.push((name, value)),
            "ALIAS" => aliases.push((name, value)),
            _ => {} // FUNC (AR06.4) and any future kinds skipped silently
        }
    }
    Ok((opts, aliases))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::thread::JoinHandle;

    fn redirect_call(ctl_sock: PathBuf, timeout_ms: u32) -> Result<()> {
        run_pre_exec_redirects(
            Uuid::nil(),
            7,
            "printf replacement > /tmp/redirect-target".to_string(),
            None,
            Some(ctl_sock),
            timeout_ms,
        )
    }

    #[test]
    fn ctl_socket_derivation_preserves_xdg_and_tmpdir_conventions() {
        assert_eq!(
            ctl_socket_for_hook(Some(Path::new("/run/user/1000/shit.sock"))),
            PathBuf::from("/run/user/1000/shit-ctl.sock")
        );
        assert_eq!(
            ctl_socket_for_hook(Some(Path::new("/tmp/shit-1000.sock"))),
            PathBuf::from("/tmp/shit-ctl-1000.sock")
        );
        assert_eq!(
            ctl_socket_for_hook(Some(Path::new("relative/shit-501.sock"))),
            PathBuf::from("relative/shit-ctl-501.sock")
        );
        assert_eq!(
            ctl_socket_for_hook(Some(Path::new("/custom/hook.sock"))),
            PathBuf::from("/custom/shit-ctl.sock")
        );
        assert_eq!(ctl_socket_for_hook(None), PathBuf::from("shit-ctl.sock"));
    }

    #[test]
    fn refuse_and_close_requires_its_dedicated_ack() {
        let (_dir, socket, join) = serve_once(CtlResponse::RefuseAndCloseAck);
        run_refuse_and_close(
            Uuid::nil(),
            12,
            9,
            "post-command capture failed".into(),
            None,
            Some(socket),
            1_000,
        )
        .unwrap();
        match join.join().unwrap() {
            CtlRequest::RefuseAndCloseCommand {
                command_seq,
                exit_code,
                detail,
                timeout_ms,
                ..
            } => {
                assert_eq!(command_seq, 12);
                assert_eq!(exit_code, 9);
                assert_eq!(detail, "post-command capture failed");
                assert_eq!(timeout_ms, 1_000);
            }
            other => panic!("unexpected request: {other:?}"),
        }

        let (_dir, socket, join) = serve_once(CtlResponse::Pong);
        let error = run_refuse_and_close(
            Uuid::nil(),
            12,
            9,
            "post-command capture failed".into(),
            None,
            Some(socket),
            1_000,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unexpected response"));
        join.join().unwrap();
    }

    #[test]
    fn refuse_and_close_rejects_zero_timeout() {
        let error = run_refuse_and_close(
            Uuid::nil(),
            1,
            0,
            "capture failed".into(),
            None,
            Some(PathBuf::from("unused.sock")),
            0,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("non-zero acknowledgement timeout")
        );
    }

    fn serve_once(response: CtlResponse) -> (tempfile::TempDir, PathBuf, JoinHandle<CtlRequest>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ctl.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let join = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0_u8; 4];
            stream.read_exact(&mut header).unwrap();
            let body_len = u32::from_be_bytes(header) as usize;
            let mut frame = vec![0_u8; 4 + body_len];
            frame[..4].copy_from_slice(&header);
            stream.read_exact(&mut frame[4..]).unwrap();
            let request: CtlRequest = decode_frame(&frame).unwrap();
            stream.write_all(&encode_frame(&response).unwrap()).unwrap();
            request
        });
        (dir, socket, join)
    }

    #[test]
    fn redirect_transport_failure_is_not_a_safe_ack() {
        let dir = tempfile::tempdir().unwrap();
        let error = redirect_call(dir.path().join("missing.sock"), 10).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("redirect pre-stash did not receive a safe acknowledgement")
        );
    }

    #[test]
    fn redirect_top_level_error_is_not_a_safe_ack() {
        let (_dir, socket, join) = serve_once(CtlResponse::Error(
            "durable CaptureRefused also failed".to_string(),
        ));
        let error = redirect_call(socket, 1000).unwrap_err();
        assert!(error.to_string().contains("was not safely acknowledged"));
        assert!(error.to_string().contains("CaptureRefused"));
        assert!(matches!(
            join.join().unwrap(),
            CtlRequest::PreStashRedirects { command_seq: 7, .. }
        ));
    }

    #[test]
    fn redirect_ack_with_durable_target_errors_is_safe() {
        let response = CtlResponse::PreStashRedirectsAck(shit_proto::PreStashRedirectsResult {
            stashed: 0,
            errors: vec![shit_proto::PreStashRedirectError {
                path: "/tmp/redirect-target".to_string(),
                reason: "durably refused".to_string(),
            }],
        });
        let (_dir, socket, join) = serve_once(response);
        redirect_call(socket, 1000).unwrap();
        assert!(matches!(
            join.join().unwrap(),
            CtlRequest::PreStashRedirects { command_seq: 7, .. }
        ));
    }

    #[test]
    fn redirect_with_zero_timeout_cannot_claim_safe_completion() {
        let error = redirect_call(PathBuf::from("unused.sock"), 0).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("non-zero acknowledgement timeout")
        );
    }

    #[test]
    fn relative_redirect_is_absolutized_against_shell_cwd() {
        let shell_root = tempfile::tempdir().unwrap();
        assert_ne!(std::env::current_dir().unwrap(), shell_root.path());
        let response = CtlResponse::PreStashRedirectsAck(shit_proto::PreStashRedirectsResult {
            stashed: 1,
            errors: Vec::new(),
        });
        let (_dir, socket, join) = serve_once(response);

        run_pre_exec_redirects_from_cwd(
            Uuid::nil(),
            7,
            "printf replacement > logs/../out.txt".to_string(),
            None,
            Some(socket),
            1000,
            shell_root.path(),
        )
        .unwrap();

        let request = join.join().unwrap();
        match request {
            CtlRequest::PreStashRedirects { targets, .. } => {
                assert_eq!(targets.len(), 1);
                assert_eq!(
                    targets[0].path,
                    shell_root.path().join("out.txt").to_str().unwrap()
                );
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn normalized_duplicate_targets_are_sent_once_with_truncate_precedence() {
        let shell_root = tempfile::tempdir().unwrap();
        let response = CtlResponse::PreStashRedirectsAck(shit_proto::PreStashRedirectsResult {
            stashed: 1,
            errors: Vec::new(),
        });
        let (_dir, socket, join) = serve_once(response);

        run_pre_exec_redirects_from_cwd(
            Uuid::nil(),
            7,
            "printf replacement >> out.txt > ./out.txt".to_string(),
            None,
            Some(socket),
            1000,
            shell_root.path(),
        )
        .unwrap();

        match join.join().unwrap() {
            CtlRequest::PreStashRedirects { targets, .. } => {
                assert_eq!(targets.len(), 1);
                assert!(matches!(targets[0].op, RedirectOpWire::Truncate));
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn unresolved_shell_expansions_fail_closed() {
        let cwd = Path::new("/tmp/shell-cwd");
        for raw in ["$OUT", "~/out", "*.log", "$(helper)"] {
            let error = normalize_redirect_target(raw, cwd).unwrap_err();
            assert!(
                error.to_string().contains("shell expansion"),
                "{raw}: {error}"
            );
        }
    }

    #[test]
    fn non_utf8_shell_cwd_cannot_be_sent_lossily() {
        use std::os::unix::ffi::OsStringExt;

        let cwd = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/non-utf8-\xff".to_vec()));
        let error = normalize_redirect_target("out", &cwd).unwrap_err();
        assert!(error.to_string().contains("not valid UTF-8"));
    }

    #[test]
    fn ctl_response_larger_than_old_eight_kib_buffer_is_read_exactly() {
        let detail = "x".repeat(12 * 1024);
        let (_dir, socket, join) = serve_once(CtlResponse::Error(detail.clone()));
        let error = redirect_call(socket, 1000).unwrap_err();
        assert!(error.to_string().contains(&detail));
        join.join().unwrap();
    }
}
