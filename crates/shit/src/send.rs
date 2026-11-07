// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Result};
use clap::Subcommand;
use shit_preload_shim::install_config::expand_tilde;
use shit_proto::{
    CtlRequest, CtlResponse, HOOK_DGRAM_MAX_FRAME, HookMessage, RedirectOpWire, RedirectTargetWire,
    ShellKind, decode_frame, encode_frame, encode_frame_large,
};
use shit_shell::redirect::{Quote, RedirectOp, RedirectTarget, parse_redirects};
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
    /// logged at debug level and do NOT fail this subcommand — a
    /// missed pre-stash is acceptable degradation (kernel tier
    /// catches up); a hard failure would block the shell.
    ///
    /// `--cmdline` carries the literal command-line string (the
    /// bash hook passes `$BASH_COMMAND`, zsh passes `$1` from
    /// preexec, fish passes `$argv` from `--on-event fish_preexec`).
    /// `--ctl-sock` defaults to the sibling `shit-ctl.sock` of the
    /// hook sock, matching the PreExec path.
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
        /// shell if the daemon is unhealthy. 0 disables the call
        /// entirely (useful when running with capture explicitly
        /// off).
        #[arg(long, default_value_t = 1500)]
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
    // PreExecRedirects doesn't ship a HookMessage — it's a direct
    // ctl call, with a fast-path "no redirects, no roundtrip" exit.
    // Handle it before the HookMessage match so the rest of the
    // function stays linear.
    if let HookSendKind::PreExecRedirects {
        session,
        seq,
        cmdline,
        sock,
        ctl_sock,
        timeout_ms,
    } = kind
    {
        return run_pre_exec_redirects(session, seq, cmdline, sock, ctl_sock, timeout_ms);
    }
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
    };
    send_message(&sock, &msg)?;
    if let Some(p) = post {
        wait_watch_ready(&p)?;
    }
    Ok(())
}

/// AR06.5 — parse the command line for stream-redirect destinations
/// and synchronously ship them to the daemon for pre-stash. Returns
/// Ok(()) on every code path that doesn't itself misuse the API —
/// daemon-down, daemon-erroring, per-target failures all log to
/// stderr (when applicable) but never propagate out of the hook.
/// The shell hook MUST NOT block on capture-tier failure.
fn run_pre_exec_redirects(
    session: Uuid,
    command_seq: u64,
    cmdline: String,
    sock: Option<PathBuf>,
    ctl_sock: Option<PathBuf>,
    timeout_ms: u32,
) -> Result<()> {
    if timeout_ms == 0 {
        return Ok(());
    }
    let analysis = parse_redirects(&cmdline);
    if analysis.is_empty() {
        return Ok(());
    }
    // This process runs in the shell's working directory, so relative
    // targets resolve here and not against the daemon's cwd.
    let cwd = std::env::current_dir().ok();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let targets: Vec<RedirectTargetWire> = analysis
        .targets
        .into_iter()
        .map(|t| RedirectTargetWire {
            op: to_op_wire(t.op),
            path: resolve_redirect_target(&t, cwd.as_deref(), home.as_deref()),
        })
        .collect();
    let ctl_path = ctl_sock
        .or_else(|| {
            sock.as_ref()
                .and_then(|s| s.parent().map(|p| p.join("shit-ctl.sock")))
        })
        .unwrap_or_else(|| PathBuf::from("shit-ctl.sock"));
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
        Ok(other) => {
            eprintln!("shit: pre-exec-redirects: unexpected response {other:?}");
            Ok(())
        }
        Err(e) => {
            // Daemon unreachable or timed out. Log + degrade — never
            // block the user's command on capture-tier health.
            eprintln!("shit: pre-exec-redirects: {e:#}");
            Ok(())
        }
    }
}

/// Resolve a redirect target to the path the kernel tiers will record.
///
/// Expansion follows the quoting the parser recorded. Only an unquoted
/// leading `~`, `~/`, `$HOME` or `${HOME}` expands to `home`; a quoted
/// `'~/x'` names a file called `~` in the cwd. Single-quoted text is
/// literal. In double-quoted or mixed text `$` and backticks still expand
/// in the shell, so those targets cannot be resolved here; `(`, `*`, `{`
/// and the like are literal there. Unquoted text with any of them is
/// unresolvable.
///
/// A relative path becomes absolute by joining it onto `cwd`, but only
/// when `t.cwd_stable` says nothing earlier on the line can change the
/// directory (`cd build && make > log` writes under `build`, not here).
/// The result keeps its final component as written, so a symlink there
/// keeps its own identity, but the parent directory is canonicalized: the
/// kernel reports `/work/out` for `sub/../out`, and a pre-image keyed to
/// `/work/sub/../out` would never match it in the planner.
///
/// An unresolvable target is sent as written; the daemon skips it in
/// default mode and refuses the command in strict mode.
fn resolve_redirect_target(t: &RedirectTarget, cwd: Option<&Path>, home: Option<&Path>) -> String {
    let raw = t.path.as_str();
    if raw.is_empty() {
        return raw.to_owned();
    }
    let expanded_home = match (t.quote, home) {
        (Quote::None, Some(home)) => {
            let e = expand_tilde(raw, home);
            (e != raw).then_some(e)
        }
        _ => None,
    };
    let resolvable = match (&expanded_home, t.quote) {
        // The tail after the home prefix is plain text; check it.
        (Some(_), _) => {
            let tail = ["~", "${HOME}", "$HOME"]
                .iter()
                .find_map(|p| raw.strip_prefix(p))
                .unwrap_or(raw);
            !has_unexpanded_syntax(tail)
        }
        (None, Quote::None) => !has_unexpanded_syntax(raw),
        (None, Quote::Single) => true,
        (None, Quote::Double | Quote::Mixed) => !raw.contains(['$', '`']),
    };
    if !resolvable {
        return raw.to_owned();
    }
    let path = expanded_home.as_deref().unwrap_or(raw);
    let joined: PathBuf = if path.starts_with('/') {
        PathBuf::from(path)
    } else {
        match cwd {
            Some(dir) if t.cwd_stable && dir.is_absolute() => dir.join(path),
            _ => return raw.to_owned(),
        }
    };
    let resolved = canonical_parent(&joined).unwrap_or(joined);
    match resolved.to_str() {
        Some(text) => text.to_owned(),
        None => raw.to_owned(),
    }
}

/// `parent.canonicalize()` joined with the final component. `None` when
/// there is no usable final component or the parent does not resolve.
fn canonical_parent(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let parent = path.parent()?.canonicalize().ok()?;
    Some(parent.join(name))
}

/// Unquoted text the shell would expand: parameters, command
/// substitution, globs, braces, escapes, and a leading `~`.
fn has_unexpanded_syntax(raw: &str) -> bool {
    raw.starts_with('~')
        || raw.chars().any(|ch| {
            matches!(
                ch,
                '$' | '`' | '*' | '?' | '[' | ']' | '{' | '}' | '\\' | '(' | ')'
            )
        })
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
    // Encode with the large cap so the transport choice, not the
    // encoder, decides what is too big (the ctl path accepts up to
    // MAX_LARGE_FRAME_SIZE; env blocks are capped at MAX_ENV_BLOCK).
    let frame = encode_frame_large(msg).context("encode frame")?;
    // Issue #6: macOS caps AF_UNIX datagrams at 2048 bytes by default.
    // Any frame over HOOK_DGRAM_MAX_FRAME (env blocks, long command
    // lines, alias tables) goes over the ctl stream socket instead.
    if frame.len() > HOOK_DGRAM_MAX_FRAME {
        return send_over_ctl(sock_path, msg);
    }
    let client = UnixDatagram::unbound().context("UnixDatagram::unbound")?;
    client
        .send_to(&frame, sock_path)
        .with_context(|| format!("send_to {}", sock_path.display()))?;
    Ok(())
}

/// Deliver a hook message via `CtlRequest::Hook` on the sibling
/// `shit-ctl.sock` of the hook socket. Pre-side frames are written and
/// the write half is shut down without waiting for a reply, so the
/// shell is not held on a round-trip before the user's command runs.
/// Post-side frames wait up to `POST_ACK_WAIT` for the ack, which only
/// bounds how long a slow daemon can delay the prompt.
fn send_over_ctl(sock_path: &Path, msg: &HookMessage) -> Result<()> {
    use std::io::Write;
    use std::net::Shutdown;
    const POST_ACK_WAIT: Duration = Duration::from_millis(200);
    let ctl_sock = sock_path
        .parent()
        .map(|p| p.join("shit-ctl.sock"))
        .unwrap_or_else(|| PathBuf::from("shit-ctl.sock"));
    let bytes = encode_frame_large(&CtlRequest::Hook(msg.clone())).context("encode ctl request")?;
    let mut stream = UnixStream::connect(&ctl_sock)
        .with_context(|| format!("connect ctl {}", ctl_sock.display()))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(&bytes).context("write ctl request")?;
    stream.shutdown(Shutdown::Write).ok();
    let post_side = matches!(
        msg,
        HookMessage::PostExec { .. }
            | HookMessage::PostExecEnv { .. }
            | HookMessage::PostExecShellState { .. }
            | HookMessage::SessionClose { .. }
    );
    if post_side {
        stream.set_read_timeout(Some(POST_ACK_WAIT))?;
        let mut buf = [0u8; 256];
        if let Ok(n) = stream.read(&mut buf)
            && let Ok(CtlResponse::Error(e)) = decode_frame::<CtlResponse>(&buf[..n])
        {
            anyhow::bail!("daemon rejected hook frame: {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod redirect_resolve_tests {
    use super::*;

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path().canonicalize().unwrap();
        (dir, root)
    }

    fn tgt(path: &str, quote: Quote, cwd_stable: bool) -> RedirectTarget {
        RedirectTarget {
            op: RedirectOp::Truncate,
            path: path.to_string(),
            quote,
            cwd_stable,
        }
    }

    /// Unquoted, cwd-stable target with no home directory.
    fn resolve(raw: &str, cwd: Option<&Path>) -> String {
        resolve_redirect_target(&tgt(raw, Quote::None, true), cwd, None)
    }

    fn resolve_q(raw: &str, quote: Quote, cwd: &Path, home: &Path) -> String {
        resolve_redirect_target(&tgt(raw, quote, true), Some(cwd), Some(home))
    }

    #[test]
    fn relative_target_joins_shell_cwd() {
        let (_d, root) = tmp();
        std::fs::create_dir(root.join("sub")).unwrap();
        let cwd = root.join("sub");
        assert_eq!(
            resolve("out", Some(&cwd)),
            root.join("sub/out").to_str().unwrap()
        );
    }

    #[test]
    fn dotdot_is_normalized_through_the_parent() {
        let (_d, root) = tmp();
        std::fs::create_dir(root.join("sub")).unwrap();
        let cwd = root.join("sub");
        assert_eq!(
            resolve("../out", Some(&cwd)),
            root.join("out").to_str().unwrap()
        );
        let abs = format!("{}/sub/../out", root.display());
        assert_eq!(resolve(&abs, None), root.join("out").to_str().unwrap());
    }

    #[test]
    fn symlinked_parent_resolves_physically_final_symlink_is_kept() {
        let (_d, root) = tmp();
        std::fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        std::os::unix::fs::symlink("elsewhere", root.join("real/final")).unwrap();
        assert_eq!(
            resolve("link/f", Some(&root)),
            root.join("real/f").to_str().unwrap()
        );
        assert_eq!(
            resolve("link/final", Some(&root)),
            root.join("real/final").to_str().unwrap()
        );
    }

    #[test]
    fn missing_parent_falls_back_to_the_plain_join() {
        let cwd = Path::new("/nonexistent-shit-root");
        assert_eq!(resolve("a/b", Some(cwd)), "/nonexistent-shit-root/a/b");
    }

    #[test]
    fn unquoted_home_forms_expand_only_when_unquoted() {
        let (_d, home) = tmp();
        let cwd = home.join("cwd");
        std::fs::create_dir(&cwd).unwrap();
        let want = home.join("new.log");
        for raw in ["~/new.log", "$HOME/new.log", "${HOME}/new.log"] {
            assert_eq!(
                resolve_q(raw, Quote::None, &cwd, &home),
                want.to_str().unwrap(),
                "{raw}"
            );
        }
        // Single quotes: a literal file named `~` (or `$HOME`) in the cwd.
        assert_eq!(
            resolve_q("~/x", Quote::Single, &cwd, &home),
            cwd.join("~/x").to_str().unwrap()
        );
        assert_eq!(
            resolve_q("$HOME/x", Quote::Single, &cwd, &home),
            cwd.join("$HOME/x").to_str().unwrap()
        );
        // Double quotes: tilde is literal, `$HOME` would expand, so it is
        // left for the daemon to skip or refuse.
        assert_eq!(
            resolve_q("~/x", Quote::Double, &cwd, &home),
            cwd.join("~/x").to_str().unwrap()
        );
        assert_eq!(resolve_q("$HOME/x", Quote::Double, &cwd, &home), "$HOME/x");
        // `~user` and `$HOMEFOO` are not the home directory.
        assert_eq!(resolve_q("~other/x", Quote::None, &cwd, &home), "~other/x");
        assert_eq!(
            resolve_q("$HOMEFOO/x", Quote::None, &cwd, &home),
            "$HOMEFOO/x"
        );
    }

    #[test]
    fn quoted_names_with_shell_punctuation_are_literal() {
        let (_d, root) = tmp();
        let want = root.join("notes (draft).txt");
        assert_eq!(
            resolve_q("notes (draft).txt", Quote::Single, &root, &root),
            want.to_str().unwrap()
        );
        assert_eq!(
            resolve_q("notes (draft).txt", Quote::Double, &root, &root),
            want.to_str().unwrap()
        );
        // The same text unquoted is a syntax error or a subshell.
        assert_eq!(
            resolve_q("notes (draft).txt", Quote::None, &root, &root),
            "notes (draft).txt"
        );
    }

    #[test]
    fn other_unexpanded_syntax_is_sent_verbatim() {
        let cwd = Path::new("/work");
        for raw in ["$NOPE/out", "a*b", "`pwd`/x", "{a,b}", "a\\ b"] {
            assert_eq!(resolve(raw, Some(cwd)), raw, "{raw}");
        }
    }

    #[test]
    fn relative_target_after_a_possible_cd_is_not_resolved() {
        let (_d, root) = tmp();
        let t = parse_redirects("cd sub && echo x > out").targets;
        assert_eq!(t.len(), 1);
        assert!(!t[0].cwd_stable);
        assert_eq!(resolve_redirect_target(&t[0], Some(&root), None), "out");
        // Absolute targets do not depend on the cwd.
        let abs = format!("cd sub && echo x > {}/out", root.display());
        let t = parse_redirects(&abs).targets;
        assert_eq!(
            resolve_redirect_target(&t[0], Some(&root), None),
            root.join("out").to_str().unwrap()
        );
        // Without a cd the same relative target resolves.
        let t = parse_redirects("echo x > out").targets;
        assert_eq!(
            resolve_redirect_target(&t[0], Some(&root), None),
            root.join("out").to_str().unwrap()
        );
    }

    #[test]
    fn missing_or_relative_cwd_leaves_target_alone() {
        assert_eq!(resolve("out", None), "out");
        assert_eq!(resolve("out", Some(Path::new("rel"))), "out");
    }
}
