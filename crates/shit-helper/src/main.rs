// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit-helper` — the privileged sidecar for `shitd`.
//!
//! Architecture lives in `.docs/sprints/S06-helper-scaffold.md` and the
//! running audit in `.docs/audits/helper-protocol.md`.
//!
//! This binary is launched by `shitd`. It connects back to the daemon
//! over a SOCK_SEQPACKET UDS handed to it via `--daemon-sock`,
//! completes a handshake, then sits ready to handle watch / auth /
//! shutdown requests. Per-OS kernel hooks land in S07/S08/S09.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Notify;

#[cfg(target_os = "freebsd")]
mod capsicum_bsd;
#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
mod capture;
mod cloud;
mod container;
mod crash;
mod db;
#[cfg(target_os = "linux")]
mod ebpf;
#[cfg(target_os = "linux")]
mod fanotify;
mod handshake;
mod health;
#[cfg(target_os = "linux")]
mod inotify_supplement;
mod ipc;
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
mod kqueue;
mod net;
mod pkg;
#[cfg(target_os = "linux")]
mod priv_linux;
mod proc;
mod sandbox;
#[cfg(target_os = "linux")]
mod seccomp_linux;
mod self_verify;
mod svc;
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
mod zfs;

const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncommit: ",
    env!("VERGEN_GIT_SHA"),
    "\nbuilt:  ",
    env!("VERGEN_BUILD_TIMESTAMP"),
    "\nrustc:  ",
    env!("VERGEN_RUSTC_SEMVER"),
    "\ntarget: ",
    env!("VERGEN_CARGO_TARGET_TRIPLE"),
);

#[derive(Parser)]
#[command(
    name = "shit-helper",
    about = "shit privileged helper",
    version = env!("CARGO_PKG_VERSION"),
    long_version = LONG_VERSION,
)]
struct Cli {
    /// Path to the SEQPACKET UDS the daemon set up for us to connect back to.
    /// Required when running as the daemon's sidecar (no subcommand). Ignored
    /// by transient subcommands like `pkg-event`.
    #[arg(long)]
    daemon_sock: Option<PathBuf>,

    /// Expected daemon PID. Helper refuses to handshake unless the
    /// peer-PID we read off the socket matches.
    #[arg(long)]
    daemon_pid: Option<u32>,

    /// Expected daemon UID. Same: refuse on mismatch.
    #[arg(long)]
    daemon_uid: Option<u32>,

    /// State dir for crash logs and per-helper bookkeeping.
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Run in foreground (currently the only mode). Reserved for future
    /// daemonize switch.
    #[arg(long, default_value_t = true)]
    foreground: bool,

    /// Transient operation mode. With no subcommand, the helper runs
    /// as the daemon's privileged sidecar (the original behavior;
    /// requires `--daemon-sock`, `--daemon-pid`, `--daemon-uid`,
    /// `--state-dir`).
    #[command(subcommand)]
    mode: Option<Mode>,
}

#[derive(Subcommand)]
// The `*Event` postfix is shared by design — each subcommand
// represents one hook event kind. Renaming for clippy's taste would
// uncouple the variant from its subcommand name.
#[allow(clippy::enum_variant_names)]
enum Mode {
    /// Single-shot package-manager hook invocation (S14). Reads
    /// package-state via the requested manager's CLI tools and ships
    /// it to the daemon over the ctl socket. Returns immediately;
    /// does not enter the privileged-sidecar runtime.
    ///
    /// Invoked by per-manager hook configs (apt's `DPkg::Pre-Invoke`,
    /// pacman's PreTransaction hook, dnf plugin, brew wrapper, FreeBSD
    /// pkg event pipe). The hook script provides `<manager> <phase>`.
    #[command(name = "pkg-event")]
    PkgEvent {
        /// Package manager identifier (apt/dpkg/pacman/dnf/brew/pkg).
        manager: String,
        /// Phase of the package transaction (pre|post).
        phase: String,
        /// Override the daemon ctl-socket path. By default we use the
        /// per-user default location.
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
    },
    /// Single-shot process-lifecycle hook invocation (S18). Sent
    /// by the kill/pkill/killall wrappers. Pre-phase enumerates
    /// the target pids and snapshots their state (argv, cwd, env,
    /// parent_pid, tty); Post re-enumerates to see which targets
    /// went away.
    ///
    /// `target_argv` is everything the user passed *after* the
    /// tool name (so `kill -9 1234` → `["-9", "1234"]`). The
    /// shell wrapper SHOULD shell-quote-and-join the argv into a
    /// single newline-separated string in `--target-argv`; we
    /// split on newlines here.
    #[command(name = "proc-event")]
    ProcEvent {
        /// Process tool identifier (kill|pkill|killall).
        tool: String,
        /// Phase of the operation (pre|post).
        phase: String,
        /// User's argv after the tool, newline-separated. Each
        /// line is one argv token. (Avoids quoting headaches.)
        #[arg(long, default_value = "")]
        target_argv: String,
        /// Override the daemon ctl-socket path.
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
    },
    /// Single-shot network-tool wrapper invocation (S17). Same
    /// hook-friendly error policy as `pkg-event` / `svc-event`. The
    /// wrapper script has already classified the verb as mutating;
    /// we just snapshot state via the tool's native dump command
    /// and ship the bytes.
    #[command(name = "net-event")]
    NetEvent {
        /// Network tool identifier (iptables|ip6tables|nft|ufw|pfctl|ip-route|...).
        tool: String,
        /// Phase of the operation (pre|post).
        phase: String,
        /// Verb the user issued (informational; the wrapper has
        /// already decided this is a mutating op).
        #[arg(long)]
        verb: String,
        /// Tool-specific scope hint (iptables family, nft table,
        /// pfctl anchor, ip object). Empty when not applicable.
        #[arg(long, default_value = "")]
        scope_hint: String,
        /// Override the daemon ctl-socket path.
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
    },
    /// Single-shot service-manager (systemctl/launchctl) hook
    /// invocation (S16). Same hook-friendly error policy as
    /// `pkg-event`: shit-side failures never break the user's
    /// `systemctl`/`launchctl` invocation.
    ///
    /// Invoked by the PATH-prepended wrapper scripts in
    /// `packaging/svc-hooks/`. The wrapper has already parsed the
    /// verb and unit out of the user's argv; we capture pre/post
    /// state via the manager's own query interface.
    #[command(name = "svc-event")]
    SvcEvent {
        /// Service-manager identifier (systemctl|launchctl).
        tool: String,
        /// Phase of the operation (pre|post).
        phase: String,
        /// Scope hint (user|system|launchd-gui|launchd-system).
        #[arg(long, default_value = "user")]
        scope: String,
        /// Unit name (e.g. `nginx.service`, `com.example.foo`).
        #[arg(long)]
        unit: String,
        /// Verb the user issued (`start`/`enable`/`bootstrap`/...).
        #[arg(long)]
        verb: String,
        /// Override the daemon ctl-socket path.
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
    },
    /// Single-shot DB CLI shim invocation (S19, stretch). Sent by the
    /// opt-in `psql`/`mysql`/`sqlite3` wrappers. The wrapper passes
    /// the user's argv (post-tool-name) newline-separated so we can
    /// recover the connection target, and pipes the statement text on
    /// `--statement-blob` (also newline-separated for `-f` multi-stmt
    /// scripts).
    ///
    /// Same hook-friendly error policy as `pkg-event` etc.: shit-side
    /// failure never breaks the user's DB invocation.
    /// Compute the running helper binary's blake3 hash and write it
    /// to `<state-dir>/helper.sha256.baseline` (DR-65). Called by the
    /// .deb/.rpm postinst (and packaging equivalents) so the first
    /// runtime self-verify returns `Match` instead of `BaselineMissing`.
    ///
    /// Idempotent: a second invocation rewrites the baseline with
    /// the current hash, which is the right behaviour after an
    /// upgrade (the binary just changed).
    #[command(name = "self-baseline-write")]
    SelfBaselineWrite {
        /// State directory under which `helper.sha256.baseline` is
        /// written. Must exist and be writable; the postinst script
        /// is responsible for creating it.
        #[arg(long)]
        state_dir: PathBuf,
    },
    #[command(name = "db-event")]
    DbEvent {
        /// DB engine identifier (psql|mysql|sqlite3).
        engine: String,
        /// Phase of the operation (pre|post).
        phase: String,
        /// User's argv after the tool name, newline-separated.
        #[arg(long, default_value = "")]
        target_argv: String,
        /// SQL text — for `-c "<stmt>"` it's the literal -c value;
        /// for `-f <file>` the wrapper reads the file and pipes its
        /// contents. Multi-statement scripts are split planner-side.
        #[arg(long, default_value = "")]
        statement_blob: String,
        /// Override the daemon ctl-socket path.
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
    },
    /// `shit doctor` probe (B03): connect to the daemon, exchange
    /// a Handshake/HandshakeAck, print a one-line JSON result to
    /// stdout, exit. No capture loop, no sandbox, no privileged
    /// setup — just the IPC round-trip so doctor can measure
    /// helper⇄daemon health.
    ///
    /// Schema of the JSON line:
    /// ```text
    /// {"ok": bool, "latency_ms": u32, "helper_version": "…",
    ///  "kernel_tier": "…", "error": "…"}
    /// ```
    /// `error` is present iff `ok=false`. Always exits 0 — the
    /// caller parses the JSON to discover whether the handshake
    /// succeeded.
    #[command(name = "handshake-probe")]
    HandshakeProbe {
        /// Path to the daemon's helper-side socket. Doctor passes
        /// the system default; alternative paths supported for
        /// test harnesses.
        #[arg(long)]
        daemon_sock: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    // S06.3: drop LD_PRELOAD before anything else. TA-3 mitigation.
    // If anything injected itself into this process via LD_PRELOAD,
    // it's already too late for *this* binary; but we make sure no
    // child or thread inherits the variable. The pkg-event path
    // still enforces this — a poisoned hook script is exactly the
    // attack surface this exists for.
    refuse_if_ld_preloaded()?;

    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // S21.2 — root span carrying schema-required fields. Entered for
    // the duration of `main`; transient *-event sidecar invocations
    // get their own child spans inside `run_mode` (deferred to S21.3
    // when the JSON subscriber lands and the inheritance becomes
    // observable end-to-end).
    let root_span = tracing::info_span!(
        "helper",
        component = "helper",
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        commit = env!("VERGEN_GIT_SHA"),
    );
    let _root_guard = root_span.enter();

    // Transient modes short-circuit before any privileged setup. They
    // need their own modest runtime; the sidecar's `current_thread`
    // runtime is overkill for a one-shot UDS write, but it's already
    // available and avoids a second build path.
    if let Some(mode) = cli.mode {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        return rt.block_on(run_mode(mode));
    }

    // Legacy sidecar invocation: the daemon spawns the helper with
    // these four flags. Validate them; emit a clear error if any are
    // missing so a misconfigured init doesn't fail with a clap panic.
    let sidecar = SidecarConfig::from_cli(&cli)?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        commit = env!("VERGEN_GIT_SHA"),
        daemon_pid = sidecar.daemon_pid,
        "shit-helper starting"
    );

    // Crash hook: panics in worker tasks get a one-line summary on disk.
    crash::install_panic_hook(&sidecar.state_dir);

    // S20.8 — self-signature gate. Defense-in-depth; on mismatch we
    // log and continue (the daemon's handshake will surface the issue
    // via degraded-mode reporting in `shit status`). Debug builds and
    // platforms without `/proc/self/exe` get a `Skipped` outcome.
    match self_verify::verify(&sidecar.state_dir) {
        Ok(self_verify::VerifyOutcome::Match) => {
            tracing::debug!("self-verify: baseline matched");
        }
        Ok(self_verify::VerifyOutcome::BaselineMissing { computed }) => {
            tracing::info!(
                "self-verify: baseline absent; install-time baseline-write missed. \
                 Helper proceeds; operator should re-run install."
            );
            // Write the current hash so subsequent runs gate on it.
            if let Err(e) = self_verify::write_baseline(&sidecar.state_dir, &computed) {
                tracing::warn!(err = %e, "self-verify: baseline write failed");
            }
        }
        Ok(self_verify::VerifyOutcome::Mismatch { computed, baseline }) => {
            tracing::warn!(
                expected = %baseline,
                actual = %computed,
                "self-verify: hash mismatch; helper continuing in degraded mode (see threat-model.md TC-8)"
            );
        }
        Ok(self_verify::VerifyOutcome::Skipped { reason }) => {
            tracing::debug!(reason, "self-verify: skipped");
        }
        Err(e) => {
            tracing::warn!(err = %e, "self-verify: probe failed; continuing");
        }
    }

    // ---- privileged phase ----
    // Open any fd that requires `CAP_SYS_ADMIN` while we still have it,
    // *then* drop caps. The order is load-bearing: dropping first
    // EPERMs the fanotify_init below.
    let setup = privileged_setup();

    // Drop privileges to the minimum keep-list *after* the fanotify fd
    // is in hand. On systems where we never had CAP_SYS_ADMIN this is
    // a no-op safety net.
    #[cfg(target_os = "linux")]
    priv_linux::drop_to_minimum().map_err(|e| anyhow::anyhow!("privilege drop failed: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(sidecar, setup))
}

/// The four daemon-supplied flags pulled out as a struct so the
/// downstream `run` doesn't have to thread `Option` through every
/// field. Validation happens once at startup; everything after this
/// can assume the fields are populated.
pub struct SidecarConfig {
    pub daemon_sock: PathBuf,
    pub daemon_pid: u32,
    pub daemon_uid: u32,
    pub state_dir: PathBuf,
}

impl SidecarConfig {
    fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        Ok(Self {
            daemon_sock: cli.daemon_sock.clone().ok_or_else(|| {
                anyhow::anyhow!("missing --daemon-sock (required in sidecar mode)")
            })?,
            daemon_pid: cli.daemon_pid.ok_or_else(|| {
                anyhow::anyhow!("missing --daemon-pid (required in sidecar mode)")
            })?,
            daemon_uid: cli.daemon_uid.ok_or_else(|| {
                anyhow::anyhow!("missing --daemon-uid (required in sidecar mode)")
            })?,
            state_dir: cli
                .state_dir
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing --state-dir (required in sidecar mode)"))?,
        })
    }
}

/// Dispatch a transient subcommand. These never enter the sidecar
/// runtime; they run, do one IPC round-trip, and exit.
async fn run_mode(mode: Mode) -> anyhow::Result<()> {
    match mode {
        Mode::PkgEvent {
            manager,
            phase,
            ctl_sock,
        } => pkg::run_event(&manager, &phase, ctl_sock.as_deref()).await,
        Mode::SvcEvent {
            tool,
            phase,
            scope,
            unit,
            verb,
            ctl_sock,
        } => svc::run_event(&tool, &phase, &scope, &unit, &verb, ctl_sock.as_deref()).await,
        Mode::NetEvent {
            tool,
            phase,
            verb,
            scope_hint,
            ctl_sock,
        } => net::run_event(&tool, &phase, &verb, &scope_hint, ctl_sock.as_deref()).await,
        Mode::ProcEvent {
            tool,
            phase,
            target_argv,
            ctl_sock,
        } => proc::run_event(&tool, &phase, &target_argv, ctl_sock.as_deref()).await,
        Mode::DbEvent {
            engine,
            phase,
            target_argv,
            statement_blob,
            ctl_sock,
        } => {
            db::run_event(
                &engine,
                &phase,
                &target_argv,
                &statement_blob,
                ctl_sock.as_deref(),
            )
            .await
        }
        Mode::SelfBaselineWrite { state_dir } => run_self_baseline_write(&state_dir),
        Mode::HandshakeProbe { daemon_sock } => run_handshake_probe(&daemon_sock).await,
    }
}

/// B03 — `shit doctor` handshake probe.
///
/// Connect to the daemon at `daemon_sock`, perform one
/// Handshake/HandshakeAck round-trip, time it, print the result as
/// a single line of JSON on stdout, and exit 0 (the JSON's `ok`
/// field carries success/failure; the caller — `shit doctor` —
/// uses that, not the exit code).
///
/// Hook-friendly: never panics, never hangs forever. A connect
/// failure or a non-Ack reply produces `ok=false` with the error
/// in the `error` field.
async fn run_handshake_probe(daemon_sock: &std::path::Path) -> anyhow::Result<()> {
    use shit_proto::{HelperCaps, HelperRequest, HelperResponse, helper::HELPER_PROTOCOL_VERSION};

    let started = std::time::Instant::now();
    // SAFETY: getpid/getuid always succeed.
    let pid = unsafe { libc::getpid() } as u32;
    let uid = unsafe { libc::getuid() };

    let result = async {
        let conn = ipc::connect(daemon_sock)
            .await
            .map_err(|e| format!("connect {}: {e}", daemon_sock.display()))?;
        let req = HelperRequest::Handshake {
            daemon_pid: 0, // probe doesn't know — daemon ignores this field
            daemon_uid: uid,
            protocol_version: HELPER_PROTOCOL_VERSION,
            capability_request: HelperCaps {
                watch_tree: false,
                auth_subscribe: false,
                package_hook: false,
            },
        };
        conn.send_request(&req).map_err(|e| format!("send: {e}"))?;
        let resp = conn.recv_response().map_err(|e| format!("recv: {e}"))?;
        match resp {
            HelperResponse::HandshakeAck {
                helper_version,
                kernel_tier,
                ..
            } => Ok((helper_version, kernel_tier)),
            other => Err(format!("unexpected response: {other:?}")),
        }
    }
    .await;

    let latency_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
    // Hand-format the JSON line. We keep shit-helper free of
    // serde_json to minimize privileged-binary attack surface; the
    // consumer (`shit doctor`'s probes::bsd::helper_handshake_probe)
    // parses with serde_json on the unprivileged side. The five-key
    // shape is fixed by the B03 sprint spec.
    let line = match result {
        Ok((helper_version, kernel_tier)) => format!(
            r#"{{"ok":true,"latency_ms":{},"helper_version":{},"kernel_tier":{},"error":null}}"#,
            latency_ms,
            json_string(&helper_version),
            json_string(&kernel_tier),
        ),
        Err(e) => format!(
            r#"{{"ok":false,"latency_ms":{},"helper_version":null,"kernel_tier":null,"error":{}}}"#,
            latency_ms,
            json_string(&e),
        ),
    };

    println!("{line}");
    let _ = pid; // currently unused; reserved for future audit log
    Ok(())
}

/// Quote a Rust string as a JSON string literal. Handles the
/// minimal set of escapes JSON requires (the seven RFC 8259
/// must-escapes plus the < 0x20 control-character range). Adequate
/// for handshake-probe payloads — helper_version and kernel_tier
/// are ASCII strings under our control; the error string comes
/// from `Display` on local errors and may contain quotes or
/// backslashes (path strings, etc.).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod handshake_probe_tests {
    use super::json_string;

    #[test]
    fn json_string_quotes_basic() {
        assert_eq!(json_string("hello"), r#""hello""#);
    }

    #[test]
    fn json_string_escapes_quotes() {
        assert_eq!(json_string(r#"a"b"#), r#""a\"b""#);
    }

    #[test]
    fn json_string_escapes_backslashes() {
        assert_eq!(json_string(r"C:\foo"), r#""C:\\foo""#);
    }

    #[test]
    fn json_string_escapes_newlines() {
        assert_eq!(json_string("line1\nline2"), r#""line1\nline2""#);
    }

    #[test]
    fn json_string_escapes_control_chars() {
        // ASCII 0x01 (SOH).
        let s = format!("a{}b", '\u{01}');
        assert_eq!(json_string(&s), r#""a\u0001b""#);
    }
}

/// DR-65 — install-time baseline writer.
///
/// Hashes the running helper binary and writes the hex digest to
/// `<state_dir>/helper.sha256.baseline`. Invoked by the packaging
/// postinst scripts (.deb / .rpm) so a fresh install passes the
/// first runtime self-verify check.
///
/// Returns `Err` if the binary can't be hashed (e.g. `/proc/self/exe`
/// missing on a non-Linux platform) or the baseline write fails. The
/// postinst script is expected to surface the error to the user.
fn run_self_baseline_write(state_dir: &std::path::Path) -> anyhow::Result<()> {
    let exe =
        std::env::current_exe().map_err(|e| anyhow::anyhow!("current_exe lookup failed: {e}"))?;
    let hash =
        self_verify::hash_path(&exe).map_err(|e| anyhow::anyhow!("hash {}: {e}", exe.display()))?;
    self_verify::write_baseline(state_dir, &hash)
        .map_err(|e| anyhow::anyhow!("write baseline to {}: {e}", state_dir.display()))?;
    eprintln!(
        "shit-helper: baseline written ({hash}) to {}",
        state_dir.display()
    );
    Ok(())
}

/// Outcome of the privileged setup phase. The fanotify fd (if present)
/// is owned here and handed to the runtime; we never re-init from the
/// async side because we no longer hold `CAP_SYS_ADMIN`.
struct PrivilegedSetup {
    caps: shit_proto::HelperCaps,
    #[cfg(target_os = "linux")]
    fanotify_fd: Option<fanotify::FanotifyFd>,
    /// The kernel-tier we'd ideally use vs. the one we'll actually
    /// run with. They can differ: a kernel that *supports* BPF-LSM
    /// may still be backed by fanotify until S09 ships the loader.
    /// Stage-1: written at privileged_setup time, not yet read in
    /// the runtime path (DR-01..DR-04 will use it).
    #[allow(dead_code)]
    tier: CaptureTier,
}

/// Which kernel-tier capture path is in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureTier {
    /// Linux fanotify-perm (S08). The shipped tier on Linux today
    /// (kernel < 5.7 or when ebpf-lsm prerequisites are missing).
    Fanotify,
    /// Linux eBPF-LSM (L04). The preferred secondary tier on
    /// kernel ≥ 5.7 with `lsm=bpf` in /proc/cmdline and the helper
    /// holding CAP_BPF + CAP_PERFMON. Avoids fanotify's userspace
    /// roundtrip per event.
    EbpfLsm,
    /// Linux BPF-LSM (S09). Detected but not yet loaded — stage-1
    /// builds advertise `Fanotify` even when this would be preferred.
    /// L04 retains this only as a debug signal: prerequisites met
    /// but we chose to *not* load (e.g. `SHIT_FORCE_TIER=fanotify-perm`).
    EbpfLsmAvailableButDeferred,
    /// macOS EndpointSecurity (S07). Reserved.
    EndpointSecurity,
    /// BSD kqueue-only (S10). Post-hoc events; no pre-mutation
    /// blocking. Used when no LD_PRELOAD shim is installed and the
    /// storage substrate isn't ZFS.
    KqueueOnly,
    /// BSD kqueue + LD_PRELOAD shim (S10). Pre-mutation events via
    /// the userspace shim, kqueue for verification.
    KqueuePreloadShim,
    /// BSD ZFS snapshot-based capture (S10). Coarse but cheap —
    /// preferred tier when `$HOME` is on ZFS.
    ZfsSnapshot,
    /// Degraded — no kernel-tier capture available; helper logs only.
    Degraded,
}

impl CaptureTier {
    pub fn label(&self) -> &'static str {
        match self {
            CaptureTier::Fanotify => "fanotify-perm (S08)",
            CaptureTier::EbpfLsm => "ebpf-lsm (L04)",
            CaptureTier::EbpfLsmAvailableButDeferred => {
                "ebpf-lsm-available (S09 loader deferred; running fanotify)"
            }
            CaptureTier::EndpointSecurity => "endpoint-security (S07)",
            CaptureTier::KqueueOnly => "kqueue-only (S10 post-hoc)",
            CaptureTier::KqueuePreloadShim => "kqueue + LD_PRELOAD shim (S10)",
            CaptureTier::ZfsSnapshot => "zfs-snapshot (S10 coarse pre-mutation)",
            CaptureTier::Degraded => "degraded (log-only)",
        }
    }
}

fn privileged_setup() -> PrivilegedSetup {
    #[cfg(target_os = "linux")]
    {
        let (caps, fanotify_fd) = linux_privileged_setup();
        let tier = pick_linux_tier(fanotify_fd.is_some());
        tracing::info!(tier = tier.label(), "kernel capture tier picked");
        PrivilegedSetup {
            caps,
            fanotify_fd,
            tier,
        }
    }
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    {
        let tier = pick_bsd_tier();
        tracing::info!(tier = tier.label(), "kernel capture tier picked");
        PrivilegedSetup {
            caps: shit_proto::HelperCaps {
                watch_tree: true,
                // BSD tier doesn't have a kernel-blocking primitive on
                // par with fanotify-perm / ES. ZFS-snapshot and the
                // LD_PRELOAD shim both capture pre-mutation state but
                // don't *block* the syscall on the helper. Advertise
                // the capability honestly.
                auth_subscribe: false,
                package_hook: false,
            },
            tier,
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    )))]
    {
        // macOS path lands in S07. Helper still claims `watch_tree`
        // since that primitive is best-effort even with no kernel
        // hooks.
        PrivilegedSetup {
            caps: shit_proto::HelperCaps {
                watch_tree: true,
                auth_subscribe: false,
                package_hook: false,
            },
            tier: CaptureTier::Degraded,
        }
    }
}

/// Decide which BSD capture tier to use. ZFS wins when available
/// because it's dramatically cheaper than per-file capture. Otherwise
/// the kqueue floor; we advertise the LD_PRELOAD upgrade when the
/// shim is installed (path probe), but the actual interposition
/// activation belongs to the shell hook installer.
#[cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
fn pick_bsd_tier() -> CaptureTier {
    let probe = shit_capture::bsd_probe::probe_bsd();
    tracing::info!(
        diagnosis = probe.diagnose(),
        is_primary = probe.family.is_primary(),
        "bsd-probe"
    );
    if probe.zfs.usable() {
        return CaptureTier::ZfsSnapshot;
    }
    // Shim install path is platform-conventional: /usr/local/lib/shit/
    // on FreeBSD, same elsewhere. The shim file existing here is the
    // signal that the user opted into the LD_PRELOAD path.
    let shim = std::path::Path::new("/usr/local/lib/shit/libshit_preload.so");
    if shim.is_file() {
        return CaptureTier::KqueuePreloadShim;
    }
    CaptureTier::KqueueOnly
}

/// Bundles the long-lived state for the eBPF-LSM tier (L04). Held
/// in the run loop's outer scope so the reader/loader stay alive
/// for the helper's lifetime. The request loop receives a
/// [`LsmDispatch`] clone for WatchTree/UnwatchTree handling — the
/// reader/loader fields don't cross the `spawn_blocking` boundary.
#[cfg(target_os = "linux")]
struct LsmCaptureState {
    /// Reader thread handle. Dropped on shutdown — `LsmReader::drop`
    /// stops the reader and joins.
    _reader: ebpf::LsmReader,
    /// Held to keep the BPF programs attached for the helper's
    /// lifetime. Dropping detaches.
    _loader: ebpf::EbpfLoader,
    /// Clone-able dispatch handle for the request loop.
    dispatch: LsmDispatch,
}

/// Send + Clone snapshot of the eBPF-LSM tier's runtime hooks. Goes
/// into the synchronous request loop via [`request_loop`].
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct LsmDispatch {
    /// Process-tree tracking for pid → CommandId resolution.
    tree: Arc<std::sync::Mutex<fanotify::tree::TreeMap>>,
    /// Shared with the LsmReader's sink. WatchTree/UnwatchTree
    /// notify the same runtime instance the BPF events feed.
    runtime: Option<Arc<std::sync::Mutex<capture::linux::LinuxCaptureRuntime>>>,
}

/// Load the eBPF-LSM unlink program, take its ringbuf, and spawn
/// the userspace reader thread wired to dispatch into the linux
/// capture runtime. Returns the long-lived state to keep alive.
///
/// Requires CAP_BPF + CAP_PERFMON on the calling process. Call
/// BEFORE `sandbox::enter` — that's the last point where the helper
/// has the caps needed for `bpf(2)`.
#[cfg(target_os = "linux")]
fn boot_ebpf_lsm(
    runtime: Option<Arc<std::sync::Mutex<capture::linux::LinuxCaptureRuntime>>>,
) -> anyhow::Result<LsmCaptureState> {
    let mut loader = ebpf::EbpfLoader::new();
    loader.load_lsm_unlink()
        .map_err(|e| anyhow::anyhow!("load_lsm_unlink failed: {e}"))?;
    let ringbuf = loader
        .take_unlink_ringbuf()
        .ok_or_else(|| anyhow::anyhow!("take_unlink_ringbuf returned None after successful load"))?;

    let tree = Arc::new(std::sync::Mutex::new(fanotify::tree::TreeMap::new()));

    let sink: Arc<dyn ebpf::LsmEventSink> = match runtime.clone() {
        Some(rt) => Arc::new(ebpf::ringbuf_reader::LinuxCaptureSink {
            runtime: rt,
            tree: Arc::clone(&tree),
        }),
        None => {
            // No capture runtime (init failed). Fall back to the
            // logging sink — events get logged but no CapturedPreImage
            // wire goes out. Better than dropping silently.
            tracing::warn!("no capture runtime; lsm reader will log-only");
            Arc::new(ebpf::LoggingSink)
        }
    };

    // 250 µs idle sleep — keeps the race-to-open window tight on
    // unlinks. See ringbuf_reader::LsmReader::spawn doc for rationale.
    let reader = ebpf::LsmReader::spawn(
        ringbuf,
        sink,
        std::time::Duration::from_micros(250),
    );

    tracing::info!("ebpf-lsm reader spawned");
    Ok(LsmCaptureState {
        _reader: reader,
        _loader: loader,
        dispatch: LsmDispatch {
            tree,
            runtime,
        },
    })
}

/// Decide which kernel-tier the helper *should* use based on the
/// runtime probe and any `SHIT_FORCE_TIER` operator override.
///
/// L04 promoted the eBPF-LSM tier from "available but deferred" to
/// "preferred when prerequisites met". The actual program load
/// happens later (`load_lsm_unlink` in the runtime spawn block); if
/// that fails we degrade to fanotify or Degraded.
///
/// Env overrides (intended for L04 smoke harnesses + CI matrix):
///   * `SHIT_FORCE_TIER=ebpf-lsm`    — pick EbpfLsm unconditionally.
///     Caller MUST verify load actually succeeds; the smoke harness
///     fails fast if not.
///   * `SHIT_FORCE_TIER=fanotify-perm` — pick Fanotify even when
///     ebpf-lsm prerequisites are met (regression test for the older
///     tier on capable kernels).
#[cfg(target_os = "linux")]
fn pick_linux_tier(have_fanotify_fd: bool) -> CaptureTier {
    let forced = std::env::var("SHIT_FORCE_TIER").ok();

    let loader = ebpf::EbpfLoader::new();
    let outcome = loader.probe();
    let ebpf_ok = outcome.should_attempt_load();

    match forced.as_deref() {
        Some("ebpf-lsm") => {
            tracing::info!(
                kernel = outcome.kernel.diagnose(),
                forced = true,
                "SHIT_FORCE_TIER=ebpf-lsm — picking EbpfLsm"
            );
            return CaptureTier::EbpfLsm;
        }
        Some("fanotify-perm") => {
            if ebpf_ok && have_fanotify_fd {
                tracing::info!("SHIT_FORCE_TIER=fanotify-perm — using Fanotify despite ebpf-lsm being available");
                return CaptureTier::EbpfLsmAvailableButDeferred;
            }
            if have_fanotify_fd {
                return CaptureTier::Fanotify;
            }
            return CaptureTier::Degraded;
        }
        Some(other) => {
            tracing::warn!(
                value = other,
                "unrecognized SHIT_FORCE_TIER value; ignoring"
            );
        }
        None => {}
    }

    if ebpf_ok {
        tracing::info!(
            kernel = outcome.kernel.diagnose(),
            cap_bpf = outcome.caps.cap_bpf,
            cap_perfmon = outcome.caps.cap_perfmon,
            "ebpf-lsm prerequisites met — picking EbpfLsm"
        );
        return CaptureTier::EbpfLsm;
    }

    tracing::info!(
        diagnosis = outcome.diagnose(),
        "ebpf-lsm not available; using fanotify if possible"
    );
    if have_fanotify_fd {
        CaptureTier::Fanotify
    } else {
        CaptureTier::Degraded
    }
}

async fn run(cli: SidecarConfig, setup: PrivilegedSetup) -> anyhow::Result<()> {
    let shutdown = Arc::new(Notify::new());

    install_signal_handlers(Arc::clone(&shutdown));

    let conn = match ipc::connect(&cli.daemon_sock).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(err = %e, "failed to connect to daemon socket; exiting");
            return Err(e.into());
        }
    };
    tracing::info!(
        path = %cli.daemon_sock.display(),
        "connected to daemon ipc socket"
    );

    let outcome =
        match handshake::perform_helper_side(&conn, cli.daemon_pid, cli.daemon_uid, setup.caps) {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(err = %e, "handshake failed; exiting");
                return Err(anyhow::anyhow!("handshake failed: {e}"));
            }
        };
    tracing::info!(
        daemon_pid = outcome.daemon_pid,
        daemon_uid = outcome.daemon_uid,
        granted = ?outcome.granted,
        "handshake complete"
    );

    // Spawn the kernel-tier reader. Exactly one of fanotify /
    // ebpf-lsm gets wired per-boot — `pick_linux_tier` already chose
    // above. The fanotify branch mirrors L01; the ebpf-lsm branch
    // is L04's promotion path.
    //
    // Both readers feed the SAME `LinuxCaptureRuntime` instance. The
    // unused fd from the other tier (e.g. the fanotify_fd when tier
    // is EbpfLsm) is left open and harmless — the kernel-side mark
    // table is empty so no events arrive.
    #[cfg(target_os = "linux")]
    let (fanotify_state, lsm_state) = {
        let staging_dir = cli.state_dir.join("helper-staging");
        let capture_rt = match capture::linux::LinuxCaptureRuntime::new(
            staging_dir,
            Arc::clone(&conn),
        ) {
            Ok(rt) => Some(Arc::new(std::sync::Mutex::new(rt))),
            Err(e) => {
                tracing::warn!(err = %e, "linux capture runtime failed to init; reader will ALLOW without capture");
                None
            }
        };

        // Fanotify branch — current default tier or fallback path.
        let fanotify_state: Option<fanotify::runtime::FanotifyState> =
            if matches!(setup.tier, CaptureTier::Fanotify | CaptureTier::EbpfLsmAvailableButDeferred) {
                setup.fanotify_fd.map(|fd| {
                    let mut state = fanotify::runtime::FanotifyState::new(fd);
                    if let Some(rt) = capture_rt.clone() {
                        state = state.with_capture_runtime(rt);
                    }
                    let reader_state = state.clone();
                    std::thread::Builder::new()
                        .name("fanotify-reader".into())
                        .spawn(move || fanotify::runtime::reader_thread(reader_state))
                        .expect("spawn fanotify reader");
                    state
                })
            } else {
                tracing::info!(tier = setup.tier.label(), "skipping fanotify reader for this tier");
                None
            };

        // eBPF-LSM branch — L04. Load + attach happens here while
        // the helper still has CAP_BPF + CAP_PERFMON (before
        // sandbox::enter). The returned state carries both the
        // tree map (for WatchTree dispatch) and the LsmReader join
        // handle (for graceful shutdown).
        let lsm_state: Option<LsmCaptureState> = if matches!(setup.tier, CaptureTier::EbpfLsm) {
            match boot_ebpf_lsm(capture_rt.clone()) {
                Ok(state) => Some(state),
                Err(e) => {
                    tracing::error!(err = %e, "ebpf-lsm load failed; this tier is unusable on this boot");
                    if std::env::var("SHIT_FORCE_TIER").as_deref() == Ok("ebpf-lsm") {
                        return Err(anyhow::anyhow!("SHIT_FORCE_TIER=ebpf-lsm but load failed: {e}"));
                    }
                    None
                }
            }
        } else {
            None
        };

        (fanotify_state, lsm_state)
    };

    // S24.B — BSD kqueue capture runtime. Spawn the pump + drain
    // threads *before* sandbox entry so any future cap_enter (S24.F)
    // sees the staging-dir fds already open.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    let bsd_capture: Option<capture::bsd::CaptureControl> = {
        let staging_dir = cli.state_dir.join("helper-staging");
        match capture::bsd::spawn(Arc::clone(&conn), staging_dir) {
            Ok((ctrl, _join)) => {
                tracing::info!("bsd capture runtime spawned");
                Some(ctrl)
            }
            Err(e) => {
                tracing::warn!(err = %e, "bsd capture runtime failed to start; continuing without it");
                None
            }
        }
    };

    // Sandbox entry — per-OS module decides what to do.
    sandbox::enter(&cli.state_dir)?;

    // S24.F — Capsicum capability mode. Off by default because
    // register_subtree currently opens by absolute path, which
    // cap_enter forbids. Gated on SHIT_CAPSICUM=1 so we can validate
    // the call site incrementally before the dir-fd rewrite in S25.
    #[cfg(target_os = "freebsd")]
    if std::env::var("SHIT_CAPSICUM").as_deref() == Ok("1") {
        match capsicum_bsd::enter_capability_mode() {
            Ok(()) => {
                tracing::info!("entered Capsicum capability mode (SHIT_CAPSICUM=1)");
            }
            Err(e) => {
                tracing::warn!(err = %e, "cap_enter failed; continuing without capability mode");
            }
        }
    }

    let request_conn = Arc::clone(&conn);
    #[cfg(target_os = "linux")]
    let request_state = fanotify_state.clone();
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    let request_bsd_capture = bsd_capture.clone();
    #[cfg(target_os = "linux")]
    let request_lsm = lsm_state.as_ref().map(|s| s.dispatch.clone());
    let request_handle = tokio::task::spawn_blocking(move || {
        request_loop(
            request_conn,
            #[cfg(target_os = "linux")]
            request_state,
            #[cfg(target_os = "linux")]
            request_lsm,
            #[cfg(any(
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd",
                target_os = "dragonfly",
            ))]
            request_bsd_capture,
        )
    });

    tokio::select! {
        _ = shutdown.notified() => {
            tracing::info!("shutdown signal received; exiting");
        }
        res = request_handle => {
            match res {
                Ok(Ok(())) => tracing::info!("request loop exited cleanly"),
                Ok(Err(e)) => tracing::warn!(err = %e, "request loop returned error"),
                Err(e) => tracing::warn!(err = %e, "request loop join failed"),
            }
        }
    }

    // Signal the reader thread (if any) to wind down before we drop
    // the FanotifyState. The thread exits within ~250ms (poll timeout).
    #[cfg(target_os = "linux")]
    if let Some(state) = &fanotify_state {
        state.shutdown();
    }
    #[cfg(target_os = "linux")]
    drop(fanotify_state);
    // L04: dropping `lsm_state` detaches the BPF program (via
    // `EbpfLoader::Drop`) and joins the reader thread (via
    // `LsmReader::Drop`). No explicit shutdown call needed.
    #[cfg(target_os = "linux")]
    drop(lsm_state);

    // S24.B — wind down the BSD capture pump. Best-effort; the JoinHandle
    // was dropped at spawn time so we can't wait on it, but Drop on
    // CaptureControl closes the control channel which signals the pump
    // to exit on its next iteration.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    if let Some(ctrl) = &bsd_capture {
        ctrl.shutdown();
    }
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    drop(bsd_capture);

    Ok(())
}

/// Synchronous daemon-request loop. Lives in `spawn_blocking` so it
/// can use the blocking `Conn::recv_request`. Exits when the daemon
/// disconnects or sends `Shutdown`.
fn request_loop(
    conn: Arc<ipc::Conn>,
    #[cfg(target_os = "linux")] fanotify_state: Option<fanotify::runtime::FanotifyState>,
    #[cfg(target_os = "linux")] lsm_state: Option<LsmDispatch>,
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    bsd_capture: Option<capture::bsd::CaptureControl>,
) -> anyhow::Result<()> {
    use shit_proto::{HelperRequest, HelperResponse};

    loop {
        let req = match conn.recv_request() {
            Ok(r) => r,
            Err(ipc::ConnError::PeerClosed) => {
                tracing::info!("daemon disconnected; request loop exiting");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(err = %e, "recv_request failed; request loop exiting");
                return Err(anyhow::anyhow!("recv_request: {e}"));
            }
        };

        match req {
            HelperRequest::Ping { nonce } => {
                let _ = conn.send_response(&HelperResponse::Pong { nonce });
            }
            HelperRequest::Shutdown { reason } => {
                tracing::info!(reason, "daemon requested shutdown");
                let _ = conn.send_response(&HelperResponse::ShutdownAck { reason });
                return Ok(());
            }
            HelperRequest::WatchTree {
                root_pid,
                descendants_too: _,
                session,
                command_seq,
                shell_kind: _,
            } => {
                #[cfg(target_os = "linux")]
                if let Some(state) = &fanotify_state {
                    state
                        .tree
                        .lock()
                        .unwrap()
                        .watch(session, command_seq, root_pid as i32);
                    // L01: explicit dedupe-state init for the command.
                    // The first event would lazy-init via `entry().or_default()`
                    // but doing it here keeps the watch_tree path explicit
                    // and matches the BSD producer's shape.
                    let cmd = shit_planner::events::CommandId {
                        session,
                        seq: command_seq,
                    };
                    if let Some(rt) = &state.capture_runtime
                        && let Ok(mut g) = rt.lock()
                    {
                        g.on_watch_tree(cmd);
                    }
                    // L01: add a narrow-scope fanotify mark on the
                    // root_pid's cwd directory (FAN_EVENT_ON_CHILD,
                    // ONLYDIR). Without this the reader sees no events.
                    // We deliberately do NOT use FAN_MARK_FILESYSTEM
                    // here (HP-18: marking $HOME at boot wedged the
                    // box). Stash the cwd path so UnwatchTree can
                    // unmark cleanly on command end.
                    let cwd_link = format!("/proc/{root_pid}/cwd");
                    match std::fs::read_link(&cwd_link) {
                        Ok(cwd) => match fanotify::mark::mark_dir_for_capture(&state.fd, &cwd) {
                            Ok(()) => {
                                state.marked_paths.lock().unwrap().insert(cmd, cwd.clone());
                                tracing::info!(
                                    %session,
                                    command_seq,
                                    root_pid,
                                    cwd = %cwd.display(),
                                    "watch_tree registered + cwd marked"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    err = %e,
                                    cwd = %cwd.display(),
                                    "mark_dir_for_capture failed; tree tracked but no events will fire"
                                );
                            }
                        },
                        Err(e) => {
                            tracing::warn!(
                                err = %e,
                                root_pid,
                                "cannot read /proc/<pid>/cwd; tree tracked but no fanotify mark"
                            );
                        }
                    }
                } else if let Some(state) = &lsm_state {
                    // L04: eBPF-LSM tier. No fanotify mark needed —
                    // the LSM hook fires globally on every unlinkat.
                    // We still track the pid tree so events from
                    // untracked pids are dropped.
                    state
                        .tree
                        .lock()
                        .unwrap()
                        .watch(session, command_seq, root_pid as i32);
                    let cmd = shit_planner::events::CommandId {
                        session,
                        seq: command_seq,
                    };
                    // L04 — pre-open every regular file in the
                    // root_pid's cwd. The held OwnedFd keeps the
                    // inode alive after vfs_unlink, so the LSM
                    // unlink handler can read the pre-image content
                    // even though the dentry's gone. Linux mirror of
                    // BSD's kqueue register_subtree.
                    let cwd_link = format!("/proc/{root_pid}/cwd");
                    let pre_open_cwd = std::fs::read_link(&cwd_link).ok();
                    if let Some(rt) = &state.runtime
                        && let Ok(mut g) = rt.lock()
                    {
                        g.on_watch_tree(cmd);
                        if let Some(cwd) = &pre_open_cwd {
                            g.pre_open_tree(cmd, cwd);
                        }
                    }
                    tracing::info!(
                        %session,
                        command_seq,
                        root_pid,
                        cwd = ?pre_open_cwd,
                        tier = "ebpf-lsm",
                        "watch_tree registered + cwd pre-opened (LSM tier)"
                    );
                } else {
                    tracing::debug!(
                        %session,
                        command_seq,
                        "watch_tree ignored — no fanotify or lsm (degraded)"
                    );
                }
                #[cfg(any(
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                ))]
                if let Some(ctrl) = &bsd_capture {
                    ctrl.on_watch_tree(session, command_seq, root_pid);
                    tracing::info!(
                        %session,
                        command_seq,
                        root_pid,
                        "watch_tree dispatched to bsd capture"
                    );
                } else {
                    tracing::debug!(
                        %session,
                        command_seq,
                        "watch_tree ignored — no bsd capture (degraded)"
                    );
                }
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                )))]
                {
                    let _ = (root_pid, session, command_seq);
                }
            }
            HelperRequest::UnwatchTree {
                session,
                command_seq,
            } => {
                #[cfg(target_os = "linux")]
                if let Some(state) = &fanotify_state {
                    state.tree.lock().unwrap().unwatch(session, command_seq);
                    let cmd = shit_planner::events::CommandId {
                        session,
                        seq: command_seq,
                    };
                    if let Some(rt) = &state.capture_runtime
                        && let Ok(mut g) = rt.lock()
                    {
                        g.on_unwatch_tree(cmd);
                    }
                    if let Some(path) = state.marked_paths.lock().unwrap().remove(&cmd)
                        && let Err(e) = fanotify::mark::unmark_dir_for_capture(&state.fd, &path)
                    {
                        tracing::warn!(
                            err = %e,
                            path = %path.display(),
                            "unmark_dir_for_capture failed (continuing)"
                        );
                    }
                    tracing::info!(%session, command_seq, "unwatch_tree");
                } else if let Some(state) = &lsm_state {
                    state.tree.lock().unwrap().unwatch(session, command_seq);
                    let cmd = shit_planner::events::CommandId {
                        session,
                        seq: command_seq,
                    };
                    if let Some(rt) = &state.runtime
                        && let Ok(mut g) = rt.lock()
                    {
                        g.on_unwatch_tree(cmd);
                    }
                    tracing::info!(%session, command_seq, tier = "ebpf-lsm", "unwatch_tree");
                }
                #[cfg(any(
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                ))]
                if let Some(ctrl) = &bsd_capture {
                    ctrl.on_unwatch_tree(session, command_seq);
                    tracing::info!(%session, command_seq, "unwatch_tree dispatched to bsd capture");
                }
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                )))]
                {
                    let _ = (session, command_seq);
                }
            }
            HelperRequest::AuthDecision { session, seq, .. } => {
                // S08 helper doesn't yet emit AuthEvents that need a
                // decision (always ALLOWs at the kernel boundary), so
                // an incoming AuthDecision is a protocol violation.
                tracing::warn!(
                    %session,
                    seq,
                    "unexpected AuthDecision in S08 mode; ignoring"
                );
            }
            HelperRequest::Handshake { .. } => {
                tracing::warn!("unexpected duplicate Handshake; ignoring");
            }
            // DR-15 wire surface lands here. The actual sandboxed
            // chown / mknod implementation is gated on DR-12 (macOS
            // entitlement) and DR-01..04 (Linux LSM); until then we
            // refuse and surface PermissionDenied so the executor
            // gets a clear signal.
            HelperRequest::ApplyChown {
                session,
                command_seq,
                ..
            }
            | HelperRequest::ApplyMknod {
                session,
                command_seq,
                ..
            } => {
                tracing::warn!(
                    %session,
                    command_seq,
                    "privileged-op request received but helper runtime is not yet wired (DR-15 stage-1)"
                );
                let _ = conn.send_response(&HelperResponse::PrivilegedOpResult {
                    session,
                    command_seq,
                    outcome: shit_proto::PrivilegedOpOutcome::PermissionDenied,
                });
            }
        }
    }
}

fn install_signal_handlers(shutdown: Arc<Notify>) {
    let shutdown_term = Arc::clone(&shutdown);
    let shutdown_int = shutdown;
    tokio::spawn(async move {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
            tracing::info!("SIGTERM received");
            shutdown_term.notify_waiters();
        }
    });
    tokio::spawn(async move {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        {
            s.recv().await;
            tracing::info!("SIGINT received");
            shutdown_int.notify_waiters();
        }
    });
}

/// Linux privileged setup. Runs while we still hold `CAP_SYS_ADMIN`
/// (if we ever did). Opens the fanotify fd; the fd works without the
/// cap once init returns, so the caller drops caps immediately after.
///
/// Returns the advertised cap set and the owned fanotify fd. The fd
/// is `None` when:
///   - we don't have `CAP_SYS_ADMIN` (EPERM) → degraded mode,
///   - kernel is pre-4.20 (no perm events) → degraded mode,
///   - any other `fanotify_init` failure.
#[cfg(target_os = "linux")]
fn linux_privileged_setup() -> (shit_proto::HelperCaps, Option<fanotify::FanotifyFd>) {
    let (version, features) = match fanotify::probe() {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(err = %e, "kernel feature probe failed; assuming no fanotify");
            return (degraded_caps(), None);
        }
    };
    tracing::info!(
        kernel = %version,
        tier = features.tier_label(),
        "kernel feature probe complete"
    );

    if !features.perm_events {
        tracing::warn!("kernel pre-4.20 — fanotify-perm unavailable, degraded mode");
        return (degraded_caps(), None);
    }

    match fanotify::init_pre_content() {
        Ok(fd) => {
            tracing::info!("fanotify pre-content client opened");
            // Intentionally *not* installing any mark here. Marks are
            // a destructive operation on a live system — every
            // process touching the marked filesystem stalls on the
            // helper's response loop. Past incident (2026-05-17):
            // marking `$HOME` at startup wedged the entire box until
            // reboot. The lesson: marks must be scoped tightly and
            // installed only when the daemon has explicitly asked
            // for a watch via `HelperRequest::WatchTree` — never
            // implicitly at startup. See HP-18 in
            // `.docs/audits/helper-protocol.md`.
            (
                shit_proto::HelperCaps {
                    watch_tree: true,
                    auth_subscribe: true,
                    package_hook: false,
                },
                Some(fd),
            )
        }
        Err(e) => {
            tracing::warn!(err = %e, "fanotify_init failed; degraded mode");
            (degraded_caps(), None)
        }
    }
}

#[cfg(target_os = "linux")]
fn degraded_caps() -> shit_proto::HelperCaps {
    shit_proto::HelperCaps {
        watch_tree: true,
        auth_subscribe: false,
        package_hook: false,
    }
}

fn refuse_if_ld_preloaded() -> anyhow::Result<()> {
    if std::env::var_os("LD_PRELOAD").is_some() {
        anyhow::bail!("LD_PRELOAD set; refusing to run (TA-3 mitigation)");
    }
    // DYLD_INSERT_LIBRARIES is the macOS equivalent.
    if std::env::var_os("DYLD_INSERT_LIBRARIES").is_some() {
        anyhow::bail!("DYLD_INSERT_LIBRARIES set; refusing to run");
    }
    Ok(())
}
