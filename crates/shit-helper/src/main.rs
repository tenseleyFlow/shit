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
    target_os = "macos",
))]
mod capture;
#[cfg(target_os = "linux")]
mod capture_token;
mod cloud;
#[cfg(target_os = "macos")]
mod codesign_verify;
mod container;
mod crash;
mod db;
#[cfg(target_os = "linux")]
mod ebpf;
#[cfg(target_os = "macos")]
mod es;
#[cfg(target_os = "linux")]
mod fanotify;
#[cfg(target_os = "macos")]
mod fsevents;
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
#[cfg(target_os = "linux")]
mod watch_scope;
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
    /// AR03 PR-B / DR-CR-26 — container destructive verb capture.
    /// Invoked by the per-tool wrappers in
    /// `packaging/container-hooks/{docker,podman,docker-compose}-
    /// wrapper` BEFORE the real tool runs. Pre-phase snapshots state
    /// (`docker save` for rmi, `docker inspect` for rm/network-rm,
    /// `docker compose config` for compose-down, volume tar via
    /// transient busybox for volume-rm), computes blake3, ships
    /// inline bytes + descriptors over ctl. Daemon writes blob,
    /// registers container_stash, journals `CaptureEvent::ContainerOp`.
    ///
    /// PR-B implements docker rmi only as the canonical AR03.2
    /// path; rm / volume-rm / network-rm / compose-down ride the
    /// same subcommand but per-verb capture is filled in incrementally.
    ///
    /// `target_argv` is everything the user passed after the tool
    /// name, newline-separated (`docker rmi alpine` →
    /// `target_argv="rmi\nalpine"`). The subcommand routes argv
    /// through the existing `container::docker::classify_docker_argv`.
    #[command(name = "container-event")]
    ContainerEvent {
        /// Container runtime / tool identifier
        /// (`docker` | `podman` | `docker-compose`).
        tool: String,
        /// Phase of the operation (currently only `pre` is
        /// supported; AR03.x sub-targets add `post` for state
        /// reconciliation when needed).
        phase: String,
        /// User's argv after the tool name, newline-separated.
        #[arg(long, default_value = "")]
        target_argv: String,
        /// Override the daemon ctl-socket path.
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
    },
    /// AR04 PR-B / DR-CR-06 — cloud / IaC destructive verb capture.
    /// Invoked by the per-tool wrappers in `packaging/cloud-hooks/
    /// {terraform,kubectl,gh,aws}-wrapper` BEFORE the real tool runs.
    /// Pre-phase snapshots state (`terraform state pull` for
    /// apply/destroy; kubectl/gh/aws verbs land in AR04.3/.4/.5) and
    /// ships descriptors + prior_state over ctl. Daemon journals
    /// `CaptureEvent::TerraformOp` (or per-runtime equivalent).
    ///
    /// AR04.1 ships Terraform Apply / Destroy. Other runtimes route
    /// here but the helper returns early until their classifiers +
    /// capture logic land.
    ///
    /// `target_argv` is everything the user passed after the tool
    /// name, newline-separated (`terraform apply -auto-approve` →
    /// `target_argv="apply\n-auto-approve"`).
    #[command(name = "cloud-event")]
    CloudEvent {
        /// Cloud tool identifier
        /// (`terraform` | `kubectl` | `gh` | `aws`).
        tool: String,
        /// Phase of the operation (currently only `pre`).
        phase: String,
        /// User's argv after the tool name, newline-separated.
        #[arg(long, default_value = "")]
        target_argv: String,
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
    /// M03.1.C — `shit doctor` ES client-creation probe (macOS only).
    ///
    /// Attempts `es_new_client` with a no-op handler, immediately
    /// tears down via `es_delete_client`, prints a single-line JSON
    /// result. Doctor parses to fill
    /// `MacReport.endpoint_security.entitlement_present`.
    ///
    /// Output shape:
    /// ```
    /// {"result":"Success"} | {"result":"NotEntitled"} | {"result":"NotPermitted"}
    ///   | {"result":"NotPrivileged"} | {"result":"InvalidArgument"}
    ///   | {"result":"InternalError"} | {"result":"TooManyClients"}
    ///   | {"result":"UnknownResult","raw":<u32>}
    /// ```
    ///
    /// Always exits 0; the caller reads the JSON to discover the
    /// kernel verdict.
    #[command(name = "es-probe")]
    EsProbe,
    /// M03.1.E — ES subscribe-and-count smoke. Subscribes to
    /// NOTIFY_EXEC for `--duration-secs` seconds, prints the number
    /// of delivered events as a single-line JSON, tears down.
    ///
    /// Output: `{"events_received":<u64>,"duration_secs":<u64>}` on
    /// success, or `{"error":"<EsClientError>"}` when the client
    /// couldn't subscribe (typically not entitled / not privileged).
    /// Always exits 0; caller reads the JSON.
    ///
    /// Requires the same ES-enabled environment as `es-probe`. On
    /// non-macOS the subcommand prints
    /// `{"error":"NotSupportedOnThisOs"}`.
    #[command(name = "es-probe-subscribe")]
    EsProbeSubscribe {
        #[arg(long, default_value_t = 2)]
        duration_secs: u64,
    },
    /// M03.1.F — AUTH-event response smoke. Subscribes to
    /// AUTH_UNLINK for `--duration-secs` seconds, responds ALLOW
    /// to every event inline, prints count.
    ///
    /// Output: `{"events_received":<u64>,"duration_secs":<u64>}` on
    /// success, or `{"error":...}` on subscription failure.
    ///
    /// CAUTION: while this is running, EVERY unlink(2) on the host
    /// briefly blocks on our ALLOW response (microseconds). Don't
    /// hold it for long on a production system.
    #[command(name = "es-auth-smoke")]
    EsAuthSmoke {
        #[arg(long, default_value_t = 2)]
        duration_secs: u64,
    },
    /// M03.1.G — Subscribe to AUTH_UNLINK, decode each message, log
    /// the target path, respond ALLOW. After `--duration-secs`
    /// seconds, prints a JSON array of paths observed.
    ///
    /// Output: `{"events_received":<u64>,"paths":[<string>,...],"duration_secs":<u64>}`
    /// on success, `{"error":...}` on failure.
    ///
    /// CAUTION: same as `es-auth-smoke` — every unlink on the host
    /// briefly blocks on our ALLOW response. Don't run long.
    #[command(name = "es-path-log-smoke")]
    EsPathLogSmoke {
        #[arg(long, default_value_t = 2)]
        duration_secs: u64,
    },
    /// M03.1.H — Tree-filter smoke. Subscribes to AUTH_UNLINK with
    /// the tree-filter handler seeded with this process's own
    /// audit_token. Only unlinks from this process's audit_token
    /// get recorded; all others are ALLOW'd but ignored.
    ///
    /// Compare event count vs `es-path-log-smoke` for the same
    /// workload: the filtered version should report only the rm's
    /// originating from this CLI's exec'd subprocesses, not
    /// host-wide unlink traffic.
    ///
    /// Output: same shape as `es-path-log-smoke` (events_received +
    /// paths + duration_secs). Note: events_received here counts
    /// ALL delivered events (system-wide) — the FILTER applies only
    /// to whether the path is recorded. So events_received can be
    /// much larger than paths.len().
    #[command(name = "es-tree-filter-smoke")]
    EsTreeFilterSmoke {
        #[arg(long, default_value_t = 2)]
        duration_secs: u64,
    },
    /// L05 — `shit doctor` Linux fanotify functional probe.
    ///
    /// Opens a fanotify-perm fd, marks a tmpdir, writes a probe
    /// file, drains one perm event, exits. Output is silent — the
    /// doctor caller checks only the exit code. Requires the
    /// helper binary to have CAP_SYS_ADMIN.
    ///
    /// Linux-only. Exits non-zero on any failure (init,
    /// mark, write, drain, timeout).
    #[command(name = "probe-fanotify")]
    ProbeFanotify,
    /// L05 — `shit doctor` Linux eBPF-LSM prerequisite probe.
    ///
    /// Runs `EbpfLoader::probe` and exits 0 iff prerequisites
    /// (kernel ≥5.7, CONFIG_BPF_LSM=y, `bpf` in active LSMs,
    /// CAP_BPF + CAP_PERFMON) are all met. Does NOT load or
    /// attach any BPF program — pure capability check.
    ///
    /// Linux-only. Exits non-zero on missing prerequisites.
    #[command(name = "probe-ebpf")]
    ProbeEbpf,
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

    // L4b - the capture-token key is drawn now, before the sandbox, and
    // never leaves this process. Non-dumpable keeps same-user ptrace and
    // /proc/<pid>/mem off it (a setcap exec already clears the flag;
    // this covers other starts and checks it stayed clear).
    // Device-node restore, the only user of the key, is Linux-only.
    #[cfg(target_os = "linux")]
    {
        let dumpable = capture_token::ensure_non_dumpable();
        tracing::info!(
            token_key = capture_token::process_key().is_some(),
            dumpable,
            "capture-token key ready"
        );
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
        Mode::ContainerEvent {
            tool,
            phase,
            target_argv,
            ctl_sock,
        } => container::run_event(&tool, &phase, &target_argv, ctl_sock.as_deref()).await,
        Mode::CloudEvent {
            tool,
            phase,
            target_argv,
            ctl_sock,
        } => cloud::run_event(&tool, &phase, &target_argv, ctl_sock.as_deref()).await,
        Mode::SelfBaselineWrite { state_dir } => run_self_baseline_write(&state_dir),
        Mode::HandshakeProbe { daemon_sock } => run_handshake_probe(&daemon_sock).await,
        Mode::EsProbe => run_es_probe(),
        Mode::EsProbeSubscribe { duration_secs } => run_es_probe_subscribe(duration_secs),
        Mode::EsAuthSmoke { duration_secs } => run_es_auth_smoke(duration_secs),
        Mode::EsPathLogSmoke { duration_secs } => run_es_path_log_smoke(duration_secs),
        Mode::EsTreeFilterSmoke { duration_secs } => run_es_tree_filter_smoke(duration_secs),
        Mode::ProbeFanotify => run_probe_fanotify(),
        Mode::ProbeEbpf => run_probe_ebpf(),
    }
}

/// M03.1.C — ES client-creation probe. Calls `es_new_client`,
/// immediately tears down via `es_delete_client`, prints a one-line
/// JSON result the doctor parses. Always exits 0; caller reads the
/// JSON.
///
/// On non-macOS targets this exits with a "not supported" JSON line
/// so the doctor (cross-platform) can call it without a target_os
/// check.
fn run_es_probe() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let r = crate::es::probe_client_creation();
        // Emit the variant name verbatim plus the raw u32 for the
        // UnknownResult variant. Hand-rolled to avoid pulling
        // serde into this binary just for one line.
        let line = match r {
            crate::es::ProbeResult::UnknownResult(raw) => {
                format!(r#"{{"result":"UnknownResult","raw":{raw}}}"#)
            }
            crate::es::ProbeResult::Success => r#"{"result":"Success"}"#.into(),
            crate::es::ProbeResult::NotEntitled => r#"{"result":"NotEntitled"}"#.into(),
            crate::es::ProbeResult::NotPermitted => r#"{"result":"NotPermitted"}"#.into(),
            crate::es::ProbeResult::NotPrivileged => r#"{"result":"NotPrivileged"}"#.into(),
            crate::es::ProbeResult::InvalidArgument => r#"{"result":"InvalidArgument"}"#.into(),
            crate::es::ProbeResult::InternalError => r#"{"result":"InternalError"}"#.into(),
            crate::es::ProbeResult::TooManyClients => r#"{"result":"TooManyClients"}"#.into(),
        };
        println!("{line}");
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        println!(r#"{{"result":"NotSupportedOnThisOs"}}"#);
        Ok(())
    }
}

/// M03.1.E — subscribe to NOTIFY_EXEC for `duration_secs` seconds,
/// print the count.
fn run_es_probe_subscribe(duration_secs: u64) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let client = match crate::es::EsClient::new_counting() {
            Ok(c) => c,
            Err(e) => {
                println!(r#"{{"error":"{e}"}}"#);
                return Ok(());
            }
        };
        std::thread::sleep(std::time::Duration::from_secs(duration_secs));
        let n = client.events_received();
        println!(r#"{{"events_received":{n},"duration_secs":{duration_secs}}}"#);
        drop(client);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = duration_secs;
        println!(r#"{{"error":"NotSupportedOnThisOs"}}"#);
        Ok(())
    }
}

/// M03.1.G — subscribe to AUTH_UNLINK with the path-logging
/// handler; drain + print observed paths as JSON after the window.
fn run_es_path_log_smoke(duration_secs: u64) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let client = match crate::es::EsClient::new_path_logging() {
            Ok(c) => c,
            Err(e) => {
                println!(r#"{{"error":"{e}"}}"#);
                return Ok(());
            }
        };
        std::thread::sleep(std::time::Duration::from_secs(duration_secs));
        let n = client.events_received();
        let paths = client.drain_logged_paths();
        // Hand-render the JSON to avoid pulling serde_json into the
        // privileged binary. Path strings get backslash-escaped for
        // any quotes / backslashes; macOS paths shouldn't contain
        // control chars but we tolerate them.
        let mut paths_json = String::from("[");
        for (i, p) in paths.iter().enumerate() {
            if i > 0 {
                paths_json.push(',');
            }
            paths_json.push('"');
            for c in p.display().to_string().chars() {
                match c {
                    '"' => paths_json.push_str("\\\""),
                    '\\' => paths_json.push_str("\\\\"),
                    c if (c as u32) < 0x20 => paths_json.push_str(&format!("\\u{:04x}", c as u32)),
                    c => paths_json.push(c),
                }
            }
            paths_json.push('"');
        }
        paths_json.push(']');
        println!(
            r#"{{"events_received":{n},"paths":{paths_json},"duration_secs":{duration_secs}}}"#
        );
        drop(client);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = duration_secs;
        println!(r#"{{"error":"NotSupportedOnThisOs"}}"#);
        Ok(())
    }
}

/// M03.1.H — subscribe to AUTH_UNLINK with tree-filter handler
/// seeded with self audit_token; do a self-unlink (helper-process)
/// to prove the ACCEPT side, then drain + print. Compare against
/// `es-path-log-smoke` (no filter) for the REJECT side: external
/// rm subprocesses have different audit_tokens and get filtered
/// out.
fn run_es_tree_filter_smoke(duration_secs: u64) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let client = match crate::es::EsClient::new_tree_filtered() {
            Ok(c) => c,
            Err(e) => {
                println!(r#"{{"error":"{e}"}}"#);
                return Ok(());
            }
        };
        // Give subscription a beat to register fully.
        std::thread::sleep(std::time::Duration::from_secs(1));
        // ACCEPT-side demo: helper-process unlinks. The event's
        // process == helper, so audit_token matches the seeded
        // self-token and the path gets recorded.
        let self_test_path =
            std::env::temp_dir().join(format!("shit-es-tree-filter-self-{}", std::process::id()));
        std::fs::write(&self_test_path, b"x").ok();
        // Brief pause so the create-side syscalls have settled into
        // a stable on-disk state before we remove (helps the kernel
        // deliver a clean unlink event).
        std::thread::sleep(std::time::Duration::from_millis(100));
        std::fs::remove_file(&self_test_path).ok();
        std::thread::sleep(std::time::Duration::from_secs(duration_secs));
        let n = client.events_received();
        let paths = client.drain_logged_paths();
        let mut paths_json = String::from("[");
        for (i, p) in paths.iter().enumerate() {
            if i > 0 {
                paths_json.push(',');
            }
            paths_json.push('"');
            for c in p.display().to_string().chars() {
                match c {
                    '"' => paths_json.push_str("\\\""),
                    '\\' => paths_json.push_str("\\\\"),
                    c if (c as u32) < 0x20 => paths_json.push_str(&format!("\\u{:04x}", c as u32)),
                    c => paths_json.push(c),
                }
            }
            paths_json.push('"');
        }
        paths_json.push(']');
        println!(
            r#"{{"events_received":{n},"paths":{paths_json},"duration_secs":{duration_secs}}}"#
        );
        drop(client);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = duration_secs;
        println!(r#"{{"error":"NotSupportedOnThisOs"}}"#);
        Ok(())
    }
}

/// M03.1.F — subscribe to AUTH_UNLINK for `duration_secs` seconds,
/// respond ALLOW to every event inline, print count.
fn run_es_auth_smoke(duration_secs: u64) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let client = match crate::es::EsClient::new_auth_counting() {
            Ok(c) => c,
            Err(e) => {
                println!(r#"{{"error":"{e}"}}"#);
                return Ok(());
            }
        };
        std::thread::sleep(std::time::Duration::from_secs(duration_secs));
        let n = client.events_received();
        println!(r#"{{"events_received":{n},"duration_secs":{duration_secs}}}"#);
        drop(client);
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = duration_secs;
        println!(r#"{{"error":"NotSupportedOnThisOs"}}"#);
        Ok(())
    }
}

/// L05 — fanotify functional probe. Opens a fanotify-perm fd,
/// marks a tmpdir, writes a probe file, drains one perm event,
/// responds ALLOW, returns. Output silent; non-zero exit on any
/// failure. Doctor only checks exit code.
#[cfg(target_os = "linux")]
fn run_probe_fanotify() -> anyhow::Result<()> {
    // Init the fanotify fd (FAN_CLASS_PRE_CONTENT).
    let fd = fanotify::init_pre_content().map_err(|e| anyhow::anyhow!("init_pre_content: {e}"))?;

    // Make a tempdir and mark it. Manual mktemp to avoid the
    // tempfile dev-dep at runtime — keeps the helper binary slim
    // for the doctor probe path.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir_path = std::env::temp_dir().join(format!(
        "shit-doctor-fanotify-{}-{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir(&dir_path).map_err(|e| anyhow::anyhow!("mkdir tempdir: {e}"))?;
    struct DirGuard(std::path::PathBuf);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _guard = DirGuard(dir_path.clone());

    let dir_fd: std::os::fd::OwnedFd = std::fs::File::open(&dir_path)
        .map_err(|e| anyhow::anyhow!("open tempdir: {e}"))?
        .into();
    fanotify::mark::mark_dir_for_capture(&fd, std::os::fd::AsFd::as_fd(&dir_fd))
        .map_err(|e| anyhow::anyhow!("mark_dir_for_capture: {e}"))?;

    // Spawn a child that opens a probe file inside the marked dir.
    // We can't open it from this process — the fanotify-perm queue
    // would deadlock (we'd block waiting for ourselves to respond).
    let probe_path = dir_path.join("probe");
    let probe_str = probe_path.to_string_lossy().into_owned();
    let child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("echo x > '{probe_str}'"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("spawn /bin/sh: {e}"))?;
    let child_pid = child.id();

    // Drain one event with a 1s budget. The event arrives via
    // read(2) on the fanotify fd. Parse it, respond ALLOW, then
    // we're done.
    let raw_fd = fd.as_raw_fd();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    let mut buf = [0u8; std::mem::size_of::<libc::fanotify_event_metadata>() * 4];
    let mut events_drained = 0u32;
    while events_drained == 0 && std::time::Instant::now() < deadline {
        let mut pfd = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is a single valid pollfd; timeout in ms.
        let rc = unsafe { libc::poll(&mut pfd, 1, 100) };
        if rc <= 0 {
            continue;
        }
        // SAFETY: raw_fd is valid; buf is writable.
        let n = unsafe { libc::read(raw_fd, buf.as_mut_ptr() as _, buf.len()) };
        if n <= 0 {
            continue;
        }
        let mut off = 0usize;
        while off + std::mem::size_of::<libc::fanotify_event_metadata>() <= n as usize {
            // SAFETY: bytes [off, off+sizeof(metadata)) are valid.
            let meta: libc::fanotify_event_metadata =
                unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const _) };
            // ALLOW the syscall and close the kernel-given fd.
            if (meta.mask & libc::FAN_OPEN_PERM) != 0 {
                let response = libc::fanotify_response {
                    fd: meta.fd,
                    response: libc::FAN_ALLOW,
                };
                let ptr = &response as *const _ as *const libc::c_void;
                let sz = std::mem::size_of::<libc::fanotify_response>();
                // SAFETY: raw_fd is the fanotify fd; ptr/sz describe
                // one response struct.
                unsafe { libc::write(raw_fd, ptr, sz) };
                events_drained += 1;
            }
            if meta.fd >= 0 {
                // SAFETY: fd from the kernel; closing per fanotify API contract.
                unsafe { libc::close(meta.fd) };
            }
            off += meta.event_len as usize;
        }
    }
    // Wait for the child to actually exit (writes succeed once we
    // ALLOW). 1s should be more than enough.
    let _ = wait_child(child_pid as i32, std::time::Duration::from_secs(1));

    if events_drained >= 1 {
        Ok(())
    } else {
        anyhow::bail!("no fanotify-perm events drained within 1s budget")
    }
}

#[cfg(not(target_os = "linux"))]
fn run_probe_fanotify() -> anyhow::Result<()> {
    anyhow::bail!("probe-fanotify is Linux-only")
}

/// L05 — eBPF-LSM prerequisite probe. Calls the loader's probe
/// (read-only) and exits 0 iff prerequisites are met.
#[cfg(target_os = "linux")]
fn run_probe_ebpf() -> anyhow::Result<()> {
    let loader = ebpf::EbpfLoader::new();
    let outcome = loader.probe();
    if outcome.should_attempt_load() {
        Ok(())
    } else {
        anyhow::bail!("ebpf-lsm prerequisites not met: {}", outcome.diagnose())
    }
}

#[cfg(not(target_os = "linux"))]
fn run_probe_ebpf() -> anyhow::Result<()> {
    anyhow::bail!("probe-ebpf is Linux-only")
}

/// Wait for `pid` to exit with a wall-clock deadline. Best-effort;
/// not a thorough reaper. Used only by the L05 fanotify probe
/// where we spawned `/bin/sh -c 'echo x > probe'`.
#[cfg(target_os = "linux")]
fn wait_child(pid: i32, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let mut status = 0i32;
        // SAFETY: waitpid is well-defined; WNOHANG never blocks.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            return true;
        }
        if r < 0 {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // Timed out; reap anyway via blocking waitpid would risk a hang.
    false
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
    /// macOS EndpointSecurity (S07/M03). Pre-mutation AUTH-event
    /// interception. Requires the
    /// `com.apple.developer.endpoint-security.client` entitlement on
    /// a SIP-enforced system; usable ad-hoc on a SIP-disabled dev
    /// target. M01 ships the FsEventsDegraded fallback; M03 lights
    /// up this tier.
    EndpointSecurity,
    /// macOS FSEvents post-hoc (M01). The degraded fallback when ES
    /// is unavailable (no entitlement, or FDA not granted, or
    /// ad-hoc-signed dev build on SIP-enforced host). Events arrive
    /// after the syscall completes, so we cannot capture file
    /// content pre-images; tree-ops and the post-state are captured
    /// with `partial = true`. Honest "(degraded)" label flows
    /// through `shit list`.
    FsEventsDegraded,
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
            CaptureTier::EndpointSecurity => "endpoint-security (S07/M03)",
            CaptureTier::FsEventsDegraded => "fsevents-degraded (M01 post-hoc)",
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
    #[cfg(target_os = "macos")]
    {
        let tier = pick_macos_tier();
        tracing::info!(tier = tier.label(), "kernel capture tier picked");
        PrivilegedSetup {
            caps: shit_proto::HelperCaps {
                watch_tree: true,
                // FSEvents is post-hoc — no syscall-blocking primitive.
                // M03's EndpointSecurity tier flips this to true.
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
        target_os = "macos",
    )))]
    {
        // No supported kernel-tier on this OS.
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
    // AU07 — canonical shim install path matches the cargo cdylib
    // artifact name (`libshit_preload_shim.{so,dylib}`). The
    // `SHIT_PRELOAD_SHIM_PATH` env var overrides for smokes that
    // need to exercise the kqueue+preload tier without sudo access
    // to /usr/local/lib/shit/. Must stay in sync with the
    // doctor probe in `crates/shit/src/doctor/probes/bsd.rs`.
    let shim_path = std::env::var_os("SHIT_PRELOAD_SHIM_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/local/lib/shit/libshit_preload_shim.so"));
    if shim_path.is_file() {
        return CaptureTier::KqueuePreloadShim;
    }
    CaptureTier::KqueueOnly
}

/// Decide which macOS capture tier to use. M01 always returns
/// `FsEventsDegraded`. M03 will try `EndpointSecurity` first
/// (entitlement + FDA probe) and fall back here.
///
/// The `partial = true` flag on every captured event downstream is
/// what flows the "(degraded)" label through `shit list`.
#[cfg(target_os = "macos")]
fn pick_macos_tier() -> CaptureTier {
    CaptureTier::FsEventsDegraded
}

/// Bundles the long-lived state for the eBPF-LSM tier (L04). Held
/// in the run loop's outer scope so the readers/loader stay alive
/// for the helper's lifetime. The request loop receives a
/// [`LsmDispatch`] clone for WatchTree/UnwatchTree handling — the
/// reader/loader fields don't cross the `spawn_blocking` boundary.
#[cfg(target_os = "linux")]
struct LsmCaptureState {
    /// Reader threads. One per ringbuf (`unlink_events`,
    /// `setattr_events`, ...). Dropped on shutdown — `LsmReader::drop`
    /// stops each reader and joins.
    _readers: Vec<ebpf::LsmReader>,
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
    /// One flush handle per ring-buffer reader. UnwatchTree drains
    /// them all before acknowledging the close barrier.
    flush: Vec<ebpf::LsmFlushHandle>,
}

/// Bound on draining every eBPF ring-buffer reader at UnwatchTree.
#[cfg(target_os = "linux")]
const LSM_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The eBPF-LSM programs, attached, with their ring buffers taken and
/// no reader thread spawned yet. #226: the helper drops its startup
/// capabilities between [`load_ebpf_lsm`] and [`spawn_lsm_readers`],
/// because each thread copies its creator's capability sets.
#[cfg(target_os = "linux")]
struct LsmLoaded {
    loader: ebpf::EbpfLoader,
    unlink_rb: aya::maps::RingBuf<aya::maps::MapData>,
    setattr_rb: aya::maps::RingBuf<aya::maps::MapData>,
    mkdir_rb: aya::maps::RingBuf<aya::maps::MapData>,
    create_rb: aya::maps::RingBuf<aya::maps::MapData>,
    open_rb: aya::maps::RingBuf<aya::maps::MapData>,
    rename_rb: aya::maps::RingBuf<aya::maps::MapData>,
    symlink_rb: aya::maps::RingBuf<aya::maps::MapData>,
    link_rb: aya::maps::RingBuf<aya::maps::MapData>,
    rmdir_rb: aya::maps::RingBuf<aya::maps::MapData>,
    mknod_rb: aya::maps::RingBuf<aya::maps::MapData>,
    release_rb_opt: Option<aya::maps::RingBuf<aya::maps::MapData>>,
}

/// Load and attach the eBPF-LSM programs and take their ring buffers.
/// Spawns no thread.
///
/// Requires CAP_BPF + CAP_PERFMON on the calling process. Call
/// BEFORE `priv_linux::finish_startup`, which drops them.
#[cfg(target_os = "linux")]
fn load_ebpf_lsm() -> anyhow::Result<LsmLoaded> {
    let mut loader = ebpf::EbpfLoader::new();
    loader
        .load_lsm_unlink()
        .map_err(|e| anyhow::anyhow!("load_lsm_unlink failed: {e}"))?;
    loader
        .load_lsm_setattr()
        .map_err(|e| anyhow::anyhow!("load_lsm_setattr failed: {e}"))?;
    loader
        .load_lsm_mkdir()
        .map_err(|e| anyhow::anyhow!("load_lsm_mkdir failed: {e}"))?;
    loader
        .load_lsm_create()
        .map_err(|e| anyhow::anyhow!("load_lsm_create failed: {e}"))?;
    loader
        .load_lsm_open()
        .map_err(|e| anyhow::anyhow!("load_lsm_open failed: {e}"))?;
    loader
        .load_lsm_rename()
        .map_err(|e| anyhow::anyhow!("load_lsm_rename failed: {e}"))?;
    loader
        .load_lsm_symlink()
        .map_err(|e| anyhow::anyhow!("load_lsm_symlink failed: {e}"))?;
    loader
        .load_lsm_link()
        .map_err(|e| anyhow::anyhow!("load_lsm_link failed: {e}"))?;
    loader
        .load_lsm_rmdir()
        .map_err(|e| anyhow::anyhow!("load_lsm_rmdir failed: {e}"))?;
    // AU29 — inode_mknod. Standard kernel hook (>=2.6); fatal-on-
    // failure like the other inode_* hooks. Captures mkfifo/mknod
    // for FIFO/Socket/Block/Char kinds that inode_create misses.
    loader
        .load_lsm_mknod()
        .map_err(|e| anyhow::anyhow!("load_lsm_mknod failed: {e}"))?;
    // L04.2 — file_release is best-effort. The hook is present in
    // BTF on kernel 7.0+ but the CI runner matrix includes 6.8 where
    // the symbol is absent. Log + continue when the hook can't be
    // resolved; the rest of the LSM tier (unlink/setattr/open/...)
    // stays functional. In-place-write capture degrades to "via
    // file_open's open-time snapshot only" on older kernels.
    let release_loaded = match loader.load_lsm_release() {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                err = %e,
                "load_lsm_release unavailable on this kernel; \
                 in-place-write capture limited to file_open path"
            );
            false
        }
    };
    let unlink_rb = loader.take_unlink_ringbuf().ok_or_else(|| {
        anyhow::anyhow!("take_unlink_ringbuf returned None after successful load")
    })?;
    let setattr_rb = loader.take_setattr_ringbuf().ok_or_else(|| {
        anyhow::anyhow!("take_setattr_ringbuf returned None after successful load")
    })?;
    let mkdir_rb = loader
        .take_mkdir_ringbuf()
        .ok_or_else(|| anyhow::anyhow!("take_mkdir_ringbuf returned None after successful load"))?;
    let create_rb = loader.take_create_ringbuf().ok_or_else(|| {
        anyhow::anyhow!("take_create_ringbuf returned None after successful load")
    })?;
    let open_rb = loader
        .take_open_ringbuf()
        .ok_or_else(|| anyhow::anyhow!("take_open_ringbuf returned None after successful load"))?;
    let rename_rb = loader.take_rename_ringbuf().ok_or_else(|| {
        anyhow::anyhow!("take_rename_ringbuf returned None after successful load")
    })?;
    let symlink_rb = loader.take_symlink_ringbuf().ok_or_else(|| {
        anyhow::anyhow!("take_symlink_ringbuf returned None after successful load")
    })?;
    let link_rb = loader
        .take_link_ringbuf()
        .ok_or_else(|| anyhow::anyhow!("take_link_ringbuf returned None after successful load"))?;
    let rmdir_rb = loader
        .take_rmdir_ringbuf()
        .ok_or_else(|| anyhow::anyhow!("take_rmdir_ringbuf returned None after successful load"))?;
    let mknod_rb = loader
        .take_mknod_ringbuf()
        .ok_or_else(|| anyhow::anyhow!("take_mknod_ringbuf returned None after successful load"))?;
    // L04.2 release ringbuf is None on kernels where the hook wasn't
    // loaded (see release_loaded above). Skip spawning the reader
    // in that case.
    let release_rb_opt = if release_loaded {
        Some(loader.take_release_ringbuf().ok_or_else(|| {
            anyhow::anyhow!("take_release_ringbuf returned None after successful load")
        })?)
    } else {
        None
    };

    Ok(LsmLoaded {
        loader,
        unlink_rb,
        setattr_rb,
        mkdir_rb,
        create_rb,
        open_rb,
        rename_rb,
        symlink_rb,
        link_rb,
        rmdir_rb,
        mknod_rb,
        release_rb_opt,
    })
}

/// Spawn the userspace reader threads for loaded eBPF-LSM programs,
/// wired to dispatch into the linux capture runtime. Returns the
/// long-lived state to keep alive. Call after
/// `priv_linux::finish_startup` so the readers hold no capability.
#[cfg(target_os = "linux")]
fn spawn_lsm_readers(
    loaded: LsmLoaded,
    runtime: Option<Arc<std::sync::Mutex<capture::linux::LinuxCaptureRuntime>>>,
    excluded_pids: Vec<u32>,
) -> LsmCaptureState {
    let LsmLoaded {
        mut loader,
        unlink_rb,
        setattr_rb,
        mkdir_rb,
        create_rb,
        open_rb,
        rename_rb,
        symlink_rb,
        link_rb,
        rmdir_rb,
        mknod_rb,
        release_rb_opt,
    } = loaded;
    let mut tree_map = fanotify::tree::TreeMap::new();
    tree_map.set_excluded(excluded_pids.iter().map(|&p| p as i32).collect());
    let tree = Arc::new(std::sync::Mutex::new(tree_map));

    let sink: Arc<dyn ebpf::LsmEventSink> = match runtime.clone() {
        Some(rt) => Arc::new(ebpf::ringbuf_reader::LinuxCaptureSink {
            runtime: rt,
            tree: Arc::clone(&tree),
            excluded_pids,
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
    let idle = std::time::Duration::from_micros(250);
    let unlink_reader = ebpf::LsmReader::spawn(
        unlink_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("unlink"),
    );
    let setattr_reader = ebpf::LsmReader::spawn_setattr(
        setattr_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("setattr"),
    );
    let mkdir_reader = ebpf::LsmReader::spawn_mkdir(
        mkdir_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("mkdir"),
    );
    let create_reader = ebpf::LsmReader::spawn_create(
        create_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("create"),
    );
    let open_reader = ebpf::LsmReader::spawn_open(
        open_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("open"),
    );
    let rename_reader = ebpf::LsmReader::spawn_rename(
        rename_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("rename"),
    );
    // DR-CR-55: both new ringbufs carry shit_create_event records;
    // reuse spawn_create so they route through the on_create sink.
    let symlink_reader = ebpf::LsmReader::spawn_create(
        symlink_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("symlink"),
    );
    let link_reader = ebpf::LsmReader::spawn_create(
        link_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("link"),
    );
    // G03: rmdir uses the same wire shape as unlink but routes via
    // on_rmdir → handle_lsm_unlink with is_directory=true.
    let rmdir_reader = ebpf::LsmReader::spawn_rmdir(
        rmdir_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("rmdir"),
    );
    // AU29: mknod payload mirrors inode_create's; the dispatcher
    // routes through on_create. handle_lsm_create's mode-aware
    // path resolves Fifo/Socket from the S_IF bits.
    let mknod_reader = ebpf::LsmReader::spawn_mknod(
        mknod_rb,
        Arc::clone(&sink),
        idle,
        loader.take_loss_counter("mknod"),
    );
    // L04.2: file_release fires at last writable-fd close; the
    // handler diffs current content against the open-time
    // snapshot and emits a CapturedPreImage iff they differ.
    // Optional — only spawned on kernels where the hook loaded.
    let release_loss = loader.take_loss_counter("release");
    let release_reader = release_rb_opt
        .map(|rb| ebpf::LsmReader::spawn_release(rb, Arc::clone(&sink), idle, release_loss));

    if release_reader.is_some() {
        tracing::info!(
            "ebpf-lsm readers spawned: unlink + setattr + mkdir + create + open + rename + symlink + link + rmdir + release"
        );
    } else {
        tracing::info!(
            "ebpf-lsm readers spawned: unlink + setattr + mkdir + create + open + rename + symlink + link + rmdir (release unavailable on this kernel)"
        );
    }
    let mut readers = vec![
        unlink_reader,
        setattr_reader,
        mkdir_reader,
        create_reader,
        open_reader,
        rename_reader,
        symlink_reader,
        link_reader,
        rmdir_reader,
        mknod_reader,
    ];
    if let Some(r) = release_reader {
        readers.push(r);
    }
    let flush: Vec<ebpf::LsmFlushHandle> =
        readers.iter().map(ebpf::LsmReader::flush_handle).collect();
    if let Some(rt) = &runtime {
        let staging = rt
            .lock()
            .map(|g| g.staging_dir().to_path_buf())
            .unwrap_or_else(|e| e.into_inner().staging_dir().to_path_buf());
        let trusted = probe_fmode_created(&staging, &flush);
        if let Ok(mut g) = rt.lock() {
            g.set_fmode_created_trusted(trusted);
        }
    }
    LsmCaptureState {
        _readers: readers,
        _loader: loader,
        dispatch: LsmDispatch {
            tree,
            runtime,
            flush,
        },
    }
}

/// Check that `file_open` reports `FMODE_CREATED` the way the born set
/// assumes (R3 slice B, D-11). The bit is a kernel macro, not BTF, so
/// the helper creates a file in its staging dir, reopens it, and looks
/// at its own two open events. Any failure leaves the bit untrusted;
/// birth is then proven only by create stats and walked parents.
#[cfg(target_os = "linux")]
fn probe_fmode_created(staging: &std::path::Path, flush: &[ebpf::LsmFlushHandle]) -> bool {
    use std::os::unix::fs::MetadataExt;
    let path = staging.join(format!(".fmode-created-probe-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    ebpf::ringbuf_reader::fmode_probe_begin(std::process::id());
    let target = (|| {
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .ok()?;
        let meta = created.metadata().ok()?;
        drop(created);
        let reopened = std::fs::OpenOptions::new().write(true).open(&path).ok()?;
        drop(reopened);
        Some((meta.dev(), meta.ino()))
    })();
    let flushed = ebpf::flush_all_readers(flush, LSM_FLUSH_TIMEOUT);
    let seen = ebpf::ringbuf_reader::fmode_probe_finish();
    let _ = std::fs::remove_file(&path);
    let passed = match (target, &flushed) {
        (Some(target), Ok(())) => capture::linux::fmode_created_probe_passed(&seen, target),
        _ => false,
    };
    if passed {
        tracing::info!("FMODE_CREATED probe passed; creating opens prove birth");
    } else {
        tracing::warn!(
            ?target,
            flush = ?flushed,
            events = seen.len(),
            "FMODE_CREATED probe failed; birth falls back to create stats and walked parents"
        );
    }
    passed
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
                tracing::info!(
                    "SHIT_FORCE_TIER=fanotify-perm — using Fanotify despite ebpf-lsm being available"
                );
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

/// Resolve the active Linux capture tier after the selected eBPF-LSM
/// tier has completed its real load/attach attempt.
///
/// Keeping the transition pure makes the safety-sensitive distinction
/// between an operator-forced tier and automatic selection directly
/// testable. The caller uses the returned tier to decide which reader
/// to start before completing the helper handshake.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxCaptureStartupError {
    /// The operator explicitly required eBPF-LSM; never silently use
    /// a different tier.
    ForcedEbpfLoadFailed,
    /// The automatic eBPF attempt failed and no fanotify fd exists.
    NoFallback,
    /// Tier selection chose fanotify, but privileged setup did not
    /// provide its fd. This is an internal startup invariant failure.
    FanotifyUnavailable,
    /// A non-Linux capture tier reached the Linux startup path.
    InvalidPreferredTier,
}

#[cfg(any(target_os = "linux", test))]
fn resolve_linux_capture_startup(
    preferred_tier: CaptureTier,
    ebpf_boot_succeeded: bool,
    forced_tier: Option<&str>,
    have_fanotify_fd: bool,
) -> Result<CaptureTier, LinuxCaptureStartupError> {
    match preferred_tier {
        CaptureTier::EbpfLsm if ebpf_boot_succeeded => Ok(CaptureTier::EbpfLsm),
        CaptureTier::EbpfLsm if forced_tier == Some("ebpf-lsm") => {
            Err(LinuxCaptureStartupError::ForcedEbpfLoadFailed)
        }
        CaptureTier::EbpfLsm if have_fanotify_fd => Ok(CaptureTier::Fanotify),
        CaptureTier::EbpfLsm => Err(LinuxCaptureStartupError::NoFallback),
        CaptureTier::Fanotify | CaptureTier::EbpfLsmAvailableButDeferred if have_fanotify_fd => {
            Ok(CaptureTier::Fanotify)
        }
        CaptureTier::Fanotify | CaptureTier::EbpfLsmAvailableButDeferred => {
            Err(LinuxCaptureStartupError::FanotifyUnavailable)
        }
        CaptureTier::Degraded => Ok(CaptureTier::Degraded),
        CaptureTier::EndpointSecurity
        | CaptureTier::FsEventsDegraded
        | CaptureTier::KqueueOnly
        | CaptureTier::KqueuePreloadShim
        | CaptureTier::ZfsSnapshot => Err(LinuxCaptureStartupError::InvalidPreferredTier),
    }
}

/// Build the Linux capture runtime for a non-degraded tier. On failure the
/// helper falls back to `CaptureTier::Degraded` rather than exiting.
#[cfg(target_os = "linux")]
fn degrade_on_runtime_failure<T, E: std::fmt::Display>(
    tier: CaptureTier,
    init: impl FnOnce() -> Result<T, E>,
) -> (Option<T>, CaptureTier) {
    if matches!(tier, CaptureTier::Degraded) {
        return (None, CaptureTier::Degraded);
    }
    match init() {
        Ok(rt) => (Some(rt), tier),
        Err(e) => {
            tracing::error!(
                err = %e,
                requested_tier = tier.label(),
                "linux capture runtime failed to initialize; degrading (no kernel capture this boot)"
            );
            (None, CaptureTier::Degraded)
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod runtime_degrade_tests {
    use super::{CaptureTier, degrade_on_runtime_failure};

    #[test]
    fn init_failure_degrades_instead_of_aborting() {
        let (rt, tier) = degrade_on_runtime_failure::<(), _>(CaptureTier::Fanotify, || Err("boom"));
        assert!(rt.is_none());
        assert_eq!(tier, CaptureTier::Degraded);
    }

    #[test]
    fn init_success_keeps_tier() {
        let (rt, tier) = degrade_on_runtime_failure(CaptureTier::EbpfLsm, || Ok::<_, &str>(7));
        assert_eq!(rt, Some(7));
        assert_eq!(tier, CaptureTier::EbpfLsm);
    }

    #[test]
    fn degraded_never_runs_init() {
        let (rt, tier) = degrade_on_runtime_failure::<(), &str>(CaptureTier::Degraded, || {
            panic!("must not init")
        });
        assert!(rt.is_none());
        assert_eq!(tier, CaptureTier::Degraded);
    }
}

#[cfg(test)]
mod linux_capture_startup_tests {
    use super::{CaptureTier, LinuxCaptureStartupError, resolve_linux_capture_startup};

    #[test]
    fn automatic_ebpf_failure_selects_fanotify_reader() {
        assert_eq!(
            resolve_linux_capture_startup(CaptureTier::EbpfLsm, false, None, true),
            Ok(CaptureTier::Fanotify)
        );
    }

    #[test]
    fn forced_ebpf_failure_is_an_error_even_with_fanotify() {
        assert_eq!(
            resolve_linux_capture_startup(CaptureTier::EbpfLsm, false, Some("ebpf-lsm"), true),
            Err(LinuxCaptureStartupError::ForcedEbpfLoadFailed)
        );
    }

    #[test]
    fn automatic_ebpf_failure_without_fanotify_is_an_error() {
        assert_eq!(
            resolve_linux_capture_startup(CaptureTier::EbpfLsm, false, None, false),
            Err(LinuxCaptureStartupError::NoFallback)
        );
    }

    #[test]
    fn successful_ebpf_boot_keeps_ebpf_active() {
        assert_eq!(
            resolve_linux_capture_startup(CaptureTier::EbpfLsm, true, Some("ebpf-lsm"), true),
            Ok(CaptureTier::EbpfLsm)
        );
    }

    #[test]
    fn selected_fanotify_requires_its_fd() {
        assert_eq!(
            resolve_linux_capture_startup(CaptureTier::Fanotify, false, None, false),
            Err(LinuxCaptureStartupError::FanotifyUnavailable)
        );
    }

    #[test]
    fn deferred_ebpf_tier_runs_fanotify() {
        assert_eq!(
            resolve_linux_capture_startup(
                CaptureTier::EbpfLsmAvailableButDeferred,
                false,
                Some("fanotify-perm"),
                true,
            ),
            Ok(CaptureTier::Fanotify)
        );
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

    // Spawn the kernel-tier reader BEFORE the handshake completes.
    // Once `handshake::perform_helper_side` returns, the daemon is
    // free to dispatch `WatchTree` / `PreExec` (and on the shell side,
    // the smoke's mutation may run any moment). If we hadn't loaded
    // BPF programs / spawned the fanotify reader by then, the kernel
    // syscall the smoke is exercising fires before its LSM hook is
    // attached and the event is lost. ~260ms of BPF program loading
    // landed us with 0 captured events across every L02/L03 smoke
    // on the linux-kernel-capture matrix; fix is to make
    // handshake-complete genuinely mean "capture is live".
    //
    // Exactly one of fanotify / ebpf-lsm gets wired per-boot.
    // `pick_linux_tier` chooses the preference; an automatic eBPF
    // load failure can still activate the already-open fanotify fd.
    // The fanotify branch mirrors L01; the ebpf-lsm branch is L04's
    // promotion path.
    //
    // Both readers feed the SAME `LinuxCaptureRuntime` instance. The
    // unused fd from the other tier (the fanotify fd after a
    // successful eBPF boot) is dropped once startup is resolved.
    #[cfg(target_os = "linux")]
    let (fanotify_state, lsm_state) = {
        let staging_dir = cli.state_dir.join("helper-staging");
        // A runtime that fails to initialize degrades the helper (as trunk
        // did) instead of aborting it; the daemon keeps working without
        // kernel capture and watch_tree is ignored for this boot.
        let (capture_rt, setup_tier) = degrade_on_runtime_failure(setup.tier, || {
            capture::linux::LinuxCaptureRuntime::new(staging_dir, Arc::clone(&conn))
        });
        let capture_rt = capture_rt.map(|rt| Arc::new(std::sync::Mutex::new(rt)));

        let mut fanotify_fd = setup.fanotify_fd;

        // eBPF-LSM branch — L04. Load + attach happens here while
        // the helper still has CAP_BPF + CAP_PERFMON (before
        // sandbox::enter). The returned state carries both the
        // tree map (for WatchTree dispatch) and the LsmReader join
        // handle (for graceful shutdown).
        let (lsm_loaded, ebpf_load_error): (Option<LsmLoaded>, Option<anyhow::Error>) =
            if matches!(setup_tier, CaptureTier::EbpfLsm) {
                match load_ebpf_lsm() {
                    Ok(loaded) => (Some(loaded), None),
                    Err(e) => (None, Some(e)),
                }
            } else {
                (None, None)
            };

        // #226: kernel-tier setup is over (programs attached, or the
        // fanotify fd opened in privileged_setup). Drop the startup
        // capabilities before any reader thread exists: each thread
        // copies its creator's sets. A failure here is a privilege
        // error and stops the helper; it is never treated as an eBPF
        // load failure or a reason to fall back to fanotify.
        priv_linux::finish_startup()
            .map_err(|e| anyhow::anyhow!("privilege drop failed; refusing to start: {e}"))?;

        // Exclude the helper's own pid + the daemon's pid from LSM event
        // dispatch. Both run as descendants of the smoke harness (or the
        // user's shell), so their internal file ops would otherwise be
        // journaled as user-visible mutations. Daemon's blob-staging
        // rename was the load-bearing miss surfaced by L04.1.
        let lsm_state: Option<LsmCaptureState> = lsm_loaded.map(|loaded| {
            let excluded = vec![std::process::id(), cli.daemon_pid];
            spawn_lsm_readers(loaded, capture_rt.clone(), excluded)
        });

        let forced_tier = std::env::var("SHIT_FORCE_TIER").ok();
        let active_tier = match resolve_linux_capture_startup(
            setup_tier,
            lsm_state.is_some(),
            forced_tier.as_deref(),
            fanotify_fd.is_some(),
        ) {
            Ok(tier) => tier,
            Err(LinuxCaptureStartupError::ForcedEbpfLoadFailed) => {
                let detail = ebpf_load_error
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown eBPF loader error".into());
                return Err(anyhow::anyhow!(
                    "SHIT_FORCE_TIER=ebpf-lsm but load failed: {detail}"
                ));
            }
            Err(LinuxCaptureStartupError::NoFallback) => {
                let detail = ebpf_load_error
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown eBPF loader error".into());
                return Err(anyhow::anyhow!(
                    "ebpf-lsm load failed and fanotify is unavailable; refusing to complete the helper handshake without live Linux capture: {detail}"
                ));
            }
            Err(LinuxCaptureStartupError::FanotifyUnavailable) => {
                return Err(anyhow::anyhow!(
                    "fanotify capture selected but no fanotify fd is available; refusing to complete the helper handshake"
                ));
            }
            Err(LinuxCaptureStartupError::InvalidPreferredTier) => {
                return Err(anyhow::anyhow!(
                    "non-Linux capture tier reached Linux startup: {}",
                    setup_tier.label()
                ));
            }
        };

        if matches!(active_tier, CaptureTier::Fanotify)
            && let Some(e) = ebpf_load_error.as_ref()
        {
            tracing::warn!(
                err = %e,
                "ebpf-lsm load failed; starting fanotify fallback"
            );
        }

        // Start fanotify only after the eBPF load result is known so
        // automatic selection can actually fall back. Reaching this
        // branch without the fd violates the tier-selection invariant;
        // fail before the handshake instead of claiming capture is live.
        let fanotify_state: Option<fanotify::runtime::FanotifyState> = if matches!(
            active_tier,
            CaptureTier::Fanotify
        ) {
            let fd = fanotify_fd.take().ok_or_else(|| {
                anyhow::anyhow!(
                    "fanotify capture selected but no fanotify fd is available; refusing to complete the helper handshake"
                )
            })?;
            let rt = capture_rt.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "fanotify capture selected without a capture runtime; refusing to complete the helper handshake"
                )
            })?;
            let state = fanotify::runtime::FanotifyState::new(fd).with_capture_runtime(rt);
            let reader_state = state.clone();
            std::thread::Builder::new()
                .name("fanotify-reader".into())
                .spawn(move || fanotify::runtime::reader_thread(reader_state))
                .expect("spawn fanotify reader");
            tracing::info!(
                tier = CaptureTier::Fanotify.label(),
                fallback_from_ebpf = matches!(setup_tier, CaptureTier::EbpfLsm),
                "kernel capture tier active"
            );
            Some(state)
        } else {
            tracing::info!(
                tier = active_tier.label(),
                "skipping fanotify reader for this tier"
            );
            None
        };

        (fanotify_state, lsm_state)
    };

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

    // B05 Phase B — pre-cap_enter `O_DIRECTORY` open of `/`.
    // capsicum's `cap_enter(2)` forbids absolute-path opens once
    // active. We pre-open `/` here and thread the fd through to
    // capture::bsd::spawn so the kqueue pump can do
    // `openat(slash_fd, abspath_minus_slash, ...)` for arbitrary
    // watch roots at runtime. On non-FreeBSD this is a no-op;
    // the capture runtime sees None and falls back to absolute opens.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    let slash_fd: Option<Arc<std::os::fd::OwnedFd>> = {
        use std::os::fd::FromRawFd;
        let cpath = std::ffi::CString::new("/").unwrap();
        // SAFETY: "/" is a stable, always-present directory; open
        // with O_DIRECTORY|O_RDONLY|O_CLOEXEC returns a dir fd or -1.
        let raw = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            tracing::warn!(
                err = ?std::io::Error::last_os_error(),
                "open(/) for slash_fd failed; cap_enter would be unsafe — skipping",
            );
            None
        } else {
            // SAFETY: raw is a fresh kernel-allocated fd we now own.
            Some(Arc::new(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) }))
        }
    };

    // S24.B — BSD kqueue capture runtime. Spawn the pump + drain
    // threads *before* sandbox entry so any future cap_enter sees
    // the staging-dir fds + slash_fd already open.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    let bsd_capture: Option<capture::bsd::CaptureControl> = {
        let staging_dir = cli.state_dir.join("helper-staging");
        match capture::bsd::spawn(Arc::clone(&conn), staging_dir, slash_fd.clone()) {
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

    // M01.A: macOS FSEvents-degraded capture producer. Mirrors the
    // BSD spawn shape.
    //
    // M03.1.I.5: ES producer (`capture::macos_es`) spawns ALONGSIDE
    // FSEvents per the coexistence ratification (design doc Decision
    // 3). Both feed the daemon; CapturedPreImage (ES) and
    // TreeOp::Unlink (FSEvents) are distinct event kinds so the
    // daemon doesn't dedup them against each other. The ES producer
    // only succeeds inside the SIP+AuthRoot+AMFI-bypassed VM today
    // (or, in production, with the entitlement); on a stock dev mac
    // it returns NotEntitled and we proceed FSEvents-only.
    #[cfg(target_os = "macos")]
    let macos_capture: Option<capture::macos::CaptureControl> = {
        match capture::macos::spawn(Arc::clone(&conn)) {
            Ok((ctrl, _join)) => {
                tracing::info!("macos fsevents capture runtime spawned");
                Some(ctrl)
            }
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    "macos fsevents capture runtime failed to start; continuing without it"
                );
                None
            }
        }
    };

    // M03.1.I.5: ES producer (coexists with FSEvents). spawn() only
    // creates the thread; EsClient creation happens inside the pump
    // and fails late (NotEntitled) on environments without the
    // entitlement — the pump thread logs + exits cleanly, the
    // CaptureControl handle still exists but its dispatches become
    // no-ops once the worker is gone. That's the desired degraded
    // posture for stock-Mac dev environments.
    #[cfg(target_os = "macos")]
    let macos_es_capture: Option<capture::macos_es::CaptureControl> = {
        let staging_dir = cli.state_dir.join("helper-staging");
        match capture::macos_es::spawn(Arc::clone(&conn), staging_dir) {
            Ok((ctrl, _join)) => {
                tracing::info!("macos endpoint-security capture runtime spawned");
                Some(ctrl)
            }
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    "macos endpoint-security capture runtime failed to start; \
                     continuing with FSEvents only"
                );
                None
            }
        }
    };

    // Sandbox entry — per-OS module decides what to do.
    sandbox::enter(&cli.state_dir)?;

    // B05 Phase C — Capsicum capability mode default-on. Opt out via
    // `SHIT_CAPSICUM=0`. Requires slash_fd (pre-cap_enter `/` open)
    // for runtime watch-root opens, and WatchTree.cwd_path (B05.10)
    // to avoid cross-pid sysctl(KERN_PROC_CWD) which isn't capsicum-
    // whitelisted in FreeBSD 14.
    #[cfg(target_os = "freebsd")]
    {
        let opt_out = std::env::var("SHIT_CAPSICUM").as_deref() == Ok("0");
        if !opt_out && slash_fd.is_some() {
            match capsicum_bsd::enter_capability_mode() {
                Ok(()) => {
                    tracing::info!("entered Capsicum capability mode (default-on)");
                }
                Err(e) => {
                    tracing::warn!(err = %e, "cap_enter failed; continuing without capability mode");
                }
            }
        } else if opt_out {
            tracing::info!("SHIT_CAPSICUM=0 — Capsicum capability mode disabled");
        } else {
            tracing::warn!(
                "slash_fd unavailable — skipping cap_enter to avoid bricking the helper"
            );
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
    #[cfg(target_os = "macos")]
    let request_macos_capture = macos_capture.clone();
    #[cfg(target_os = "macos")]
    let request_macos_es_capture = macos_es_capture.clone();
    #[cfg(target_os = "linux")]
    let peer_uid = outcome.daemon_uid;
    let request_handle = tokio::task::spawn_blocking(move || {
        request_loop(
            request_conn,
            #[cfg(target_os = "linux")]
            peer_uid,
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
            #[cfg(target_os = "macos")]
            request_macos_capture,
            #[cfg(target_os = "macos")]
            request_macos_es_capture,
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

    // M01.A: same wind-down shape for macOS. Drop on CaptureControl
    // closes the control channel; the FSEvents pump exits on its
    // next iteration.
    #[cfg(target_os = "macos")]
    if let Some(ctrl) = &macos_capture {
        ctrl.shutdown();
    }
    #[cfg(target_os = "macos")]
    drop(macos_capture);

    // M03.1.I.5: shut down the ES pump alongside FSEvents. Same
    // best-effort posture — the EsClient is held by PumpState
    // (!Send) and only drops when the pump thread exits, which
    // happens after it processes our Shutdown ControlMsg.
    #[cfg(target_os = "macos")]
    if let Some(ctrl) = &macos_es_capture {
        ctrl.shutdown();
    }
    #[cfg(target_os = "macos")]
    drop(macos_es_capture);

    Ok(())
}

/// The hook-reported watch cwd, canonicalized so captured paths match
/// what `/proc/<pid>/cwd` would report. `/proc/<pid>/cwd` alone is racy
/// for a short-lived root process (issue #22 family).
#[cfg(target_os = "linux")]
fn validated_linux_watch_cwd(raw: &str) -> Result<WatchCwd, String> {
    if !std::path::Path::new(raw).is_absolute() {
        return Err(format!("watch cwd {raw:?} is not absolute"));
    }
    open_watch_dir(raw).map_err(|e| format!("watch cwd {raw:?} is unavailable: {e}"))
}

/// #230 - a Linux watch root, held open. `path` is what the held fd
/// names (for pre-opens and logs); the fanotify mark is made on `fd`.
#[cfg(target_os = "linux")]
struct WatchCwd {
    fd: std::os::fd::OwnedFd,
    path: PathBuf,
}

/// Open `path` as a directory for reading with the helper's own
/// credentials. After startup the helper has no effective capability
/// (#226) and its euid is the peer's uid (checked by
/// [`watch_scope::WatchScope`]), so this open succeeds only for a
/// directory the peer could open itself. A deleted directory (no links
/// left) is refused.
#[cfg(target_os = "linux")]
fn open_watch_dir(path: &str) -> Result<WatchCwd, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c = std::ffi::CString::new(path).map_err(|e| format!("path contains NUL: {e}"))?;
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if st.st_nlink == 0 {
        return Err("the directory was deleted".to_string());
    }
    let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map_err(|e| format!("cannot name the opened directory: {e}"))?;
    Ok(WatchCwd { fd, path })
}

/// Resolve the Linux watch root: the hook-reported cwd, or the root
/// process's real cwd when that report cannot be used.
///
/// The hook path crosses the wire as a lossy string, so a non-UTF-8
/// directory arrives with U+FFFD in it. It cannot name the real directory
/// even if a path spelled that way exists. A stale `$PWD`, after the
/// directory was renamed, does not resolve either. Canonicalizing the
/// magic link gives real bytes, and fails for a deleted cwd.
#[cfg(target_os = "linux")]
fn resolve_linux_watch_cwd(raw: &str, root_pid: u32) -> Result<WatchCwd, String> {
    let reported = if raw.contains(char::REPLACEMENT_CHARACTER) {
        Err(format!("watch cwd {raw:?} is not valid UTF-8"))
    } else {
        validated_linux_watch_cwd(raw)
    };
    reported.or_else(|reason| open_watch_dir(&format!("/proc/{root_pid}/cwd")).map_err(|_| reason))
}

/// Close-barrier marker for `UnwatchTree`. Sent on every path, degraded
/// included: it means "nothing more will arrive for this command".
/// macOS sends it through `capture::UnwatchFlushMarker` instead.
#[cfg(not(target_os = "macos"))]
fn send_unwatch_flushed(conn: &ipc::Conn, command: shit_planner::events::CommandId) {
    let resp = shit_proto::HelperResponse::UnwatchTreeFlushed {
        session: command.session,
        command_seq: command.seq,
    };
    if let Err(e) = conn.send_response(&resp) {
        tracing::warn!(err = %e, %command, "UnwatchTreeFlushed send failed; daemon close will time out");
    }
}

/// Record a WatchTree. Returns false for a command already being
/// watched: a duplicate must not reset its capture window, and it is
/// reported as an observation so strict mode can refuse the command.
fn begin_watch(
    conn: &ipc::Conn,
    active_watches: &mut std::collections::BTreeSet<shit_planner::events::CommandId>,
    command: shit_planner::events::CommandId,
) -> bool {
    if active_watches.insert(command) {
        return true;
    }
    tracing::warn!(%command, "duplicate WatchTree ignored");
    capture::accounting::send_capture_observation(
        conn,
        command,
        None,
        "duplicate WatchTree for an active command was ignored".to_string(),
    );
    false
}

/// #230 - a WatchTree the peer may not make: nothing is tracked or
/// marked. The refusal is logged, reported as a capture observation
/// (journaled in strict mode), and returned as the WatchTreeFailed
/// reason.
#[cfg(target_os = "linux")]
fn refuse_watch(
    conn: &ipc::Conn,
    command: shit_planner::events::CommandId,
    root_pid: u32,
    reason: &str,
) -> String {
    tracing::warn!(%command, root_pid, %reason, "WatchTree refused");
    let detail = format!("watch refused: {reason}");
    capture::accounting::send_capture_observation(conn, command, None, detail.clone());
    detail
}

/// Linux WatchTree attach. `Ok` means the tier is set up for this
/// command, possibly with less than a full capture: no tier at all, or
/// an LSM attach whose cwd is unusable. Those are reported as
/// observations and still count as ready, as on trunk. `Err` is a
/// fanotify attach failure: the tree stays tracked, as on trunk, but no
/// mark covers the cwd, so the caller reports WatchTreeFailed.
#[cfg(target_os = "linux")]
fn linux_watch_tree(
    conn: &ipc::Conn,
    fanotify_state: Option<&fanotify::runtime::FanotifyState>,
    lsm_state: Option<&LsmDispatch>,
    command: shit_planner::events::CommandId,
    root_pid: u32,
    cwd_path: &str,
) -> Result<(), String> {
    let (session, command_seq) = (command.session, command.seq);
    if let Some(state) = fanotify_state {
        // The tree is tracked before anything can fail. Another command's
        // mark can still fire for a pid in this tree, and UnwatchTree
        // releases the tree whatever happened here.
        state
            .tree
            .lock()
            .unwrap()
            .watch(session, command_seq, root_pid as i32);
        // L01: explicit dedupe-state init for the command.
        let cwd = resolve_linux_watch_cwd(cwd_path, root_pid);
        if let Some(rt) = &state.capture_runtime
            && let Ok(mut g) = rt.lock()
        {
            g.on_watch_tree(command);
            g.mark_kernel_losses(
                command,
                "the fanotify queue",
                state.overflows.load(std::sync::atomic::Ordering::Acquire),
            );
            if let Ok(cwd) = &cwd {
                g.note_direct_children_baseline(command, &cwd.path);
            }
        }
        let WatchCwd {
            fd: cwd_fd,
            path: cwd,
        } = cwd?;
        // L01: narrow-scope fanotify mark on the watch cwd
        // (FAN_EVENT_ON_CHILD, ONLYDIR). We deliberately do NOT use
        // FAN_MARK_FILESYSTEM here (HP-18: marking $HOME at boot wedged
        // the box). Stash the path so UnwatchTree can unmark it.
        match fanotify::mark::mark_dir_for_capture(&state.fd, std::os::fd::AsFd::as_fd(&cwd_fd)) {
            Ok(()) => {
                state.marked_paths.lock().unwrap().insert(
                    command,
                    fanotify::runtime::MarkedDir {
                        path: cwd.clone(),
                        fd: cwd_fd,
                    },
                );
                tracing::info!(
                    %session,
                    command_seq,
                    root_pid,
                    cwd = %cwd.display(),
                    "watch_tree registered + cwd marked"
                );
                Ok(())
            }
            Err(e) => Err(format!("fanotify mark on {} failed: {e}", cwd.display())),
        }
    } else if let Some(state) = lsm_state {
        // L04: eBPF-LSM tier. No fanotify mark needed — the LSM hooks
        // fire globally. We still track the pid tree so events from
        // untracked pids are dropped. The tree is tracked whatever the
        // cwd's state: `cd /tmp/x; rm -rf /tmp/x; rm ~/important` has no
        // usable cwd, and its descendants must stay attributed.
        state
            .tree
            .lock()
            .unwrap()
            .watch(session, command_seq, root_pid as i32);
        let cwd = resolve_linux_watch_cwd(cwd_path, root_pid);
        // L04 — pre-open every regular file under the cwd. The held
        // OwnedFd keeps the inode alive after vfs_unlink, so the LSM
        // unlink handler can read the pre-image content even though
        // the dentry is gone. Linux mirror of BSD's register_subtree.
        if let Some(rt) = &state.runtime
            && let Ok(mut g) = rt.lock()
        {
            g.on_watch_tree(command);
            g.mark_kernel_losses(
                command,
                "the eBPF ring buffers",
                ebpf::ringbuf_losses_observed(),
            );
            if let Ok(cwd) = &cwd {
                g.pre_open_tree(command, &cwd.path);
            }
        }
        match &cwd {
            Ok(cwd) => tracing::info!(
                %session,
                command_seq,
                root_pid,
                cwd = %cwd.path.display(),
                tier = "ebpf-lsm",
                "watch_tree registered + cwd pre-opened (LSM tier)"
            ),
            Err(reason) => {
                tracing::warn!(
                    %session,
                    command_seq,
                    root_pid,
                    %reason,
                    tier = "ebpf-lsm",
                    "watch_tree registered without pre-opens (LSM tier)"
                );
                capture::accounting::send_capture_observation(
                    conn,
                    command,
                    None,
                    format!("capture attach failed: {reason}"),
                );
            }
        }
        Ok(())
    } else {
        tracing::debug!(
            %session,
            command_seq,
            "watch_tree with no fanotify or lsm tier (degraded)"
        );
        capture::accounting::send_capture_observation(
            conn,
            command,
            None,
            "no Linux capture tier is active; file changes are not captured".to_string(),
        );
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_watch_tests {
    use super::*;

    /// A pid with no /proc entry, so the fallback cannot resolve.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    #[test]
    fn watch_root_prefers_the_reported_cwd() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_linux_watch_cwd(dir.path().to_str().unwrap(), std::process::id())
                .unwrap()
                .path,
            std::fs::canonicalize(dir.path()).unwrap()
        );
    }

    #[test]
    fn watch_root_falls_back_when_the_report_does_not_resolve() {
        let own = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(
            resolve_linux_watch_cwd("/nonexistent/shit-r3a-cwd", std::process::id())
                .unwrap()
                .path,
            own
        );
    }

    #[test]
    fn watch_root_never_trusts_a_lossy_report() {
        // A real directory spelled with U+FFFD is still not the shell's cwd.
        let dir = tempfile::tempdir().unwrap();
        let lossy = dir.path().join("caf\u{FFFD}");
        std::fs::create_dir(&lossy).unwrap();
        let own = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(
            resolve_linux_watch_cwd(lossy.to_str().unwrap(), std::process::id())
                .unwrap()
                .path,
            own
        );
    }

    #[test]
    fn watch_root_reports_the_reason_when_neither_resolves() {
        let err = resolve_linux_watch_cwd("/nonexistent/shit-r3a-cwd", dead_pid())
            .err()
            .unwrap();
        assert!(err.contains("shit-r3a-cwd"), "{err}");
    }

    #[test]
    fn watch_cwd_must_be_an_absolute_existing_directory() {
        assert!(validated_linux_watch_cwd("relative/dir").is_err());
        assert!(validated_linux_watch_cwd("/nonexistent/shit-r3a-cwd").is_err());
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"x").unwrap();
        assert!(validated_linux_watch_cwd(file.to_str().unwrap()).is_err());
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(
            validated_linux_watch_cwd(dir.path().to_str().unwrap())
                .unwrap()
                .path,
            canonical
        );
    }

    /// #230: a directory the peer cannot open (no read permission) is
    /// not watched, though it exists and is reachable.
    #[test]
    fn watch_cwd_the_peer_cannot_open_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o100)).unwrap();
        let err = validated_linux_watch_cwd(locked.to_str().unwrap())
            .err()
            .unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(err.contains("Permission denied"), "{err}");
    }

    /// #230: the process fallback does not reach a cwd the peer may not
    /// inspect (pid 1's cwd belongs to root).
    #[test]
    fn fallback_to_another_users_cwd_is_refused() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        assert!(resolve_linux_watch_cwd("/nonexistent/shit-230", 1).is_err());
    }

    /// A deleted directory is not a watch root.
    #[test]
    fn deleted_watch_cwd_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let gone = dir.path().join("gone");
        std::fs::create_dir(&gone).unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .current_dir(&gone)
            .spawn()
            .unwrap();
        std::fs::remove_dir(&gone).unwrap();
        let r = resolve_linux_watch_cwd("/nonexistent/shit-230", child.id());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(r.is_err());
    }

    fn lsm_dispatch() -> LsmDispatch {
        LsmDispatch {
            tree: Arc::new(std::sync::Mutex::new(fanotify::tree::TreeMap::new())),
            runtime: None,
            flush: Vec::new(),
        }
    }

    #[test]
    fn lsm_attach_with_unusable_cwd_tracks_the_tree_and_reports_an_observation() {
        let (helper, daemon) = ipc::socketpair().unwrap();
        let command = shit_planner::events::CommandId {
            session: uuid::Uuid::from_u128(9),
            seq: 4,
        };
        let dispatch = lsm_dispatch();
        let root = dead_pid();
        assert!(
            linux_watch_tree(
                &helper,
                None,
                Some(&dispatch),
                command,
                root,
                "/nonexistent/shit-r3a-cwd"
            )
            .is_ok()
        );
        assert_eq!(
            dispatch.tree.lock().unwrap().is_tracked(root as i32),
            Some((command.session, command.seq)),
            "descendants must stay attributed without a cwd"
        );
        assert!(matches!(
            daemon.recv_response().unwrap(),
            shit_proto::HelperResponse::CaptureRefused { seq: 4, detail, .. }
                if detail.starts_with("capture attach failed: ")
        ));
    }

    /// A fd that is not a fanotify group, so marking it fails. Building a
    /// real group needs CAP_SYS_ADMIN, which unit tests do not have.
    fn fanotify_state_that_cannot_mark() -> fanotify::runtime::FanotifyState {
        let fd = std::fs::File::open("/dev/null").unwrap().into();
        fanotify::runtime::FanotifyState::new(fanotify::init::FanotifyFd::for_test(fd))
    }

    #[test]
    fn fanotify_attach_failures_keep_the_tree_tracked() {
        let (helper, _daemon) = ipc::socketpair().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let usable = dir.path().to_str().unwrap();
        for (seq, cwd) in [(7, "/nonexistent/shit-r3a-cwd"), (8, usable)] {
            let command = shit_planner::events::CommandId {
                session: uuid::Uuid::from_u128(9),
                seq,
            };
            let state = fanotify_state_that_cannot_mark();
            let root = dead_pid();
            let result = linux_watch_tree(&helper, Some(&state), None, command, root, cwd);
            assert!(result.is_err(), "{cwd}");
            assert_eq!(
                state.tree.lock().unwrap().is_tracked(root as i32),
                Some((command.session, command.seq)),
                "{cwd}"
            );
            assert!(state.marked_paths.lock().unwrap().is_empty(), "{cwd}");
        }
    }

    #[test]
    fn lsm_attach_with_a_usable_cwd_sends_no_observation() {
        let (helper, daemon) = ipc::socketpair().unwrap();
        daemon.set_nonblocking_for_test();
        let command = shit_planner::events::CommandId {
            session: uuid::Uuid::from_u128(9),
            seq: 5,
        };
        let dir = tempfile::tempdir().unwrap();
        let dispatch = lsm_dispatch();
        assert!(
            linux_watch_tree(
                &helper,
                None,
                Some(&dispatch),
                command,
                1,
                dir.path().to_str().unwrap()
            )
            .is_ok()
        );
        assert!(daemon.recv_response().is_err());
    }

    #[test]
    fn duplicate_watch_is_refused_with_an_observation() {
        let (helper, daemon) = ipc::socketpair().unwrap();
        let command = shit_planner::events::CommandId {
            session: uuid::Uuid::from_u128(9),
            seq: 6,
        };
        let mut active = std::collections::BTreeSet::new();
        assert!(begin_watch(&helper, &mut active, command));
        assert!(!begin_watch(&helper, &mut active, command));
        assert!(matches!(
            daemon.recv_response().unwrap(),
            shit_proto::HelperResponse::CaptureRefused { seq: 6, detail, .. }
                if detail.contains("duplicate WatchTree")
        ));
    }

    #[test]
    fn degraded_watch_reports_an_observation_and_stays_ready() {
        let (helper, daemon) = ipc::socketpair().unwrap();
        let command = shit_planner::events::CommandId {
            session: uuid::Uuid::from_u128(9),
            seq: 2,
        };
        assert!(linux_watch_tree(&helper, None, None, command, 1, "/nonexistent").is_ok());
        assert!(matches!(
            daemon.recv_response().unwrap(),
            shit_proto::HelperResponse::CaptureRefused { seq: 2, path: None, detail, .. }
                if detail.contains("no Linux capture tier")
        ));
    }

    #[test]
    fn unwatch_flushed_marker_is_sent() {
        let (helper, daemon) = ipc::socketpair().unwrap();
        let command = shit_planner::events::CommandId {
            session: uuid::Uuid::from_u128(9),
            seq: 3,
        };
        send_unwatch_flushed(&helper, command);
        assert!(matches!(
            daemon.recv_response().unwrap(),
            shit_proto::HelperResponse::UnwatchTreeFlushed { command_seq: 3, .. }
        ));
    }
}

/// Synchronous daemon-request loop. Lives in `spawn_blocking` so it
/// can use the blocking `Conn::recv_request`. Exits when the daemon
/// disconnects or sends `Shutdown`.
fn request_loop(
    conn: Arc<ipc::Conn>,
    #[cfg(target_os = "linux")] peer_uid: u32,
    #[cfg(target_os = "linux")] fanotify_state: Option<fanotify::runtime::FanotifyState>,
    #[cfg(target_os = "linux")] lsm_state: Option<LsmDispatch>,
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    bsd_capture: Option<capture::bsd::CaptureControl>,
    #[cfg(target_os = "macos")] macos_capture: Option<capture::macos::CaptureControl>,
    #[cfg(target_os = "macos")] macos_es_capture: Option<capture::macos_es::CaptureControl>,
) -> anyhow::Result<()> {
    use shit_proto::{HelperRequest, HelperResponse};

    // Commands with a WatchTree and no UnwatchTree yet. A duplicate
    // WatchTree must not reset an active capture window.
    let mut active_watches = std::collections::BTreeSet::new();
    // #230: which processes this peer may watch.
    #[cfg(target_os = "linux")]
    let mut watch_scope = watch_scope::WatchScope::new(peer_uid);

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
                cwd_path,
            } => {
                let command = shit_planner::events::CommandId {
                    session,
                    seq: command_seq,
                };
                if !begin_watch(&conn, &mut active_watches, command) {
                    continue;
                }
                #[cfg(target_os = "linux")]
                let attach = match watch_scope.authorize(session, root_pid) {
                    Ok(()) => linux_watch_tree(
                        &conn,
                        fanotify_state.as_ref(),
                        lsm_state.as_ref(),
                        command,
                        root_pid,
                        &cwd_path,
                    ),
                    Err(reason) => Err(refuse_watch(&conn, command, root_pid, &reason)),
                };
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                )))]
                #[allow(unused_mut)]
                let mut attach: Result<(), String> = Ok(());
                #[cfg(any(
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                ))]
                {
                    let attach = match &bsd_capture {
                        Some(ctrl) => ctrl
                            .on_watch_tree(session, command_seq, root_pid, &cwd_path)
                            .map_err(|e| e.to_string()),
                        None => Err("BSD capture runtime unavailable".to_string()),
                    };
                    if let Err(reason) = attach {
                        tracing::error!(
                            %reason,
                            %session,
                            command_seq,
                            root_pid,
                            cwd_path = %cwd_path,
                            "BSD watch attach could not be queued; reporting not-ready"
                        );
                        // Explicit not-ready so the pre-exec hook is
                        // released now instead of at its timeout. Capture
                        // is still not claimed for this command.
                        let failed = HelperResponse::WatchTreeFailed {
                            session,
                            command_seq,
                            reason,
                        };
                        if let Err(e) = conn.send_response(&failed) {
                            tracing::warn!(err = %e, "WatchTreeFailed send failed");
                        }
                        continue;
                    }
                    tracing::info!(
                        %session,
                        command_seq,
                        root_pid,
                        cwd_path = %cwd_path,
                        "BSD watch attach queued; pump reports readiness"
                    );
                    // The pump sends WatchTreeReady / WatchTreeFailed when
                    // the attach finishes. Do not claim readiness here.
                    continue;
                }
                #[cfg(target_os = "macos")]
                if let Some(ctrl) = &macos_capture {
                    if let Err(e) = ctrl.on_watch_tree(session, command_seq, root_pid, &cwd_path) {
                        attach = Err(format!("fsevents attach failed: {e}"));
                    }
                    tracing::info!(
                        %session,
                        command_seq,
                        root_pid,
                        cwd_path = %cwd_path,
                        "watch_tree dispatched to macos fsevents capture"
                    );
                } else {
                    tracing::debug!(
                        %session,
                        command_seq,
                        "watch_tree ignored — no macos capture (degraded)"
                    );
                    if macos_es_capture.is_none() {
                        capture::accounting::send_capture_observation(
                            &conn,
                            command,
                            None,
                            "no macOS capture tier is active; file changes are not captured"
                                .to_string(),
                        );
                    }
                }
                // M03.1.I.5: ES producer runs alongside FSEvents per
                // the coexistence ratification. Both receive every
                // WatchTree; ES filters by audit_token (kernel-stable
                // identity), FSEvents by path prefix. Daemon ingests
                // the distinct event kinds without dedup conflict.
                #[cfg(target_os = "macos")]
                if let Some(ctrl) = &macos_es_capture {
                    if let Err(e) = ctrl.on_watch_tree(session, command_seq, root_pid, &cwd_path)
                        && attach.is_ok()
                    {
                        attach = Err(format!("endpoint-security attach failed: {e}"));
                    }
                    tracing::info!(
                        %session,
                        command_seq,
                        root_pid,
                        cwd_path = %cwd_path,
                        "watch_tree dispatched to macos endpoint-security capture"
                    );
                }
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                    target_os = "macos",
                )))]
                {
                    let _ = (root_pid, session, command_seq, &cwd_path);
                }
                // Task #105: signal to the daemon that THIS specific
                // (session, command_seq) is fully set up — kernel-tier
                // reader is live (BPF programs attached on LSM, mark
                // installed on fanotify-perm, kqueue subtree registered
                // on BSD) AND the watch root has been snapshotted into
                // per-CommandId pre-image state. The daemon's
                // CtlRequest::WaitWatchReady handler awaits this signal
                // before releasing the shell hook (`shit hook-send
                // pre-exec`) that triggered the WatchTree, so the
                // user's command never runs before capture is ready.
                //
                // This send is fire-and-forget per the wire contract;
                // the daemon doesn't ack readiness, it just routes the
                // signal into its per-command readiness map. If the
                // send fails (helper-daemon link torn down between the
                // WatchTree dispatch and now) the shell hook will time
                // out on its own — the daemon doesn't hang on us.
                // BSD reports readiness from the capture pump once the
                // attach completes, so it does not send it here.
                #[cfg(not(any(
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                )))]
                {
                    let outcome = match attach {
                        Ok(()) => HelperResponse::WatchTreeReady {
                            session,
                            command_seq,
                        },
                        Err(reason) => {
                            tracing::error!(
                                %session,
                                command_seq,
                                root_pid,
                                cwd_path = %cwd_path,
                                %reason,
                                "watch attach failed; reporting WatchTreeFailed"
                            );
                            HelperResponse::WatchTreeFailed {
                                session,
                                command_seq,
                                reason,
                            }
                        }
                    };
                    if let Err(e) = conn.send_response(&outcome) {
                        tracing::warn!(
                            err = %e,
                            %session,
                            command_seq,
                            "watch attach outcome send failed; shell hook will time out"
                        );
                    }
                }
            }
            HelperRequest::UnwatchTree {
                session,
                command_seq,
            } => {
                let command = shit_planner::events::CommandId {
                    session,
                    seq: command_seq,
                };
                active_watches.remove(&command);
                #[cfg(target_os = "linux")]
                if let Some(state) = &fanotify_state {
                    let cmd = command;
                    // No drain needed: the reader captures before it allows
                    // the syscall, so every mutation that completed is
                    // already on the wire. Holding the runtime lock across
                    // the unwatch orders this against the reader's handling
                    // of an in-flight event, so nothing for this command
                    // follows the marker.
                    let runtime = state.capture_runtime.as_ref().and_then(|rt| rt.lock().ok());
                    state.tree.lock().unwrap().unwatch(session, command_seq);
                    if let Some(mut g) = runtime {
                        g.on_unwatch_tree_counting(
                            cmd,
                            Some(state.overflows.load(std::sync::atomic::Ordering::Acquire)),
                        );
                    }
                    if let Some(dir) = state.marked_paths.lock().unwrap().remove(&cmd)
                        && let Err(e) = fanotify::mark::unmark_dir_for_capture(
                            &state.fd,
                            std::os::fd::AsFd::as_fd(&dir.fd),
                        )
                    {
                        tracing::warn!(
                            err = %e,
                            path = %dir.path.display(),
                            "unmark_dir_for_capture failed (continuing)"
                        );
                    }
                    tracing::info!(%session, command_seq, "unwatch_tree");
                } else if let Some(state) = &lsm_state {
                    // Close barrier: dispatch everything already in the
                    // ring buffers while the pid tree still attributes it
                    // to this command, then stop watching.
                    if let Err(detail) = ebpf::flush_all_readers(&state.flush, LSM_FLUSH_TIMEOUT) {
                        tracing::warn!(%session, command_seq, %detail, "eBPF reader flush incomplete");
                        capture::accounting::send_capture_observation(
                            &conn,
                            command,
                            None,
                            format!("capture tail may be missing: {detail}"),
                        );
                    }
                    state.tree.lock().unwrap().unwatch(session, command_seq);
                    let cmd = command;
                    if let Some(rt) = &state.runtime
                        && let Ok(mut g) = rt.lock()
                    {
                        g.on_unwatch_tree_counting(cmd, Some(ebpf::ringbuf_losses_observed()));
                    }
                    tracing::info!(%session, command_seq, tier = "ebpf-lsm", "unwatch_tree");
                }
                #[cfg(any(
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                ))]
                {
                    // The pump sends UnwatchTreeFlushed after it detaches,
                    // so the marker is ordered after the pump's own
                    // responses for this command.
                    use capture::DetachOutcome;
                    match bsd_capture
                        .as_ref()
                        .map(|ctrl| ctrl.on_unwatch_tree(session, command_seq))
                    {
                        Some(DetachOutcome::Queued) => {
                            tracing::info!(%session, command_seq, "unwatch_tree dispatched to bsd capture");
                        }
                        Some(DetachOutcome::Deferred) => {
                            capture::accounting::send_capture_observation(
                                &conn,
                                command,
                                None,
                                capture::DETACH_DEFERRED_DETAIL.to_string(),
                            );
                        }
                        Some(DetachOutcome::PumpGone) => {
                            capture::accounting::send_capture_observation(
                                &conn,
                                command,
                                None,
                                capture::DETACH_PUMP_GONE_DETAIL.to_string(),
                            );
                            send_unwatch_flushed(&conn, command);
                        }
                        None => send_unwatch_flushed(&conn, command),
                    }
                }
                // Each pump drops its clone after handling the detach. The
                // marker goes out when the last clone goes, including this
                // one when no producer is running.
                #[cfg(target_os = "macos")]
                {
                    use capture::DetachOutcome;
                    let flush = capture::UnwatchFlushMarker::new(Arc::clone(&conn), command);
                    let mut outcomes = Vec::new();
                    if let Some(ctrl) = &macos_capture {
                        outcomes.push(ctrl.on_unwatch_tree(
                            session,
                            command_seq,
                            Arc::clone(&flush),
                        ));
                        tracing::info!(%session, command_seq, "unwatch_tree dispatched to macos fsevents capture");
                    }
                    if let Some(ctrl) = &macos_es_capture {
                        outcomes.push(ctrl.on_unwatch_tree(
                            session,
                            command_seq,
                            Arc::clone(&flush),
                        ));
                        tracing::info!(%session, command_seq, "unwatch_tree dispatched to macos endpoint-security capture");
                    }
                    // `flush` is still held here, so these go out ahead of
                    // the marker however fast the pumps are.
                    if outcomes.contains(&DetachOutcome::PumpGone) {
                        capture::accounting::send_capture_observation(
                            &conn,
                            command,
                            None,
                            capture::DETACH_PUMP_GONE_DETAIL.to_string(),
                        );
                    } else if outcomes.contains(&DetachOutcome::Deferred) {
                        capture::accounting::send_capture_observation(
                            &conn,
                            command,
                            None,
                            capture::DETACH_DEFERRED_DETAIL.to_string(),
                        );
                    }
                    // FSEvents delivers with latency and has no way to ask
                    // for what the kernel still holds. ES has no such gap.
                    if macos_capture.is_some() && macos_es_capture.is_none() {
                        capture::accounting::send_capture_observation(
                            &conn,
                            command,
                            None,
                            "capture tail may be missing: FSEvents delivers with latency"
                                .to_string(),
                        );
                    }
                }
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                    target_os = "macos",
                )))]
                {
                    let _ = (session, command_seq);
                }
                #[cfg(not(any(
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly",
                    target_os = "macos",
                )))]
                send_unwatch_flushed(&conn, command);
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
            // AU28 / DR-15 stage-1, scoped by #227: the helper changes an
            // owner only with a capture token it issued for that file.
            HelperRequest::ApplyChown {
                session,
                command_seq,
                path,
                uid,
                gid,
                no_dereference,
                owner,
            } => {
                #[cfg(target_os = "linux")]
                let outcome = apply_chown(
                    &path,
                    uid,
                    gid,
                    no_dereference,
                    owner.as_ref(),
                    capture_token::process_key(),
                );
                #[cfg(not(target_os = "linux"))]
                let outcome = apply_chown(&path, uid, gid, no_dereference, owner.as_ref());
                tracing::info!(
                    %session,
                    command_seq,
                    path = %path,
                    uid,
                    gid,
                    no_dereference,
                    ?outcome,
                    "apply_chown"
                );
                let _ = conn.send_response(&HelperResponse::PrivilegedOpResult {
                    session,
                    command_seq,
                    outcome,
                });
            }
            HelperRequest::ApplyMknod {
                session,
                command_seq,
                path,
                mode,
                dev,
                device,
            } => {
                let outcome = apply_mknod(&path, mode, dev, device.as_ref());
                tracing::info!(
                    %session,
                    command_seq,
                    path = %path,
                    mode = format!("{mode:#o}"),
                    dev,
                    ?outcome,
                    "apply_mknod"
                );
                let _ = conn.send_response(&HelperResponse::PrivilegedOpResult {
                    session,
                    command_seq,
                    outcome,
                });
            }
        }
    }
}

/// AU28 / #227 - helper-side ApplyChown handler. Every field of the
/// request is attacker-controlled (D-28), so the helper changes an owner
/// only on its own evidence, in this order:
///
/// 1. capture evidence is present and its token verifies under this
///    process's key against the requested owner, the file's
///    `(dev, ino)`, the path and the capturing command (another
///    helper's token is refused as expired);
/// 2. the parent is opened one component at a time without following
///    symlinks;
/// 3. the entry is opened `O_PATH|O_NOFOLLOW` under that dirfd and must
///    still be the captured inode on the captured device (D-31: a
///    different `st_dev` is a different file);
/// 4. the owner is changed through that fd. The helper holds no
///    `CAP_CHOWN` (the startup drop strips it from permitted), so the
///    kernel allows only what the invoking user could do anyway.
#[cfg(target_os = "linux")]
fn apply_chown(
    path: &str,
    uid: u32,
    gid: u32,
    no_dereference: bool,
    owner: Option<&shit_proto::OwnerEvidence>,
    key: Option<&capture_token::TokenKey>,
) -> shit_proto::PrivilegedOpOutcome {
    use shit_proto::PrivilegedOpOutcome;
    let refuse = |reason: String| PrivilegedOpOutcome::Refused { reason };
    let Some(ev) = owner else {
        return refuse("no capture evidence for this ownership change".to_string());
    };
    let Some(key) = key else {
        return refuse("helper has no capture-token key (kernel RNG unavailable at start)".into());
    };
    let facts = capture_token::OwnerFacts {
        uid,
        gid,
        dev: ev.dev,
        ino: ev.inode,
        path,
        session: ev.session,
        seq: ev.command_seq,
    };
    if let Err(e) = key.verify(&facts, &ev.token) {
        return refuse(e.reason().to_string());
    }
    let (parent, name) = match dirfd::open_parent_nofollow(path) {
        Ok(v) => v,
        Err(o) => return o,
    };
    dirfd::owner_at(
        &parent,
        &name,
        (ev.dev, ev.inode),
        uid,
        gid,
        !no_dereference,
    )
}

/// AU28 - non-Linux ApplyChown, unchanged by #227: chown(2), or
/// lchown(2) for `no_dereference`, on the path. The owner-evidence gate
/// is Linux-only until the macOS and FreeBSD helpers issue capture
/// tokens of their own; `owner` is ignored here.
#[cfg(not(target_os = "linux"))]
fn apply_chown(
    path: &str,
    uid: u32,
    gid: u32,
    no_dereference: bool,
    _owner: Option<&shit_proto::OwnerEvidence>,
) -> shit_proto::PrivilegedOpOutcome {
    use shit_proto::PrivilegedOpOutcome;
    let c_path = match std::ffi::CString::new(path) {
        Ok(s) => s,
        Err(e) => {
            return PrivilegedOpOutcome::Failed {
                err: format!("path contains NUL: {e}"),
            };
        }
    };
    let rc = unsafe {
        if no_dereference {
            libc::lchown(c_path.as_ptr(), uid, gid)
        } else {
            libc::chown(c_path.as_ptr(), uid, gid)
        }
    };
    if rc == 0 {
        return PrivilegedOpOutcome::Applied;
    }
    let errno = std::io::Error::last_os_error();
    match errno.raw_os_error() {
        Some(libc::EPERM) => PrivilegedOpOutcome::PermissionDenied,
        Some(libc::ENOENT) => PrivilegedOpOutcome::NotFound,
        _ => PrivilegedOpOutcome::Failed {
            err: format!(
                "{}: {errno}",
                if no_dereference { "lchown" } else { "chown" }
            ),
        },
    }
}

/// AU22 / DR-15.1 — helper-side ApplyMknod handler. `mode` is the
/// wire's S_IF* | perm_bits composite; libc::mknod expects that exact
/// shape.
///
/// Fifo and Socket ignore `dev` and need no privilege, so they keep the
/// path-based flow. Block and char nodes go through
/// [`apply_device_mknod`]: L4b, the helper acts on them only with a
/// capture token this helper process issued for exactly the requested
/// fields.
fn apply_mknod(
    path: &str,
    mode: u32,
    dev: u64,
    device: Option<&shit_proto::DeviceEvidence>,
) -> shit_proto::PrivilegedOpOutcome {
    use shit_proto::PrivilegedOpOutcome;
    #[cfg(not(target_os = "linux"))]
    use std::os::unix::fs::FileTypeExt;
    // libc::mode_t is u32 on Linux, u16 on macOS — cast at the
    // boundary so bitops + comparisons against libc constants
    // type-check on both platforms.
    let mode_native: libc::mode_t = mode as libc::mode_t;
    let ifmt = mode_native & libc::S_IFMT;
    if ifmt == libc::S_IFBLK || ifmt == libc::S_IFCHR {
        #[cfg(target_os = "linux")]
        return apply_device_mknod(path, mode, dev, device, capture_token::process_key());
        #[cfg(not(target_os = "linux"))]
        return apply_device_mknod(path, mode, dev, device);
    }
    if ifmt != libc::S_IFIFO && ifmt != libc::S_IFSOCK {
        // Regular (S_IFREG — planner shouldn't route Regular here),
        // or 0 (caller forgot to set the kind). Refused.
        return PrivilegedOpOutcome::PermissionDenied;
    }
    // Linux: through the parent dirfd, like device restores. Making a
    // fifo or socket needs no privilege, so the parent may be reached
    // through symlinks; the node itself is never re-resolved by name.
    #[cfg(target_os = "linux")]
    {
        match dirfd::open_parent(path) {
            Ok((parent, name)) => {
                dirfd::special_node_at(&parent, &name, ifmt, mode_native & 0o7777)
            }
            Err(o) => o,
        }
    }
    #[cfg(not(target_os = "linux"))]
    let c_path = match std::ffi::CString::new(path) {
        Ok(s) => s,
        Err(e) => {
            return PrivilegedOpOutcome::Failed {
                err: format!("path contains NUL: {e}"),
            };
        }
    };
    // EEXIST handling: if the path already exists AND is the
    // expected kind, treat as Applied (idempotent restore — the
    // planner might have already replayed the op, or a parallel
    // command recreated the same path). Anything else is a real
    // conflict and bubbles up as Failed.
    #[cfg(not(target_os = "linux"))]
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        let ft = meta.file_type();
        let already_right =
            (ifmt == libc::S_IFIFO && ft.is_fifo()) || (ifmt == libc::S_IFSOCK && ft.is_socket());
        if already_right {
            return PrivilegedOpOutcome::Applied;
        }
        return PrivilegedOpOutcome::Failed {
            err: format!("path exists with wrong kind: {ft:?}"),
        };
    }
    // Create with permission bits 0, then set the captured bits on the
    // new node itself. No umask change: a process-wide umask(0) would
    // race with capture threads creating staging files, and the umask
    // can only clear bits, so 0 needs none.
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::MetadataExt;
        // mknod(2) makes neither a fifo nor a socket on the BSDs: a fifo
        // comes from mkfifo, a socket from binding an AF_UNIX socket.
        let made = if ifmt == libc::S_IFIFO {
            if unsafe { libc::mkfifo(c_path.as_ptr(), 0) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        } else {
            std::os::unix::net::UnixListener::bind(path).map(drop)
        };
        if made.is_ok() {
            let ours = std::fs::symlink_metadata(path)
                .map(|m| (m.dev(), m.ino()))
                .ok();
            let perms = mode_native & 0o7777;
            return match set_new_node_mode(&c_path, ifmt, perms) {
                Ok(()) => PrivilegedOpOutcome::Applied,
                Err(e) => {
                    // Remove only the node just made, not a swapped-in entry.
                    let still = std::fs::symlink_metadata(path)
                        .map(|m| (m.dev(), m.ino()))
                        .ok();
                    if ours.is_some() && still == ours {
                        unsafe { libc::unlink(c_path.as_ptr()) };
                    }
                    PrivilegedOpOutcome::Failed {
                        err: format!("chmod {perms:o}: {e}; node removed"),
                    }
                }
            };
        }
        let errno = made.unwrap_err();
        match errno.raw_os_error() {
            Some(libc::EPERM) => PrivilegedOpOutcome::PermissionDenied,
            Some(libc::ENOENT) => PrivilegedOpOutcome::NotFound,
            _ => PrivilegedOpOutcome::Failed {
                err: format!("create {ifmt:o}: {errno}"),
            },
        }
    }
}

/// Non-Linux: give a just-made fifo/socket its captured permission
/// bits without following a symlink.
#[cfg(not(target_os = "linux"))]
fn set_new_node_mode(
    c_path: &std::ffi::CStr,
    _ifmt: libc::mode_t,
    perms: libc::mode_t,
) -> std::io::Result<()> {
    let rc = unsafe {
        libc::fchmodat(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            perms,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// L4b - block/char node restore. Every field of the request is
/// attacker-controlled, so the order of checks is fixed:
///
/// 1. a nonzero rdev and capture evidence are present;
/// 2. the token verifies under this process's key against the
///    requested mode, rdev, owner, `(dev, ino)`, path, session and seq
///    (another helper's token is refused as expired);
/// 3. the captured owner is the invoking user (the helper's euid). The
///    helper gives no other owner: that needs CAP_CHOWN, which it does
///    not use for this (#226, #227);
/// 4. the parent is opened one component at a time without following
///    symlinks, and everything after that is relative to that dirfd.
///
/// Only then is the node made, with no permission bits, and widened to
/// the captured mode once its owner is right.
#[cfg(target_os = "linux")]
fn apply_device_mknod(
    path: &str,
    mode: u32,
    rdev: u64,
    evidence: Option<&shit_proto::DeviceEvidence>,
    key: Option<&capture_token::TokenKey>,
) -> shit_proto::PrivilegedOpOutcome {
    use shit_proto::PrivilegedOpOutcome;
    let refuse = |reason: String| PrivilegedOpOutcome::Refused { reason };
    if rdev == 0 {
        return refuse("no device number captured for this node".to_string());
    }
    let Some(ev) = evidence else {
        return refuse("no capture evidence for this device node".to_string());
    };
    let Some(key) = key else {
        return refuse("helper has no capture-token key (kernel RNG unavailable at start)".into());
    };
    let facts = capture_token::DeviceFacts {
        mode,
        rdev,
        uid: ev.uid,
        gid: ev.gid,
        dev: ev.dev,
        ino: ev.inode,
        path,
        session: ev.session,
        seq: ev.command_seq,
    };
    if let Err(e) = key.verify(&facts, &ev.token) {
        return refuse(e.reason().to_string());
    }
    let euid = unsafe { libc::geteuid() };
    if ev.uid != euid {
        return refuse(format!(
            "captured owner uid {} is not the invoking user (uid {euid}); giving the node \
             another owner needs CAP_CHOWN, which the helper does not use",
            ev.uid
        ));
    }
    let (parent, name) = match dirfd::open_parent_nofollow(path) {
        Ok(v) => v,
        Err(o) => return o,
    };
    // Review round 2, item 1: the node is made only on the filesystem the
    // token was issued for (its signed st_dev), and only where device
    // nodes are honored.
    match dirfd::fstat_fd(&parent) {
        Ok(st) if st.st_dev == ev.dev => {}
        Ok(_) => {
            return refuse(
                "the parent directory is on a different filesystem than the captured node"
                    .to_string(),
            );
        }
        Err(e) => {
            return PrivilegedOpOutcome::Failed {
                err: format!("fstat parent: {e}"),
            };
        }
    }
    match capture_token::fs_is_nodev(std::os::fd::AsRawFd::as_raw_fd(&parent)) {
        Ok(false) => {}
        Ok(true) => {
            return refuse("target filesystem does not allow device nodes (nodev)".to_string());
        }
        Err(e) => {
            return PrivilegedOpOutcome::Failed {
                err: format!("statvfs parent: {e}"),
            };
        }
    }
    dirfd::device_node_at(&parent, &name, mode, rdev, ev.uid, ev.gid)
}

#[cfg(not(target_os = "linux"))]
fn apply_device_mknod(
    _path: &str,
    _mode: u32,
    _rdev: u64,
    _evidence: Option<&shit_proto::DeviceEvidence>,
) -> shit_proto::PrivilegedOpOutcome {
    shit_proto::PrivilegedOpOutcome::Refused {
        reason: "block/char node restore is Linux-only".to_string(),
    }
}

/// L4b - dirfd-relative filesystem steps for the device restore. No
/// function here re-resolves the request's path string after
/// [`open_parent_nofollow`] has opened the parent.
#[cfg(target_os = "linux")]
mod dirfd {
    use shit_proto::PrivilegedOpOutcome;
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn errno() -> std::io::Error {
        std::io::Error::last_os_error()
    }

    fn open_at(dir: libc::c_int, name: &CStr, flags: libc::c_int) -> std::io::Result<OwnedFd> {
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(errno());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    pub(super) fn fstat_fd(fd: &OwnedFd) -> std::io::Result<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
            return Err(errno());
        }
        Ok(st)
    }

    fn fstatat_nofollow(dir: &OwnedFd, name: &CStr) -> std::io::Result<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(errno());
        }
        Ok(st)
    }

    /// Open the parent directory of the absolute `path` from `/`, one
    /// component at a time with `O_PATH|O_DIRECTORY|O_NOFOLLOW`, and
    /// return it with the final name. A symlink anywhere in the parent
    /// chain, a `.` or `..` component, or a relative path is refused.
    pub(super) fn open_parent_nofollow(
        path: &str,
    ) -> Result<(OwnedFd, CString), PrivilegedOpOutcome> {
        let refuse = |reason: String| PrivilegedOpOutcome::Refused { reason };
        if !path.starts_with('/') || path.ends_with('/') {
            return Err(refuse(format!(
                "path {path:?} is not an absolute path to a file"
            )));
        }
        let mut comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let Some(name) = comps.pop() else {
            return Err(refuse(format!("path {path:?} has no file name")));
        };
        if comps
            .iter()
            .chain(std::iter::once(&name))
            .any(|c| *c == "." || *c == "..")
        {
            return Err(refuse(format!("path {path:?} has a . or .. component")));
        }
        let to_c = |s: &str| {
            CString::new(s).map_err(|e| PrivilegedOpOutcome::Failed {
                err: format!("path contains NUL: {e}"),
            })
        };
        let flags = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        let mut dir =
            open_at(libc::AT_FDCWD, c"/", flags).map_err(|e| PrivilegedOpOutcome::Failed {
                err: format!("open /: {e}"),
            })?;
        for c in comps {
            let next = match open_at(dir.as_raw_fd(), &to_c(c)?, flags) {
                Ok(fd) => fd,
                Err(e) => {
                    return Err(match e.raw_os_error() {
                        Some(libc::ENOENT) => PrivilegedOpOutcome::NotFound,
                        Some(libc::ELOOP) | Some(libc::ENOTDIR) => refuse(format!(
                            "parent component {c:?} of {path:?} is a symlink or not a \
                             directory; the helper does not follow it"
                        )),
                        _ => PrivilegedOpOutcome::Failed {
                            err: format!("open parent component {c:?}: {e}"),
                        },
                    });
                }
            };
            match fstat_fd(&next) {
                Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
                _ => {
                    return Err(refuse(format!(
                        "parent component {c:?} of {path:?} is not a directory"
                    )));
                }
            }
            dir = next;
        }
        Ok((dir, to_c(name)?))
    }

    /// Open the parent of `path` (`O_PATH|O_DIRECTORY`, symlinks in the
    /// parent chain followed) for a fifo/socket restore, which needs no
    /// privilege. Returns it with the final name.
    pub(super) fn open_parent(path: &str) -> Result<(OwnedFd, CString), PrivilegedOpOutcome> {
        let p = std::path::Path::new(path);
        let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else {
            return Err(PrivilegedOpOutcome::Failed {
                err: format!("path {path:?} has no parent or file name"),
            });
        };
        use std::os::unix::ffi::OsStrExt;
        let to_c = |b: &[u8]| {
            CString::new(b).map_err(|e| PrivilegedOpOutcome::Failed {
                err: format!("path contains NUL: {e}"),
            })
        };
        let parent_c = to_c(parent.as_os_str().as_bytes())?;
        let name_c = to_c(name.as_bytes())?;
        match open_at(libc::AT_FDCWD, &parent_c, libc::O_PATH | libc::O_DIRECTORY) {
            Ok(fd) => Ok((fd, name_c)),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Err(PrivilegedOpOutcome::NotFound),
            Err(e) => Err(PrivilegedOpOutcome::Failed {
                err: format!("open parent: {e}"),
            }),
        }
    }

    /// Remove `name` under `parent` only if it is still the entry
    /// `(st_dev, st_ino)`; a swapped-in entry is left alone.
    pub(super) fn unlink_if_same(parent: &OwnedFd, name: &CStr, ours: (u64, u64)) {
        if let Ok(st) = fstatat_nofollow(parent, name)
            && (st.st_dev, st.st_ino) == ours
        {
            unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
        }
    }

    /// Set `perms` on the node held by `node` (O_PATH) through
    /// `/proc/self/fd/N`, which names that inode, not what is at a path.
    fn chmod_held(node: &OwnedFd, perms: libc::mode_t) -> std::io::Result<()> {
        let proc = CString::new(format!("/proc/self/fd/{}", node.as_raw_fd()))
            .map_err(std::io::Error::other)?;
        if unsafe { libc::fchmodat(libc::AT_FDCWD, proc.as_ptr(), perms, 0) } != 0 {
            return Err(errno());
        }
        Ok(())
    }

    /// Fifo/socket restore under `parent`: an entry of the same kind
    /// already there is Applied; anything else there is refused. The
    /// node is made with bits 0 and given `perms` through its own fd;
    /// on failure it is removed only if the entry is still that node.
    pub(super) fn special_node_at(
        parent: &OwnedFd,
        name: &CStr,
        ifmt: libc::mode_t,
        perms: libc::mode_t,
    ) -> PrivilegedOpOutcome {
        match fstatat_nofollow(parent, name) {
            Ok(st) if st.st_mode & libc::S_IFMT == ifmt => return PrivilegedOpOutcome::Applied,
            Ok(st) => {
                return PrivilegedOpOutcome::Failed {
                    err: format!("path exists with wrong kind: mode {:o}", st.st_mode),
                };
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => {
                return PrivilegedOpOutcome::Failed {
                    err: format!("fstatat: {e}"),
                };
            }
        }
        if unsafe { libc::mknodat(parent.as_raw_fd(), name.as_ptr(), ifmt, 0) } != 0 {
            let e = errno();
            return match e.raw_os_error() {
                Some(libc::EPERM) => PrivilegedOpOutcome::PermissionDenied,
                Some(libc::ENOENT) => PrivilegedOpOutcome::NotFound,
                _ => PrivilegedOpOutcome::Failed {
                    err: format!("mknod: {e}"),
                },
            };
        }
        let ours = match fstatat_nofollow(parent, name) {
            Ok(st) if st.st_mode & libc::S_IFMT == ifmt => (st.st_dev, st.st_ino),
            _ => {
                return PrivilegedOpOutcome::Failed {
                    err: "node at path is not the one just created".to_string(),
                };
            }
        };
        let held = open_at(parent.as_raw_fd(), name, libc::O_PATH | libc::O_NOFOLLOW)
            .and_then(|fd| match fstat_fd(&fd) {
                Ok(st) if (st.st_dev, st.st_ino) == ours => Ok(fd),
                Ok(_) => Err(std::io::Error::other("node changed during restore")),
                Err(e) => Err(e),
            })
            .and_then(|fd| chmod_held(&fd, perms));
        match held {
            Ok(()) => PrivilegedOpOutcome::Applied,
            Err(e) => {
                unlink_if_same(parent, name, ours);
                PrivilegedOpOutcome::Failed {
                    err: format!("chmod {perms:o}: {e}; node removed"),
                }
            }
        }
    }

    /// #227 - give the entry `name` under `parent` the owner `uid:gid`,
    /// only if it is still the inode `ident` (`(st_dev, st_ino)`). The
    /// entry is opened without following a symlink and changed through
    /// that fd; `follow` (a chown(2) rather than lchown(2) request) on a
    /// symlink is refused.
    pub(super) fn owner_at(
        parent: &OwnedFd,
        name: &CStr,
        ident: (u64, u64),
        uid: u32,
        gid: u32,
        follow: bool,
    ) -> PrivilegedOpOutcome {
        let node = match open_at(parent.as_raw_fd(), name, libc::O_PATH | libc::O_NOFOLLOW) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                return PrivilegedOpOutcome::NotFound;
            }
            Err(e) => {
                return PrivilegedOpOutcome::Failed {
                    err: format!("open entry: {e}"),
                };
            }
        };
        let st = match fstat_fd(&node) {
            Ok(st) => st,
            Err(e) => {
                return PrivilegedOpOutcome::Failed {
                    err: format!("fstat entry: {e}"),
                };
            }
        };
        if (st.st_dev, st.st_ino) != ident {
            return PrivilegedOpOutcome::Conflict {
                detail: format!(
                    "the entry at the path is {:#x}:{}, not the captured file {:#x}:{}",
                    st.st_dev, st.st_ino, ident.0, ident.1
                ),
            };
        }
        if follow && st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return PrivilegedOpOutcome::Refused {
                reason: "the captured file is a symlink and the request would follow it; \
                         the helper does not follow symlinks"
                    .to_string(),
            };
        }
        if st.st_uid == uid && st.st_gid == gid {
            return PrivilegedOpOutcome::Applied;
        }
        let rc = unsafe {
            libc::fchownat(
                node.as_raw_fd(),
                c"".as_ptr(),
                uid,
                gid,
                libc::AT_EMPTY_PATH,
            )
        };
        if rc != 0 {
            let e = errno();
            return match e.raw_os_error() {
                Some(libc::EPERM) => PrivilegedOpOutcome::PermissionDenied,
                _ => PrivilegedOpOutcome::Failed {
                    err: format!("fchownat {uid}:{gid}: {e}"),
                },
            };
        }
        match fstat_fd(&node) {
            Ok(st) if st.st_uid == uid && st.st_gid == gid => PrivilegedOpOutcome::Applied,
            Ok(st) => PrivilegedOpOutcome::Failed {
                err: format!("owner is {}:{} after the change", st.st_uid, st.st_gid),
            },
            Err(e) => PrivilegedOpOutcome::Failed {
                err: format!("fstat after chown: {e}"),
            },
        }
    }

    fn describe(st: &libc::stat) -> String {
        format!(
            "mode {:o}, rdev {:#x}, owner {}:{}",
            st.st_mode, st.st_rdev, st.st_uid, st.st_gid
        )
    }

    /// Make the node `name` under `parent`: mknodat with no permission
    /// bits, check it is the node just made, give it the captured group
    /// if it differs (a group the user is in; the kernel decides), then
    /// the captured permission bits, and check the result. Any failure
    /// after mknodat removes the node, but only if the entry at `name`
    /// is still that node.
    pub(super) fn device_node_at(
        parent: &OwnedFd,
        name: &CStr,
        mode: u32,
        rdev: u64,
        uid: u32,
        gid: u32,
    ) -> PrivilegedOpOutcome {
        let ifmt = mode & libc::S_IFMT;
        let perms = mode & 0o7777;
        let kind_ok = |st: &libc::stat| st.st_mode & libc::S_IFMT == ifmt && st.st_rdev == rdev;
        let all_ok = |st: &libc::stat| {
            kind_ok(st) && st.st_uid == uid && st.st_gid == gid && st.st_mode & 0o7777 == perms
        };
        // Something already there: Applied only if it is exactly the
        // captured node (an earlier replay of this restore).
        match fstatat_nofollow(parent, name) {
            Ok(st) if all_ok(&st) => return PrivilegedOpOutcome::Applied,
            Ok(st) => {
                return PrivilegedOpOutcome::Conflict {
                    detail: format!(
                        "path exists as {}; captured mode {mode:o}, rdev {rdev:#x}, owner {uid}:{gid}",
                        describe(&st)
                    ),
                };
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => {
                return PrivilegedOpOutcome::Failed {
                    err: format!("fstatat: {e}"),
                };
            }
        }
        // Permission bits 0: the umask can only clear bits, so it needs no
        // change (a process-wide umask(0) would race with capture threads
        // creating staging files). The fchmod step below sets the mode.
        // #226: CAP_MKNOD is effective for this one call, on this thread.
        let rc = crate::priv_linux::with_cap(crate::priv_linux::CAP_MKNOD, || unsafe {
            libc::mknodat(
                parent.as_raw_fd(),
                name.as_ptr(),
                ifmt as libc::mode_t,
                rdev as libc::dev_t,
            )
        });
        if rc != 0 {
            let e = errno();
            return match e.raw_os_error() {
                Some(libc::EPERM) => PrivilegedOpOutcome::PermissionDenied,
                Some(libc::EEXIST) => PrivilegedOpOutcome::Conflict {
                    detail: "a node appeared at the path during restore".to_string(),
                },
                Some(libc::ENOENT) => PrivilegedOpOutcome::NotFound,
                _ => PrivilegedOpOutcome::Failed {
                    err: format!("mknodat: {e}"),
                },
            };
        }
        let euid = unsafe { libc::geteuid() };
        let made = match fstatat_nofollow(parent, name) {
            Ok(st) if kind_ok(&st) && st.st_uid == euid && st.st_mode & 0o7777 == 0 => st,
            _ => {
                // Not the node just made (swapped already); leave it.
                return PrivilegedOpOutcome::Failed {
                    err: "node at path is not the one just created".to_string(),
                };
            }
        };
        let ours = (made.st_dev, made.st_ino);
        let remove = || unlink_if_same(parent, name, ours);
        let node = match open_at(parent.as_raw_fd(), name, libc::O_PATH | libc::O_NOFOLLOW) {
            Ok(fd) => fd,
            Err(e) => {
                remove();
                return PrivilegedOpOutcome::Failed {
                    err: format!("open new node: {e}; removed"),
                };
            }
        };
        match fstat_fd(&node) {
            Ok(st) if (st.st_dev, st.st_ino) == ours => {}
            _ => {
                remove();
                return PrivilegedOpOutcome::Failed {
                    err: "node at path changed during restore; removed".to_string(),
                };
            }
        }
        if made.st_gid != gid {
            // uid -1: owner stays the invoking user.
            let rc = unsafe {
                libc::fchownat(
                    node.as_raw_fd(),
                    c"".as_ptr(),
                    libc::uid_t::MAX,
                    gid,
                    libc::AT_EMPTY_PATH,
                )
            };
            if rc != 0 {
                let e = errno();
                remove();
                return match e.raw_os_error() {
                    Some(libc::EPERM) => PrivilegedOpOutcome::Refused {
                        reason: format!(
                            "captured group {gid} is not one the invoking user can give \
                             without CAP_CHOWN; node removed"
                        ),
                    },
                    _ => PrivilegedOpOutcome::Failed {
                        err: format!("fchownat group {gid}: {e}; node removed"),
                    },
                };
            }
        }
        // chmod through the held O_PATH fd: /proc/self/fd/N names this
        // inode, not whatever is at `name` now.
        if let Err(e) = chmod_held(&node, perms) {
            remove();
            return PrivilegedOpOutcome::Failed {
                err: format!("chmod {perms:o}: {e}; node removed"),
            };
        }
        match fstat_fd(&node) {
            Ok(st) if all_ok(&st) => PrivilegedOpOutcome::Applied,
            Ok(st) => {
                remove();
                PrivilegedOpOutcome::Failed {
                    err: format!("restored node is {}; node removed", describe(&st)),
                }
            }
            Err(e) => {
                remove();
                PrivilegedOpOutcome::Failed {
                    err: format!("fstat new node: {e}; node removed"),
                }
            }
        }
    }
}

#[cfg(test)]
mod apply_mknod_tests {
    use super::*;
    use shit_proto::PrivilegedOpOutcome;
    use std::os::unix::fs::FileTypeExt;

    #[test]
    fn fifo_create_at_clean_path_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a_fifo");
        let mode = 0o010000 | 0o644;
        let outcome = apply_mknod(p.to_str().unwrap(), mode, 0, None);
        assert_eq!(outcome, PrivilegedOpOutcome::Applied);
        let ft = std::fs::symlink_metadata(&p).unwrap().file_type();
        assert!(ft.is_fifo(), "expected fifo, got {ft:?}");
    }

    /// Fifo and socket restores get exactly the captured permission bits
    /// (here bits a usual umask would clear) with no umask change: made
    /// with bits 0, then chmod'ed on the node.
    #[test]
    fn fifo_and_socket_get_the_captured_mode_without_a_umask_change() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let dir = tempfile::tempdir().unwrap();
        for (name, ifmt) in [("f", 0o010000u32), ("s", 0o140000u32)] {
            let p = dir.path().join(name);
            let outcome = apply_mknod(p.to_str().unwrap(), ifmt | 0o666, 0, None);
            assert_eq!(outcome, PrivilegedOpOutcome::Applied, "{name}");
            let m = std::fs::symlink_metadata(&p).unwrap();
            assert!(
                m.file_type().is_fifo() || m.file_type().is_socket(),
                "{name}"
            );
            assert_eq!(m.mode() & 0o7777, 0o666, "{name}");
        }
    }

    #[test]
    fn fifo_create_at_existing_fifo_is_idempotent_applied() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a_fifo");
        let mode = 0o010000 | 0o644;
        assert_eq!(
            apply_mknod(p.to_str().unwrap(), mode, 0, None),
            PrivilegedOpOutcome::Applied
        );
        // Second call on the same path with the same kind — applied.
        assert_eq!(
            apply_mknod(p.to_str().unwrap(), mode, 0, None),
            PrivilegedOpOutcome::Applied
        );
    }

    /// L4b: block/char nodes need this helper's capture token
    /// (Linux-only, like the restore itself).
    #[cfg(target_os = "linux")]
    mod device {
        use super::*;

        const CHR: u32 = 0o020000;
        /// 1:3, the number /dev/null has. Never a real disk.
        const NULL_DEV: u64 = (1 << 8) | 3;

        fn me() -> (u32, u32) {
            unsafe { (libc::geteuid(), libc::getegid()) }
        }

        /// Evidence as the daemon would send it back for a capture of
        /// `path` with these fields, signed by `key`.
        fn evidence(
            key: &capture_token::TokenKey,
            path: &str,
            mode: u32,
            rdev: u64,
            owner: (u32, u32),
        ) -> shit_proto::DeviceEvidence {
            use std::os::unix::fs::MetadataExt;
            // The node's filesystem: the parent's st_dev, as a capture on
            // this filesystem would have signed.
            let dev = std::path::Path::new(path)
                .parent()
                .and_then(|p| std::fs::metadata(p).ok())
                .map(|m| m.dev())
                .unwrap_or(0x803);
            evidence_on(key, path, mode, rdev, owner, dev)
        }

        fn evidence_on(
            key: &capture_token::TokenKey,
            path: &str,
            mode: u32,
            rdev: u64,
            owner: (u32, u32),
            dev: u64,
        ) -> shit_proto::DeviceEvidence {
            let session = uuid::Uuid::from_u128(0x004c_3462);
            let facts = capture_token::DeviceFacts {
                mode,
                rdev,
                uid: owner.0,
                gid: owner.1,
                dev,
                ino: 77,
                path,
                session,
                seq: 9,
            };
            shit_proto::DeviceEvidence {
                uid: owner.0,
                gid: owner.1,
                dev,
                inode: 77,
                session,
                command_seq: 9,
                token: key.issue(&facts),
            }
        }

        fn this_helper() -> &'static capture_token::TokenKey {
            capture_token::process_key().expect("kernel RNG")
        }

        fn refused(o: &PrivilegedOpOutcome, needle: &str) -> bool {
            matches!(o, PrivilegedOpOutcome::Refused { reason } if reason.contains(needle))
        }

        #[test]
        fn device_mknod_without_a_captured_number_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("blk");
            let ps = p.to_str().unwrap();
            let ev = evidence(this_helper(), ps, 0o060644, 0, me());
            let outcome = apply_mknod(ps, 0o060644, 0, Some(&ev));
            assert!(refused(&outcome, "no device number"), "{outcome:?}");
            assert!(!p.exists());
        }

        #[test]
        fn forged_device_mknod_without_a_token_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("chr");
            let outcome = apply_mknod(p.to_str().unwrap(), CHR | 0o666, NULL_DEV, None);
            assert!(refused(&outcome, "no capture evidence"), "{outcome:?}");
            assert!(std::fs::symlink_metadata(&p).is_err());
        }

        #[test]
        fn forged_device_mknod_with_a_bad_token_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("chr");
            let ps = p.to_str().unwrap();
            let mut ev = evidence(this_helper(), ps, CHR | 0o640, NULL_DEV, me());
            ev.token.mac[5] ^= 0x40;
            let outcome = apply_mknod(ps, CHR | 0o640, NULL_DEV, Some(&ev));
            assert!(refused(&outcome, "does not match"), "{outcome:?}");
            assert!(std::fs::symlink_metadata(&p).is_err());
        }

        #[test]
        fn token_for_other_fields_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("chr");
            let q = dir.path().join("elsewhere");
            let (ps, qs) = (p.to_str().unwrap(), q.to_str().unwrap());
            let (u, g) = me();
            let ev = evidence(this_helper(), ps, CHR | 0o640, NULL_DEV, (u, g));
            // Another rdev, another kind, wider mode, another path.
            for (path, mode, rdev) in [
                (ps, CHR | 0o640, (1u64 << 8) | 5),
                (ps, 0o060640, NULL_DEV),
                (ps, CHR | 0o666, NULL_DEV),
                (qs, CHR | 0o640, NULL_DEV),
            ] {
                let outcome = apply_mknod(path, mode, rdev, Some(&ev));
                assert!(
                    refused(&outcome, "does not match"),
                    "{path} {mode:o} {rdev:#x}: {outcome:?}"
                );
            }
            // Another owner or another removed inode than the token covers.
            for forged in [
                shit_proto::DeviceEvidence { uid: 0, ..ev },
                shit_proto::DeviceEvidence { gid: 0, ..ev },
                shit_proto::DeviceEvidence { inode: 78, ..ev },
                shit_proto::DeviceEvidence {
                    command_seq: 10,
                    ..ev
                },
            ] {
                let outcome = apply_mknod(ps, CHR | 0o640, NULL_DEV, Some(&forged));
                assert!(
                    refused(&outcome, "does not match"),
                    "{forged:?}: {outcome:?}"
                );
            }
            assert!(std::fs::symlink_metadata(&p).is_err());
            assert!(std::fs::symlink_metadata(&q).is_err());
        }

        #[test]
        fn token_from_a_previous_helper_process_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("chr");
            let ps = p.to_str().unwrap();
            // A key this process never held stands in for the helper that
            // ran before a restart.
            let previous = capture_token::TokenKey::generate().unwrap();
            let ev = evidence(&previous, ps, CHR | 0o640, NULL_DEV, me());
            let outcome = apply_mknod(ps, CHR | 0o640, NULL_DEV, Some(&ev));
            assert_eq!(
                outcome,
                PrivilegedOpOutcome::Refused {
                    reason: "capture evidence expired: helper restarted".to_string()
                }
            );
            assert!(std::fs::symlink_metadata(&p).is_err());
        }

        #[test]
        fn owner_other_than_the_invoking_user_is_refused_before_mknod() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("chr");
            let ps = p.to_str().unwrap();
            let (u, g) = me();
            let other = if u == 0 { 1 } else { 0 };
            let ev = evidence(this_helper(), ps, CHR | 0o640, NULL_DEV, (other, g));
            let outcome = apply_mknod(ps, CHR | 0o640, NULL_DEV, Some(&ev));
            assert!(refused(&outcome, "not the invoking user"), "{outcome:?}");
            assert!(std::fs::symlink_metadata(&p).is_err());
        }

        /// Review round 3, item 1: cleanup after a failed restore removes
        /// only the node it made; an entry swapped in at the name stays.
        #[test]
        fn cleanup_leaves_a_swapped_in_entry_alone() {
            use std::os::unix::fs::MetadataExt;
            let dir = tempfile::tempdir().unwrap();
            let a = dir.path().join("a");
            std::fs::write(&a, b"ours").unwrap();
            let m = std::fs::metadata(&a).unwrap();
            let ours = (m.dev(), m.ino());
            let b = dir.path().join("b");
            std::fs::write(&b, b"theirs").unwrap();
            std::fs::rename(&b, &a).unwrap();
            let (parent, name) = dirfd::open_parent(a.to_str().unwrap()).unwrap();
            dirfd::unlink_if_same(&parent, &name, ours);
            assert_eq!(std::fs::read(&a).unwrap(), b"theirs");
            let now = std::fs::metadata(&a).unwrap();
            dirfd::unlink_if_same(&parent, &name, (now.dev(), now.ino()));
            assert!(std::fs::symlink_metadata(&a).is_err());
        }

        /// Review round 2, item 1: a token signed for one filesystem is not
        /// honored on another.
        #[test]
        fn parent_on_another_filesystem_than_the_signed_dev_is_refused() {
            use std::os::unix::fs::MetadataExt;
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("chr");
            let ps = p.to_str().unwrap();
            let real = std::fs::metadata(dir.path()).unwrap().dev();
            let ev = evidence_on(this_helper(), ps, CHR | 0o640, NULL_DEV, me(), real ^ 1);
            let outcome = apply_mknod(ps, CHR | 0o640, NULL_DEV, Some(&ev));
            assert!(refused(&outcome, "different filesystem"), "{outcome:?}");
            assert!(std::fs::symlink_metadata(&p).is_err());
        }

        /// Review round 2, item 1: never made on a `nodev` filesystem.
        /// /dev/shm is nodev on the usual Linux setups; skipped otherwise.
        #[test]
        fn nodev_target_filesystem_is_refused() {
            let Ok(shm) = tempfile::tempdir_in("/dev/shm") else {
                return;
            };
            let fd = std::fs::File::open(shm.path()).unwrap();
            if !capture_token::fs_is_nodev(std::os::fd::AsRawFd::as_raw_fd(&fd)).unwrap() {
                return;
            }
            let p = shm.path().join("chr");
            let ps = p.to_str().unwrap();
            let ev = evidence(this_helper(), ps, CHR | 0o640, NULL_DEV, me());
            let outcome = apply_mknod(ps, CHR | 0o640, NULL_DEV, Some(&ev));
            assert!(
                refused(&outcome, "does not allow device nodes"),
                "{outcome:?}"
            );
            assert!(std::fs::symlink_metadata(&p).is_err());
        }

        #[test]
        fn parent_swapped_to_a_symlink_is_refused() {
            // The token is for <dir>/sub/chr. Before the apply, `sub` is
            // replaced by a symlink to another directory; the helper must
            // not follow it.
            let dir = tempfile::tempdir().unwrap();
            let elsewhere = dir.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).unwrap();
            let sub = dir.path().join("sub");
            std::os::unix::fs::symlink(&elsewhere, &sub).unwrap();
            let p = sub.join("chr");
            let ps = p.to_str().unwrap();
            let ev = evidence(this_helper(), ps, CHR | 0o640, NULL_DEV, me());
            let outcome = apply_mknod(ps, CHR | 0o640, NULL_DEV, Some(&ev));
            assert!(refused(&outcome, "symlink"), "{outcome:?}");
            assert!(std::fs::symlink_metadata(elsewhere.join("chr")).is_err());
            // A `..` in a token-backed path is refused too.
            let dotdot = format!("{}/sub/../chr", dir.path().display());
            let ev = evidence(this_helper(), &dotdot, CHR | 0o640, NULL_DEV, me());
            let outcome = apply_mknod(&dotdot, CHR | 0o640, NULL_DEV, Some(&ev));
            assert!(refused(&outcome, ".."), "{outcome:?}");
        }

        #[test]
        fn valid_token_and_own_owner_reach_mknod_with_the_captured_mode() {
            use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("chr");
            let ps = p.to_str().unwrap();
            let (u, g) = me();
            let mode = CHR | 0o640;
            let ev = evidence(this_helper(), ps, mode, NULL_DEV, (u, g));
            let outcome = apply_mknod(ps, mode, NULL_DEV, Some(&ev));
            if outcome == PrivilegedOpOutcome::PermissionDenied {
                // No CAP_MKNOD in this test process: every check passed and
                // the kernel refused mknodat. Nothing was created. Set
                // SHIT_TEST_REQUIRE_MKNOD=1 when the binary has cap_mknod.
                assert!(
                    std::env::var_os("SHIT_TEST_REQUIRE_MKNOD").is_none(),
                    "mknodat refused although SHIT_TEST_REQUIRE_MKNOD is set"
                );
                assert!(std::fs::symlink_metadata(&p).is_err());
                return;
            }
            assert_eq!(outcome, PrivilegedOpOutcome::Applied);
            let m = std::fs::symlink_metadata(&p).unwrap();
            assert!(m.file_type().is_char_device());
            assert_eq!(m.rdev(), NULL_DEV);
            assert_eq!(m.mode() & 0o7777, 0o640);
            assert_eq!((m.uid(), m.gid()), (u, g));
            // Replaying the same restore is idempotent.
            assert_eq!(
                apply_mknod(ps, mode, NULL_DEV, Some(&ev)),
                PrivilegedOpOutcome::Applied
            );
            // A node whose mode now differs is a conflict and is left alone.
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                apply_mknod(ps, mode, NULL_DEV, Some(&ev)),
                PrivilegedOpOutcome::Conflict { .. }
            ));
            assert_eq!(
                std::fs::symlink_metadata(&p).unwrap().mode() & 0o7777,
                0o600
            );
        }

        #[test]
        fn existing_node_with_another_number_is_a_conflict() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("chr");
            let ps = p.to_str().unwrap();
            // A fifo where the char node should go: kind differs.
            let c = std::ffi::CString::new(ps).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o640) }, 0);
            let ev = evidence(this_helper(), ps, CHR | 0o640, NULL_DEV, me());
            assert!(matches!(
                apply_mknod(ps, CHR | 0o640, NULL_DEV, Some(&ev)),
                PrivilegedOpOutcome::Conflict { .. }
            ));
        }
    }

    #[test]
    fn refuses_zero_kind() {
        // No file-type bits set — caller forgot to encode the kind.
        let outcome = apply_mknod("/tmp/au22_nokind", 0o644, 0, None);
        assert_eq!(outcome, PrivilegedOpOutcome::PermissionDenied);
    }

    #[test]
    fn fifo_create_with_missing_parent_returns_not_found() {
        let outcome = apply_mknod("/nonexistent/au22/parent/fifo", 0o010000 | 0o644, 0, None);
        assert_eq!(outcome, PrivilegedOpOutcome::NotFound);
    }

    #[test]
    fn rejects_path_with_nul_byte() {
        let outcome = apply_mknod("/tmp/has\0nul", 0o010000 | 0o644, 0, None);
        assert!(matches!(outcome, PrivilegedOpOutcome::Failed { .. }));
    }

    #[test]
    fn existing_regular_file_at_path_is_failed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("regfile");
        std::fs::write(&p, b"x").unwrap();
        let outcome = apply_mknod(p.to_str().unwrap(), 0o010000 | 0o644, 0, None);
        assert!(matches!(outcome, PrivilegedOpOutcome::Failed { .. }));
    }
}

#[cfg(test)]
mod apply_chown_tests {
    use super::*;
    use shit_proto::PrivilegedOpOutcome;

    /// #227: on Linux a chown with no capture evidence is refused,
    /// before anything is touched.
    #[cfg(target_os = "linux")]
    #[test]
    fn chown_without_evidence_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let key = capture_token::process_key();
        let o = apply_chown(p.to_str().unwrap(), uid, gid, true, None, key);
        assert!(matches!(o, PrivilegedOpOutcome::Refused { .. }), "{o:?}");
        // Not even an arbitrary root path gets past the evidence check.
        let o = apply_chown("/etc/shadow", uid, gid, false, None, key);
        assert!(matches!(o, PrivilegedOpOutcome::Refused { .. }), "{o:?}");
    }

    /// Off Linux the pre-#227 path-based chown is kept until those
    /// helpers issue capture tokens.
    #[cfg(not(target_os = "linux"))]
    mod non_linux {
        use super::*;

        #[test]
        fn chown_to_self_uid_is_applied() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("self_chown");
            std::fs::write(&p, b"x").unwrap();
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };
            let outcome = apply_chown(p.to_str().unwrap(), uid, gid, false, None);
            assert_eq!(outcome, PrivilegedOpOutcome::Applied);
        }

        #[test]
        fn chown_nonexistent_path_is_not_found() {
            let outcome = apply_chown("/nonexistent/au28/does/not/exist", 0, 0, false, None);
            assert_eq!(outcome, PrivilegedOpOutcome::NotFound);
        }

        #[test]
        fn chown_path_with_nul_byte_fails() {
            let outcome = apply_chown("/tmp/has\0nul", 0, 0, false, None);
            assert!(matches!(outcome, PrivilegedOpOutcome::Failed { .. }));
        }

        #[test]
        fn lchown_branch_is_reachable() {
            let dir = tempfile::tempdir().unwrap();
            let link = dir.path().join("au28_link");
            std::os::unix::fs::symlink("/nonexistent-target", &link).unwrap();
            let uid = unsafe { libc::geteuid() };
            let gid = unsafe { libc::getegid() };
            let outcome = apply_chown(link.to_str().unwrap(), uid, gid, true, None);
            assert_eq!(outcome, PrivilegedOpOutcome::Applied);
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::os::unix::fs::MetadataExt;

        fn this_helper() -> &'static capture_token::TokenKey {
            capture_token::process_key().expect("kernel RNG")
        }

        fn me() -> (u32, u32) {
            unsafe { (libc::geteuid(), libc::getegid()) }
        }

        /// Evidence `key` would issue for `path` as it is on disk now,
        /// claiming `owner` as the captured owner.
        fn evidence(
            key: &capture_token::TokenKey,
            path: &str,
            owner: (u32, u32),
        ) -> shit_proto::OwnerEvidence {
            let m = std::fs::symlink_metadata(path).unwrap();
            let session = uuid::Uuid::from_u128(0x227);
            let token = key.issue(&capture_token::OwnerFacts {
                uid: owner.0,
                gid: owner.1,
                dev: m.dev(),
                ino: m.ino(),
                path,
                session,
                seq: 9,
            });
            shit_proto::OwnerEvidence {
                dev: m.dev(),
                inode: m.ino(),
                session,
                command_seq: 9,
                token,
            }
        }

        fn chown(
            path: &str,
            owner: (u32, u32),
            follow: bool,
            ev: &shit_proto::OwnerEvidence,
        ) -> PrivilegedOpOutcome {
            apply_chown(
                path,
                owner.0,
                owner.1,
                !follow,
                Some(ev),
                Some(this_helper()),
            )
        }

        fn refused(o: &PrivilegedOpOutcome, needle: &str) -> bool {
            matches!(o, PrivilegedOpOutcome::Refused { reason } if reason.contains(needle))
        }

        #[test]
        fn valid_evidence_for_the_current_owner_is_applied() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("f");
            std::fs::write(&p, b"x").unwrap();
            let ps = p.to_str().unwrap();
            let ev = evidence(this_helper(), ps, me());
            assert_eq!(chown(ps, me(), false, &ev), PrivilegedOpOutcome::Applied);
        }

        /// A token with its MAC flipped, or for other fields than the
        /// request, is refused and nothing changes.
        #[test]
        fn forged_or_mismatched_evidence_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("f");
            std::fs::write(&p, b"x").unwrap();
            let ps = p.to_str().unwrap();
            let ev = evidence(this_helper(), ps, me());
            let mut bad = ev;
            bad.token.mac[0] ^= 1;
            assert!(refused(&chown(ps, me(), false, &bad), "does not match"));
            // Same token, another owner (root): the classic escalation.
            assert!(refused(&chown(ps, (0, 0), false, &ev), "does not match"));
            // Same token, another path.
            let q = dir.path().join("g");
            std::fs::write(&q, b"y").unwrap();
            assert!(refused(
                &chown(q.to_str().unwrap(), me(), false, &ev),
                "does not match"
            ));
            // Another inode or device claimed for the same token.
            for v in [
                shit_proto::OwnerEvidence {
                    inode: ev.inode + 1,
                    ..ev
                },
                shit_proto::OwnerEvidence {
                    dev: ev.dev + 1,
                    ..ev
                },
                shit_proto::OwnerEvidence {
                    command_seq: 10,
                    ..ev
                },
            ] {
                assert!(refused(&chown(ps, me(), false, &v), "does not match"));
            }
            assert_eq!(std::fs::metadata(&p).unwrap().uid(), me().0);
        }

        #[test]
        fn token_from_a_previous_helper_process_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("f");
            std::fs::write(&p, b"x").unwrap();
            let ps = p.to_str().unwrap();
            let old = capture_token::TokenKey::generate().unwrap();
            let ev = evidence(&old, ps, me());
            assert!(refused(
                &chown(ps, me(), false, &ev),
                "capture evidence expired: helper restarted"
            ));
        }

        /// The file at the path was replaced after capture: the token
        /// names the old inode, so the new file is a conflict.
        #[test]
        fn replaced_file_is_a_conflict() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("f");
            std::fs::write(&p, b"x").unwrap();
            let ps = p.to_str().unwrap();
            let ev = evidence(this_helper(), ps, me());
            let keep = dir.path().join("keep");
            std::fs::rename(&p, &keep).unwrap();
            std::fs::write(&p, b"new").unwrap();
            assert!(matches!(
                chown(ps, me(), false, &ev),
                PrivilegedOpOutcome::Conflict { .. }
            ));
        }

        /// A parent swapped to a symlink after capture is not followed,
        /// even when the symlink leads to the captured file.
        #[test]
        fn parent_swapped_to_a_symlink_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let real = dir.path().join("real");
            std::fs::create_dir(&real).unwrap();
            std::fs::write(real.join("f"), b"x").unwrap();
            let link = dir.path().join("d");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let ps = format!("{}/f", link.to_str().unwrap());
            let ev = evidence(this_helper(), &ps, me());
            assert!(refused(&chown(&ps, me(), false, &ev), "symlink"));
        }

        /// The entry is a symlink and the request asks for chown(2),
        /// which would follow it: refused. lchown(2) of the link itself
        /// is applied.
        #[test]
        fn following_a_symlink_entry_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("t");
            std::fs::write(&target, b"x").unwrap();
            let link = dir.path().join("l");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let ps = link.to_str().unwrap();
            let ev = evidence(this_helper(), ps, me());
            assert!(refused(&chown(ps, me(), true, &ev), "symlink"));
            assert_eq!(chown(ps, me(), false, &ev), PrivilegedOpOutcome::Applied);
        }

        /// With a valid token for a foreign owner the helper still cannot
        /// give it: it holds no CAP_CHOWN, so the kernel says no and the
        /// file keeps its owner.
        #[test]
        fn valid_evidence_for_a_foreign_owner_is_denied_without_cap_chown() {
            if me().0 == 0
                || crate::priv_linux::capget().unwrap().permitted
                    & (1 << crate::priv_linux::CAP_CHOWN)
                    != 0
            {
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("f");
            std::fs::write(&p, b"x").unwrap();
            let ps = p.to_str().unwrap();
            let ev = evidence(this_helper(), ps, (0, 0));
            assert_eq!(
                chown(ps, (0, 0), false, &ev),
                PrivilegedOpOutcome::PermissionDenied
            );
            assert_eq!(std::fs::metadata(&p).unwrap().uid(), me().0);
        }

        #[test]
        fn missing_file_is_not_found() {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("f");
            std::fs::write(&p, b"x").unwrap();
            let ps = p.to_str().unwrap();
            let ev = evidence(this_helper(), ps, me());
            std::fs::remove_file(&p).unwrap();
            assert_eq!(chown(ps, me(), false, &ev), PrivilegedOpOutcome::NotFound);
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
