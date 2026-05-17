// SPDX-License-Identifier: AGPL-3.0-or-later

use clap::{Parser, Subcommand, ValueEnum};
use shit_proto::ShellKind;
use std::path::PathBuf;

mod cmd;
mod crash;
mod doctor;
mod exitcode;
mod hooks;
mod paths;
mod prompt;
mod render;
mod send;
mod service;
mod status;

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
    name = "shit",
    about = "magic undo for the command line",
    version = env!("CARGO_PKG_VERSION"),
    long_version = LONG_VERSION,
    // Bare `shit` (no subcommand, no args) must work — it's the
    // headline UX. clap's `args_conflicts_with_subcommands` would
    // let us also accept top-level flags as a shorthand, but we
    // *do not* want that: bare `shit` only accepts the no-arg form.
    // `shit --dry-run`, `shit 3`, `shit --on-conflict=skip` must all
    // be rejected — those belong to `shit undo`. The `Option<Cmd>`
    // + no top-level args achieves that.
)]
pub struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Reverse the effects of recent commands.
    ///
    /// Bare `shit` is equivalent to `shit undo` with default args.
    /// To use a non-default arg (like `--dry-run` or `N`), you MUST
    /// type `shit undo` explicitly — the top-level `shit` does not
    /// accept undo's flags.
    Undo(cmd::undo::UndoArgs),
    /// Re-apply the most recently-undone command.
    Redo(cmd::redo::RedoArgs),
    /// Cathartic alias for `shit undo`. Same args.
    #[command(name = "fuck")]
    Fuck(cmd::undo::UndoArgs),
    /// List captured commands (most recent first).
    List(cmd::list::ListArgs),
    /// Show details for one captured command.
    Show(cmd::show::ShowArgs),
    /// Pin a command's savepoint to protect it from GC.
    Pin(cmd::pin::PinArgs),
    /// Install/remove/status the package-manager hooks (apt, pacman,
    /// dnf, brew, FreeBSD pkg). See `shit pkg-hooks --help`.
    #[command(name = "pkg-hooks")]
    PkgHooks(cmd::pkg_hooks::PkgHooksArgs),
    /// Install/remove/status the service-manager wrappers (systemctl,
    /// launchctl). See `shit svc-hooks --help`.
    #[command(name = "svc-hooks")]
    SvcHooks(cmd::svc_hooks::SvcHooksArgs),
    /// Install/remove/status the network-tool wrappers (iptables,
    /// nft, ufw, pfctl, ip). See `shit net-hooks --help`.
    #[command(name = "net-hooks")]
    NetHooks(cmd::net_hooks::NetHooksArgs),
    /// Install/remove/status the process-tool wrappers (kill, pkill,
    /// killall). See `shit proc-hooks --help`.
    #[command(name = "proc-hooks")]
    ProcHooks(cmd::proc_hooks::ProcHooksArgs),
    /// Install/remove/status the DB CLI wrappers (psql, mysql,
    /// sqlite3). Opt-in stretch UX. See `shit db-hooks --help`.
    #[command(name = "db-hooks")]
    DbHooks(cmd::db_hooks::DbHooksArgs),
    /// Query the daemon's perf-counter snapshot. `--format prometheus`
    /// for scraping; `--watch 1s` for live updates.
    Metrics(cmd::metrics::MetricsArgs),
    /// Drop a captured command's savepoint.
    Forget(cmd::forget::ForgetArgs),
    /// Manual blob-store garbage collection.
    Gc(cmd::gc::GcArgs),
    /// Read or write the user's config file.
    Config(cmd::config::ConfigArgs),
    /// Temporarily disable capture (this session or this shell).
    Disable(cmd::disable::DisableArgs),
    /// Re-enable capture after `shit disable`.
    Enable(cmd::disable::EnableArgs),
    /// Run a command WITHOUT capture protection (bypass hard-fail).
    #[command(name = "no-protect")]
    NoProtect(cmd::no_protect::NoProtectArgs),
    /// Emit a shell-completion script for the given shell.
    Completions(cmd::completions::CompletionsArgs),
    /// Write roff man pages for `shit` and each subcommand to a directory.
    /// (Packaging helper; users should use `shit help` instead.)
    #[command(hide = true)]
    Manpages(cmd::manpages::ManpagesArgs),
    /// Manage shell hook integration.
    Hooks {
        #[command(subcommand)]
        action: HooksCmd,
    },
    /// Show daemon status.
    Status {
        /// Override the ctl socket path.
        #[arg(long)]
        ctl_sock: Option<PathBuf>,
    },
    /// Install / manage the daemon under launchd, systemd --user, runit, or manual mode.
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    /// Send one hook event to the daemon. Invoked by shell hooks.
    #[command(name = "hook-send", hide = true)]
    HookSend {
        #[command(subcommand)]
        kind: send::HookSendKind,
    },
    /// Internal helpers (used by shell hooks on platforms without `/proc`).
    #[command(hide = true)]
    Internal {
        #[command(subcommand)]
        action: InternalCmd,
    },
    /// Inspect filesystem support and capture-tier choices for your mounts.
    Doctor,
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Render the right template, write it, and register with the service manager.
    Install,
    /// Deregister from the service manager and remove the template file.
    Uninstall,
    /// Ask the service manager to start the daemon.
    Start,
    /// Ask the service manager to stop the daemon.
    Stop,
    /// Print service-manager-side status for the daemon.
    Status,
}

#[derive(Subcommand)]
enum HooksCmd {
    /// Install the hook script and source it from the user's rc file.
    Install {
        #[arg(long, value_enum, default_value_t = ShellOpt::Auto)]
        shell: ShellOpt,
    },
    /// Remove the shit marker block from the rc file. Leaves the hook script in place.
    Uninstall {
        #[arg(long, value_enum, default_value_t = ShellOpt::Auto)]
        shell: ShellOpt,
    },
    /// Show install state per shell.
    Status,
}

#[derive(Subcommand)]
enum InternalCmd {
    /// Print a fresh v4 UUID. Used by shell hooks on systems without /proc.
    NewUuid,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ShellOpt {
    Auto,
    Bash,
    Zsh,
    Fish,
}

impl ShellOpt {
    fn resolve(self) -> Option<ShellKind> {
        match self {
            Self::Auto => detect_shell(),
            Self::Bash => Some(ShellKind::Bash),
            Self::Zsh => Some(ShellKind::Zsh),
            Self::Fish => Some(ShellKind::Fish),
        }
    }
}

fn detect_shell() -> Option<ShellKind> {
    let shell = std::env::var("SHELL").ok()?;
    let name = std::path::Path::new(&shell).file_name()?.to_str()?;
    match name {
        "bash" => Some(ShellKind::Bash),
        "zsh" => Some(ShellKind::Zsh),
        "fish" => Some(ShellKind::Fish),
        _ => None,
    }
}

fn main() -> std::process::ExitCode {
    // S21.8 — install panic hook first so any panic during
    // tracing init or arg parsing produces a canonical crash file.
    // No-op if state_dir isn't writable (sandboxed CI runs).
    crash::install_panic_hook();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    // S21.2 — root span carrying schema-required fields. The CLI is
    // one-shot per invocation, so this span lives for the duration of
    // `main`. Subcommand handlers see it via tracing's task-local
    // span stack.
    let root_span = tracing::info_span!(
        "cli",
        component = "cli",
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        commit = env!("VERGEN_GIT_SHA"),
    );
    let _root_guard = root_span.enter();
    // Bare `shit` (cli.cmd == None) → dispatch to undo with defaults.
    // Do NOT parse further argv tokens here — see the doc-comment on
    // the `Cli` struct for why.
    let cmd = cli.cmd.unwrap_or(Cmd::Undo(cmd::undo::UndoArgs::default()));
    let result = run_cmd(cmd);
    match result {
        Ok(()) => exitcode::exit(exitcode::SUCCESS),
        Err(CliMainErr::Cli(e)) => {
            eprintln!("shit: {e}");
            exitcode::exit(e.code())
        }
        Err(CliMainErr::Anyhow(e)) => {
            eprintln!("shit: {e}");
            exitcode::exit(exitcode::GENERIC_FAILURE)
        }
    }
}

/// Marshals the two possible error types subcommands return into
/// something `main` can pattern-match. New subcommands should return
/// `CliError` directly — `anyhow::Result` is the legacy shape.
enum CliMainErr {
    Cli(exitcode::CliError),
    Anyhow(anyhow::Error),
}

impl From<exitcode::CliError> for CliMainErr {
    fn from(e: exitcode::CliError) -> Self {
        Self::Cli(e)
    }
}
impl From<anyhow::Error> for CliMainErr {
    fn from(e: anyhow::Error) -> Self {
        Self::Anyhow(e)
    }
}

fn run_cmd(cmd: Cmd) -> Result<(), CliMainErr> {
    match cmd {
        Cmd::Undo(args) | Cmd::Fuck(args) => Ok(cmd::undo::run(args)?),
        Cmd::Redo(args) => Ok(cmd::redo::run(args)?),
        Cmd::List(args) => Ok(cmd::list::run(args)?),
        Cmd::Show(args) => Ok(cmd::show::run(args)?),
        Cmd::Pin(args) => Ok(cmd::pin::run(args)?),
        Cmd::PkgHooks(args) => Ok(cmd::pkg_hooks::run(args)?),
        Cmd::SvcHooks(args) => Ok(cmd::svc_hooks::run(args)?),
        Cmd::NetHooks(args) => Ok(cmd::net_hooks::run(args)?),
        Cmd::ProcHooks(args) => Ok(cmd::proc_hooks::run(args)?),
        Cmd::DbHooks(args) => Ok(cmd::db_hooks::run(args)?),
        Cmd::Metrics(args) => Ok(cmd::metrics::run(args)?),
        Cmd::Forget(args) => Ok(cmd::forget::run(args)?),
        Cmd::Gc(args) => Ok(cmd::gc::run(args)?),
        Cmd::Config(args) => Ok(cmd::config::run(args)?),
        Cmd::Disable(args) => Ok(cmd::disable::run(args)?),
        Cmd::Enable(args) => Ok(cmd::disable::enable(args)?),
        Cmd::NoProtect(args) => Ok(cmd::no_protect::run(args)?),
        Cmd::Completions(args) => Ok(cmd::completions::run(args)?),
        Cmd::Manpages(args) => Ok(cmd::manpages::run(args)?),
        Cmd::Hooks { action } => match action {
            HooksCmd::Install { shell } => Ok(hooks::install(shell.resolve())?),
            HooksCmd::Uninstall { shell } => Ok(hooks::uninstall(shell.resolve())?),
            HooksCmd::Status => Ok(hooks::status()?),
        },
        Cmd::Status { ctl_sock } => Ok(status::run(ctl_sock)?),
        Cmd::Service { action } => match action {
            ServiceCmd::Install => Ok(service::install()?),
            ServiceCmd::Uninstall => Ok(service::uninstall()?),
            ServiceCmd::Start => Ok(service::start()?),
            ServiceCmd::Stop => Ok(service::stop()?),
            ServiceCmd::Status => Ok(service::status()?),
        },
        Cmd::HookSend { kind } => Ok(send::run(kind)?),
        Cmd::Internal { action } => match action {
            InternalCmd::NewUuid => {
                println!("{}", uuid::Uuid::now_v7());
                Ok(())
            }
        },
        Cmd::Doctor => Ok(doctor::run()?),
    }
}

fn home_dir() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("$HOME is not set"))
}

fn config_home() -> anyhow::Result<PathBuf> {
    if let Some(s) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(s));
    }
    Ok(home_dir()?.join(".config"))
}
