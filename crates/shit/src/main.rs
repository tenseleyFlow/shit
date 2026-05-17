// SPDX-License-Identifier: AGPL-3.0-or-later

use clap::{Parser, Subcommand, ValueEnum};
use shit_proto::ShellKind;
use std::path::PathBuf;

mod cmd;
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

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    // Bare `shit` (cli.cmd == None) → dispatch to undo with defaults.
    // Do NOT parse further argv tokens here — see the doc-comment on
    // the `Cli` struct for why.
    let cmd = cli.cmd.unwrap_or(Cmd::Undo(cmd::undo::UndoArgs::default()));
    match cmd {
        Cmd::Undo(args) | Cmd::Fuck(args) => cmd::undo::run(args),
        Cmd::Redo(args) => cmd::redo::run(args).map_err(|e| e.into()),
        Cmd::List(args) => cmd::list::run(args).map_err(|e| e.into()),
        Cmd::Show(args) => cmd::show::run(args).map_err(|e| e.into()),
        Cmd::Pin(args) => cmd::pin::run(args).map_err(|e| e.into()),
        Cmd::Forget(args) => cmd::forget::run(args).map_err(|e| e.into()),
        Cmd::Gc(args) => cmd::gc::run(args).map_err(|e| e.into()),
        Cmd::Config(args) => cmd::config::run(args).map_err(|e| e.into()),
        Cmd::Disable(args) => cmd::disable::run(args).map_err(|e| e.into()),
        Cmd::Enable(args) => cmd::disable::enable(args).map_err(|e| e.into()),
        Cmd::NoProtect(args) => cmd::no_protect::run(args).map_err(|e| e.into()),
        Cmd::Completions(args) => cmd::completions::run(args).map_err(|e| e.into()),
        Cmd::Manpages(args) => cmd::manpages::run(args).map_err(|e| e.into()),
        Cmd::Hooks { action } => match action {
            HooksCmd::Install { shell } => hooks::install(shell.resolve()),
            HooksCmd::Uninstall { shell } => hooks::uninstall(shell.resolve()),
            HooksCmd::Status => hooks::status(),
        },
        Cmd::Status { ctl_sock } => status::run(ctl_sock),
        Cmd::Service { action } => match action {
            ServiceCmd::Install => service::install(),
            ServiceCmd::Uninstall => service::uninstall(),
            ServiceCmd::Start => service::start(),
            ServiceCmd::Stop => service::stop(),
            ServiceCmd::Status => service::status(),
        },
        Cmd::HookSend { kind } => send::run(kind),
        Cmd::Internal { action } => match action {
            InternalCmd::NewUuid => {
                println!("{}", uuid::Uuid::now_v7());
                Ok(())
            }
        },
        Cmd::Doctor => doctor::run(),
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
