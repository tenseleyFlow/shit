// SPDX-License-Identifier: AGPL-3.0-or-later

use clap::{Parser, Subcommand, ValueEnum};
use shit_proto::ShellKind;
use std::path::PathBuf;

mod hooks;
mod paths;
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
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
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
    match cli.cmd {
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
