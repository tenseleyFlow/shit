// SPDX-License-Identifier: AGPL-3.0-or-later

use clap::Parser;

#[derive(Parser)]
#[command(name = "shitd", about = "shit daemon", version = build_version())]
struct Cli {
    #[arg(long)]
    foreground: bool,
}

fn build_version() -> &'static str {
    concat!(env!("CARGO_PKG_VERSION"), " (", env!("CARGO_PKG_NAME"), ")")
}

fn main() -> anyhow::Result<()> {
    let _ = Cli::parse();
    Ok(())
}
