// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit forget <id>` — drop a captured command's savepoint
//! (real implementation, S13.8).

use clap::Args;
use shit_proto::{CtlRequest, CtlResponse};

use crate::cmd::ctl_client;
use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct ForgetArgs {
    /// Command id to forget. Format `<session>:<seq>`.
    pub id: String,
    /// Don't prompt before forgetting. Required when stdin isn't a TTY.
    #[arg(long, default_value_t = false)]
    pub yes: bool,
    /// Override the daemon ctl socket path.
    #[arg(long)]
    pub ctl_sock: Option<std::path::PathBuf>,
}

pub fn run(args: ForgetArgs) -> Result<(), CliError> {
    let ctl_path = args
        .ctl_sock
        .clone()
        .unwrap_or_else(crate::paths::default_ctl_socket_path);
    let resp = ctl_client::call(
        &ctl_path,
        &CtlRequest::Forget {
            id: args.id.clone(),
            yes: args.yes,
        },
    )?;
    match resp {
        CtlResponse::PinAck => {
            println!("forgotten: {}", args.id);
            Ok(())
        }
        CtlResponse::Error(e) => Err(CliError::fail(GENERIC_FAILURE, format!("daemon: {e}"))),
        other => Err(CliError::fail(
            GENERIC_FAILURE,
            format!("unexpected response: {other:?}"),
        )),
    }
}
