// SPDX-License-Identifier: AGPL-3.0-or-later

//! ufw inspector (S17.6).
//!
//! ufw has no native dump-and-restore. The capture combines:
//!
//! - `ufw status verbose` — overall on/off, default policies, logging.
//! - `ufw status numbered` — rule list with positional numbers and
//!   the full rule strings (the strings, not the numbers, are what
//!   the inverse uses — rule numbers shift if other rules change
//!   between capture and undo).
//!
//! Both outputs are returned concatenated, separated by a `\n---\n`
//! sentinel so the planner can split them.

use std::process::Command;

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct UfwInspector;

const SEP: &[u8] = b"\n---\n";

impl NetInspector for UfwInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Ufw
    }
    fn collect_state(&self, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        let verbose = run(&["status", "verbose"])?;
        let numbered = run(&["status", "numbered"])?;
        let mut out = Vec::with_capacity(verbose.len() + SEP.len() + numbered.len());
        out.extend_from_slice(&verbose);
        out.extend_from_slice(SEP);
        out.extend_from_slice(&numbered);
        Ok(out)
    }
}

fn run(args: &[&str]) -> anyhow::Result<Vec<u8>> {
    let out = Command::new("ufw").args(args).output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "ufw {} exited {:?}: {}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ufw_tool() {
        assert_eq!(UfwInspector.tool(), NetToolWire::Ufw);
    }
}
