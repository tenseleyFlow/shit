// SPDX-License-Identifier: AGPL-3.0-or-later

//! pfctl inspector (S17.7).
//!
//! pf state lives across several query commands; we capture all of
//! them and concatenate. The dump is delineated by section markers
//! the executor splits on:
//!
//! ```text
//! # SHIT pfctl section: rules
//! ...output of pfctl -s rules -a '*'...
//! # SHIT pfctl section: nat
//! ...output of pfctl -s nat...
//! # SHIT pfctl section: tables
//! ...output of pfctl -s tables -v...
//! # SHIT pfctl section: all
//! ...output of pfctl -sa...
//! ```
//!
//! `pfctl -s rules` requires root on BSD; the inspector runs as the
//! user, so on a non-root invocation those sections may be empty.
//! That's documented in the audit doc and surfaces as a clear
//! warning in `shit show`.

use std::process::Command;

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct PfctlInspector;

impl NetInspector for PfctlInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Pfctl
    }
    fn collect_state(&self, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        let sections: &[(&str, &[&str])] = &[
            ("rules", &["-s", "rules", "-a", "*"]),
            ("nat", &["-s", "nat"]),
            ("tables", &["-s", "tables", "-v"]),
            ("all", &["-sa"]),
        ];
        let mut out = Vec::new();
        for (name, args) in sections {
            out.extend_from_slice(format!("# SHIT pfctl section: {name}\n").as_bytes());
            match run(args) {
                Ok(bytes) => out.extend_from_slice(&bytes),
                Err(e) => {
                    tracing::warn!(section = name, err = %e, "pfctl section failed; skipping");
                }
            }
        }
        Ok(out)
    }
}

fn run(args: &[&str]) -> anyhow::Result<Vec<u8>> {
    let out = Command::new("pfctl").args(args).output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "pfctl {} exited {:?}: {}",
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
    fn pfctl_tool() {
        assert_eq!(PfctlInspector.tool(), NetToolWire::Pfctl);
    }
}
