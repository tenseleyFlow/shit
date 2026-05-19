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
//! `pfctl -s rules` requires root on BSD (reads /dev/pf, which is
//! mode 0600 root:wheel). If the inspector runs as a non-root user,
//! it auto-escalates via `doas` or `sudo` at runtime — same pattern
//! S29.6 established for the FreeBSD service(8) probe. Without an
//! escalator available AND the helper isn't already root, the
//! affected sections come back empty and the daemon's net-track
//! reports "unchanged; dropping" — which means undo can't fire.

use std::path::Path;
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

/// Resolve the `pfctl` invocation with privilege escalation if the
/// helper isn't already root. `doas` is preferred (BSD canonical);
/// `sudo` is the fallback. If neither is present, fall back to
/// direct invocation — works when the helper happens to be root.
fn run(args: &[&str]) -> anyhow::Result<Vec<u8>> {
    // SAFETY: getuid always succeeds.
    let is_root = unsafe { libc::getuid() } == 0;
    let escalator = if is_root {
        None
    } else {
        ["/usr/local/bin/doas", "/usr/local/bin/sudo", "/usr/bin/sudo"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
    };
    let mut cmd = match escalator {
        Some(e) => {
            let mut c = Command::new(e);
            c.arg("/sbin/pfctl");
            c.args(args);
            c
        }
        None => {
            let mut c = Command::new("/sbin/pfctl");
            c.args(args);
            c
        }
    };
    let out = cmd.output()?;
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
