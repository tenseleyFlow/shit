// SPDX-License-Identifier: AGPL-3.0-or-later

//! iptables/ip6tables inspector (S17.4).
//!
//! State capture runs `iptables-save -c` (or `ip6tables-save -c`).
//! The `-c` flag preserves packet/byte counters; the executor's
//! `iptables-restore` happily replays them. From an undo
//! perspective, counter-restoration is intentional: the counters
//! roll back along with the rules.
//!
//! Output is binary-safe (the dump may contain non-UTF-8 bytes
//! inside comment strings, in theory) so we return `Vec<u8>` from
//! stdout directly.

use std::process::Command;

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct IptablesInspector {
    pub v6: bool,
}

impl NetInspector for IptablesInspector {
    fn tool(&self) -> NetToolWire {
        if self.v6 {
            NetToolWire::Ip6tables
        } else {
            NetToolWire::Iptables
        }
    }
    fn collect_state(&self, _verb: &str, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        let bin = if self.v6 {
            "ip6tables-save"
        } else {
            "iptables-save"
        };
        let out = Command::new(bin).arg("-c").output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "{bin} exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iptables_v4_tool() {
        let i = IptablesInspector { v6: false };
        assert_eq!(i.tool(), NetToolWire::Iptables);
    }

    #[test]
    fn iptables_v6_tool() {
        let i = IptablesInspector { v6: true };
        assert_eq!(i.tool(), NetToolWire::Ip6tables);
    }

    // Live iptables-save smoke is DR-39.
}
