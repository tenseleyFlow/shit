// SPDX-License-Identifier: AGPL-3.0-or-later

//! iptables/ip6tables inspector (S17.4 fills in real iptables-save).

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
    fn collect_state(&self, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        // S17.4 wires `iptables-save -c` (or `ip6tables-save -c`).
        Ok(Vec::new())
    }
}
