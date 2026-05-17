// SPDX-License-Identifier: AGPL-3.0-or-later

//! ufw inspector (S17.6 fills in `ufw status` capture).

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct UfwInspector;

impl NetInspector for UfwInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Ufw
    }
    fn collect_state(&self, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
