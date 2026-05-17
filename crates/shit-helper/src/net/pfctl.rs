// SPDX-License-Identifier: AGPL-3.0-or-later

//! pfctl inspector (S17.7 fills in real pfctl state capture).

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct PfctlInspector;

impl NetInspector for PfctlInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Pfctl
    }
    fn collect_state(&self, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
