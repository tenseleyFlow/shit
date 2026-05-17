// SPDX-License-Identifier: AGPL-3.0-or-later

//! nft inspector (S17.5 fills in real `nft list ruleset -a`).

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct NftInspector;

impl NetInspector for NftInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Nft
    }
    fn collect_state(&self, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
