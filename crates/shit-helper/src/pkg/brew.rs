// SPDX-License-Identifier: AGPL-3.0-or-later

//! Homebrew inspector (S14.7 fills in the real implementation).

use std::collections::BTreeMap;

use shit_proto::PkgManagerWire;

use super::PkgInspector;

pub struct BrewInspector;

impl PkgInspector for BrewInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Brew
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        // S14.7 wires `brew list --versions` parsing.
        Ok(BTreeMap::new())
    }
}
