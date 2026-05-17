// SPDX-License-Identifier: AGPL-3.0-or-later

//! pacman inspector (S14.5 fills in the real implementation).

use std::collections::BTreeMap;

use shit_proto::PkgManagerWire;

use super::PkgInspector;

pub struct PacmanInspector;

impl PkgInspector for PacmanInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Pacman
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        // S14.5 wires `pacman -Q` parsing.
        Ok(BTreeMap::new())
    }
}
