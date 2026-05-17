// SPDX-License-Identifier: AGPL-3.0-or-later

//! dnf inspector (S14.6 fills in the real implementation).

use std::collections::BTreeMap;

use shit_proto::PkgManagerWire;

use super::PkgInspector;

pub struct DnfInspector;

impl PkgInspector for DnfInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Dnf
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        // S14.6 wires `dnf history list` parsing.
        Ok(BTreeMap::new())
    }
}
