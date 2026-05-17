// SPDX-License-Identifier: AGPL-3.0-or-later

//! apt/dpkg inspector (S14.4 fills in the real implementation).

use std::collections::BTreeMap;

use shit_proto::PkgManagerWire;

use super::PkgInspector;

pub struct AptInspector;

impl PkgInspector for AptInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Apt
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        // S14.4 wires `dpkg-query -W -f='${Package} ${Version}\n'`.
        // Stage-1 stub returns an empty map so the trait composes
        // cleanly and the hook-friendly error policy is exercised.
        Ok(BTreeMap::new())
    }
}
