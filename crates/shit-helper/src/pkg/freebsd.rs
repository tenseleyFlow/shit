// SPDX-License-Identifier: AGPL-3.0-or-later

//! FreeBSD pkg(8) inspector (S14.8 fills in the real implementation).
//!
//! Module is named `freebsd` rather than `pkg` to avoid shadowing the
//! parent `pkg` module path.

use std::collections::BTreeMap;

use shit_proto::PkgManagerWire;

pub struct PkgInspector;

impl super::PkgInspector for PkgInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Pkg
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        // S14.8 wires `pkg query "%n %v"` parsing.
        Ok(BTreeMap::new())
    }
}
