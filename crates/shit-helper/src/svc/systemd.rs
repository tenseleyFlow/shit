// SPDX-License-Identifier: AGPL-3.0-or-later

//! systemd inspector (S16.4 fills in the real query).

use shit_proto::{SvcScopeWire, SvcToolWire};

use super::SvcInspector;

pub struct SystemdInspector;

impl SvcInspector for SystemdInspector {
    fn tool(&self) -> SvcToolWire {
        SvcToolWire::Systemctl
    }
    fn collect_state(&self, _scope: SvcScopeWire, _unit: &str) -> anyhow::Result<String> {
        // S16.4 wires `systemctl [--user] show -p ... <unit>`.
        Ok(String::new())
    }
}
