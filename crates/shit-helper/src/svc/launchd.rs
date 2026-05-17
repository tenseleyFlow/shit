// SPDX-License-Identifier: AGPL-3.0-or-later

//! launchd inspector (S16.5 fills in the real query).

use shit_proto::{SvcScopeWire, SvcToolWire};

use super::SvcInspector;

pub struct LaunchdInspector;

impl SvcInspector for LaunchdInspector {
    fn tool(&self) -> SvcToolWire {
        SvcToolWire::Launchctl
    }
    fn collect_state(&self, _scope: SvcScopeWire, _unit: &str) -> anyhow::Result<String> {
        // S16.5 wires `launchctl print` + `launchctl list` fallback.
        Ok(String::new())
    }
}
