// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS `route` and `ifconfig` inspectors (M06.3 — DR-44).
//!
//! Stage 1 (this slice): captures the full routing table /
//! interface table as the pre and post snapshots. The planner's
//! diff-apply synthesiser compares pre vs post and emits the
//! inverse command (route add ↔ delete; ifconfig up ↔ down;
//! alias ↔ -alias).
//!
//! Both tools predate `ip` and don't ship a JSON dump mode on
//! macOS, so we snapshot the human-formatted output and parse it
//! on the planner side. Output is stable across macOS 13–15 and
//! has been since BSD; the diff is computed from text-derived
//! identity tuples rather than reproducing route(8) or ifconfig(8)'s
//! exact formatter.
//!
//! ## Tools invoked
//!
//! - `RouteInspector` → `netstat -nrf inet` (IPv4 only first ship;
//!   IPv6 follow-up). The route(8) binary itself has no dump form,
//!   so netstat is canonical. We strip the trailing `Expire` column
//!   if present (BSD adds it for routes with a TTL).
//! - `IfconfigInspector` → `ifconfig -a`. Captures every interface
//!   with its flags + addresses; the planner diffs to derive
//!   up/down + alias toggles.
//!
//! ## Why no `scope_hint` semantics
//!
//! The diff is global (whole table). Unlike networksetup, the
//! wrapper has no per-service scope to thread through. The
//! `scope_hint` is accepted but ignored by these inspectors.

use std::process::Command;

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct RouteInspector;
pub struct IfconfigInspector;

impl NetInspector for RouteInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Route
    }

    fn collect_state(&self, _verb: &str, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        // `-n` numeric (no DNS round-trips during capture), `-r`
        // dump routing tables, `-f inet` v4 family.
        let out = Command::new("netstat").args(["-nrf", "inet"]).output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "netstat -nrf inet exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    }
}

impl NetInspector for IfconfigInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Ifconfig
    }

    fn collect_state(&self, _verb: &str, _scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        let out = Command::new("ifconfig").arg("-a").output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "ifconfig -a exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_inspector_tool() {
        assert_eq!(RouteInspector.tool(), NetToolWire::Route);
    }

    #[test]
    fn ifconfig_inspector_tool() {
        assert_eq!(IfconfigInspector.tool(), NetToolWire::Ifconfig);
    }

    // The actual `netstat` / `ifconfig` invocations are exercised
    // by the M06.3 smoke (route-add-undo-macos.sh). Unit tests
    // here would just be reading process output — covered by the
    // smoke's end-to-end assertion instead.
}
