// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS `networksetup` inspector (M06.1).
//!
//! Scope: DNS-only first ship. The wrapper today only brackets
//! `-setdnsservers <service> <dns...>`; the inspector captures the
//! pre-mutation DNS list via `networksetup -getdnsservers <service>`
//! and ships it as the wire `before_state`. The planner's
//! `synthesise_networksetup_inverse` reads that state and emits
//! `["networksetup", "-setdnsservers", <service>, <dns...>]` as
//! the inverse — restoring the prior DNS list verbatim.
//!
//! Other `-set*` verbs (DHCP, manual-IP, location-switch) plumb
//! through the same wrapper + inspector + planner code paths, just
//! with different `-get*` queries; they're M06.x follow-ups.
//!
//! ## Output shape
//!
//! `networksetup -getdnsservers <service>` returns:
//!   - "There aren't any DNS Servers set on <service>." (no DNS configured)
//!   - One DNS server per line, e.g. "1.1.1.1\n8.8.8.8\n"
//!
//! We capture the raw stdout verbatim; the planner parses it.

use std::process::Command;

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct NetworksetupInspector;

impl NetInspector for NetworksetupInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Networksetup
    }

    /// `scope_hint` carries the network service name (e.g. "Wi-Fi",
    /// "Ethernet"). The wrapper passes the service from
    /// `-setdnsservers <service> ...`.
    fn collect_state(&self, scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        if scope_hint.is_empty() {
            return Err(anyhow::anyhow!(
                "networksetup inspector: empty scope_hint (need service name)"
            ));
        }
        // M06.1 — DNS-only. Other verbs (setmanual / setdhcp /
        // switchtolocation) need different `-get*` queries; route
        // them via a sub-verb in scope_hint in a follow-up. For
        // Stage 1 every networksetup capture is a DNS capture.
        let out = Command::new("networksetup")
            .args(["-getdnsservers", scope_hint])
            .output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "networksetup -getdnsservers {} exited {:?}: {}",
                scope_hint,
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        // M06.1 — prepend a `# scope=<service>` header so the
        // planner's `synthesise_networksetup_inverse` knows which
        // service to target without needing scope_hint plumbed
        // through the wire (CaptureEventKind::NetworkOp doesn't
        // currently carry per-event scope; adding a field there
        // would be a wider blast radius). The synthesizer strips
        // this prefix before parsing the DNS list. `#`-prefixed
        // lines are not valid networksetup output, so the header
        // is unambiguous.
        let mut bytes = format!("# scope={scope_hint}\n").into_bytes();
        bytes.extend_from_slice(&out.stdout);
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_is_networksetup() {
        assert_eq!(NetworksetupInspector.tool(), NetToolWire::Networksetup);
    }

    #[test]
    fn empty_scope_hint_errors() {
        let err = NetworksetupInspector.collect_state("").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("empty scope_hint"), "got: {msg}");
    }
}
