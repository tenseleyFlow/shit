// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS `networksetup` inspector (M06.1 + M06.5).
//!
//! Supported verbs (mutating subcommands the wrapper brackets):
//!
//! | wire `verb`             | pre-state query                 |
//! |-------------------------|---------------------------------|
//! | `setdnsservers` (M06.1) | `networksetup -getdnsservers <svc>` |
//! | `setmanual`     (M06.5) | `networksetup -getinfo <svc>`       |
//! | `setdhcp`       (M06.5) | `networksetup -getinfo <svc>`       |
//! | `switchtolocation` (M06.5) | `networksetup -getcurrentlocation` |
//!
//! The captured bytes are prefixed with a metadata header so the
//! planner-side synthesiser can route to the correct per-verb
//! inverse logic without needing new fields on the
//! `CaptureEventKind::NetworkOp` wire:
//!
//! ```text
//! # verb=<v>
//! # scope=<service or empty>
//! <raw -get* stdout>
//! ```
//!
//! Backcompat for M06.1: when no `# verb=` line is present the
//! planner defaults to `setdnsservers`. The M06.1 inspector only
//! emitted `# scope=`; that captures-on-trunk remain replayable.

use std::process::Command;

use shit_proto::NetToolWire;

use super::NetInspector;

pub struct NetworksetupInspector;

impl NetInspector for NetworksetupInspector {
    fn tool(&self) -> NetToolWire {
        NetToolWire::Networksetup
    }

    /// `verb` is the stripped CLI verb (`setdnsservers`, `setmanual`,
    /// `setdhcp`, `switchtolocation`). `scope_hint` carries the
    /// network-service name for the per-service verbs (empty for
    /// `switchtolocation` which is global).
    fn collect_state(&self, verb: &str, scope_hint: &str) -> anyhow::Result<Vec<u8>> {
        let raw = match verb {
            // M06.1 — DNS list.
            "setdnsservers" => {
                require_scope(verb, scope_hint)?;
                run_networksetup(&["-getdnsservers", scope_hint])?
            }
            // M06.5 — service-level IP config (DHCP/Manual/Off/BOOTP).
            // Both setmanual and setdhcp read the same -getinfo dump;
            // the synthesiser parses "DHCP Configuration" vs
            // "Manual Configuration" from the first line to pick the
            // right inverse verb.
            "setmanual" | "setdhcp" => {
                require_scope(verb, scope_hint)?;
                run_networksetup(&["-getinfo", scope_hint])?
            }
            // M06.5 — current location name; no service scope.
            "switchtolocation" => run_networksetup(&["-getcurrentlocation"])?,
            // M06.1 backcompat: unknown verbs that still reach the
            // inspector (e.g., an empty verb from the M06.1 helper
            // before --verb plumbing landed) fall back to DNS so
            // existing journal entries keep replaying.
            "" => {
                require_scope("setdnsservers", scope_hint)?;
                run_networksetup(&["-getdnsservers", scope_hint])?
            }
            other => {
                return Err(anyhow::anyhow!(
                    "networksetup inspector: unsupported verb {other:?}"
                ));
            }
        };

        // Prepend the metadata header. `#`-prefixed lines are not
        // valid networksetup output, so the header is unambiguous to
        // the parser on the planner side.
        let mut bytes = format!("# verb={verb}\n# scope={scope_hint}\n").into_bytes();
        bytes.extend_from_slice(&raw);
        Ok(bytes)
    }
}

fn require_scope(verb: &str, scope_hint: &str) -> anyhow::Result<()> {
    if scope_hint.is_empty() {
        return Err(anyhow::anyhow!(
            "networksetup inspector: {verb} requires a service name (empty scope_hint)"
        ));
    }
    Ok(())
}

fn run_networksetup(args: &[&str]) -> anyhow::Result<Vec<u8>> {
    let out = Command::new("networksetup").args(args).output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "networksetup {} exited {:?}: {}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_is_networksetup() {
        assert_eq!(NetworksetupInspector.tool(), NetToolWire::Networksetup);
    }

    #[test]
    fn empty_scope_hint_errors_for_per_service_verbs() {
        for verb in ["setdnsservers", "setmanual", "setdhcp"] {
            let err = NetworksetupInspector.collect_state(verb, "").unwrap_err();
            let msg = format!("{err}");
            assert!(msg.contains("requires a service name"), "{verb}: got {msg}");
        }
    }

    #[test]
    fn unknown_verb_errors() {
        let err = NetworksetupInspector
            .collect_state("bogus", "Wi-Fi")
            .unwrap_err();
        assert!(format!("{err}").contains("unsupported verb"));
    }
}
