// SPDX-License-Identifier: AGPL-3.0-or-later

//! systemd inspector (S16.4).
//!
//! State capture runs:
//!
//! ```text
//! systemctl [--user] show \
//!     -p ActiveState -p UnitFileState -p LoadState \
//!     -p Description -p Type -p Restart \
//!     <unit>
//! ```
//!
//! and returns the raw output verbatim. The planner's
//! [`shit_planner::parse_systemctl_show`] decodes the three
//! state-relevant keys; `Description` / `Type` / `Restart` are
//! carried through for `shit show` rendering without re-querying.

use std::process::Command;

use shit_proto::{SvcScopeWire, SvcToolWire};

use super::SvcInspector;

pub struct SystemdInspector;

impl SvcInspector for SystemdInspector {
    fn tool(&self) -> SvcToolWire {
        SvcToolWire::Systemctl
    }
    fn collect_state(&self, scope: SvcScopeWire, unit: &str) -> anyhow::Result<String> {
        let mut cmd = Command::new("systemctl");
        if matches!(scope, SvcScopeWire::User) {
            cmd.arg("--user");
        }
        cmd.args([
            "show",
            "-p",
            "ActiveState",
            "-p",
            "UnitFileState",
            "-p",
            "LoadState",
            "-p",
            "Description",
            "-p",
            "Type",
            "-p",
            "Restart",
            unit,
        ]);
        let out = cmd.output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "systemctl show exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shit_proto::SvcToolWire;

    #[test]
    fn tool_is_systemctl() {
        assert_eq!(SystemdInspector.tool(), SvcToolWire::Systemctl);
    }

    // Live-systemctl smoke is gated on DR-34 (Linux runner with a
    // user-scope unit). Stage 1 unit tests are confined to the pure
    // parser in shit-planner::services; the shell-out path is
    // covered by the broader integration matrix in S22.
}
