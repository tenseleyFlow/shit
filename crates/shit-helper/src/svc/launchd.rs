// SPDX-License-Identifier: AGPL-3.0-or-later

//! launchd inspector (S16.5).
//!
//! State capture is two-tier:
//!
//! 1. Prefer `launchctl print <domain>/<label>`. The `print`
//!    subcommand is the modern (macOS 10.11+) authoritative source;
//!    output includes `state =`, `disabled =`, `path =`, and the
//!    `path-state =` block.
//! 2. Fall back to `launchctl list <label>` for older systems that
//!    pre-date `print`. The legacy form returns a tab-separated
//!    `PID Status Label` row; we convert it into the loose
//!    key/value shape the planner's [`parse_launchctl_print`]
//!    accepts.
//!
//! The domain is derived from the scope:
//! - `LaunchdGui` → `gui/<uid>`
//! - `LaunchdSystem` → `system`
//! - `User` is a legacy alias for `gui/<uid>`; same handling.
//! - `System` is a legacy alias for `system`.

use std::process::Command;

use shit_proto::{SvcScopeWire, SvcToolWire};

use super::SvcInspector;

pub struct LaunchdInspector;

impl SvcInspector for LaunchdInspector {
    fn tool(&self) -> SvcToolWire {
        SvcToolWire::Launchctl
    }
    fn collect_state(&self, scope: SvcScopeWire, unit: &str) -> anyhow::Result<String> {
        let domain = domain_for(scope);
        let target = format!("{domain}/{unit}");
        if let Some(out) = try_print(&target) {
            return Ok(out);
        }
        // Fallback: legacy `launchctl list <label>`. Output is
        // tab-separated: `PID Status Label`. We synthesize the
        // key=value lines the planner accepts.
        if let Some(legacy) = try_list(unit) {
            return Ok(legacy);
        }
        Ok(String::new())
    }
}

fn domain_for(scope: SvcScopeWire) -> String {
    match scope {
        SvcScopeWire::LaunchdGui | SvcScopeWire::User => {
            // SAFETY: getuid always succeeds.
            let uid = unsafe { libc::getuid() };
            format!("gui/{uid}")
        }
        SvcScopeWire::LaunchdSystem | SvcScopeWire::System => "system".to_string(),
        // Not applicable on macOS; route to system as the best-effort
        // closest match. The launchd inspector caller is only ever
        // dispatched from a `launchctl` invocation, so RcBase
        // shouldn't get here in practice.
        SvcScopeWire::RcBase => "system".to_string(),
    }
}

fn try_print(target: &str) -> Option<String> {
    let out = Command::new("launchctl")
        .args(["print", target])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn try_list(label: &str) -> Option<String> {
    let out = Command::new("launchctl")
        .args(["list", label])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    // launchctl list emits one block of pseudo-plist when given a
    // label argument. Sample (heavily abbreviated):
    //
    //     {
    //         "Label" = "com.example.foo";
    //         "PID" = 1234;
    //         "LastExitStatus" = 0;
    //     };
    //
    // The planner's parser accepts a `state = N` form (legacy PID
    // representation). Massage the PID field into that shape so the
    // shared parser doesn't need a launchctl-list-specific path.
    let mut out_lines = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim().trim_end_matches([';', ',']);
        if let Some(rest) = trimmed.strip_prefix("\"PID\" =") {
            let pid = rest.trim().parse::<i64>().unwrap_or(0);
            out_lines.push(format!("state = {pid}"));
        } else if trimmed == "{" || trimmed == "}" {
            // skip braces — the parser is line-shaped
        } else {
            out_lines.push(line.to_string());
        }
    }
    Some(out_lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_is_launchctl() {
        assert_eq!(LaunchdInspector.tool(), SvcToolWire::Launchctl);
    }

    #[test]
    fn domain_for_gui_uses_uid() {
        let d = domain_for(SvcScopeWire::LaunchdGui);
        assert!(d.starts_with("gui/"));
    }

    #[test]
    fn domain_for_system_is_system() {
        assert_eq!(domain_for(SvcScopeWire::LaunchdSystem), "system");
        assert_eq!(domain_for(SvcScopeWire::System), "system");
    }

    // Live-launchctl smoke is gated on DR-35.
}
