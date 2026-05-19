// SPDX-License-Identifier: AGPL-3.0-or-later

//! FreeBSD `service(8)` inspector (S29.6).
//!
//! State capture runs `/usr/sbin/service <unit> onestatus` and folds
//! its exit code + a small set of derived flags into a stable text
//! shape the planner can parse. Unlike systemd's `show -p key=value`
//! output, `service`'s output is human-readable and varies per rc.d
//! script. We normalize into:
//!
//! ```text
//! ActiveState=<running|stopped|unknown>
//! ScriptPath=/etc/rc.d/<unit>  (or /usr/local/etc/rc.d/<unit>)
//! EnabledFlag=<YES|NO|UNKNOWN>
//! ```
//!
//! `ActiveState` derives from `service <unit> onestatus`'s exit code
//! (0 = running, 1 = stopped). `EnabledFlag` checks
//! `service -e | grep <unit>` to see if the unit is in the enabled
//! list. The script path is needed for the planner's undo plan so
//! the executor can call `service <unit> {start,stop}` with the
//! right binary path.

use std::process::Command;

use shit_proto::{SvcScopeWire, SvcToolWire};

use super::SvcInspector;

pub struct ServiceInspector;

impl SvcInspector for ServiceInspector {
    fn tool(&self) -> SvcToolWire {
        SvcToolWire::Service
    }
    fn collect_state(&self, scope: SvcScopeWire, unit: &str) -> anyhow::Result<String> {
        // FreeBSD service(8) doesn't have a user scope; reject any
        // non-`RcBase` request so the wrapper script's caller sees a
        // clear error instead of silently using the wrong scope.
        if !matches!(scope, SvcScopeWire::RcBase) {
            return Err(anyhow::anyhow!(
                "freebsd service(8) only supports RcBase scope; got {:?}",
                scope
            ));
        }

        let active = service_active_state(unit);
        let enabled = service_enabled_flag(unit);
        let script = service_script_path(unit).unwrap_or_else(|| "<unknown>".into());

        let mut out = String::new();
        out.push_str(&format!("ActiveState={active}\n"));
        out.push_str(&format!("ScriptPath={script}\n"));
        out.push_str(&format!("EnabledFlag={enabled}\n"));
        Ok(out)
    }
}

/// Active-state probe. `service <unit> onestatus` is the rc.d
/// idiomatic answer, but rc.d scripts read `/var/run/<unit>.pid` which
/// is mode 0600 root:wheel on most installs — so an unprivileged
/// helper sees "not running" for everything. We use `pgrep -q <unit>`
/// as the primary signal (process name typically matches the unit
/// name on FreeBSD: cron, sshd, nginx, etc.) and fall back to
/// `service onestatus` if pgrep is absent.
///
/// **Known limitation:** when the unit name differs from the process
/// name (e.g. rc.d script `postgresql` → binary `postgres`), pgrep
/// returns "stopped" even when the unit is up. Documented in
/// `bsd-coverage.md`; the proper fix requires parsing the rc.d
/// script's `procname` variable and is deferred.
fn service_active_state(unit: &str) -> &'static str {
    if let Ok(out) = Command::new("/bin/pgrep").args(["-q", unit]).output() {
        return match out.status.code() {
            Some(0) => "running",
            Some(1) => "stopped",
            _ => "unknown",
        };
    }
    let out = Command::new("/usr/sbin/service")
        .args([unit, "onestatus"])
        .output();
    match out {
        Ok(o) => match o.status.code() {
            Some(0) => "running",
            Some(1) => "stopped",
            _ => "unknown",
        },
        Err(_) => "unknown",
    }
}

/// Run `service -e` and look for the unit in the enabled list.
/// Returns "YES" / "NO" / "UNKNOWN".
fn service_enabled_flag(unit: &str) -> &'static str {
    let out = match Command::new("/usr/sbin/service").arg("-e").output() {
        Ok(o) if o.status.success() => o,
        _ => return "UNKNOWN",
    };
    let text = String::from_utf8_lossy(&out.stdout);
    // service -e prints one absolute path per line, e.g. /etc/rc.d/cron.
    // Match the basename to handle both base + ports scripts.
    for line in text.lines() {
        let basename = std::path::Path::new(line.trim())
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if basename == unit {
            return "YES";
        }
    }
    "NO"
}

/// Locate the rc.d script for `unit`. Checks /etc/rc.d (base) then
/// /usr/local/etc/rc.d (ports). Returns the absolute path or None.
fn service_script_path(unit: &str) -> Option<String> {
    for prefix in ["/etc/rc.d", "/usr/local/etc/rc.d"] {
        let p = std::path::Path::new(prefix).join(unit);
        if p.is_file() {
            return p.to_str().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_is_service() {
        assert_eq!(ServiceInspector.tool(), SvcToolWire::Service);
    }

    #[test]
    fn rejects_non_rc_base_scope() {
        let r = ServiceInspector.collect_state(SvcScopeWire::User, "cron");
        assert!(r.is_err());
    }

    /// Live test — only runs on FreeBSD where /usr/sbin/service exists.
    /// Picks `cron` (always present on FreeBSD base) and verifies the
    /// output shape, not the exact state.
    #[cfg(target_os = "freebsd")]
    #[test]
    fn collect_state_for_cron_returns_three_keys() {
        let out = ServiceInspector
            .collect_state(SvcScopeWire::RcBase, "cron")
            .expect("collect");
        assert!(out.contains("ActiveState="));
        assert!(out.contains("ScriptPath="));
        assert!(out.contains("EnabledFlag="));
    }
}
