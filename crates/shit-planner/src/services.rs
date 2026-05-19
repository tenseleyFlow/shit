// SPDX-License-Identifier: AGPL-3.0-or-later

//! systemctl/launchctl state parsers + verb classifiers (S16.2).
//!
//! Pure helpers shared between the helper-side inspector (which
//! captures Pre/Post snapshots) and the planner-side executor
//! (which synthesizes the inverse invocation). No I/O.
//!
//! ## State capture
//!
//! - **systemctl** state is queried via
//!   `systemctl show -p ActiveState,UnitFileState,LoadState <unit>`.
//!   Output is a stable `KEY=VALUE` block, one per line. We parse
//!   just the three keys we care about; everything else is opaque
//!   and forwarded verbatim into [`ServiceState::raw`] for `shit
//!   show`.
//! - **launchctl** state is queried via
//!   `launchctl print gui/<uid>/<label>` (modern) or
//!   `launchctl list <label>` (older macOS). Both produce
//!   key-value-ish output; we extract `state` and `disabled` (and
//!   whether the unit is bootstrapped at all).
//!
//! ## Verb classification
//!
//! Only a handful of subcommands mutate state. The wrapper queries
//! [`is_systemctl_mutating`] / [`is_launchctl_mutating`] to decide
//! whether to capture; non-mutating verbs are pass-through.

use crate::events::ServiceState;

/// systemctl subcommands that mutate runtime state. The list matches
/// the sprint's stated coverage; we err on capturing more rather
/// than missing real mutations.
pub const SYSTEMCTL_MUTATING_VERBS: &[&str] = &[
    "start",
    "stop",
    "restart",
    "reload",
    "try-restart",
    "reload-or-restart",
    "enable",
    "disable",
    "mask",
    "unmask",
    "kill",
    "preset",
    "set-property",
    "edit",
    "link",
    "revert",
    "isolate",
    "daemon-reload",
];

/// launchctl subcommands that mutate runtime state.
pub const LAUNCHCTL_MUTATING_VERBS: &[&str] = &[
    "bootstrap",
    "bootout",
    "enable",
    "disable",
    "kickstart",
    "kill",
    "start",
    "stop",
    "reboot-user",
    "load",
    "unload",
];

/// True when the given systemctl verb mutates state. Reads matching
/// is case-sensitive (systemctl itself is).
pub fn is_systemctl_mutating(verb: &str) -> bool {
    SYSTEMCTL_MUTATING_VERBS.contains(&verb)
}

/// True when the given launchctl verb mutates state.
pub fn is_launchctl_mutating(verb: &str) -> bool {
    LAUNCHCTL_MUTATING_VERBS.contains(&verb)
}

/// Parse the output of
/// `systemctl show -p ActiveState,UnitFileState,LoadState <unit>`.
///
/// Real-world output sample:
///
/// ```text
/// ActiveState=active
/// UnitFileState=enabled
/// LoadState=loaded
/// ```
///
/// We accept any order, ignore unknown keys, and treat absent keys
/// as `LoadState=not-found` / `ActiveState=inactive` / `UnitFileState=disabled`
/// rather than failing. Failure modes (the command exits non-zero,
/// the unit doesn't exist) are the caller's to handle; this fn is
/// pure parsing.
pub fn parse_systemctl_show(text: &str) -> ServiceState {
    let mut active_state = None;
    let mut unit_file_state = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "ActiveState" => active_state = Some(v.to_string()),
                "UnitFileState" => unit_file_state = Some(v.to_string()),
                // `LoadState` is captured into `raw` below; we don't
                // need to decode it explicitly. Other keys (Description,
                // etc.) flow through `raw` for `shit show`.
                _ => {}
            }
        }
    }
    let active = matches!(
        active_state.as_deref(),
        Some("active" | "activating" | "reloading")
    );
    let unit_file = unit_file_state.as_deref().unwrap_or("disabled");
    let enabled = matches!(
        unit_file,
        "enabled" | "enabled-runtime" | "alias" | "linked" | "linked-runtime" | "static"
    );
    let masked = matches!(unit_file, "masked" | "masked-runtime");
    ServiceState {
        active,
        enabled,
        masked,
        raw: text.trim().to_string(),
    }
}

/// Parse `launchctl print gui/<uid>/<label>` output. The format is
/// dense and bracketed; for state-tracking we only need a small
/// subset:
///
/// ```text
/// com.example.foo = {
///     active count = 0
///     path = /Library/LaunchAgents/com.example.foo.plist
///     state = running
///     disabled = false
///     ...
/// }
/// ```
///
/// We also accept `launchctl list <label>` legacy output, which has
/// `state = N` (PID; 0 means not running) and no explicit `disabled`
/// — we infer `enabled` from the unit being present in the listing
/// at all.
pub fn parse_launchctl_print(text: &str) -> ServiceState {
    let mut active = false;
    let mut enabled = true;
    let mut found_unit = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        found_unit = true;
        // The modern `print` form uses `state = running`; the older
        // `list` form uses an integer state (the PID or 0/-).
        if let Some(rest) = line.strip_prefix("state =") {
            let rest = rest.trim();
            // Modern: word like "running" / "not running" / "waiting".
            if rest.starts_with("running") {
                active = true;
            } else if rest.starts_with("not running") || rest.starts_with("waiting") {
                active = false;
            } else {
                // Legacy: integer.
                match rest.parse::<i64>() {
                    Ok(n) if n > 0 => active = true,
                    _ => active = false,
                }
            }
        }
        if let Some(rest) = line.strip_prefix("disabled =") {
            let rest = rest.trim().trim_end_matches([';', ',']);
            enabled = !matches!(rest, "true" | "1");
        }
    }
    if !found_unit {
        // launchctl print of a non-existent label prints an error
        // line on stderr and an empty stdout. We treat empty as
        // not-present-and-not-active.
        return ServiceState {
            active: false,
            enabled: false,
            masked: false,
            raw: text.trim().to_string(),
        };
    }
    ServiceState {
        active,
        enabled,
        masked: false,
        raw: text.trim().to_string(),
    }
}

/// FreeBSD `service(8)` mutating subcommands. The rc.d framework
/// accepts `start`, `stop`, `restart`, `reload`, plus `one*` variants
/// that bypass the `<name>_enable` rc.conf gate. Capture all of them.
pub const SERVICE_MUTATING_VERBS: &[&str] = &[
    "start",
    "stop",
    "restart",
    "reload",
    "onestart",
    "onestop",
    "onerestart",
    "forcestart",
    "forcestop",
    "forcerestart",
    "quietstart",
    "quietstop",
    "quietrestart",
    "enable",
    "disable",
];

/// True when the given FreeBSD `service(8)` verb mutates state.
pub fn is_service_mutating(verb: &str) -> bool {
    SERVICE_MUTATING_VERBS.contains(&verb)
}

/// Parse the normalized output produced by
/// `crates/shit-helper/src/svc/freebsd.rs::ServiceInspector::collect_state`.
///
/// The inspector emits a stable three-line `KEY=VALUE` block:
///
/// ```text
/// ActiveState=<running|stopped|unknown>
/// ScriptPath=/etc/rc.d/<unit>
/// EnabledFlag=<YES|NO|UNKNOWN>
/// ```
///
/// `service(8)` has no concept of "masked" — that's a systemd-ism —
/// so `masked` is always false. `raw` holds the verbatim block for
/// `shit show` to render.
pub fn parse_freebsd_service(text: &str) -> ServiceState {
    let mut active_state: Option<&str> = None;
    let mut enabled_flag: Option<&str> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "ActiveState" => active_state = Some(v.trim()),
                "EnabledFlag" => enabled_flag = Some(v.trim()),
                _ => {}
            }
        }
    }
    let active = matches!(active_state, Some("running"));
    let enabled = matches!(enabled_flag, Some("YES"));
    ServiceState {
        active,
        enabled,
        masked: false,
        raw: text.trim().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemctl_mutating_classification() {
        assert!(is_systemctl_mutating("start"));
        assert!(is_systemctl_mutating("enable"));
        assert!(is_systemctl_mutating("daemon-reload"));
        assert!(!is_systemctl_mutating("status"));
        assert!(!is_systemctl_mutating("list-units"));
        assert!(!is_systemctl_mutating("show"));
    }

    #[test]
    fn launchctl_mutating_classification() {
        assert!(is_launchctl_mutating("bootstrap"));
        assert!(is_launchctl_mutating("bootout"));
        assert!(is_launchctl_mutating("load"));
        assert!(!is_launchctl_mutating("print"));
        assert!(!is_launchctl_mutating("list"));
    }

    #[test]
    fn parse_systemctl_show_active_enabled() {
        let input = "\
ActiveState=active
UnitFileState=enabled
LoadState=loaded
";
        let s = parse_systemctl_show(input);
        assert!(s.active);
        assert!(s.enabled);
        assert!(!s.masked);
    }

    #[test]
    fn parse_systemctl_show_inactive_disabled() {
        let input = "\
ActiveState=inactive
UnitFileState=disabled
LoadState=loaded
";
        let s = parse_systemctl_show(input);
        assert!(!s.active);
        assert!(!s.enabled);
        assert!(!s.masked);
    }

    #[test]
    fn parse_systemctl_show_masked() {
        let input = "\
ActiveState=inactive
UnitFileState=masked
LoadState=masked
";
        let s = parse_systemctl_show(input);
        assert!(!s.active);
        assert!(!s.enabled);
        assert!(s.masked);
    }

    #[test]
    fn parse_systemctl_show_activating_counts_as_active() {
        let input = "\
ActiveState=activating
UnitFileState=enabled
LoadState=loaded
";
        assert!(parse_systemctl_show(input).active);
    }

    #[test]
    fn parse_systemctl_show_missing_keys_defaults_to_inactive_disabled() {
        let s = parse_systemctl_show("");
        assert!(!s.active);
        assert!(!s.enabled);
        assert!(!s.masked);
    }

    #[test]
    fn parse_systemctl_show_unknown_keys_ignored() {
        let input = "\
ActiveState=active
UnitFileState=enabled
LoadState=loaded
Description=A useful service
ExecStart=/usr/bin/foo
";
        let s = parse_systemctl_show(input);
        assert!(s.active);
        assert!(s.enabled);
        assert!(s.raw.contains("Description="));
    }

    #[test]
    fn parse_launchctl_print_modern_running() {
        let input = "\
com.example.foo = {
    active count = 1
    path = /Library/LaunchAgents/com.example.foo.plist
    state = running
    disabled = false
}
";
        let s = parse_launchctl_print(input);
        assert!(s.active);
        assert!(s.enabled);
    }

    #[test]
    fn parse_launchctl_print_modern_not_running_disabled() {
        let input = "\
com.example.foo = {
    state = not running
    disabled = true
}
";
        let s = parse_launchctl_print(input);
        assert!(!s.active);
        assert!(!s.enabled);
    }

    #[test]
    fn parse_launchctl_print_legacy_running_via_pid() {
        // `launchctl list com.example.foo` form: state column is an
        // integer PID (or 0/- for not running).
        let input = "\
state = 1234
";
        let s = parse_launchctl_print(input);
        assert!(s.active);
    }

    #[test]
    fn parse_launchctl_print_empty_text_is_not_present() {
        let s = parse_launchctl_print("");
        assert!(!s.active);
        assert!(!s.enabled);
    }

    #[test]
    fn service_mutating_classification() {
        assert!(is_service_mutating("start"));
        assert!(is_service_mutating("onestart"));
        assert!(is_service_mutating("restart"));
        assert!(is_service_mutating("enable"));
        assert!(!is_service_mutating("status"));
        assert!(!is_service_mutating("onestatus"));
        assert!(!is_service_mutating("rcvar"));
    }

    #[test]
    fn parse_freebsd_service_running_enabled() {
        let input = "\
ActiveState=running
ScriptPath=/etc/rc.d/cron
EnabledFlag=YES
";
        let s = parse_freebsd_service(input);
        assert!(s.active);
        assert!(s.enabled);
        assert!(!s.masked);
        assert!(s.raw.contains("ScriptPath=/etc/rc.d/cron"));
    }

    #[test]
    fn parse_freebsd_service_stopped_disabled() {
        let input = "\
ActiveState=stopped
ScriptPath=/usr/local/etc/rc.d/foo
EnabledFlag=NO
";
        let s = parse_freebsd_service(input);
        assert!(!s.active);
        assert!(!s.enabled);
    }

    #[test]
    fn parse_freebsd_service_unknown_treated_as_inactive() {
        let input = "\
ActiveState=unknown
ScriptPath=<unknown>
EnabledFlag=UNKNOWN
";
        let s = parse_freebsd_service(input);
        assert!(!s.active);
        assert!(!s.enabled);
    }

    #[test]
    fn parse_freebsd_service_empty_defaults_to_inactive_disabled() {
        let s = parse_freebsd_service("");
        assert!(!s.active);
        assert!(!s.enabled);
        assert!(!s.masked);
    }
}
