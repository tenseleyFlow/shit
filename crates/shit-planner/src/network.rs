// SPDX-License-Identifier: AGPL-3.0-or-later

//! Network-tool verb classifiers + restore-method classifier (S17.2).
//!
//! Pure helpers shared between the helper-side wrappers (which
//! capture Pre/Post snapshots) and the planner-side executor (which
//! synthesizes the inverse). No I/O.
//!
//! ## Restore methods
//!
//! Network tools split cleanly along whether they support atomic
//! "reload the whole state from a dump file":
//!
//! - **FullReload**: `iptables-restore`, `ip6tables-restore`,
//!   `nft -f <file>` (preceded by `nft flush ruleset`), `pfctl -f`.
//!   On undo, write the captured `before_state` to a temp file and
//!   run the restore command. Atomic; restores rules the user
//!   didn't touch as a side-effect, which is the correct behavior
//!   (their pre-state, after all).
//! - **DiffApply**: `ip route`/`ip addr`/`ip link`, `route`,
//!   `ifconfig`, `networksetup`. No atomic reload. Planner
//!   synthesizes per-row add/del commands from the captured JSON.
//! - **DiffApplyWithReset**: `ufw`. Atomic-ish: try delete-by-string
//!   first, fall back to `ufw reset` + reapply if too many changes.
//!
//! ## Verb classifiers
//!
//! Each tool has a list of mutating subcommands/verbs. Read-only
//! invocations pass through the wrapper without capture.

use crate::events::NetworkTool;

/// How the executor should restore `before_state` for a given tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreMethod {
    /// Pipe `before_state` into the tool's native restore command.
    /// One-shot, atomic where the tool supports it.
    FullReload,
    /// No atomic reload; replay synthesized add/del invocations
    /// from `inverse_invocations`.
    DiffApply,
    /// ufw's hybrid: try delete-by-string first, fall back to
    /// `ufw reset` + reapply when too many deltas.
    DiffApplyWithReset,
}

/// Pick the restore method per [`NetworkTool`]. The mapping is
/// stable across the project's lifetime — change it carefully.
pub fn restore_method(tool: NetworkTool) -> RestoreMethod {
    match tool {
        NetworkTool::Iptables | NetworkTool::Ip6tables => RestoreMethod::FullReload,
        NetworkTool::Nft => RestoreMethod::FullReload,
        NetworkTool::Pfctl => RestoreMethod::FullReload,
        NetworkTool::Ufw => RestoreMethod::DiffApplyWithReset,
        NetworkTool::IpRoute
        | NetworkTool::IpAddr
        | NetworkTool::IpLink
        | NetworkTool::Route
        | NetworkTool::Ifconfig
        | NetworkTool::Networksetup => RestoreMethod::DiffApply,
    }
}

/// iptables / ip6tables verbs that mutate state. The `-` short
/// forms (e.g. `-A` for `--append`) are matched as full argv tokens.
pub const IPTABLES_MUTATING: &[&str] = &[
    "-A",
    "--append",
    "-I",
    "--insert",
    "-D",
    "--delete",
    "-R",
    "--replace",
    "-F",
    "--flush",
    "-X",
    "--delete-chain",
    "-N",
    "--new-chain",
    "-E",
    "--rename-chain",
    "-P",
    "--policy",
    "-Z",
    "--zero",
];

pub fn is_iptables_mutating(args: &[String]) -> bool {
    args.iter().any(|a| IPTABLES_MUTATING.contains(&a.as_str()))
}

/// `nft` verbs that mutate state.
pub const NFT_MUTATING: &[&str] = &[
    "add", "delete", "replace", "create", "rename", "flush", "insert", "reset", "destroy",
];

pub fn is_nft_mutating(args: &[String]) -> bool {
    args.first()
        .is_some_and(|v| NFT_MUTATING.contains(&v.as_str()))
}

/// `ufw` verbs that mutate state.
pub const UFW_MUTATING: &[&str] = &[
    "enable", "disable", "reset", "default", "allow", "deny", "limit", "reject", "insert",
    "delete", "logging", "reload",
];

pub fn is_ufw_mutating(args: &[String]) -> bool {
    args.first()
        .is_some_and(|v| UFW_MUTATING.contains(&v.as_str()))
}

/// `pfctl` verbs that mutate state. pfctl is unusual: a single
/// invocation can both query and mutate (e.g. `-f <file>` reloads).
/// The classifier inspects all argv tokens.
pub const PFCTL_MUTATING: &[&str] = &["-f", "-F", "-d", "-e", "-O", "-R", "-T"];

pub fn is_pfctl_mutating(args: &[String]) -> bool {
    args.iter().any(|a| PFCTL_MUTATING.contains(&a.as_str()))
}

/// `ip` verbs (the second-position word after `ip [-options] OBJ`).
/// We classify by the OBJ + verb; only mutating verbs trigger
/// capture.
pub const IP_MUTATING: &[&str] = &[
    "add", "del", "delete", "change", "replace", "flush", "set", "up", "down",
];

pub fn is_ip_mutating(args: &[String]) -> bool {
    // Skip leading flags like `-4`/`-6`/`-j` to find the OBJ.
    let mut tail = args.iter().skip_while(|a| a.starts_with('-'));
    let _obj = tail.next();
    tail.next()
        .is_some_and(|v| IP_MUTATING.contains(&v.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn restore_method_per_tool() {
        assert_eq!(
            restore_method(NetworkTool::Iptables),
            RestoreMethod::FullReload
        );
        assert_eq!(restore_method(NetworkTool::Nft), RestoreMethod::FullReload);
        assert_eq!(
            restore_method(NetworkTool::Pfctl),
            RestoreMethod::FullReload
        );
        assert_eq!(
            restore_method(NetworkTool::Ufw),
            RestoreMethod::DiffApplyWithReset
        );
        assert_eq!(
            restore_method(NetworkTool::IpRoute),
            RestoreMethod::DiffApply
        );
        assert_eq!(
            restore_method(NetworkTool::Networksetup),
            RestoreMethod::DiffApply
        );
    }

    #[test]
    fn iptables_classifier_catches_short_and_long() {
        assert!(is_iptables_mutating(&argv(&[
            "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "ACCEPT"
        ])));
        assert!(is_iptables_mutating(&argv(&["--insert", "INPUT", "1"])));
        assert!(is_iptables_mutating(&argv(&["-F"])));
        assert!(!is_iptables_mutating(&argv(&["-L"]))); // list — read-only
        assert!(!is_iptables_mutating(&argv(&["-S"]))); // save — read-only
        assert!(!is_iptables_mutating(&argv(&[])));
    }

    #[test]
    fn nft_classifier_checks_first_token() {
        assert!(is_nft_mutating(&argv(&["add", "rule", "inet", "filter"])));
        assert!(is_nft_mutating(&argv(&["flush", "ruleset"])));
        assert!(is_nft_mutating(&argv(&["delete", "chain"])));
        assert!(!is_nft_mutating(&argv(&["list", "ruleset"])));
        assert!(!is_nft_mutating(&argv(&[])));
    }

    #[test]
    fn ufw_classifier_first_token() {
        assert!(is_ufw_mutating(&argv(&["allow", "8080"])));
        assert!(is_ufw_mutating(&argv(&["enable"])));
        assert!(is_ufw_mutating(&argv(&["delete", "3"])));
        assert!(!is_ufw_mutating(&argv(&["status", "verbose"])));
        assert!(!is_ufw_mutating(&argv(&["version"])));
    }

    #[test]
    fn pfctl_classifier_catches_mutators_anywhere() {
        assert!(is_pfctl_mutating(&argv(&["-f", "/etc/pf.conf"])));
        assert!(is_pfctl_mutating(&argv(&[
            "-a",
            "com.example/anchor",
            "-f",
            "-"
        ])));
        assert!(is_pfctl_mutating(&argv(&["-e"]))); // enable
        assert!(is_pfctl_mutating(&argv(&["-d"]))); // disable
        assert!(!is_pfctl_mutating(&argv(&["-s", "rules"]))); // show
        assert!(!is_pfctl_mutating(&argv(&["-sa"]))); // show all
    }

    #[test]
    fn ip_classifier_skips_leading_options() {
        assert!(is_ip_mutating(&argv(&[
            "route",
            "add",
            "10.0.0.0/24",
            "via",
            "10.0.0.1"
        ])));
        assert!(is_ip_mutating(&argv(&[
            "-6",
            "addr",
            "add",
            "fe80::1/64",
            "dev",
            "eth0"
        ])));
        assert!(is_ip_mutating(&argv(&["link", "set", "eth0", "down"])));
        assert!(!is_ip_mutating(&argv(&["route", "show"])));
        assert!(!is_ip_mutating(&argv(&["-j", "addr", "show"])));
        assert!(!is_ip_mutating(&argv(&["link"])));
    }
}
