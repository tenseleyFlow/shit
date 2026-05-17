// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-lifecycle argv parsers (S18.2).
//!
//! Pure helpers that take a user's `kill`/`pkill`/`killall` argv
//! (minus the tool name) and return a list of [`KillTarget`]s the
//! helper-side resolver can act on. No I/O.
//!
//! ## kill argv grammar (POSIX + GNU)
//!
//! ```text
//! kill [-SIGNAME | -SIGNUM | -s SIGNAME | --signal SIGNAME]
//!      [--] PID [PID...]
//! kill -l [SIGNUM]
//! kill -L
//! ```
//!
//! `PID` can be `<integer>`, `-<integer>` (negative — process group),
//! or `%<job>` (shell job-control reference). Job refs are resolved
//! by the wrapper against the shell's job table; the parser just
//! records them.
//!
//! ## pkill / killall
//!
//! Pattern-based. The classifier returns `KillTarget::Pattern` with
//! the pattern + optional `-u <user>` / `-g <pgid>` constraints. The
//! helper resolves against the process listing.

use std::collections::BTreeMap;

/// One target of a kill-family command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillTarget {
    /// A specific pid. Negative integers (process groups) are
    /// stored as the negative i32 the user wrote.
    Pid(i32),
    /// A shell job-control reference like `%1` or `%+`.
    JobSpec(String),
    /// A pattern (for pkill/killall) plus filter constraints.
    Pattern {
        pattern: String,
        filters: BTreeMap<String, String>,
    },
}

/// Parsed shape of a kill-family invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillCommand {
    /// Signal name or number (without the leading `-`). Defaults
    /// to `TERM` when not specified.
    pub signal: String,
    pub targets: Vec<KillTarget>,
}

/// Parse the argv of a `kill` invocation (sans the `kill` token
/// itself).
///
/// Returns `None` on a list-mode invocation (`kill -l`) since
/// there's no mutation to capture.
pub fn parse_kill(argv: &[String]) -> Option<KillCommand> {
    let mut signal = String::from("TERM");
    let mut targets = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];
        match tok.as_str() {
            "--" => {
                i += 1;
                // Everything after `--` is a target.
                while i < argv.len() {
                    push_target(&argv[i], &mut targets);
                    i += 1;
                }
                break;
            }
            "-l" | "-L" => return None,
            "-s" | "--signal" => {
                if let Some(next) = argv.get(i + 1) {
                    signal = next.clone();
                    i += 2;
                    continue;
                }
                return None;
            }
            t if t.starts_with('-') && t.len() > 1 => {
                let rest = &t[1..];
                // Could be `-9`, `-KILL`, `-SIGKILL`, or a target
                // like `-1234` (process group). Distinguish by
                // whether the rest is a valid signal-ish token vs.
                // a pure positive integer (which would be a
                // process group when negated).
                if looks_like_signal(rest) {
                    signal = rest.to_string();
                    i += 1;
                    continue;
                }
                // Otherwise it's a process-group target.
                push_target(t, &mut targets);
                i += 1;
            }
            _ => {
                push_target(tok, &mut targets);
                i += 1;
            }
        }
    }
    if targets.is_empty() {
        return None;
    }
    Some(KillCommand { signal, targets })
}

fn looks_like_signal(s: &str) -> bool {
    // POSIX: signal numbers 1..64 roughly. SIGNAME or SIG-prefixed.
    if let Ok(n) = s.parse::<u32>() {
        return (1..=64).contains(&n);
    }
    // Common names: SIGTERM, SIGKILL, SIGHUP, ... or bare TERM/KILL/HUP.
    let upper = s.to_ascii_uppercase();
    let stripped = upper.strip_prefix("SIG").unwrap_or(&upper);
    matches!(
        stripped,
        "HUP"
            | "INT"
            | "QUIT"
            | "ILL"
            | "TRAP"
            | "ABRT"
            | "BUS"
            | "FPE"
            | "KILL"
            | "USR1"
            | "SEGV"
            | "USR2"
            | "PIPE"
            | "ALRM"
            | "TERM"
            | "STKFLT"
            | "CHLD"
            | "CONT"
            | "STOP"
            | "TSTP"
            | "TTIN"
            | "TTOU"
            | "URG"
            | "XCPU"
            | "XFSZ"
            | "VTALRM"
            | "PROF"
            | "WINCH"
            | "IO"
            | "POLL"
            | "PWR"
            | "SYS"
    )
}

fn push_target(tok: &str, out: &mut Vec<KillTarget>) {
    if let Some(rest) = tok.strip_prefix('%') {
        out.push(KillTarget::JobSpec(format!("%{rest}")));
        return;
    }
    if let Ok(n) = tok.parse::<i32>() {
        out.push(KillTarget::Pid(n));
        return;
    }
    // Bare names sometimes appear in kill argv (rare); treat as
    // a pattern so the resolver can decide.
    out.push(KillTarget::Pattern {
        pattern: tok.to_string(),
        filters: BTreeMap::new(),
    });
}

/// Parse a `pkill` or `killall` argv (sans tool name). Both have
/// the same shape for our purposes: a pattern + optional `-SIGNAL`
/// + filter flags.
pub fn parse_pattern_kill(argv: &[String]) -> Option<KillCommand> {
    let mut signal = String::from("TERM");
    let mut filters = BTreeMap::new();
    let mut pattern: Option<String> = None;
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];
        match tok.as_str() {
            "-s" | "--signal" => {
                if let Some(n) = argv.get(i + 1) {
                    signal = n.clone();
                    i += 2;
                    continue;
                }
                return None;
            }
            "-u" | "--euid" | "--uid" => {
                if let Some(n) = argv.get(i + 1) {
                    filters.insert("user".into(), n.clone());
                    i += 2;
                    continue;
                }
                return None;
            }
            "-g" | "--group" | "-G" | "--pgroup" => {
                if let Some(n) = argv.get(i + 1) {
                    filters.insert("group".into(), n.clone());
                    i += 2;
                    continue;
                }
                return None;
            }
            t if t.starts_with('-') && t.len() > 1 => {
                let rest = &t[1..];
                if looks_like_signal(rest) {
                    signal = rest.to_string();
                    i += 1;
                    continue;
                }
                // Unknown flag — skip; we don't model every pkill
                // option (-f for full-cmdline matching, etc.).
                i += 1;
            }
            _ => {
                if pattern.is_none() {
                    pattern = Some(tok.clone());
                }
                i += 1;
            }
        }
    }
    let pattern = pattern?;
    Some(KillCommand {
        signal,
        targets: vec![KillTarget::Pattern { pattern, filters }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn kill_default_signal_is_term() {
        let c = parse_kill(&argv(&["1234"])).unwrap();
        assert_eq!(c.signal, "TERM");
        assert_eq!(c.targets, vec![KillTarget::Pid(1234)]);
    }

    #[test]
    fn kill_dash_9_signal() {
        let c = parse_kill(&argv(&["-9", "1234"])).unwrap();
        assert_eq!(c.signal, "9");
        assert_eq!(c.targets, vec![KillTarget::Pid(1234)]);
    }

    #[test]
    fn kill_named_signal() {
        let c = parse_kill(&argv(&["-KILL", "1234"])).unwrap();
        assert_eq!(c.signal, "KILL");
    }

    #[test]
    fn kill_sigprefix_signal() {
        let c = parse_kill(&argv(&["-SIGTERM", "1234"])).unwrap();
        assert_eq!(c.signal, "SIGTERM");
    }

    #[test]
    fn kill_s_long_form() {
        let c = parse_kill(&argv(&["-s", "HUP", "1234"])).unwrap();
        assert_eq!(c.signal, "HUP");
    }

    #[test]
    fn kill_job_spec() {
        let c = parse_kill(&argv(&["%1"])).unwrap();
        assert_eq!(c.targets, vec![KillTarget::JobSpec("%1".into())]);
    }

    #[test]
    fn kill_pgroup_negative_pid() {
        let c = parse_kill(&argv(&["--", "-1234"])).unwrap();
        assert_eq!(c.targets, vec![KillTarget::Pid(-1234)]);
    }

    #[test]
    fn kill_l_is_list_mode_none() {
        assert!(parse_kill(&argv(&["-l"])).is_none());
        assert!(parse_kill(&argv(&["-L"])).is_none());
    }

    #[test]
    fn kill_no_targets_is_none() {
        assert!(parse_kill(&argv(&["-9"])).is_none());
        assert!(parse_kill(&argv(&[])).is_none());
    }

    #[test]
    fn kill_multiple_targets() {
        let c = parse_kill(&argv(&["-TERM", "100", "200", "%1"])).unwrap();
        assert_eq!(c.targets.len(), 3);
        assert_eq!(c.signal, "TERM");
    }

    #[test]
    fn pkill_pattern() {
        let c = parse_pattern_kill(&argv(&["firefox"])).unwrap();
        assert_eq!(c.signal, "TERM");
        match &c.targets[0] {
            KillTarget::Pattern { pattern, filters } => {
                assert_eq!(pattern, "firefox");
                assert!(filters.is_empty());
            }
            other => panic!("expected Pattern, got {other:?}"),
        }
    }

    #[test]
    fn pkill_with_signal_and_user() {
        let c = parse_pattern_kill(&argv(&["-9", "-u", "alice", "firefox"])).unwrap();
        assert_eq!(c.signal, "9");
        match &c.targets[0] {
            KillTarget::Pattern { pattern, filters } => {
                assert_eq!(pattern, "firefox");
                assert_eq!(filters.get("user").map(String::as_str), Some("alice"));
            }
            other => panic!("expected Pattern, got {other:?}"),
        }
    }

    #[test]
    fn pkill_no_pattern_is_none() {
        assert!(parse_pattern_kill(&argv(&["-9"])).is_none());
    }
}
