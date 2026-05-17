// SPDX-License-Identifier: AGPL-3.0-or-later

//! Homebrew inspector (S14.7).
//!
//! State collection runs `brew list --versions`. Brew has no native
//! hook system; the integration is a PATH-prepended wrapper script
//! that invokes `shit-helper pkg-event brew pre` before delegating to
//! the real `brew`, then `... post` after.
//!
//! `brew list --versions` emits `<name> <version>` per line. When a
//! formula has multiple versions installed simultaneously, it prints
//! them space-separated on the same line. We keep only the highest
//! (lexicographic; brew's own ordering is also lexicographic). The
//! daemon doesn't need the full history here — the planner only ever
//! synthesizes `brew install pkg@<version>` against the single version
//! that was active before the operation.

use std::collections::BTreeMap;
use std::process::Command;

use shit_proto::PkgManagerWire;

use super::PkgInspector;

pub struct BrewInspector;

impl PkgInspector for BrewInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Brew
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        let out = Command::new("brew").args(["list", "--versions"]).output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "brew list exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(parse_brew_list(&String::from_utf8_lossy(&out.stdout)))
    }
    fn extras(&self) -> BTreeMap<String, String> {
        let mut e = BTreeMap::new();
        if let Some(pinned) = read_pinned() {
            e.insert("brew_pinned".into(), pinned);
        }
        if let Some(taps) = read_taps() {
            e.insert("brew_taps".into(), taps);
        }
        e
    }
}

/// Parse `brew list --versions`. Each line is `<formula> <version>
/// [<version> ...]`. Multiple versions are space-separated; we take
/// the *last* one (highest by brew's own ordering — brew sorts
/// ascending).
fn parse_brew_list(s: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut toks = line.split_whitespace();
        let Some(name) = toks.next() else {
            continue;
        };
        let Some(version) = toks.last() else {
            continue;
        };
        out.insert(name.to_string(), version.to_string());
    }
    out
}

fn read_pinned() -> Option<String> {
    let out = Command::new("brew")
        .args(["list", "--pinned"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let names: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names.join("\n"))
    }
}

fn read_taps() -> Option<String> {
    let out = Command::new("brew").arg("tap").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let taps: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if taps.is_empty() {
        None
    } else {
        Some(taps.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_brew_list_canonical() {
        // Captured from a macOS arm64 system.
        let input = "\
bat 0.24.0
fd 10.2.0
git 2.47.1
jq 1.7.1
ripgrep 14.1.1
";
        let map = parse_brew_list(input);
        assert_eq!(map.get("bat").map(String::as_str), Some("0.24.0"));
        assert_eq!(map.get("jq").map(String::as_str), Some("1.7.1"));
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn parse_brew_list_multiple_versions_takes_last() {
        // A formula with two side-by-side installs.
        let input = "\
openssl@3 3.3.2 3.4.0
jq 1.7.1
";
        let map = parse_brew_list(input);
        assert_eq!(map.get("openssl@3").map(String::as_str), Some("3.4.0"));
        assert_eq!(map.get("jq").map(String::as_str), Some("1.7.1"));
    }

    #[test]
    fn parse_brew_list_skips_blanks() {
        let input = "\n\
                     jq 1.7.1\n\
                     \n\
                     fd 10.2.0\n";
        let map = parse_brew_list(input);
        assert_eq!(map.len(), 2);
    }
}
