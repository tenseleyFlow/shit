// SPDX-License-Identifier: AGPL-3.0-or-later

//! dnf inspector (S14.6).
//!
//! State collection runs `rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n'`
//! rather than `dnf list installed` because `rpm` returns a clean
//! parseable stream while `dnf` decorates with headings ("Installed
//! Packages") and column alignment. The package database is shared.
//!
//! Extras captured: the most-recent dnf transaction ID
//! (`dnf history --reverse | head` parser), which is what makes
//! dnf's undo story straightforward — the planner emits
//! `dnf history undo <id>` and lets dnf handle the dependency math.

use std::collections::BTreeMap;
use std::process::Command;

use shit_proto::PkgManagerWire;

use super::PkgInspector;

pub struct DnfInspector;

impl PkgInspector for DnfInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Dnf
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        let out = Command::new("rpm")
            .args(["-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"])
            .output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "rpm -qa exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(parse_rpm_qa(&String::from_utf8_lossy(&out.stdout)))
    }
    fn extras(&self) -> BTreeMap<String, String> {
        let mut e = BTreeMap::new();
        if let Some(id) = latest_history_id() {
            e.insert("dnf_history_id".into(), id);
        }
        e
    }
}

/// Parse `rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n'`.
fn parse_rpm_qa(s: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, version)) = line.split_once(' ') else {
            continue;
        };
        let version = version.trim();
        if version.is_empty() {
            continue;
        }
        out.insert(name.to_string(), version.to_string());
    }
    out
}

/// Run `dnf history --reverse` and parse the first data row to find
/// the most-recent transaction ID. dnf's output is column-aligned
/// with a header; we look for the first line whose first token parses
/// as an integer.
fn latest_history_id() -> Option<String> {
    let out = Command::new("dnf")
        .args(["history", "--reverse"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_history_id(&String::from_utf8_lossy(&out.stdout))
}

/// Pull the first integer-looking token from a `dnf history` listing.
/// The header lines ("ID", "----", "Command line ...") don't have a
/// leading integer so they're skipped naturally.
fn parse_history_id(s: &str) -> Option<String> {
    for line in s.lines() {
        let first = line.split_whitespace().next()?;
        if first.parse::<u64>().is_ok() {
            return Some(first.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rpm_qa_canonical() {
        // Fedora 41 output. Names sometimes contain dots (e.g.
        // `coreutils-common`), versions have a tilde for pre-releases.
        let input = "\
bash 5.2.32-4.fc41
coreutils 9.5-12.fc41
ca-certificates 2024.2.69_v8.0.401-2.fc41
libgcc 14.2.1-7.fc41
systemd 256.10-1.fc41
";
        let map = parse_rpm_qa(input);
        assert_eq!(map.get("bash").map(String::as_str), Some("5.2.32-4.fc41"));
        assert_eq!(
            map.get("ca-certificates").map(String::as_str),
            Some("2024.2.69_v8.0.401-2.fc41")
        );
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn parse_history_id_picks_first_integer_row() {
        // Real dnf history output, headers and a few rows.
        let input = "\
ID     | Command line             | Date and time    | Action(s)      | Altered
-------------------------------------------------------------------------------
    42 | install jq               | 2026-05-15 14:32 | Install        |    1
    41 | upgrade                  | 2026-05-14 09:00 | Upgrade        |   18
    40 | install vim              | 2026-05-13 21:11 | Install        |    1
";
        assert_eq!(parse_history_id(input).as_deref(), Some("42"));
    }

    #[test]
    fn parse_history_id_empty() {
        assert_eq!(parse_history_id(""), None);
        assert_eq!(parse_history_id("ID  | Command line\n----\n"), None);
    }
}
