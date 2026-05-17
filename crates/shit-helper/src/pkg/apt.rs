// SPDX-License-Identifier: AGPL-3.0-or-later

//! apt/dpkg inspector (S14.4).
//!
//! State collection runs `dpkg-query -W -f='${Package} ${Version}\n'`
//! and parses the two-column output. The query is system-wide; the
//! daemon diffs Pre vs. Post to discover what changed without having
//! to know which packages the user asked for.
//!
//! Extras captured: the dpkg holds list (`dpkg --get-selections | grep
//! hold`) and the apt sources directory path, so the planner can
//! later synthesize a faithful inverse invocation. Cheap to record,
//! useful in the rare downgrade case where the package's repo has
//! shifted between Pre and Post.

use std::collections::BTreeMap;
use std::process::Command;

use shit_proto::PkgManagerWire;

use super::PkgInspector;

pub struct AptInspector;

impl PkgInspector for AptInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Apt
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        let out = Command::new("dpkg-query")
            .args(["-W", "-f=${Package} ${Version}\n"])
            .output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "dpkg-query exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(parse_dpkg_query(&String::from_utf8_lossy(&out.stdout)))
    }
    fn extras(&self) -> BTreeMap<String, String> {
        let mut e = BTreeMap::new();
        if let Some(holds) = read_holds() {
            e.insert("dpkg_holds".into(), holds);
        }
        e.insert("apt_sources_dir".into(), "/etc/apt/sources.list.d".into());
        e
    }
}

/// Parse one block of `dpkg-query -W -f='${Package} ${Version}\n'`
/// output. Each line is `<name> <version>`; lines that don't match
/// are skipped silently (dpkg sometimes emits diagnostics on stdout
/// when it would rather not). Empty version means the package is
/// in the database but not installed — we drop those entries.
fn parse_dpkg_query(s: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (name, version) = match line.split_once(' ') {
            Some(v) => v,
            None => continue,
        };
        let version = version.trim();
        if version.is_empty() {
            continue;
        }
        out.insert(name.to_string(), version.to_string());
    }
    out
}

/// Snapshot held packages via `dpkg --get-selections`. Returns the
/// raw list as a newline-joined string; the daemon stores it verbatim
/// in extras and the planner consults it on undo.
fn read_holds() -> Option<String> {
    let out = Command::new("dpkg")
        .args(["--get-selections"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut held = Vec::new();
    for line in text.lines() {
        if let Some((name, kind)) = line.split_once(char::is_whitespace)
            && kind.trim() == "hold"
        {
            held.push(name.to_string());
        }
    }
    if held.is_empty() {
        None
    } else {
        Some(held.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dpkg_query_canonical() {
        // Captured from an Ubuntu 22.04 system. dpkg-query emits a
        // single space between fields; some package versions include
        // dashes, tildes, and colons (epoch).
        let input = "\
adduser 3.118ubuntu5
apt 2.4.13
base-files 12ubuntu4.7
bash 5.1-6ubuntu1.1
ca-certificates 20240203~22.04.1
libc6:amd64 2.35-0ubuntu3.10
";
        let map = parse_dpkg_query(input);
        assert_eq!(map.get("adduser").map(String::as_str), Some("3.118ubuntu5"));
        assert_eq!(map.get("apt").map(String::as_str), Some("2.4.13"));
        assert_eq!(
            map.get("ca-certificates").map(String::as_str),
            Some("20240203~22.04.1")
        );
        assert_eq!(
            map.get("libc6:amd64").map(String::as_str),
            Some("2.35-0ubuntu3.10")
        );
        assert_eq!(map.len(), 6);
    }

    #[test]
    fn parse_dpkg_query_skips_blank_and_versionless() {
        // First line is blank; third has the version-column missing
        // (a deinstall-but-not-purged record). Both should be dropped.
        let input = "\n\
                     adduser 3.118ubuntu5\n\
                     ghostpkg \n\
                     \n\
                     apt 2.4.13\n";
        let map = parse_dpkg_query(input);
        assert!(!map.contains_key("ghostpkg"), "{map:?}");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_dpkg_query_empty_input() {
        let map = parse_dpkg_query("");
        assert!(map.is_empty());
    }
}
