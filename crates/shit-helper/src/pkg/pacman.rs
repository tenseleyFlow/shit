// SPDX-License-Identifier: AGPL-3.0-or-later

//! pacman inspector (S14.5).
//!
//! State collection runs `pacman -Q` (all installed) and parses the
//! two-column output. Pacman writes affected packages to the hook's
//! stdin (one path per line), but we don't need to consume it: the
//! daemon classifies the operation from the Pre/Post diff.
//!
//! Extras captured: the list of *explicitly* installed packages
//! (`pacman -Qe`) so the planner can prefer keeping non-explicit
//! dependents intact when synthesizing an inverse, and the pacman
//! cache directory (`/var/cache/pacman/pkg/`) which is consulted on
//! downgrade-undo (`pacman -U <cached.pkg.tar.zst>`).

use std::collections::BTreeMap;
use std::process::Command;

use shit_proto::PkgManagerWire;

use super::PkgInspector;

pub struct PacmanInspector;

impl PkgInspector for PacmanInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Pacman
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        let out = Command::new("pacman").arg("-Q").output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "pacman -Q exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(parse_pacman_q(&String::from_utf8_lossy(&out.stdout)))
    }
    fn extras(&self) -> BTreeMap<String, String> {
        let mut e = BTreeMap::new();
        if let Some(explicit) = read_explicit() {
            e.insert("pacman_explicit".into(), explicit);
        }
        e.insert("pacman_cache_dir".into(), "/var/cache/pacman/pkg/".into());
        e
    }
}

/// Parse `pacman -Q` output: `<name> <version>` per line. Pacman uses
/// a single space; versions may contain hyphens (release suffix) and
/// epoch colons.
fn parse_pacman_q(s: &str) -> BTreeMap<String, String> {
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

/// `pacman -Qe` lists explicitly-installed packages. We just need the
/// names; format matches `pacman -Q` but only explicit ones.
fn read_explicit() -> Option<String> {
    let out = Command::new("pacman").arg("-Qe").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(n, _)| n.trim()))
        .filter(|n| !n.is_empty())
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pacman_q_canonical() {
        // Captured from an Arch Linux system. Versions have a release
        // suffix; some have epoch.
        let input = "\
acl 2.3.2-1
attr 2.5.2-1
audit 4.0.5-1
bash 5.2.037-2
ca-certificates 20240618-1
glibc 2.40+r16+gaa533d58ff-2
linux 6.13.5.arch1-1
";
        let map = parse_pacman_q(input);
        assert_eq!(map.get("acl").map(String::as_str), Some("2.3.2-1"));
        assert_eq!(map.get("bash").map(String::as_str), Some("5.2.037-2"));
        assert_eq!(
            map.get("glibc").map(String::as_str),
            Some("2.40+r16+gaa533d58ff-2")
        );
        assert_eq!(map.len(), 7);
    }

    #[test]
    fn parse_pacman_q_skips_blanks() {
        let input = "\n\
                     acl 2.3.2-1\n\
                     \n\
                     orphan\n\
                     bash 5.2.037-2\n";
        let map = parse_pacman_q(input);
        assert!(!map.contains_key("orphan"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_pacman_q_empty() {
        assert!(parse_pacman_q("").is_empty());
    }
}
