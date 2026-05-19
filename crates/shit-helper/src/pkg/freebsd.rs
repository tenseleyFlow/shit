// SPDX-License-Identifier: AGPL-3.0-or-later

//! FreeBSD pkg(8) inspector (S14.8).
//!
//! Module is named `freebsd` rather than `pkg` to avoid shadowing the
//! parent `pkg` module path. The inspector struct is
//! `freebsd::PkgInspector` and the trait it implements is
//! `super::PkgInspector` — see the impl block.
//!
//! State collection runs `pkg query "%n %v"` which prints
//! `<name> <version>` per installed package. Extras capture the
//! locked-packages list (`pkg lock -l`) so the planner can refuse to
//! synthesize an inverse for locked installs.
//!
//! The hook is driven by pkg(8)'s `EVENT_PIPE` config option pointing
//! at a tiny FIFO consumer that calls
//! `shit-helper pkg-event pkg {pre,post}`. Wiring lands in S14.11.

use std::collections::BTreeMap;
use std::process::Command;

use shit_proto::PkgManagerWire;

pub struct PkgInspector;

impl super::PkgInspector for PkgInspector {
    fn manager(&self) -> PkgManagerWire {
        PkgManagerWire::Pkg
    }
    fn collect_state(&self) -> anyhow::Result<BTreeMap<String, String>> {
        // Absolute path: the helper inherits the daemon's PATH, which
        // commonly lacks /usr/sbin/local on the SSH-non-interactive
        // and systemd-spawned paths. `pkg` lives at /usr/sbin/pkg on
        // FreeBSD ≥ 11 (the base bootstrap) and /usr/local/sbin/pkg
        // once pkg(8) installs itself — both work, prefer base path
        // for predictability.
        let pkg_path = ["/usr/sbin/pkg", "/usr/local/sbin/pkg"]
            .iter()
            .find(|p| std::path::Path::new(p).is_file())
            .copied()
            .unwrap_or("pkg");
        let out = Command::new(pkg_path).args(["query", "%n %v"]).output()?;
        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "pkg query exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(parse_pkg_query(&String::from_utf8_lossy(&out.stdout)))
    }
    fn extras(&self) -> BTreeMap<String, String> {
        let mut e = BTreeMap::new();
        if let Some(locked) = read_locked() {
            e.insert("pkg_locked".into(), locked);
        }
        e
    }
}

/// Parse `pkg query "%n %v"` output: `<name> <version>` per line.
fn parse_pkg_query(s: &str) -> BTreeMap<String, String> {
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

/// `pkg lock -l` lists locked packages, one per line, each prefixed
/// with a fixed header. We grep names out.
fn read_locked() -> Option<String> {
    let out = Command::new("pkg").args(["lock", "-l"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut names = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("Currently") {
            continue;
        }
        names.push(line.to_string());
    }
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
    fn parse_pkg_query_canonical() {
        // Captured from a FreeBSD 14 system. Versions use the
        // `<upstream>_<port-revision>,<epoch>` shape unique to pkg.
        let input = "\
bash 5.2.32
ca_root_nss 3.101
curl 8.10.1
git 2.46.0
sudo 1.9.16p1
";
        let map = parse_pkg_query(input);
        assert_eq!(map.get("bash").map(String::as_str), Some("5.2.32"));
        assert_eq!(map.get("git").map(String::as_str), Some("2.46.0"));
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn parse_pkg_query_skips_blanks() {
        let input = "\n\
                     bash 5.2.32\n\
                     \n\
                     ghostpkg\n\
                     git 2.46.0\n";
        let map = parse_pkg_query(input);
        assert!(!map.contains_key("ghostpkg"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_pkg_query_empty() {
        assert!(parse_pkg_query("").is_empty());
    }
}
