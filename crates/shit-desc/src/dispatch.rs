// SPDX-License-Identifier: AGPL-3.0-or-later

//! Descriptor pack loader + dispatcher.
//!
//! Loads `.toml` files from a set of search roots, runs lint on each,
//! files by authority tier, and resolves `dispatch(argv)` by scoring
//! every descriptor's match. User overrides system on duplicate names;
//! within the same authority, duplicate names are a hard error.
//!
//! Standard search roots:
//! - System: `/usr/share/shit/descriptors/`
//! - User:   `$XDG_CONFIG_HOME/shit/descriptors/` (or `~/.config/shit/descriptors/`)
//! - Third-party: `/etc/shit/descriptors/<vendor>/`
//!
//! Tests inject their own roots via [`Loader::from_roots`].

use super::matcher::match_descriptor;
use super::schema::{Descriptor, DescriptorAuthority, SchemaError};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("io reading `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("schema for `{path}`: {source}")]
    Schema {
        path: PathBuf,
        #[source]
        source: SchemaError,
    },
    #[error(
        "duplicate descriptor name `{name}` in authority `{authority}` (files: `{first}` and `{second}`)"
    )]
    DuplicateName {
        name: String,
        authority: String,
        first: PathBuf,
        second: PathBuf,
    },
}

/// A loaded descriptor with its source path retained for diagnostics.
#[derive(Debug, Clone)]
pub struct LoadedDescriptor {
    pub descriptor: Descriptor,
    pub source: PathBuf,
}

/// Loader holds the parsed packs, partitioned by authority tier.
#[derive(Debug)]
pub struct Loader {
    by_authority: BTreeMap<String, BTreeMap<String, LoadedDescriptor>>,
}

impl Loader {
    /// Build a loader by walking each root and treating *every* file
    /// under it as belonging to the corresponding authority. `roots`
    /// is `(authority, path)` pairs; later roots override earlier ones
    /// at dispatch time. Each root is walked recursively for `*.toml`.
    ///
    /// Authority parsing inside the file is cross-checked against the
    /// `expected_authority` for that root: a mismatch is a lint
    /// failure.
    pub fn from_roots(roots: &[(DescriptorAuthority, &Path)]) -> Result<Self, LoadError> {
        let mut by_authority: BTreeMap<String, BTreeMap<String, LoadedDescriptor>> =
            BTreeMap::new();
        for (auth, path) in roots {
            if !path.exists() {
                continue;
            }
            let bucket = by_authority.entry(auth.to_string()).or_default();
            walk(path, auth, bucket)?;
        }
        Ok(Self { by_authority })
    }

    /// Total descriptor count across all authority tiers.
    pub fn len(&self) -> usize {
        self.by_authority.values().map(BTreeMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// List all loaded packs, grouped by authority. Used by `shit
    /// descriptors list` (C02.9).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &LoadedDescriptor)> {
        self.by_authority
            .iter()
            .flat_map(|(auth, bucket)| bucket.values().map(move |d| (auth.as_str(), d)))
    }

    /// Resolve the best-scoring descriptor for `argv`. Returns `None`
    /// if no descriptor matches.
    ///
    /// Tie-breaking order:
    /// 1. Higher specificity score wins.
    /// 2. On equal score, `user` beats `builtin`; `builtin` beats
    ///    `third-party:*`.
    pub fn dispatch(&self, argv: &[String]) -> Option<&LoadedDescriptor> {
        let mut best: Option<(f32, AuthorityRank, &LoadedDescriptor)> = None;
        for (auth, bucket) in &self.by_authority {
            let rank = authority_rank(auth);
            for ld in bucket.values() {
                let out = match_descriptor(&ld.descriptor.match_, argv);
                if !out.matched {
                    continue;
                }
                let candidate = (out.score, rank, ld);
                best = match best {
                    None => Some(candidate),
                    Some(prev) => {
                        if candidate.0 > prev.0 || (candidate.0 == prev.0 && candidate.1 < prev.1) {
                            Some(candidate)
                        } else {
                            Some(prev)
                        }
                    }
                };
            }
        }
        best.map(|(_, _, ld)| ld)
    }

    /// Look up a single descriptor by `name` across all authority tiers.
    /// User authority wins on collision (consistent with the dispatch
    /// rule). Used by `shit descriptors validate <name>`.
    pub fn get(&self, name: &str) -> Option<&LoadedDescriptor> {
        for auth in &["user", "builtin"] {
            if let Some(bucket) = self.by_authority.get(*auth)
                && let Some(ld) = bucket.get(name)
            {
                return Some(ld);
            }
        }
        for (auth, bucket) in &self.by_authority {
            if !(*auth == "user" || *auth == "builtin")
                && let Some(ld) = bucket.get(name)
            {
                return Some(ld);
            }
        }
        None
    }
}

fn walk(
    root: &Path,
    expected: &DescriptorAuthority,
    bucket: &mut BTreeMap<String, LoadedDescriptor>,
) -> Result<(), LoadError> {
    let entries = std::fs::read_dir(root).map_err(|e| LoadError::Io {
        path: root.to_path_buf(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| LoadError::Io {
            path: root.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| LoadError::Io {
            path: path.clone(),
            source: e,
        })?;
        if file_type.is_dir() {
            walk(&path, expected, bucket)?;
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| LoadError::Io {
            path: path.clone(),
            source: e,
        })?;
        let descriptor = Descriptor::from_toml(&text).map_err(|e| LoadError::Schema {
            path: path.clone(),
            source: e,
        })?;
        // Authority cross-check: file's [descriptor].authority must match
        // the directory it lives under. Mismatch is treated as a schema
        // error to keep the failure mode loud.
        if !authority_matches(&descriptor.descriptor.authority, expected) {
            return Err(LoadError::Schema {
                path: path.clone(),
                source: SchemaError::Lint(super::schema::LintError::BadName(format!(
                    "{} (file declares authority `{}`, directory expects `{}`)",
                    descriptor.descriptor.name, descriptor.descriptor.authority, expected
                ))),
            });
        }
        let name = descriptor.descriptor.name.clone();
        if let Some(existing) = bucket.get(&name) {
            return Err(LoadError::DuplicateName {
                name,
                authority: expected.to_string(),
                first: existing.source.clone(),
                second: path,
            });
        }
        bucket.insert(
            name,
            LoadedDescriptor {
                descriptor,
                source: path,
            },
        );
    }
    Ok(())
}

fn authority_matches(actual: &DescriptorAuthority, expected: &DescriptorAuthority) -> bool {
    match (actual, expected) {
        (DescriptorAuthority::Builtin, DescriptorAuthority::Builtin) => true,
        (DescriptorAuthority::User, DescriptorAuthority::User) => true,
        (DescriptorAuthority::ThirdParty(a), DescriptorAuthority::ThirdParty(b)) => a == b,
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AuthorityRank(u8);

fn authority_rank(auth: &str) -> AuthorityRank {
    // Lower value = wins ties. Ordering matches the dispatch rule:
    // user > builtin > third-party.
    if auth == "user" {
        AuthorityRank(0)
    } else if auth == "builtin" {
        AuthorityRank(1)
    } else {
        AuthorityRank(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_toml(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(format!("{name}.toml"));
        fs::write(&path, body).unwrap();
        path
    }

    fn builtin_pack(name: &str, argv: &str) -> String {
        format!(
            r#"
[descriptor]
version = 1
name = "{name}"
description = "test"
authority = "builtin"

[match]
argv = {argv}

[snapshot.pre]
command = ["echo"]
parse = "raw"
extract.v = ".raw"

[reverse]
requires_confirmation = false
command = ["echo", "{{{{v}}}}"]
privileged = true
"#
        )
    }

    fn user_pack(name: &str, argv: &str) -> String {
        format!(
            r#"
[descriptor]
version = 1
name = "{name}"
description = "test"
authority = "user"

[match]
argv = {argv}

[snapshot.pre]
command = ["echo"]
parse = "raw"
extract.v = ".raw"

[reverse]
requires_confirmation = true
command = ["echo", "{{{{v}}}}"]
"#
        )
    }

    #[test]
    fn empty_roots_load_clean() {
        let l = Loader::from_roots(&[]).unwrap();
        assert!(l.is_empty());
        assert!(l.dispatch(&["foo".to_string()]).is_none());
    }

    #[test]
    fn loads_one_builtin_pack() {
        let dir = tempdir().unwrap();
        write_toml(dir.path(), "h", &builtin_pack("h", r#"["echo", "*"]"#));
        let l = Loader::from_roots(&[(DescriptorAuthority::Builtin, dir.path())]).unwrap();
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn dispatch_finds_matching_descriptor() {
        let dir = tempdir().unwrap();
        write_toml(
            dir.path(),
            "echo-pack",
            &builtin_pack("echo-pack", r#"["echo", "*"]"#),
        );
        let l = Loader::from_roots(&[(DescriptorAuthority::Builtin, dir.path())]).unwrap();
        let argv = vec!["echo".to_string(), "hi".to_string()];
        let got = l.dispatch(&argv).unwrap();
        assert_eq!(got.descriptor.descriptor.name, "echo-pack");
    }

    #[test]
    fn dispatch_returns_none_when_no_match() {
        let dir = tempdir().unwrap();
        write_toml(dir.path(), "h", &builtin_pack("h", r#"["echo", "*"]"#));
        let l = Loader::from_roots(&[(DescriptorAuthority::Builtin, dir.path())]).unwrap();
        let argv = vec!["something-else".to_string()];
        assert!(l.dispatch(&argv).is_none());
    }

    #[test]
    fn most_specific_pack_wins() {
        // Two builtin packs: one specific to "echo hi", one generic on "echo *".
        let dir = tempdir().unwrap();
        write_toml(
            dir.path(),
            "general",
            &builtin_pack("general", r#"["echo", "*"]"#),
        );
        write_toml(
            dir.path(),
            "specific",
            &builtin_pack("specific", r#"["echo", "hi"]"#),
        );
        let l = Loader::from_roots(&[(DescriptorAuthority::Builtin, dir.path())]).unwrap();
        let argv = vec!["echo".to_string(), "hi".to_string()];
        let got = l.dispatch(&argv).unwrap();
        assert_eq!(got.descriptor.descriptor.name, "specific");
    }

    #[test]
    fn user_beats_builtin_on_same_score() {
        // Same match pattern, same score; user wins.
        let system = tempdir().unwrap();
        let userdir = tempdir().unwrap();
        write_toml(
            system.path(),
            "echo-builtin",
            &builtin_pack("echo-builtin", r#"["echo", "*"]"#),
        );
        write_toml(
            userdir.path(),
            "echo-user",
            &user_pack("echo-user", r#"["echo", "*"]"#),
        );
        let l = Loader::from_roots(&[
            (DescriptorAuthority::Builtin, system.path()),
            (DescriptorAuthority::User, userdir.path()),
        ])
        .unwrap();
        let argv = vec!["echo".to_string(), "hi".to_string()];
        let got = l.dispatch(&argv).unwrap();
        assert_eq!(got.descriptor.descriptor.name, "echo-user");
    }

    #[test]
    fn duplicate_name_in_same_authority_errors() {
        let dir = tempdir().unwrap();
        write_toml(dir.path(), "first", &builtin_pack("dup-name", r#"["a"]"#));
        write_toml(dir.path(), "second", &builtin_pack("dup-name", r#"["b"]"#));
        let err = Loader::from_roots(&[(DescriptorAuthority::Builtin, dir.path())]).unwrap_err();
        assert!(matches!(err, LoadError::DuplicateName { .. }));
    }

    #[test]
    fn directory_authority_mismatch_errors() {
        // File declares user, but lives under a builtin root.
        let dir = tempdir().unwrap();
        write_toml(dir.path(), "bad", &user_pack("bad", r#"["x"]"#));
        let err = Loader::from_roots(&[(DescriptorAuthority::Builtin, dir.path())]).unwrap_err();
        assert!(matches!(err, LoadError::Schema { .. }));
    }

    #[test]
    fn non_toml_files_ignored() {
        let dir = tempdir().unwrap();
        write_toml(dir.path(), "h", &builtin_pack("h", r#"["x"]"#));
        fs::write(dir.path().join("readme.md"), "ignore me").unwrap();
        fs::write(dir.path().join("config.json"), "{}").unwrap();
        let l = Loader::from_roots(&[(DescriptorAuthority::Builtin, dir.path())]).unwrap();
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn nested_directories_walked() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();
        write_toml(&sub, "h", &builtin_pack("h", r#"["x"]"#));
        let l = Loader::from_roots(&[(DescriptorAuthority::Builtin, dir.path())]).unwrap();
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn missing_root_is_silently_skipped() {
        let l = Loader::from_roots(&[(
            DescriptorAuthority::Builtin,
            Path::new("/this/does/not/exist/anywhere-xyz123"),
        )])
        .unwrap();
        assert!(l.is_empty());
    }

    #[test]
    fn get_by_name_finds_descriptor() {
        let dir = tempdir().unwrap();
        write_toml(dir.path(), "x", &builtin_pack("x", r#"["a"]"#));
        let l = Loader::from_roots(&[(DescriptorAuthority::Builtin, dir.path())]).unwrap();
        assert!(l.get("x").is_some());
        assert!(l.get("nope").is_none());
    }

    #[test]
    fn iter_yields_all_packs() {
        let s = tempdir().unwrap();
        let u = tempdir().unwrap();
        write_toml(s.path(), "a", &builtin_pack("a", r#"["a"]"#));
        write_toml(u.path(), "b", &user_pack("b", r#"["b"]"#));
        let l = Loader::from_roots(&[
            (DescriptorAuthority::Builtin, s.path()),
            (DescriptorAuthority::User, u.path()),
        ])
        .unwrap();
        let names: Vec<&str> = l
            .iter()
            .map(|(_, d)| d.descriptor.descriptor.name.as_str())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
    }
}
