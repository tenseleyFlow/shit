// SPDX-License-Identifier: AGPL-3.0-or-later

//! Descriptor TOML schema (frozen at version 1).
//!
//! Parsing is `serde` against the on-disk representation, followed by
//! [`Descriptor::lint`] which enforces the rules documented in
//! `.docs/audits/descriptor-format.md`. The loader runs `lint` before
//! exposing a descriptor; tests run it directly against fixtures.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The maximum descriptor `version` this build understands. Newer
/// versions are refused at load time. v1 is frozen and v1.x adds only
/// optional fields.
pub const MAX_SUPPORTED_VERSION: u32 = 1;

/// Top-level descriptor — what `[descriptor]` parses into, plus the
/// nested sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Descriptor {
    pub descriptor: DescriptorHead,
    #[serde(rename = "match")]
    pub match_: DescriptorMatch,
    pub snapshot: DescriptorSnapshotPair,
    pub reverse: DescriptorReverse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorHead {
    pub version: u32,
    pub name: String,
    pub description: String,
    pub authority: DescriptorAuthority,
}

/// Origin of the descriptor pack. Loaders set this; descriptor files
/// must declare it for clarity (the loader can also verify).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DescriptorAuthority {
    Builtin,
    User,
    /// Third-party packs use this with a slug — `third-party:vendor-x`.
    /// The `Display` impl emits the slug form.
    #[serde(untagged, deserialize_with = "deserialize_third_party")]
    ThirdParty(String),
}

impl std::fmt::Display for DescriptorAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Builtin => f.write_str("builtin"),
            Self::User => f.write_str("user"),
            Self::ThirdParty(slug) => write!(f, "third-party:{slug}"),
        }
    }
}

fn deserialize_third_party<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let raw: String = String::deserialize(d)?;
    let rest = raw.strip_prefix("third-party:").ok_or_else(|| {
        D::Error::custom(format!(
            "authority must be `builtin` | `user` | `third-party:<slug>`, got `{raw}`"
        ))
    })?;
    if rest.is_empty() {
        return Err(D::Error::custom("third-party authority needs a slug"));
    }
    Ok(rest.to_string())
}

/// `[match]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorMatch {
    pub argv: Vec<String>,
    #[serde(default)]
    pub exclude_argv: Vec<Vec<String>>,
    #[serde(default = "default_success_codes")]
    pub exit_codes_count_as_success: Vec<i32>,
}

fn default_success_codes() -> Vec<i32> {
    vec![0]
}

/// `[snapshot]` table with `.pre` and optional `.post`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorSnapshotPair {
    pub pre: DescriptorSnapshot,
    #[serde(default)]
    pub post: Option<DescriptorSnapshot>,
}

/// A single snapshot phase (`pre` or `post`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorSnapshot {
    pub command: Vec<String>,
    pub parse: ParseKind,
    pub extract: BTreeMap<String, String>,
}

/// How to interpret a snapshot command's stdout.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ParseKind {
    Raw,
    Lines,
    Json,
    Toml,
}

/// `[reverse]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorReverse {
    #[serde(default = "default_requires_confirmation")]
    pub requires_confirmation: bool,
    pub command: Vec<String>,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub guard: Option<DescriptorGuard>,
}

fn default_requires_confirmation() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorGuard {
    pub command: Vec<String>,
    pub expected_substring: String,
}

// -----------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("toml decode: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("lint: {0}")]
    Lint(#[from] LintError),
}

#[derive(Debug, thiserror::Error)]
pub enum LintError {
    #[error("unsupported descriptor version {actual}: this build understands up to {supported}")]
    UnsupportedVersion { actual: u32, supported: u32 },
    #[error("name `{0}` does not match `^[a-z0-9][a-z0-9-]{{0,63}}$`")]
    BadName(String),
    #[error("description must be 1..=200 chars, got {0}")]
    BadDescription(usize),
    #[error("match.argv must be non-empty")]
    EmptyArgv,
    #[error("match.argv[0] must be a literal binary name (no globs); got `{0}`")]
    GlobInArgvZero(String),
    #[error("`**` may appear at most once and only as the last argv token; got `{0:?}`")]
    BadDoubleStar(Vec<String>),
    #[error("snapshot.{phase}.command must be non-empty")]
    EmptySnapshotCommand { phase: &'static str },
    #[error("reverse.command must be non-empty")]
    EmptyReverseCommand,
    #[error(
        "argv[0] of snapshot.{phase}.command contains a shell metachar or path traversal: `{token}`"
    )]
    UnsafeSnapshotBinary { phase: &'static str, token: String },
    #[error("argv[0] of reverse.command contains a shell metachar or path traversal: `{0}`")]
    UnsafeReverseBinary(String),
    #[error(
        "reverse.command references variable `{0}` that is not extracted by any snapshot phase"
    )]
    UnresolvedReverseVar(String),
    #[error("guard.expected_substring references variable `{0}` that is not extracted")]
    UnresolvedGuardVar(String),
    #[error("`{0}` extract.<key> path `{1}` is not a valid extractor path")]
    BadExtractorPath(String, String),
    #[error("snapshot.{phase} declares no extractor paths (need at least one)")]
    NoExtractors { phase: &'static str },
    #[error("reverse.privileged=true requires builtin authority (got {authority})")]
    PrivilegedNeedsBuiltin { authority: String },
    #[error("reverse.requires_confirmation=false requires builtin authority (got {authority})")]
    NoConfirmNeedsBuiltin { authority: String },
    #[error("invalid extractor for parse=raw: only `.raw` is allowed, got `{0}`")]
    BadRawExtractor(String),
    #[error("invalid extractor for parse=lines: must be `[N]`, got `{0}`")]
    BadLinesExtractor(String),
}

// -----------------------------------------------------------------------
// Lint
// -----------------------------------------------------------------------

impl Descriptor {
    /// Parse and lint a descriptor TOML in one shot. The loader runs this
    /// before exposing the descriptor; `shit descriptors validate` runs it
    /// for user-authored packs.
    pub fn from_toml(s: &str) -> Result<Self, SchemaError> {
        let d: Self = toml::from_str(s)?;
        d.lint()?;
        Ok(d)
    }

    /// Run the lint rules documented in `.docs/audits/descriptor-format.md`.
    pub fn lint(&self) -> Result<(), LintError> {
        // Rule 1: supported version.
        if self.descriptor.version > MAX_SUPPORTED_VERSION {
            return Err(LintError::UnsupportedVersion {
                actual: self.descriptor.version,
                supported: MAX_SUPPORTED_VERSION,
            });
        }

        // Rule 2: name slug.
        if !is_valid_slug(&self.descriptor.name) {
            return Err(LintError::BadName(self.descriptor.name.clone()));
        }

        // Rule: description length.
        let dlen = self.descriptor.description.chars().count();
        if !(1..=200).contains(&dlen) {
            return Err(LintError::BadDescription(dlen));
        }

        // Rule 4 + 5: argv[0] literal; `**` placement.
        check_match_argv(&self.match_.argv)?;
        for pat in &self.match_.exclude_argv {
            check_match_argv(pat)?;
        }

        // Rule 6: snapshot binaries.
        check_snapshot_section("pre", &self.snapshot.pre)?;
        if let Some(post) = &self.snapshot.post {
            check_snapshot_section("post", post)?;
        }

        // Rule 6 (reverse): reverse binary.
        if self.reverse.command.is_empty() {
            return Err(LintError::EmptyReverseCommand);
        }
        if !is_safe_binary_token(&self.reverse.command[0]) {
            return Err(LintError::UnsafeReverseBinary(
                self.reverse.command[0].clone(),
            ));
        }

        // Build the union of all extract keys for cross-references.
        let mut extracted = std::collections::HashSet::new();
        for k in self.snapshot.pre.extract.keys() {
            extracted.insert(k.clone());
        }
        if let Some(post) = &self.snapshot.post {
            for k in post.extract.keys() {
                extracted.insert(k.clone());
            }
        }
        if extracted.is_empty() {
            // snapshot.pre is required to extract at least one key
            // (per the schema doc — "extract.<key>: yes (≥1)").
            return Err(LintError::NoExtractors { phase: "pre" });
        }

        // Rule 7: every {{var}} in reverse.command + guard resolves.
        for tok in &self.reverse.command {
            for var in interpolation_vars(tok) {
                if !extracted.contains(&var) {
                    return Err(LintError::UnresolvedReverseVar(var));
                }
            }
        }
        if let Some(g) = &self.reverse.guard {
            for var in interpolation_vars(&g.expected_substring) {
                if !extracted.contains(&var) {
                    return Err(LintError::UnresolvedGuardVar(var));
                }
            }
            if g.command.is_empty() {
                return Err(LintError::EmptyReverseCommand); // close enough
            }
            if !is_safe_binary_token(&g.command[0]) {
                return Err(LintError::UnsafeReverseBinary(g.command[0].clone()));
            }
        }

        // Rule 8: extractor paths parse + are appropriate for the parse kind.
        check_extractor_paths("pre", self.snapshot.pre.parse, &self.snapshot.pre.extract)?;
        if let Some(post) = &self.snapshot.post {
            check_extractor_paths("post", post.parse, &post.extract)?;
        }

        // Rule 9 + 10: privilege / confirmation tier rules.
        let is_builtin = matches!(self.descriptor.authority, DescriptorAuthority::Builtin);
        if self.reverse.privileged && !is_builtin {
            return Err(LintError::PrivilegedNeedsBuiltin {
                authority: self.descriptor.authority.to_string(),
            });
        }
        if !self.reverse.requires_confirmation && !is_builtin {
            return Err(LintError::NoConfirmNeedsBuiltin {
                authority: self.descriptor.authority.to_string(),
            });
        }

        Ok(())
    }
}

fn is_valid_slug(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let first = bytes[0];
    let first_ok = first.is_ascii_lowercase() || first.is_ascii_digit();
    if !first_ok {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// argv[0] must be a literal; `**` only at the end and at most once.
fn check_match_argv(argv: &[String]) -> Result<(), LintError> {
    if argv.is_empty() {
        return Err(LintError::EmptyArgv);
    }
    if argv[0] == "*" || argv[0] == "**" {
        return Err(LintError::GlobInArgvZero(argv[0].clone()));
    }
    let mut seen_double = false;
    for (i, tok) in argv.iter().enumerate() {
        if tok == "**" {
            if seen_double || i + 1 != argv.len() {
                return Err(LintError::BadDoubleStar(argv.to_vec()));
            }
            seen_double = true;
        }
    }
    Ok(())
}

const SHELL_META: &[char] = &[';', '&', '|', '$', '`', '<', '>', '(', ')', '\n'];

fn is_safe_binary_token(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.contains("..") {
        return false;
    }
    !s.chars().any(|c| SHELL_META.contains(&c))
}

fn check_snapshot_section(phase: &'static str, snap: &DescriptorSnapshot) -> Result<(), LintError> {
    if snap.command.is_empty() {
        return Err(LintError::EmptySnapshotCommand { phase });
    }
    if !is_safe_binary_token(&snap.command[0]) {
        return Err(LintError::UnsafeSnapshotBinary {
            phase,
            token: snap.command[0].clone(),
        });
    }
    if snap.extract.is_empty() {
        return Err(LintError::NoExtractors { phase });
    }
    Ok(())
}

fn check_extractor_paths(
    phase: &'static str,
    parse: ParseKind,
    extract: &BTreeMap<String, String>,
) -> Result<(), LintError> {
    for path in extract.values() {
        match parse {
            ParseKind::Raw => {
                if path != ".raw" {
                    return Err(LintError::BadRawExtractor(path.clone()));
                }
            }
            ParseKind::Lines => {
                // Must be `[N]` or `.lines[N]`.
                if !is_lines_path(path) {
                    return Err(LintError::BadLinesExtractor(path.clone()));
                }
            }
            ParseKind::Json | ParseKind::Toml => {
                if !is_structured_path(path) {
                    return Err(LintError::BadExtractorPath(phase.to_string(), path.clone()));
                }
            }
        }
    }
    Ok(())
}

fn is_lines_path(s: &str) -> bool {
    // Accept `[N]` or `.lines[N]`. N is non-negative integer.
    let body = s.strip_prefix(".lines").unwrap_or(s);
    let inside = match body.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        Some(i) => i,
        None => return false,
    };
    inside.chars().all(|c| c.is_ascii_digit()) && !inside.is_empty()
}

fn is_structured_path(s: &str) -> bool {
    // Accept `.foo`, `.foo.bar`, `.foo[0].bar`, etc. No whitespace, no
    // pipes, no slices, no recursive descent.
    if s.is_empty() {
        return false;
    }
    // Skip a leading `.raw` for the structured grammar (it's a `Raw`
    // construct, not structured).
    if s == ".raw" {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes[0] != b'.' && bytes[0] != b'[' {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                i += 1;
                // Expect [a-zA-Z_][a-zA-Z0-9_]* or end-of-segment via '['
                if i >= bytes.len() {
                    return false;
                }
                let start = i;
                if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
                    return false;
                }
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                if i == start {
                    return false;
                }
            }
            b'[' => {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i == start || i >= bytes.len() || bytes[i] != b']' {
                    return false;
                }
                i += 1; // consume ]
            }
            _ => return false,
        }
    }
    true
}

/// Extract all `{{var}}` identifiers from a template token. Used by lint
/// (Rule 7) and by the interpolation engine (C02.4).
pub fn interpolation_vars(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let close = match after.find("}}") {
            Some(p) => p,
            None => break,
        };
        let name = &after[..close];
        if !name.is_empty() && is_var_name(name) {
            out.push(name.to_string());
        }
        rest = &after[close + 2..];
    }
    out
}

fn is_var_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let first_ok = bytes[0].is_ascii_alphabetic() || bytes[0] == b'_';
    if !first_ok {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_descriptor() -> &'static str {
        r#"
[descriptor]
version = 1
name = "hostname-set"
description = "Capture+reverse hostname mutations via hostname(1)."
authority = "builtin"

[match]
argv = ["hostname", "*"]

[snapshot.pre]
command = ["hostname"]
parse = "raw"
extract.old_hostname = ".raw"

[reverse]
requires_confirmation = false
command = ["hostname", "{{old_hostname}}"]
privileged = true
"#
    }

    #[test]
    fn parses_good_descriptor() {
        let d = Descriptor::from_toml(good_descriptor()).unwrap();
        assert_eq!(d.descriptor.name, "hostname-set");
        assert_eq!(d.descriptor.version, 1);
        assert!(matches!(
            d.descriptor.authority,
            DescriptorAuthority::Builtin
        ));
        assert!(!d.reverse.requires_confirmation);
        assert!(d.reverse.privileged);
    }

    #[test]
    fn rejects_unsupported_version() {
        let s = good_descriptor().replace("version = 1", "version = 2");
        let err = Descriptor::from_toml(&s).unwrap_err();
        assert!(matches!(
            err,
            SchemaError::Lint(LintError::UnsupportedVersion { actual: 2, .. })
        ));
    }

    #[test]
    fn rejects_bad_slug() {
        let s = good_descriptor().replace("hostname-set", "Hostname_Set");
        let err = Descriptor::from_toml(&s).unwrap_err();
        assert!(matches!(err, SchemaError::Lint(LintError::BadName(_))));
    }

    #[test]
    fn rejects_argv0_glob() {
        let s =
            good_descriptor().replace(r#"argv = ["hostname", "*"]"#, r#"argv = ["*", "hostname"]"#);
        let err = Descriptor::from_toml(&s).unwrap_err();
        assert!(matches!(
            err,
            SchemaError::Lint(LintError::GlobInArgvZero(_))
        ));
    }

    #[test]
    fn rejects_double_star_in_middle() {
        let s = good_descriptor().replace(
            r#"argv = ["hostname", "*"]"#,
            r#"argv = ["hostname", "**", "foo"]"#,
        );
        let err = Descriptor::from_toml(&s).unwrap_err();
        assert!(matches!(
            err,
            SchemaError::Lint(LintError::BadDoubleStar(_))
        ));
    }

    #[test]
    fn accepts_double_star_at_end() {
        let s = good_descriptor().replace(
            r#"argv = ["hostname", "*"]"#,
            r#"argv = ["hostname", "**"]"#,
        );
        let d = Descriptor::from_toml(&s).unwrap();
        assert_eq!(d.match_.argv.last().unwrap(), "**");
    }

    #[test]
    fn rejects_shell_metachar_in_reverse_binary() {
        // SHELL_META lists `; & | $ backtick < > ( )` newline. Spaces are
        // NOT metachars per this rule (some valid binary paths contain
        // them) — the rule blocks shell-injection, not weird filenames.
        let s = good_descriptor().replace(
            r#"command = ["hostname", "{{old_hostname}}"]"#,
            r#"command = ["sh;evil", "{{old_hostname}}"]"#,
        );
        let err = Descriptor::from_toml(&s).unwrap_err();
        assert!(matches!(
            err,
            SchemaError::Lint(LintError::UnsafeReverseBinary(_))
        ));
    }

    #[test]
    fn rejects_path_traversal_in_binary() {
        let s = good_descriptor().replace(
            r#"command = ["hostname"]"#,
            r#"command = ["../usr/bin/evil"]"#,
        );
        let err = Descriptor::from_toml(&s).unwrap_err();
        assert!(matches!(
            err,
            SchemaError::Lint(LintError::UnsafeSnapshotBinary { .. })
        ));
    }

    #[test]
    fn rejects_unresolved_reverse_var() {
        let s = good_descriptor().replace("{{old_hostname}}", "{{nope_not_extracted}}");
        let err = Descriptor::from_toml(&s).unwrap_err();
        assert!(matches!(
            err,
            SchemaError::Lint(LintError::UnresolvedReverseVar(_))
        ));
    }

    #[test]
    fn rejects_privileged_for_non_builtin() {
        let s = good_descriptor().replace(r#"authority = "builtin""#, r#"authority = "user""#);
        let err = Descriptor::from_toml(&s).unwrap_err();
        // Either privilege or confirmation rule will fire first; both are correct rejections.
        assert!(matches!(
            err,
            SchemaError::Lint(LintError::PrivilegedNeedsBuiltin { .. })
                | SchemaError::Lint(LintError::NoConfirmNeedsBuiltin { .. })
        ));
    }

    #[test]
    fn rejects_bad_raw_extractor() {
        let s = good_descriptor().replace(
            r#"extract.old_hostname = ".raw""#,
            r#"extract.old_hostname = ".foo""#,
        );
        let err = Descriptor::from_toml(&s).unwrap_err();
        assert!(matches!(
            err,
            SchemaError::Lint(LintError::BadRawExtractor(_))
        ));
    }

    #[test]
    fn accepts_json_structured_paths() {
        let s = r#"
[descriptor]
version = 1
name = "aws-s3-head"
description = "S3 head test"
authority = "builtin"

[match]
argv = ["aws", "s3api", "head-object", "**"]

[snapshot.pre]
command = ["aws", "s3api", "head-object"]
parse = "json"
extract.etag = ".ETag"
extract.version_id = ".VersionId"
extract.tag = ".TagSet[0].Value"

[reverse]
requires_confirmation = true
command = ["aws", "s3api", "delete-object", "--version-id={{version_id}}"]
"#;
        Descriptor::from_toml(s).unwrap();
    }

    #[test]
    fn rejects_lines_path_without_index() {
        let s = r#"
[descriptor]
version = 1
name = "lines-bad"
description = "lines"
authority = "builtin"

[match]
argv = ["foo"]

[snapshot.pre]
command = ["foo"]
parse = "lines"
extract.first = ".foo"

[reverse]
requires_confirmation = true
command = ["bar", "{{first}}"]
"#;
        let err = Descriptor::from_toml(s).unwrap_err();
        assert!(matches!(
            err,
            SchemaError::Lint(LintError::BadLinesExtractor(_))
        ));
    }

    #[test]
    fn third_party_authority_round_trips() {
        let s = r#"
[descriptor]
version = 1
name = "tp"
description = "third-party test"
authority = "third-party:vendor-x"

[match]
argv = ["tp"]

[snapshot.pre]
command = ["tp"]
parse = "raw"
extract.v = ".raw"

[reverse]
requires_confirmation = true
command = ["tp", "{{v}}"]
"#;
        let d = Descriptor::from_toml(s).unwrap();
        assert_eq!(d.descriptor.authority.to_string(), "third-party:vendor-x");
    }

    #[test]
    fn interpolation_vars_finds_all() {
        let toks = interpolation_vars("hello {{a}} world {{b_2}} {{}}");
        assert_eq!(toks, vec!["a".to_string(), "b_2".to_string()]);
    }

    #[test]
    fn interpolation_vars_ignores_unclosed() {
        let toks = interpolation_vars("hello {{a}} world {{b");
        assert_eq!(toks, vec!["a".to_string()]);
    }

    /// C02.8: every built-in descriptor pack ships parseable + lint-clean.
    /// This is the only sprint-level guarantee that the packs in
    /// `packaging/descriptors/builtin/` stay in sync with the schema; if
    /// the schema tightens a rule, this test catches it before release.
    #[test]
    fn builtin_descriptor_packs_parse_and_lint() {
        let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let pack_dir = here
            .parent() // crates/
            .and_then(|p| p.parent()) // workspace root
            .map(|p| p.join("packaging/descriptors/builtin"))
            .expect("locate builtin pack dir");
        assert!(
            pack_dir.is_dir(),
            "expected builtin pack dir at {}",
            pack_dir.display()
        );
        let mut found = 0usize;
        for entry in std::fs::read_dir(&pack_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            match Descriptor::from_toml(&text) {
                Ok(_) => found += 1,
                Err(e) => panic!("pack {} failed: {e}", path.display()),
            }
        }
        // We ship six builtins in C02.8 (hostname, hostnamectl, date,
        // timedatectl, sysctl, modprobe-r). The lower-bound check lets
        // future packs join without breaking this test.
        assert!(found >= 6, "expected ≥6 builtin packs, found {found}");
    }
}
