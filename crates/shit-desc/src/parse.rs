// SPDX-License-Identifier: AGPL-3.0-or-later

//! Snapshot-output parsers and extractors.
//!
//! Four parse kinds — `raw`, `lines`, `json`, `toml` — each with a
//! strict extractor-path subset. The grammar is documented in
//! `.docs/audits/descriptor-format.md`. Authors who need richer
//! extraction can `jq` themselves in the pre-command and emit a
//! pre-extracted scalar.

use super::schema::ParseKind;
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("malformed json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("malformed toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("extractor path `{0}` not found in input")]
    NotFound(String),
    #[error("extractor path `{0}` resolved to a non-scalar value (must be string/number/bool)")]
    NonScalar(String),
    #[error("extractor path `{path}` is syntactically invalid: {detail}")]
    BadPath { path: String, detail: &'static str },
    #[error("extractor `.raw` is only valid for parse=raw, used with parse={kind:?}")]
    RawWithStructured { kind: ParseKind },
    #[error("extractor `[N]` is only valid for parse=lines, used with parse={kind:?}")]
    LinesIndexWithStructured { kind: ParseKind },
}

/// Apply a descriptor's extract map to a snapshot's raw stdout.
/// Returns a key→value map suitable for [`super::interpolate`] (added
/// in C02.4).
pub fn extract_all(
    kind: ParseKind,
    stdout: &[u8],
    extracts: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ParseError> {
    let stdout_str = std::str::from_utf8(stdout).map_err(|_| ParseError::BadPath {
        path: String::new(),
        detail: "non-utf8 stdout",
    })?;
    let mut out = BTreeMap::new();
    match kind {
        ParseKind::Raw => {
            let trimmed = stdout_str.trim_end_matches('\n').to_string();
            for (key, path) in extracts {
                if path != ".raw" {
                    return Err(ParseError::BadPath {
                        path: path.clone(),
                        detail: "raw parse accepts only `.raw`",
                    });
                }
                out.insert(key.clone(), trimmed.clone());
            }
        }
        ParseKind::Lines => {
            let lines: Vec<&str> = stdout_str.split('\n').collect();
            // The trailing newline produces a final empty element; drop it.
            let lines: Vec<&str> = if lines.last() == Some(&"") {
                lines[..lines.len() - 1].to_vec()
            } else {
                lines
            };
            for (key, path) in extracts {
                let idx = parse_lines_path(path)?;
                let v = lines
                    .get(idx)
                    .ok_or_else(|| ParseError::NotFound(path.clone()))?;
                out.insert(key.clone(), v.to_string());
            }
        }
        ParseKind::Json => {
            let v: serde_json::Value = serde_json::from_str(stdout_str)?;
            for (key, path) in extracts {
                let extracted = walk_json(&v, path)?;
                out.insert(key.clone(), extracted);
            }
        }
        ParseKind::Toml => {
            let v: toml::Value = toml::from_str(stdout_str)?;
            for (key, path) in extracts {
                let extracted = walk_toml(&v, path)?;
                out.insert(key.clone(), extracted);
            }
        }
    }
    Ok(out)
}

fn parse_lines_path(path: &str) -> Result<usize, ParseError> {
    let body = path.strip_prefix(".lines").unwrap_or(path);
    let inside = body
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .ok_or_else(|| ParseError::BadPath {
            path: path.to_string(),
            detail: "expected `[N]` or `.lines[N]`",
        })?;
    if inside.is_empty() {
        return Err(ParseError::BadPath {
            path: path.to_string(),
            detail: "empty index",
        });
    }
    inside.parse::<usize>().map_err(|_| ParseError::BadPath {
        path: path.to_string(),
        detail: "non-numeric line index",
    })
}

/// Walk a parsed JSON/TOML/etc. value by an extractor path. The grammar:
/// `.field` then `.subfield` then `[N]` etc. Returns the value
/// stringified if scalar, errors otherwise.
fn walk_json(root: &serde_json::Value, path: &str) -> Result<String, ParseError> {
    let segments = parse_structured_path(path)?;
    let mut cur = root;
    for seg in segments {
        cur = match seg {
            Segment::Field(name) => cur
                .get(&name)
                .ok_or_else(|| ParseError::NotFound(path.to_string()))?,
            Segment::Index(i) => cur
                .get(i)
                .ok_or_else(|| ParseError::NotFound(path.to_string()))?,
        };
    }
    match cur {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err(ParseError::NonScalar(path.to_string())),
    }
}

fn walk_toml(root: &toml::Value, path: &str) -> Result<String, ParseError> {
    let segments = parse_structured_path(path)?;
    let mut cur = root;
    for seg in segments {
        cur = match seg {
            Segment::Field(name) => cur
                .get(&name)
                .ok_or_else(|| ParseError::NotFound(path.to_string()))?,
            Segment::Index(i) => match cur.as_array().and_then(|a| a.get(i)) {
                Some(v) => v,
                None => return Err(ParseError::NotFound(path.to_string())),
            },
        };
    }
    match cur {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(n) => Ok(n.to_string()),
        toml::Value::Float(n) => Ok(n.to_string()),
        toml::Value::Boolean(b) => Ok(b.to_string()),
        _ => Err(ParseError::NonScalar(path.to_string())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Field(String),
    Index(usize),
}

fn parse_structured_path(path: &str) -> Result<Vec<Segment>, ParseError> {
    if path.is_empty() {
        return Err(ParseError::BadPath {
            path: path.to_string(),
            detail: "empty path",
        });
    }
    if path == ".raw" {
        return Err(ParseError::RawWithStructured {
            kind: ParseKind::Json,
        });
    }
    let bytes = path.as_bytes();
    let mut segments = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                i += 1;
                let start = i;
                if i >= bytes.len() {
                    return Err(ParseError::BadPath {
                        path: path.to_string(),
                        detail: "trailing dot",
                    });
                }
                if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') {
                    return Err(ParseError::BadPath {
                        path: path.to_string(),
                        detail: "field name must start with letter or underscore",
                    });
                }
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let name = std::str::from_utf8(&bytes[start..i]).unwrap().to_string();
                segments.push(Segment::Field(name));
            }
            b'[' => {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i == start || i >= bytes.len() || bytes[i] != b']' {
                    return Err(ParseError::BadPath {
                        path: path.to_string(),
                        detail: "malformed index",
                    });
                }
                let idx: usize = std::str::from_utf8(&bytes[start..i])
                    .unwrap()
                    .parse()
                    .map_err(|_| ParseError::BadPath {
                        path: path.to_string(),
                        detail: "non-numeric index",
                    })?;
                segments.push(Segment::Index(idx));
                i += 1; // consume ]
            }
            _ => {
                return Err(ParseError::BadPath {
                    path: path.to_string(),
                    detail: "unexpected character in path",
                });
            }
        }
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn extracts(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // ------- raw -------

    #[test]
    fn raw_extracts_whole_stdout_trimmed() {
        let out = extract_all(ParseKind::Raw, b"my-host\n", &extracts(&[("h", ".raw")])).unwrap();
        assert_eq!(out.get("h"), Some(&"my-host".to_string()));
    }

    #[test]
    fn raw_rejects_non_raw_path() {
        let err = extract_all(ParseKind::Raw, b"x", &extracts(&[("v", ".foo")])).unwrap_err();
        assert!(matches!(err, ParseError::BadPath { .. }));
    }

    // ------- lines -------

    #[test]
    fn lines_indexes_by_offset() {
        let stdout = b"one\ntwo\nthree\n";
        let out = extract_all(
            ParseKind::Lines,
            stdout,
            &extracts(&[("first", "[0]"), ("second", "[1]"), ("third", "[2]")]),
        )
        .unwrap();
        assert_eq!(out.get("first"), Some(&"one".to_string()));
        assert_eq!(out.get("second"), Some(&"two".to_string()));
        assert_eq!(out.get("third"), Some(&"three".to_string()));
    }

    #[test]
    fn lines_accepts_dot_lines_prefix() {
        let stdout = b"alpha\nbeta\n";
        let out = extract_all(ParseKind::Lines, stdout, &extracts(&[("v", ".lines[1]")])).unwrap();
        assert_eq!(out.get("v"), Some(&"beta".to_string()));
    }

    #[test]
    fn lines_out_of_range_errors() {
        let err = extract_all(ParseKind::Lines, b"only\n", &extracts(&[("v", "[5]")])).unwrap_err();
        assert!(matches!(err, ParseError::NotFound(_)));
    }

    // ------- json -------

    #[test]
    fn json_extracts_top_level() {
        let stdout = br#"{"name":"foo","count":3,"flag":true}"#;
        let out = extract_all(
            ParseKind::Json,
            stdout,
            &extracts(&[("name", ".name"), ("count", ".count"), ("flag", ".flag")]),
        )
        .unwrap();
        assert_eq!(out.get("name"), Some(&"foo".to_string()));
        assert_eq!(out.get("count"), Some(&"3".to_string()));
        assert_eq!(out.get("flag"), Some(&"true".to_string()));
    }

    #[test]
    fn json_extracts_nested() {
        let stdout = br#"{"outer":{"inner":{"x":42}}}"#;
        let out = extract_all(
            ParseKind::Json,
            stdout,
            &extracts(&[("v", ".outer.inner.x")]),
        )
        .unwrap();
        assert_eq!(out.get("v"), Some(&"42".to_string()));
    }

    #[test]
    fn json_extracts_through_array_index() {
        let stdout = br#"{"items":[{"id":"a"},{"id":"b"},{"id":"c"}]}"#;
        let out = extract_all(
            ParseKind::Json,
            stdout,
            &extracts(&[("second", ".items[1].id")]),
        )
        .unwrap();
        assert_eq!(out.get("second"), Some(&"b".to_string()));
    }

    #[test]
    fn json_missing_path_errors_not_found() {
        let stdout = br#"{"a":1}"#;
        let err = extract_all(ParseKind::Json, stdout, &extracts(&[("v", ".b")])).unwrap_err();
        assert!(matches!(err, ParseError::NotFound(_)));
    }

    #[test]
    fn json_non_scalar_errors() {
        let stdout = br#"{"obj":{"x":1}}"#;
        let err = extract_all(ParseKind::Json, stdout, &extracts(&[("v", ".obj")])).unwrap_err();
        assert!(matches!(err, ParseError::NonScalar(_)));
    }

    #[test]
    fn json_malformed_input_errors() {
        let err =
            extract_all(ParseKind::Json, b"not json {", &extracts(&[("v", ".x")])).unwrap_err();
        assert!(matches!(err, ParseError::Json(_)));
    }

    // ------- toml -------

    #[test]
    fn toml_extracts_field() {
        let stdout = b"name = \"foo\"\ncount = 7\n";
        let out = extract_all(
            ParseKind::Toml,
            stdout,
            &extracts(&[("n", ".name"), ("c", ".count")]),
        )
        .unwrap();
        assert_eq!(out.get("n"), Some(&"foo".to_string()));
        assert_eq!(out.get("c"), Some(&"7".to_string()));
    }

    #[test]
    fn toml_extracts_nested_table_and_array() {
        let stdout = b"[server]\nhost = \"x\"\n[[items]]\nid = \"a\"\n[[items]]\nid = \"b\"\n";
        let out = extract_all(
            ParseKind::Toml,
            stdout,
            &extracts(&[("host", ".server.host"), ("second", ".items[1].id")]),
        )
        .unwrap();
        assert_eq!(out.get("host"), Some(&"x".to_string()));
        assert_eq!(out.get("second"), Some(&"b".to_string()));
    }

    // ------- path grammar -------

    #[test]
    fn structured_path_rejects_whitespace() {
        let stdout = br#"{"a":1}"#;
        let err = extract_all(ParseKind::Json, stdout, &extracts(&[("v", ". a")])).unwrap_err();
        assert!(matches!(err, ParseError::BadPath { .. }));
    }

    #[test]
    fn structured_path_rejects_pipe_or_filter() {
        let stdout = br#"{"a":1}"#;
        let err = extract_all(
            ParseKind::Json,
            stdout,
            &extracts(&[("v", ".a | select(.>0)")]),
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::BadPath { .. }));
    }

    #[test]
    fn structured_path_rejects_trailing_dot() {
        let stdout = br#"{"a":1}"#;
        let err = extract_all(ParseKind::Json, stdout, &extracts(&[("v", ".a.")])).unwrap_err();
        assert!(matches!(err, ParseError::BadPath { .. }));
    }
}
