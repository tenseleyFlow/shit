// SPDX-License-Identifier: AGPL-3.0-or-later

//! Template interpolation for descriptor `reverse.command` (and guard).
//!
//! Per-argv-token substitution. Never invokes a shell — every argv element
//! stays a distinct token, with `{{var}}` replaced by the captured value.
//! Missing variables and empty-string values are hard errors at apply
//! time. The grammar matches `schema::interpolation_vars`.

use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum InterpolateError {
    #[error("missing variable `{0}` (not in captured_state)")]
    MissingVariable(String),
    #[error("empty value for variable `{0}` (strict mode rejects empty interpolation)")]
    EmptyVariable(String),
    #[error("unterminated `{{{{var` in template `{0}`")]
    Unterminated(String),
    #[error("malformed variable name `{0}`")]
    BadName(String),
}

/// Interpolate one argv token. Returns the fully-substituted string.
pub fn interpolate_token(
    tok: &str,
    state: &BTreeMap<String, String>,
) -> Result<String, InterpolateError> {
    let mut out = String::with_capacity(tok.len());
    let mut rest = tok;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let close = match after.find("}}") {
            Some(p) => p,
            None => return Err(InterpolateError::Unterminated(tok.to_string())),
        };
        let name = &after[..close];
        if !is_valid_name(name) {
            return Err(InterpolateError::BadName(name.to_string()));
        }
        let value = state
            .get(name)
            .ok_or_else(|| InterpolateError::MissingVariable(name.to_string()))?;
        if value.is_empty() {
            return Err(InterpolateError::EmptyVariable(name.to_string()));
        }
        out.push_str(value);
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Interpolate every token of an argv array.
pub fn interpolate_argv(
    argv: &[String],
    state: &BTreeMap<String, String>,
) -> Result<Vec<String>, InterpolateError> {
    argv.iter().map(|t| interpolate_token(t, state)).collect()
}

fn is_valid_name(s: &str) -> bool {
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

    fn state(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn interpolates_single_variable() {
        let out = interpolate_token("{{name}}", &state(&[("name", "alice")])).unwrap();
        assert_eq!(out, "alice");
    }

    #[test]
    fn interpolates_with_surrounding_text() {
        let out = interpolate_token("--user={{name}}", &state(&[("name", "alice")])).unwrap();
        assert_eq!(out, "--user=alice");
    }

    #[test]
    fn interpolates_multiple_vars_in_one_token() {
        let out = interpolate_token("{{a}}={{b}}", &state(&[("a", "X"), ("b", "Y")])).unwrap();
        assert_eq!(out, "X=Y");
    }

    #[test]
    fn interpolates_adjacent_vars() {
        let out = interpolate_token("{{a}}{{b}}", &state(&[("a", "foo"), ("b", "bar")])).unwrap();
        assert_eq!(out, "foobar");
    }

    #[test]
    fn literal_token_without_braces_unchanged() {
        let out = interpolate_token("hostname", &state(&[])).unwrap();
        assert_eq!(out, "hostname");
    }

    #[test]
    fn missing_variable_errors() {
        let err = interpolate_token("{{nope}}", &state(&[])).unwrap_err();
        assert!(matches!(err, InterpolateError::MissingVariable(_)));
    }

    #[test]
    fn empty_value_errors_strict() {
        let err = interpolate_token("{{v}}", &state(&[("v", "")])).unwrap_err();
        assert!(matches!(err, InterpolateError::EmptyVariable(_)));
    }

    #[test]
    fn unterminated_template_errors() {
        let err = interpolate_token("{{nope", &state(&[("nope", "x")])).unwrap_err();
        assert!(matches!(err, InterpolateError::Unterminated(_)));
    }

    #[test]
    fn bad_variable_name_errors() {
        let err = interpolate_token("{{2bad}}", &state(&[])).unwrap_err();
        assert!(matches!(err, InterpolateError::BadName(_)));
    }

    #[test]
    fn shell_metachar_passes_through_as_argv_content() {
        // Critical security property: interpolated values containing
        // shell metachars are passed verbatim. The OS does not re-parse;
        // argv tokens stay tokens.
        let out = interpolate_token("{{evil}}", &state(&[("evil", "; rm -rf /")])).unwrap();
        assert_eq!(out, "; rm -rf /");
        // The token's bytes are exactly what was interpolated. There is
        // no shell in this pipeline; whatever process consumes this
        // value sees it as a single argv element.
    }

    #[test]
    fn interpolate_argv_processes_every_token() {
        let argv = vec![
            "aws".to_string(),
            "s3api".to_string(),
            "delete-object".to_string(),
            "--bucket={{bucket}}".to_string(),
            "--key={{key}}".to_string(),
            "--version-id={{vid}}".to_string(),
        ];
        let s = state(&[("bucket", "b"), ("key", "k"), ("vid", "v123")]);
        let out = interpolate_argv(&argv, &s).unwrap();
        assert_eq!(
            out,
            vec![
                "aws".to_string(),
                "s3api".to_string(),
                "delete-object".to_string(),
                "--bucket=b".to_string(),
                "--key=k".to_string(),
                "--version-id=v123".to_string(),
            ]
        );
    }

    #[test]
    fn interpolate_argv_short_circuits_on_first_missing() {
        let argv = vec!["a".to_string(), "{{missing}}".to_string()];
        let err = interpolate_argv(&argv, &state(&[])).unwrap_err();
        assert!(matches!(err, InterpolateError::MissingVariable(_)));
    }

    #[test]
    fn unicode_values_round_trip() {
        let out = interpolate_token("host={{h}}", &state(&[("h", "ホスト")])).unwrap();
        assert_eq!(out, "host=ホスト");
    }
}
