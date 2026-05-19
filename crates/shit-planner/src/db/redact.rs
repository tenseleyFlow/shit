// SPDX-License-Identifier: AGPL-3.0-or-later

//! Statement-text redaction (DR-54).
//!
//! The DB-CLI shim ships raw SQL statements through the journal so
//! `shit show` and `shit undo` can reconstruct what the user did.
//! That blob can carry credentials in-band: `CREATE USER alice
//! IDENTIFIED BY 'hunter2'`, `INSERT INTO secrets (key, value)
//! VALUES ('GITHUB_TOKEN', 'ghp_...')`, `UPDATE users SET password =
//! 'x'`. Those values must never reach the on-disk journal in
//! plaintext.
//!
//! This module rewrites the statement before it crosses the wire,
//! replacing sensitive literal values with the env-style
//! `<redacted:HASH>` marker. The renderer layer (see
//! `crates/shit/src/render/db.rs`) masks that marker again on
//! display — defence in depth.
//!
//! ## Heuristic, not a parser
//!
//! Building a real SQL parser on the hot path is overkill (and the
//! statement classifier intentionally avoids one — see [`crate::db::stmt`]).
//! We scan for a small set of high-signal patterns:
//!
//! 1. `IDENTIFIED BY '<x>'` (and `IDENTIFIED WITH <plugin> BY '<x>'`)
//!    — MySQL/MariaDB `CREATE USER` / `GRANT ... IDENTIFIED BY` form.
//! 2. `PASSWORD '<x>'` — PostgreSQL `CREATE ROLE ... PASSWORD 'x'`,
//!    `ALTER USER ... PASSWORD 'x'`. The keyword is rare outside this
//!    context as a standalone token followed by a literal.
//! 3. `INSERT INTO <t> (col1, ..., colN) VALUES (v1, ..., vN)` —
//!    when any `colK` matches a sensitive substring
//!    (`PASSWORD` / `SECRET` / `TOKEN` / `API_KEY` / `APIKEY`),
//!    redact `vK` at the matching position.
//! 4. `UPDATE <t> SET col1 = v1, col2 = v2 ...` — same column match.
//!
//! False negatives we accept: dollar-quoted Postgres literals
//! (`$tag$...$tag$`), `EXECUTE` with bind parameters, statements that
//! bury credentials in a string concatenation (`'hun' || 'ter2'`).
//! DR-55 tracks dollar-quote handling.
//!
//! False positives are the bigger risk — over-redacting wrecks `shit
//! show` output. We err on the side of *under*-redacting unless the
//! pattern is unambiguous. Two compensating layers catch what we
//! miss: the renderer's `<redacted:HASH>` masking and the S20 audit
//! tests in `crates/shit/src/render/mod.rs`.

use crate::env::{DEFAULT_REDACT_SUBSTRINGS, redact_value};

/// Redact sensitive literal values in a SQL statement. Idempotent on
/// already-redacted markers — the marker uses `<redacted:HASH>` and
/// passes through unchanged because it isn't a single-quoted literal.
pub fn redact_statement(stmt: &str) -> String {
    let s = redact_keyword_then_literal(stmt, &[&["IDENTIFIED", "BY"], &["PASSWORD"]]);
    let s = redact_insert(&s);
    redact_update(&s)
}

/// Is this column name one whose value we should redact?
pub fn is_sensitive_column(name: &str) -> bool {
    let upper = trim_identifier(name).to_ascii_uppercase();
    DEFAULT_REDACT_SUBSTRINGS
        .iter()
        .any(|sub| upper.contains(sub))
}

/// Strip surrounding quoting/backticks from a column identifier so
/// `"password"` and `` `password` `` match the sensitive list.
fn trim_identifier(name: &str) -> &str {
    let n = name.trim();
    let bytes = n.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"')
            || (first == b'`' && last == b'`')
            || (first == b'[' && last == b']')
        {
            return &n[1..n.len() - 1];
        }
    }
    n
}

/// Find each keyword *phrase* (a sequence of identifiers that must
/// appear in order, possibly separated by other tokens), then redact
/// the next single-quoted literal that follows.
///
/// Each phrase is `&[&str]`: e.g. `&["IDENTIFIED", "BY"]` matches
/// `IDENTIFIED BY 'x'` and `IDENTIFIED WITH mysql_native_password BY 'x'`.
fn redact_keyword_then_literal(stmt: &str, phrases: &[&[&str]]) -> String {
    let chars: Vec<char> = stmt.chars().collect();
    let mut out = String::with_capacity(stmt.len());
    let mut i = 0;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let c = chars[i];
        if in_single {
            out.push(c);
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\'') {
                    out.push('\'');
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            out.push(c);
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if c == '\'' {
            in_single = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '"' {
            in_double = true;
            out.push(c);
            i += 1;
            continue;
        }
        // Try to match the start of any phrase.
        if c.is_ascii_alphabetic() {
            let (word, word_end) = read_word(&chars, i);
            let upper = word.to_ascii_uppercase();
            let matched_phrase = phrases.iter().find(|p| !p.is_empty() && p[0] == upper);
            if let Some(phrase) = matched_phrase {
                let mut cursor = word_end;
                let mut phrase_idx = 1;
                let mut ok = true;
                // Each subsequent phrase token must appear within a
                // bounded window of intervening words. Without a
                // bound, `PASSWORD ... '...'` would slurp half the
                // statement; we cap at 6 intervening tokens.
                const MAX_GAP_TOKENS: usize = 6;
                while phrase_idx < phrase.len() {
                    let needed = phrase[phrase_idx];
                    let mut gap = 0;
                    let mut found = false;
                    let mut probe = skip_ws(&chars, cursor);
                    while probe < chars.len() && gap <= MAX_GAP_TOKENS {
                        if chars[probe] == '\'' || chars[probe] == '"' {
                            ok = false;
                            break;
                        }
                        if !chars[probe].is_ascii_alphabetic() {
                            // Punctuation / digits aren't part of an
                            // identifier; advance one char and retry.
                            probe += 1;
                            probe = skip_ws(&chars, probe);
                            continue;
                        }
                        let (w, end) = read_word(&chars, probe);
                        if w.eq_ignore_ascii_case(needed) {
                            cursor = end;
                            found = true;
                            break;
                        }
                        probe = skip_ws(&chars, end);
                        gap += 1;
                    }
                    if !found {
                        ok = false;
                        break;
                    }
                    phrase_idx += 1;
                }
                if ok {
                    // Emit the entire span `word..cursor` verbatim,
                    // then redact the next single-quoted literal.
                    out.extend(chars[i..cursor].iter());
                    let probe = skip_ws(&chars, cursor);
                    if probe < chars.len() && chars[probe] == '\'' {
                        // Emit whitespace between cursor and probe.
                        out.extend(chars[cursor..probe].iter());
                        let (literal, after) = read_single_quoted(&chars, probe);
                        out.push('\'');
                        if is_redacted_marker(&literal) {
                            out.push_str(&literal);
                        } else {
                            out.push_str(&redact_value(&literal));
                        }
                        out.push('\'');
                        i = after;
                        continue;
                    }
                    i = cursor;
                    continue;
                }
            }
            // Fall through: emit the original word.
            out.extend(chars[i..word_end].iter());
            i = word_end;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Redact sensitive-column values in `INSERT INTO ... (cols) VALUES (...)`.
/// Handles multiple value tuples after a single column list.
fn redact_insert(stmt: &str) -> String {
    let trimmed = stmt.trim_start();
    if !starts_with_keyword(trimmed, "INSERT") {
        return stmt.to_string();
    }
    // Find the column list: first `(...)` after the table identifier.
    let chars: Vec<char> = stmt.chars().collect();
    let cols_open = match find_unquoted(&chars, 0, '(') {
        Some(i) => i,
        None => return stmt.to_string(),
    };
    let cols_close = match match_paren(&chars, cols_open) {
        Some(i) => i,
        None => return stmt.to_string(),
    };
    let col_list: String = chars[cols_open + 1..cols_close].iter().collect();
    let columns = split_top_level_commas(&col_list);
    let sensitive_idxs: Vec<usize> = columns
        .iter()
        .enumerate()
        .filter_map(|(i, c)| is_sensitive_column(c).then_some(i))
        .collect();
    if sensitive_idxs.is_empty() {
        return stmt.to_string();
    }

    // Walk every following `(...)` group, redacting the values at
    // sensitive positions. The VALUES keyword may not even be
    // present in `INSERT INTO ... SELECT ...`; in that case there
    // are no value tuples to redact and we return unchanged.
    let mut out = String::with_capacity(stmt.len());
    out.extend(chars[..=cols_close].iter());
    let mut i = cols_close + 1;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            let (lit, after) = read_single_quoted(&chars, i);
            out.push('\'');
            out.push_str(&lit);
            out.push('\'');
            i = after;
            continue;
        }
        if c == '(' {
            let close = match match_paren(&chars, i) {
                Some(j) => j,
                None => {
                    out.extend(chars[i..].iter());
                    return out;
                }
            };
            let group: String = chars[i + 1..close].iter().collect();
            let values = split_top_level_commas(&group);
            if values.len() == columns.len() {
                let mut rewritten_values: Vec<String> = values.clone();
                for &idx in &sensitive_idxs {
                    rewritten_values[idx] = redact_value_literal(&values[idx]);
                }
                out.push('(');
                out.push_str(&rewritten_values.join(", "));
                out.push(')');
            } else {
                // Mismatch — emit verbatim. Better to leak than to
                // mis-redact the wrong column.
                out.extend(chars[i..=close].iter());
            }
            i = close + 1;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Redact `col = '<val>'` pairs in `UPDATE ... SET ...` when `col`
/// matches a sensitive name.
fn redact_update(stmt: &str) -> String {
    let trimmed = stmt.trim_start();
    if !starts_with_keyword(trimmed, "UPDATE") {
        return stmt.to_string();
    }
    let chars: Vec<char> = stmt.chars().collect();
    // Find the SET keyword (word-boundary), outside quotes.
    let set_pos = match find_keyword_outside_quotes(&chars, 0, "SET") {
        Some(i) => i,
        None => return stmt.to_string(),
    };
    // Find where the SET clause ends — at WHERE, RETURNING, ORDER, LIMIT, or end.
    let set_start = set_pos + 3; // past "SET"
    let set_end = find_clause_terminator(&chars, set_start);

    let assignments_src: String = chars[set_start..set_end].iter().collect();
    let assignments = split_top_level_commas(&assignments_src);
    if assignments.is_empty() {
        return stmt.to_string();
    }

    let mut rewritten: Vec<String> = Vec::with_capacity(assignments.len());
    let mut any_redacted = false;
    for assign in &assignments {
        if let Some(eq_pos) = find_unquoted_byte(assign.as_bytes(), 0, b'=') {
            let lhs = assign[..eq_pos].trim();
            let rhs = assign[eq_pos + 1..].to_string();
            if is_sensitive_column(lhs) {
                let rhs_trimmed = rhs.trim();
                let leading_ws_len = rhs.len() - rhs.trim_start().len();
                let leading_ws = &rhs[..leading_ws_len];
                let new_rhs = redact_value_literal(rhs_trimmed);
                rewritten.push(format!("{lhs} ={leading_ws}{new_rhs}"));
                any_redacted = true;
                continue;
            }
        }
        rewritten.push(assign.clone());
    }

    if !any_redacted {
        return stmt.to_string();
    }

    let mut out = String::with_capacity(stmt.len());
    out.extend(chars[..set_start].iter());
    // Preserve leading whitespace after SET.
    let after_set_ws_end = skip_ws(&chars, set_start);
    out.extend(chars[set_start..after_set_ws_end].iter());
    out.push_str(&rewritten.join(", "));
    out.extend(chars[set_end..].iter());
    out
}

/// Redact a single value expression. If the expression is a quoted
/// literal, the inner value is hashed. If it's a non-literal (bind
/// param, numeric, function call), pass through — we can't redact
/// what isn't there.
///
/// Already-redacted literals (`'<redacted:HASH>'`) pass through
/// unchanged so the function is idempotent — re-hashing would
/// produce a different marker each pass.
fn redact_value_literal(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(stripped) = strip_single_quotes(trimmed) {
        if is_redacted_marker(&stripped) {
            return value.to_string();
        }
        let red = redact_value(&stripped);
        return format!("'{red}'");
    }
    if let Some(stripped) = strip_double_quotes(trimmed) {
        if is_redacted_marker(&stripped) {
            return value.to_string();
        }
        let red = redact_value(&stripped);
        return format!("\"{red}\"");
    }
    value.to_string()
}

fn is_redacted_marker(s: &str) -> bool {
    s.starts_with("<redacted:") && s.ends_with('>')
}

fn strip_single_quotes(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'' {
        let inner = &s[1..s.len() - 1];
        Some(inner.replace("''", "'"))
    } else {
        None
    }
}

fn strip_double_quotes(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        Some(s[1..s.len() - 1].to_string())
    } else {
        None
    }
}

fn starts_with_keyword(s: &str, kw: &str) -> bool {
    let bytes = s.as_bytes();
    let kw_bytes = kw.as_bytes();
    if bytes.len() < kw_bytes.len() {
        return false;
    }
    for (a, b) in bytes.iter().zip(kw_bytes.iter()) {
        if !a.eq_ignore_ascii_case(b) {
            return false;
        }
    }
    bytes.get(kw_bytes.len()).is_none_or(|c| !is_ident_byte(*c))
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn read_word(chars: &[char], mut i: usize) -> (String, usize) {
    let start = i;
    while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
        i += 1;
    }
    (chars[start..i].iter().collect(), i)
}

fn skip_ws(chars: &[char], mut i: usize) -> usize {
    while i < chars.len() && chars[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn read_single_quoted(chars: &[char], start: usize) -> (String, usize) {
    debug_assert_eq!(chars[start], '\'');
    let mut buf = String::new();
    let mut i = start + 1;
    while i < chars.len() {
        let c = chars[i];
        if c == '\'' {
            if chars.get(i + 1) == Some(&'\'') {
                buf.push('\'');
                i += 2;
                continue;
            }
            return (buf, i + 1);
        }
        buf.push(c);
        i += 1;
    }
    (buf, i)
}

fn find_unquoted(chars: &[char], from: usize, target: char) -> Option<usize> {
    let mut i = from;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let c = chars[i];
        if in_single {
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\'') {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if c == '\'' {
            in_single = true;
            i += 1;
            continue;
        }
        if c == '"' {
            in_double = true;
            i += 1;
            continue;
        }
        if c == target {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn find_unquoted_byte(bytes: &[u8], from: usize, target: u8) -> Option<usize> {
    let mut i = from;
    let mut in_single = false;
    let mut in_double = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_single {
            if b == b'\'' {
                if bytes.get(i + 1) == Some(&b'\'') {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if b == b'"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if b == b'\'' {
            in_single = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            in_double = true;
            i += 1;
            continue;
        }
        if b == target {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn match_paren(chars: &[char], open: usize) -> Option<usize> {
    debug_assert_eq!(chars[open], '(');
    let mut depth: i32 = 0;
    let mut i = open;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let c = chars[i];
        if in_single {
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\'') {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if c == '\'' {
            in_single = true;
            i += 1;
            continue;
        }
        if c == '"' {
            in_double = true;
            i += 1;
            continue;
        }
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut depth: i32 = 0;
    let mut in_single = false;
    let mut in_double = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_single {
            buf.push(c);
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\'') {
                    buf.push('\'');
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            buf.push(c);
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if c == '\'' {
            in_single = true;
            buf.push(c);
            i += 1;
            continue;
        }
        if c == '"' {
            in_double = true;
            buf.push(c);
            i += 1;
            continue;
        }
        if c == '(' {
            depth += 1;
            buf.push(c);
        } else if c == ')' {
            depth -= 1;
            buf.push(c);
        } else if c == ',' && depth == 0 {
            let trimmed = buf.trim().to_string();
            if !trimmed.is_empty() {
                out.push(trimmed);
            }
            buf.clear();
        } else {
            buf.push(c);
        }
        i += 1;
    }
    let last = buf.trim();
    if !last.is_empty() {
        out.push(last.to_string());
    }
    out
}

fn find_keyword_outside_quotes(chars: &[char], from: usize, kw: &str) -> Option<usize> {
    let mut i = from;
    let mut in_single = false;
    let mut in_double = false;
    while i < chars.len() {
        let c = chars[i];
        if in_single {
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\'') {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if c == '\'' {
            in_single = true;
            i += 1;
            continue;
        }
        if c == '"' {
            in_double = true;
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() {
            let (w, end) = read_word(chars, i);
            if w.eq_ignore_ascii_case(kw) {
                return Some(i);
            }
            i = end;
            continue;
        }
        i += 1;
    }
    None
}

/// In an UPDATE statement, the SET clause ends where one of these
/// top-level keywords starts: WHERE, RETURNING, ORDER, LIMIT, or end.
fn find_clause_terminator(chars: &[char], from: usize) -> usize {
    const TERMINATORS: &[&str] = &["WHERE", "RETURNING", "ORDER", "LIMIT"];
    let mut i = from;
    let mut in_single = false;
    let mut in_double = false;
    let mut depth: i32 = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_single {
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\'') {
                    i += 2;
                    continue;
                }
                in_single = false;
            }
            i += 1;
            continue;
        }
        if in_double {
            if c == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }
        if c == '\'' {
            in_single = true;
            i += 1;
            continue;
        }
        if c == '"' {
            in_double = true;
            i += 1;
            continue;
        }
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        } else if depth == 0 && c.is_ascii_alphabetic() {
            let (w, end) = read_word(chars, i);
            let upper = w.to_ascii_uppercase();
            if TERMINATORS.iter().any(|t| *t == upper) {
                return i;
            }
            i = end;
            continue;
        }
        i += 1;
    }
    chars.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains_marker(s: &str) -> bool {
        s.contains("<redacted:")
    }

    #[test]
    fn identified_by_redacts_password() {
        let s = redact_statement("CREATE USER alice IDENTIFIED BY 'hunter2'");
        assert!(contains_marker(&s), "{s}");
        assert!(!s.contains("hunter2"), "{s}");
        assert!(s.contains("IDENTIFIED BY"), "{s}");
    }

    #[test]
    fn identified_with_plugin_by_redacts() {
        let s = redact_statement(
            "ALTER USER 'bob'@'%' IDENTIFIED WITH mysql_native_password BY 'sekret'",
        );
        assert!(contains_marker(&s), "{s}");
        assert!(!s.contains("sekret"), "{s}");
    }

    #[test]
    fn password_keyword_redacts_postgres_form() {
        let s = redact_statement("CREATE ROLE bob PASSWORD 'topsecret'");
        assert!(contains_marker(&s), "{s}");
        assert!(!s.contains("topsecret"), "{s}");
    }

    #[test]
    fn alter_user_with_password_redacts() {
        let s = redact_statement("ALTER USER bob WITH PASSWORD 'hush'");
        assert!(contains_marker(&s), "{s}");
        assert!(!s.contains("hush"), "{s}");
    }

    #[test]
    fn insert_into_sensitive_column_redacts_value() {
        let s = redact_statement(
            "INSERT INTO users (name, password, email) VALUES ('alice', 'plaintext', 'a@e.com')",
        );
        assert!(contains_marker(&s), "{s}");
        assert!(!s.contains("plaintext"), "{s}");
        assert!(s.contains("'alice'"), "{s}");
        assert!(s.contains("'a@e.com'"), "{s}");
    }

    #[test]
    fn insert_with_multiple_value_tuples_redacts_all() {
        let s = redact_statement(
            "INSERT INTO secrets (key, token) VALUES ('a', 'first'), ('b', 'second')",
        );
        assert!(!s.contains("first"), "{s}");
        assert!(!s.contains("second"), "{s}");
        assert_eq!(s.matches("<redacted:").count(), 2, "{s}");
    }

    #[test]
    fn insert_with_quoted_column_identifiers_still_matches() {
        let s = redact_statement(r#"INSERT INTO t ("name", "api_key") VALUES ('svc', 'ghp_xxx')"#);
        assert!(!s.contains("ghp_xxx"), "{s}");
    }

    #[test]
    fn insert_with_backtick_column_identifiers_still_matches() {
        let s = redact_statement("INSERT INTO t (`name`, `secret`) VALUES ('svc', 'oops_leaked')");
        assert!(!s.contains("oops_leaked"), "{s}");
    }

    #[test]
    fn insert_without_sensitive_column_passes_through() {
        let input = "INSERT INTO logs (id, message) VALUES (1, 'hello world')";
        assert_eq!(redact_statement(input), input);
    }

    #[test]
    fn update_set_sensitive_column_redacts() {
        let s = redact_statement("UPDATE users SET password = 'newpass' WHERE id = 1");
        assert!(contains_marker(&s), "{s}");
        assert!(!s.contains("newpass"), "{s}");
        assert!(s.contains("WHERE id = 1"), "{s}");
    }

    #[test]
    fn update_set_multiple_columns_only_redacts_sensitive() {
        let s = redact_statement(
            "UPDATE users SET name = 'alice', api_key = 'leak', email = 'a@e.com' WHERE id = 1",
        );
        assert!(!s.contains("'leak'"), "{s}");
        assert!(s.contains("'alice'"), "{s}");
        assert!(s.contains("'a@e.com'"), "{s}");
    }

    #[test]
    fn update_set_without_where_still_redacts() {
        let s = redact_statement("UPDATE users SET token = 'x'");
        assert!(contains_marker(&s), "{s}");
    }

    #[test]
    fn update_set_with_returning_preserves_returning_clause() {
        let s = redact_statement("UPDATE u SET secret = 'x' RETURNING id");
        assert!(contains_marker(&s), "{s}");
        assert!(s.contains("RETURNING id"), "{s}");
    }

    #[test]
    fn non_sensitive_select_passes_through() {
        let input = "SELECT * FROM users WHERE password = 'foo'";
        assert_eq!(redact_statement(input), input);
    }

    #[test]
    fn idempotent_on_already_redacted_marker() {
        let once = redact_statement("UPDATE u SET password = 'plain'");
        let twice = redact_statement(&once);
        assert_eq!(once, twice);
    }

    #[test]
    fn empty_statement_returns_empty() {
        assert_eq!(redact_statement(""), "");
        assert_eq!(redact_statement("   "), "   ");
    }

    #[test]
    fn equal_values_produce_equal_redactions() {
        let a = redact_statement("UPDATE u SET password = 'same'");
        let b = redact_statement("UPDATE u SET password = 'same'");
        assert_eq!(a, b);
    }

    #[test]
    fn case_insensitive_keyword_matching() {
        let s = redact_statement("update users set Password = 'lower'");
        assert!(contains_marker(&s), "{s}");
    }

    #[test]
    fn is_sensitive_column_matches_known_substrings() {
        assert!(is_sensitive_column("password"));
        assert!(is_sensitive_column("PASSWORD"));
        assert!(is_sensitive_column("user_password"));
        assert!(is_sensitive_column("api_key"));
        assert!(is_sensitive_column("apikey"));
        assert!(is_sensitive_column("auth_token"));
        assert!(is_sensitive_column("client_secret"));
        assert!(is_sensitive_column("\"password\""));
        assert!(is_sensitive_column("`api_key`"));
    }

    #[test]
    fn is_sensitive_column_rejects_innocuous() {
        assert!(!is_sensitive_column("name"));
        assert!(!is_sensitive_column("email"));
        assert!(!is_sensitive_column("created_at"));
        assert!(!is_sensitive_column("id"));
    }

    #[test]
    fn quoted_literal_containing_keyword_is_not_a_trigger() {
        // The literal `'IDENTIFIED BY'` is a value, not a keyword.
        let input = "SELECT 'IDENTIFIED BY 'inner_value'' FROM t";
        let out = redact_statement(input);
        // The pattern only triggers on unquoted keywords; this should pass through.
        assert_eq!(out, input);
    }

    #[test]
    fn column_count_mismatch_leaves_values_alone() {
        // 2 cols, 3 vals — refuse to redact (mismatch implies we
        // misparsed; better to leak than to redact the wrong column).
        let input = "INSERT INTO t (password, email) VALUES ('a', 'b', 'c')";
        let out = redact_statement(input);
        assert!(out.contains("'a'"));
        assert!(out.contains("'b'"));
        assert!(out.contains("'c'"));
    }

    #[test]
    fn insert_select_form_does_not_falsely_redact() {
        // INSERT ... SELECT has no `(values)` tuple to redact. The
        // column list parser must not corrupt the statement.
        let input = "INSERT INTO secrets (id, token) SELECT id, t FROM staging";
        let out = redact_statement(input);
        assert_eq!(out, input);
    }
}
