// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL-statement classifier (S19.3).
//!
//! Lightweight heuristic — *not* a SQL parser. The classifier looks
//! at the first non-comment-non-whitespace keyword to decide
//! "mutating or not." A real parser would resolve `SELECT ... FOR
//! UPDATE` (locking) vs. `SELECT ... INTO new_table` (mutating);
//! we honor the latter (it materializes a table) but ignore the
//! former (it doesn't write).
//!
//! ## Why not a full SQL parser
//!
//! The shim sits in the hot path of every `psql -c` invocation. A
//! full parser (sqlparser-rs at ~25k lines of dependency tree) is
//! overkill for "is this a SELECT or an INSERT." We classify by
//! leading keyword and trust the user not to bury an `UPDATE` inside
//! a string literal of a `SELECT 'UPDATE ...'`.
//!
//! ## Statement splitting
//!
//! `psql -f migrations.sql` may carry hundreds of `;`-separated
//! statements in one file. [`split_statements`] does a
//! string-literal-aware split (`'foo;bar'` stays one token); it
//! does *not* handle dollar-quoted strings (`$tag$ ... $tag$` —
//! psql/postgres extension). DR-55 tracks that.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    /// SELECT / SHOW / EXPLAIN-without-INTO / VALUES / WITH ... SELECT.
    /// These are dropped before journal-write — they don't mutate.
    ReadOnly,
    /// INSERT / UPDATE / DELETE / DDL (CREATE/DROP/ALTER/TRUNCATE/RENAME) /
    /// SELECT ... INTO / EXPLAIN ... INTO / CALL / GRANT/REVOKE /
    /// COPY ... FROM / BEGIN / COMMIT / ROLLBACK.
    Mutating,
    /// We couldn't strip a leading keyword (empty or only a comment).
    /// Conservatively classified as mutating — better to over-record
    /// than miss a real change.
    Unknown,
}

impl StatementKind {
    pub fn is_mutating(self) -> bool {
        matches!(self, Self::Mutating | Self::Unknown)
    }
}

/// Classify a single statement (no trailing `;` required).
pub fn classify_statement(sql: &str) -> StatementKind {
    let trimmed = strip_leading_comments_and_whitespace(sql);
    if trimmed.is_empty() {
        return StatementKind::Unknown;
    }
    // First keyword: alphanumeric run.
    let first: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_ascii_uppercase();
    let rest = &trimmed[first.len()..];

    match first.as_str() {
        // Read-only families.
        "SELECT" => {
            // SELECT ... INTO writes. Detect "INTO" as a separate word
            // (avoid "select_into_view" false-matching).
            if has_word(rest, "INTO") {
                StatementKind::Mutating
            } else {
                StatementKind::ReadOnly
            }
        }
        "SHOW" | "DESCRIBE" | "DESC" | "EXPLAIN" => {
            // EXPLAIN can wrap any statement; for read-only conservativeness,
            // only flag mutating if "INTO" appears.
            if first == "EXPLAIN" && has_word(rest, "INTO") {
                StatementKind::Mutating
            } else {
                StatementKind::ReadOnly
            }
        }
        "VALUES" | "TABLE" => StatementKind::ReadOnly,
        "WITH" => {
            // CTE: `WITH foo AS (...) SELECT/INSERT/UPDATE/DELETE/...`
            // — classify by the body, not the prelude.
            classify_with_body(rest)
        }
        // Mutating families.
        "INSERT" | "UPDATE" | "DELETE" | "MERGE" | "REPLACE" | "UPSERT" | "TRUNCATE" | "CREATE"
        | "DROP" | "ALTER" | "RENAME" | "GRANT" | "REVOKE" | "COMMENT" | "VACUUM" | "ANALYZE"
        | "REINDEX" | "CLUSTER" | "COPY" | "LOAD" | "IMPORT" | "EXPORT" | "CALL" | "DO"
        | "BEGIN" | "COMMIT" | "ROLLBACK" | "SAVEPOINT" | "RELEASE" | "SET" | "RESET"
        | "PRAGMA" | "ATTACH" | "DETACH" | "VACUUMING" | "USE" => StatementKind::Mutating,
        // sqlite3 dot-meta-commands are usually informational; treat
        // them as Unknown so they're recorded but flagged for review.
        "" => StatementKind::Unknown,
        _ => StatementKind::Unknown,
    }
}

fn classify_with_body(rest: &str) -> StatementKind {
    // Walk forward, balancing parens, until we hit the top-level
    // SELECT/INSERT/UPDATE/DELETE keyword.
    let mut depth: i32 = 0;
    let chars: Vec<char> = rest.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        } else if depth == 0 && c.is_ascii_alphabetic() {
            // Read a word.
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i]
                .iter()
                .collect::<String>()
                .to_ascii_uppercase();
            match word.as_str() {
                "SELECT" => return StatementKind::ReadOnly,
                "INSERT" | "UPDATE" | "DELETE" | "MERGE" => return StatementKind::Mutating,
                _ => continue,
            }
        }
        i += 1;
    }
    // Defaulted out: a `WITH ... ` with no recognizable body — Unknown.
    StatementKind::Unknown
}

fn has_word(haystack: &str, needle: &str) -> bool {
    let upper = haystack.to_ascii_uppercase();
    let target = needle.to_ascii_uppercase();
    let mut start = 0;
    while let Some(idx) = upper[start..].find(&target) {
        let abs = start + idx;
        let before_ok = abs == 0
            || !upper.as_bytes()[abs - 1].is_ascii_alphanumeric()
                && upper.as_bytes()[abs - 1] != b'_';
        let after_idx = abs + target.len();
        let after_ok = after_idx == upper.len()
            || !upper.as_bytes()[after_idx].is_ascii_alphanumeric()
                && upper.as_bytes()[after_idx] != b'_';
        if before_ok && after_ok {
            return true;
        }
        start = abs + target.len();
    }
    false
}

fn strip_leading_comments_and_whitespace(s: &str) -> &str {
    let mut rest = s.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix("--") {
            // Line comment.
            if let Some(nl) = after.find('\n') {
                rest = after[nl + 1..].trim_start();
                continue;
            }
            return "";
        }
        if let Some(after) = rest.strip_prefix("/*") {
            // Block comment.
            if let Some(end) = after.find("*/") {
                rest = after[end + 2..].trim_start();
                continue;
            }
            return "";
        }
        return rest;
    }
}

/// Split a multi-statement script on `;`, honoring `'...'`, `"..."`,
/// and Postgres `$tag$ ... $tag$` literals (DR-55). Tags are
/// case-sensitive and may be empty (`$$ ... $$`) or alphanumeric +
/// underscore — anything else `$` precedes is treated as a plain
/// dollar sign.
pub fn split_statements(script: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut line_comment = false;
    let mut block_comment = false;
    let mut dollar_tag: Option<String> = None;
    let chars: Vec<char> = script.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if line_comment {
            buf.push(c);
            if c == '\n' {
                line_comment = false;
            }
            i += 1;
            continue;
        }
        if block_comment {
            buf.push(c);
            if c == '*' && next == Some('/') {
                buf.push('/');
                i += 2;
                block_comment = false;
                continue;
            }
            i += 1;
            continue;
        }
        if let Some(tag) = dollar_tag.as_ref() {
            // Inside a $tag$...$tag$ block. Look for the matching
            // closing $tag$ at the current position.
            if c == '$'
                && let Some(consumed) = match_dollar_tag(&chars, i, tag)
            {
                buf.extend(chars[i..i + consumed].iter());
                i += consumed;
                dollar_tag = None;
                continue;
            }
            buf.push(c);
            i += 1;
            continue;
        }
        if in_single {
            buf.push(c);
            if c == '\'' {
                // Postgres-style '' escape for a literal quote.
                if next == Some('\'') {
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
        // Dollar-quote opener?
        if c == '$'
            && let Some((tag, consumed)) = read_dollar_open(&chars, i)
        {
            buf.extend(chars[i..i + consumed].iter());
            i += consumed;
            dollar_tag = Some(tag);
            continue;
        }
        match c {
            '\'' => {
                in_single = true;
                buf.push(c);
            }
            '"' => {
                in_double = true;
                buf.push(c);
            }
            '-' if next == Some('-') => {
                line_comment = true;
                buf.push(c);
            }
            '/' if next == Some('*') => {
                block_comment = true;
                buf.push(c);
                buf.push('*');
                i += 2;
                continue;
            }
            ';' => {
                let stmt = buf.trim().to_string();
                if !stmt.is_empty() {
                    out.push(stmt);
                }
                buf.clear();
            }
            _ => buf.push(c),
        }
        i += 1;
    }
    let last = buf.trim();
    if !last.is_empty() {
        out.push(last.to_string());
    }
    out
}

/// At an opening `$`, attempt to read a dollar-quote tag. Returns
/// `Some((tag, total_chars_consumed))` if the syntax is a valid
/// `$<tag>$` opener — otherwise `None` and the caller treats `$` as
/// a plain character.
///
/// A dollar tag matches `$[A-Za-z_][A-Za-z0-9_]*$` or the empty form
/// `$$`. Anything else (e.g. `$1` as a bind param, `$foo bar`) is
/// not a dollar-quote opener.
fn read_dollar_open(chars: &[char], start: usize) -> Option<(String, usize)> {
    debug_assert_eq!(chars[start], '$');
    let mut end = start + 1;
    let mut first = true;
    while end < chars.len() {
        let c = chars[end];
        if c == '$' {
            // Found the closing `$`. Tag is chars[start+1..end].
            let tag: String = chars[start + 1..end].iter().collect();
            return Some((tag, end - start + 1));
        }
        let ok = if first {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_'
        };
        if !ok {
            return None;
        }
        first = false;
        end += 1;
    }
    None
}

/// At a `$`, check whether the next characters spell `$<tag>$`.
/// Returns the number of chars consumed if matched, or `None`.
fn match_dollar_tag(chars: &[char], at: usize, tag: &str) -> Option<usize> {
    debug_assert_eq!(chars[at], '$');
    let tag_chars: Vec<char> = tag.chars().collect();
    let needed = 2 + tag_chars.len();
    if at + needed > chars.len() {
        return None;
    }
    for (k, t) in tag_chars.iter().enumerate() {
        if chars[at + 1 + k] != *t {
            return None;
        }
    }
    if chars[at + 1 + tag_chars.len()] != '$' {
        return None;
    }
    Some(needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_is_readonly() {
        assert_eq!(
            classify_statement("SELECT * FROM t"),
            StatementKind::ReadOnly
        );
        assert_eq!(classify_statement("select 1"), StatementKind::ReadOnly);
    }

    #[test]
    fn select_into_is_mutating() {
        assert_eq!(
            classify_statement("SELECT * INTO new_t FROM old_t"),
            StatementKind::Mutating
        );
    }

    #[test]
    fn select_for_update_is_still_readonly() {
        // FOR UPDATE locks rows but doesn't mutate them; we don't
        // record it. (Locking visibility is the user's concern, not
        // a state delta worth journaling.)
        assert_eq!(
            classify_statement("SELECT * FROM t FOR UPDATE"),
            StatementKind::ReadOnly
        );
    }

    #[test]
    fn show_describe_explain_are_readonly() {
        for s in [
            "SHOW TABLES",
            "SHOW VARIABLES LIKE 'log_bin'",
            "DESCRIBE users",
            "DESC users",
            "EXPLAIN SELECT * FROM t",
        ] {
            assert_eq!(classify_statement(s), StatementKind::ReadOnly, "{s}");
        }
    }

    #[test]
    fn explain_into_is_mutating() {
        assert_eq!(
            classify_statement("EXPLAIN SELECT * INTO snap FROM t"),
            StatementKind::Mutating
        );
    }

    #[test]
    fn mutations_are_mutating() {
        for s in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x = 1",
            "DELETE FROM t",
            "CREATE TABLE t (id INT)",
            "DROP TABLE t",
            "ALTER TABLE t ADD COLUMN x INT",
            "TRUNCATE t",
            "GRANT SELECT ON t TO alice",
            "REVOKE SELECT ON t FROM alice",
            "COPY t FROM '/tmp/data.csv'",
            "CALL my_proc(1)",
            "MERGE INTO t USING s ON t.id = s.id",
            "REPLACE INTO t VALUES (1)",
        ] {
            assert_eq!(classify_statement(s), StatementKind::Mutating, "{s}");
        }
    }

    #[test]
    fn transaction_control_is_mutating() {
        for s in [
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "SAVEPOINT sp1",
            "RELEASE sp1",
        ] {
            assert_eq!(classify_statement(s), StatementKind::Mutating, "{s}");
        }
    }

    #[test]
    fn leading_comments_are_stripped() {
        let s = "-- comment\n\nSELECT 1";
        assert_eq!(classify_statement(s), StatementKind::ReadOnly);
        let s = "/* block */ INSERT INTO t VALUES (1)";
        assert_eq!(classify_statement(s), StatementKind::Mutating);
        let s = "-- one\n-- two\n/* three */ DELETE FROM t";
        assert_eq!(classify_statement(s), StatementKind::Mutating);
    }

    #[test]
    fn with_cte_classified_by_body() {
        assert_eq!(
            classify_statement("WITH cte AS (SELECT 1) SELECT * FROM cte"),
            StatementKind::ReadOnly
        );
        assert_eq!(
            classify_statement("WITH cte AS (SELECT * FROM old) INSERT INTO new SELECT * FROM cte"),
            StatementKind::Mutating
        );
        assert_eq!(
            classify_statement("WITH RECURSIVE cte AS (SELECT 1) UPDATE t SET x = 1 FROM cte"),
            StatementKind::Mutating
        );
    }

    #[test]
    fn empty_and_only_comments_are_unknown() {
        assert_eq!(classify_statement(""), StatementKind::Unknown);
        assert_eq!(
            classify_statement("-- only a comment"),
            StatementKind::Unknown
        );
        assert_eq!(
            classify_statement("/* only block */"),
            StatementKind::Unknown
        );
    }

    #[test]
    fn is_mutating_counts_unknown_as_mutating() {
        // Conservative — better to over-record than miss a real mutation.
        assert!(StatementKind::Unknown.is_mutating());
        assert!(StatementKind::Mutating.is_mutating());
        assert!(!StatementKind::ReadOnly.is_mutating());
    }

    #[test]
    fn split_on_semicolon() {
        let stmts = split_statements("SELECT 1; INSERT INTO t VALUES (1); SELECT 2");
        assert_eq!(stmts.len(), 3);
        assert_eq!(stmts[0], "SELECT 1");
        assert_eq!(stmts[1], "INSERT INTO t VALUES (1)");
        assert_eq!(stmts[2], "SELECT 2");
    }

    #[test]
    fn split_honors_single_quoted_literal() {
        let stmts = split_statements("INSERT INTO t VALUES ('a;b;c'); SELECT 1");
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0], "INSERT INTO t VALUES ('a;b;c')");
        assert_eq!(stmts[1], "SELECT 1");
    }

    #[test]
    fn split_honors_double_quoted_identifier() {
        let stmts = split_statements(r#"SELECT "col;weird" FROM t; SELECT 1"#);
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn split_honors_escaped_quote_in_literal() {
        let stmts = split_statements("INSERT INTO t VALUES ('it''s ok'); SELECT 1");
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0], "INSERT INTO t VALUES ('it''s ok')");
    }

    #[test]
    fn split_honors_line_comment() {
        let stmts = split_statements("SELECT 1 -- ;not a delim\n; SELECT 2");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("not a delim"));
    }

    #[test]
    fn split_honors_block_comment() {
        let stmts = split_statements("SELECT 1 /* ;not a delim; */ ; SELECT 2");
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn split_drops_trailing_empty_statement() {
        let stmts = split_statements("SELECT 1;");
        assert_eq!(stmts, vec!["SELECT 1".to_string()]);
        let stmts = split_statements("SELECT 1;;;");
        assert_eq!(stmts, vec!["SELECT 1".to_string()]);
    }

    #[test]
    fn classifier_handles_lower_and_mixed_case() {
        assert_eq!(
            classify_statement("insert into t values (1)"),
            StatementKind::Mutating
        );
        assert_eq!(
            classify_statement("Update t SET x = 1"),
            StatementKind::Mutating
        );
        assert_eq!(classify_statement("select 1"), StatementKind::ReadOnly);
    }

    #[test]
    fn split_honors_dollar_quote_no_tag() {
        let stmts = split_statements("DO $$ BEGIN RAISE NOTICE 'a;b'; END; $$; SELECT 1");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("BEGIN RAISE"));
        assert!(stmts[0].contains("END;"));
        assert_eq!(stmts[1], "SELECT 1");
    }

    #[test]
    fn split_honors_dollar_quote_with_tag() {
        let stmts = split_statements(
            "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $body$ BEGIN \
             RAISE NOTICE 'x;y'; SELECT 1; END $body$; SELECT 2",
        );
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("$body$"));
        assert!(stmts[0].contains("SELECT 1"));
        assert_eq!(stmts[1], "SELECT 2");
    }

    #[test]
    fn split_does_not_match_wrong_tag() {
        // $foo$ ... $bar$ — the $bar$ does NOT close the $foo$ block.
        // The whole thing stays one (malformed) statement.
        let stmts = split_statements("SELECT $foo$ inner;text $bar$ junk $foo$; SELECT 2");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("$foo$"));
        assert!(stmts[0].contains("$bar$"));
        assert_eq!(stmts[1], "SELECT 2");
    }

    #[test]
    fn split_treats_dollar_bindparam_as_plain() {
        // `$1`, `$2` are bind parameters in psql, not dollar quotes.
        // They must not start a quote block.
        let stmts = split_statements("SELECT $1; INSERT INTO t VALUES ($2)");
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[0], "SELECT $1");
        assert_eq!(stmts[1], "INSERT INTO t VALUES ($2)");
    }

    #[test]
    fn split_treats_isolated_dollar_as_plain() {
        // A bare `$` followed by whitespace / EOF / non-tag char is
        // just a dollar sign.
        let stmts = split_statements("SELECT '$amount'; SELECT $");
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].contains("$amount"));
    }

    #[test]
    fn split_handles_nested_quotes_inside_dollar_block() {
        let stmts = split_statements(
            "DO $$ BEGIN PERFORM 'it''s; ok'; PERFORM \"col;name\"; END $$; SELECT 1",
        );
        assert_eq!(stmts.len(), 2);
        assert_eq!(stmts[1], "SELECT 1");
    }

    #[test]
    fn split_handles_two_dollar_blocks_in_one_script() {
        let stmts = split_statements("DO $$ a; $$; DO $tag$ b; $tag$; SELECT 1");
        assert_eq!(stmts.len(), 3);
        assert!(stmts[0].contains("$$"));
        assert!(stmts[1].contains("$tag$"));
        assert_eq!(stmts[2], "SELECT 1");
    }
}
