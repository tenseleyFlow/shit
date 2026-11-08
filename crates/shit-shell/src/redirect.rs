// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shell-redirect parser (C06.2).
//!
//! Walks a raw command line (the literal string the user typed, not
//! the argv-after-shell-quoting) and identifies destination paths
//! that the shell will open with `O_TRUNC` or `O_APPEND` before the
//! child process runs. The shell hook synchronously asks the daemon
//! to pre-stash each `Truncate` target's pre-state, so `shit undo`
//! can restore the original content — closing the race window where
//! the kernel-tier capture sees the open AFTER the truncate has
//! already discarded the file's bytes.
//!
//! ## What we match
//!
//! - `> file` / `>| file` / `>> file` (stdout truncate, clobber-
//!   override truncate, append).
//! - `2> file` / `2>> file` (stderr truncate / append).
//! - `&> file` / `&>> file` (bash combined-stream truncate / append).
//! - `| tee file` / `| tee -a file` / `|& tee file` (the targets
//!   passed to `tee` get truncated or appended).
//! - `dd of=file ...` (the `of=` argument; `dd` typically truncates).
//!
//! ## What we skip
//!
//! - **Process substitution** (`>(cmd)`, `<(cmd)`) — no fixed
//!   destination file.
//! - **FD duplication** (`2>&1`) — no file path involved.
//! - **Input redirects** (`< file`, `<< 'EOF'`, `<<< "string"`) — the
//!   destination isn't mutated.
//! - **Ephemeral / special paths** (`/dev/null`, `/dev/zero`,
//!   `/dev/random`, `/dev/urandom`, any `/dev/tty…`, `/proc/...`,
//!   `/sys/...`) — pre-stashing those is either pointless or
//!   actively wrong (the file is kernel-generated).
//!
//! ## Heuristic, not a full shell grammar
//!
//! The parser handles single-command lines with redirections —
//! roughly the 95% case. Compound constructs (`if cmd > f; then ...
//! fi`, `cmd > f && cmd2 > f2`, function bodies that include
//! redirects) MAY produce wrong or absent results. We default-skip
//! when ambiguous; a missed pre-stash falls back to kernel-tier
//! capture (a smaller-but-real race window), which is acceptable
//! degradation, not silent data loss.
//!
//! ## Path expansion
//!
//! The parser returns the path **as it appears in the command line**
//! — with `$VAR`, `~/`, glob characters etc. still in place. Shell-
//! native expansion happens at a different layer (the hook calls the
//! shell to expand each captured path; see `state.rs` for the
//! per-shell expansion entry points). This separation lets the
//! parser stay pure (no I/O, no shell escaping risk).

use std::collections::HashSet;

/// Which operator wrote this destination. Drives the
/// [`InverseOp`](shit_planner::InverseOp) the planner emits:
///
/// - `Truncate` / `TeeTruncate` / `DdOf` ⇒
///   `InverseOp::RestoreContent` (pre-stash captures the bytes).
/// - `Append` / `TeeAppend` ⇒ `InverseOp::FileExtend` (pre-stash
///   captures only the pre-size; reverse is a single truncate-back).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedirectOp {
    Truncate,
    Append,
    TeeTruncate,
    TeeAppend,
    DdOf,
}

/// How a token was quoted on the command line. The parser strips the
/// quote characters, so this is the only record of whether the shell
/// would expand `~`, `$VAR` and the like in the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Quote {
    /// No quote characters: tilde, parameter and glob expansion apply.
    None,
    /// Only single-quoted segments: the text is literal.
    Single,
    /// Only double-quoted segments: `$` and backticks still expand,
    /// tilde and globs do not.
    Double,
    /// Both kinds, or a quoted segment glued to an unquoted one.
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectTarget {
    pub op: RedirectOp,
    /// Path as it appears in the command line, with quote characters
    /// removed and nothing expanded.
    pub path: String,
    /// How the path token was quoted.
    pub quote: Quote,
    /// True when nothing earlier on the line can change the working
    /// directory, so a relative `path` resolves against the cwd the
    /// parser's caller sees. False after `cd`, `pushd`, `popd`, a
    /// subshell, a brace group, command substitution, `eval`, `source`
    /// and the like. Aliases and functions are invisible here.
    pub cwd_stable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedirectAnalysis {
    pub targets: Vec<RedirectTarget>,
}

impl RedirectAnalysis {
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

/// Parse `line` and return all destination paths that the shell will
/// truncate or append before the child runs. Returns an empty
/// analysis if no redirects are found (or the line is too complex to
/// parse safely).
pub fn parse_redirects(line: &str) -> RedirectAnalysis {
    let (tokens, quotes): (Vec<String>, Vec<Quote>) = tokenize(line).into_iter().unzip();
    let mut targets = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];
        // dd's `of=path` is positional (not a separate operator), so
        // catch it before the > / >> dispatch.
        if let Some(path) = tok.strip_prefix("of=") {
            if !path.is_empty() && !is_special_path(path) {
                targets.push(RedirectTarget {
                    op: RedirectOp::DdOf,
                    path: path.to_string(),
                    quote: quotes[i],
                    cwd_stable: cwd_stable(&tokens[..i], &quotes[..i]),
                });
            }
            i += 1;
            continue;
        }
        // `tee` / `tee -a` consumes path arguments until the next
        // pipe / control char. Walk forward.
        if tok == "tee" {
            let append = tokens
                .get(i + 1)
                .map(|s| s == "-a" || s == "--append")
                .unwrap_or(false);
            let path_start = if append { i + 2 } else { i + 1 };
            for (pi, p) in tokens.iter().enumerate().skip(path_start) {
                if is_pipe_or_control(p) {
                    break;
                }
                if p.starts_with('-') {
                    continue;
                }
                if is_special_path(p) {
                    continue;
                }
                targets.push(RedirectTarget {
                    op: if append {
                        RedirectOp::TeeAppend
                    } else {
                        RedirectOp::TeeTruncate
                    },
                    path: p.clone(),
                    quote: quotes[pi],
                    cwd_stable: cwd_stable(&tokens[..i], &quotes[..i]),
                });
            }
            i += 1;
            continue;
        }
        // Standard redirect operators. We accept exact-match tokens
        // only — `>file` (no space) is also legal in real shells, so
        // catch that variant too.
        if let Some((op, attached_path)) = classify_redirect_token(tok) {
            let op_idx = i;
            let mut quote = quotes[i];
            let path = if let Some(p) = attached_path {
                // `>file` glued form.
                p.to_string()
            } else {
                // Look at the next token. Skip empty tokens (defensive).
                let mut j = i + 1;
                while j < tokens.len() && tokens[j].is_empty() {
                    j += 1;
                }
                if j >= tokens.len() {
                    i += 1;
                    continue;
                }
                let p = tokens[j].clone();
                quote = quotes[j];
                i = j;
                p
            };
            if !is_special_path(&path) && !is_fd_dup_target(&path) {
                targets.push(RedirectTarget {
                    op,
                    path,
                    quote,
                    cwd_stable: cwd_stable(&tokens[..op_idx], &quotes[..op_idx]),
                });
            }
        }
        i += 1;
    }
    // Dedupe identical (op, path) pairs (a line like `>f >f` is
    // legal but only needs one pre-stash).
    let mut seen = HashSet::new();
    targets.retain(|t| seen.insert((t.op, t.path.clone(), t.quote, t.cwd_stable)));
    RedirectAnalysis { targets }
}

/// Recognise the standard redirect-operator forms.
/// Returns `Some((op, glued_path))` — `glued_path` is set when the
/// path is attached directly (`>file`), `None` when the next token is
/// the path (`> file`).
fn classify_redirect_token(tok: &str) -> Option<(RedirectOp, Option<&str>)> {
    let table: &[(&str, RedirectOp)] = &[
        // Order matters: longer prefixes first so `>>` doesn't get
        // greedily peeled to `>` with `>` as path.
        ("&>>", RedirectOp::Append),
        ("&>", RedirectOp::Truncate),
        ("2>>", RedirectOp::Append),
        ("2>", RedirectOp::Truncate),
        (">>", RedirectOp::Append),
        (">|", RedirectOp::Truncate),
        (">", RedirectOp::Truncate),
    ];
    for (lit, op) in table {
        if tok == *lit {
            return Some((*op, None));
        }
        if let Some(rest) = tok.strip_prefix(lit)
            && !rest.is_empty()
        {
            return Some((*op, Some(rest)));
        }
    }
    None
}

/// Commands that can change the shell's working directory or run code
/// the parser cannot see through. Matched only in command position.
const CWD_CHANGING_WORDS: &[&str] = &[
    "cd", "pushd", "popd", "chdir", "eval", "source", ".", "exec", "builtin", "command", "env",
    "sudo", "sh", "bash", "zsh", "fish", "dash",
];

/// True for `NAME=value`, the assignment prefix that can precede a
/// command word (`FOO=1 cd sub`).
fn is_assignment(tok: &str) -> bool {
    match tok.split_once('=') {
        Some((name, _)) => {
            let mut chars = name.chars();
            chars
                .next()
                .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
                && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
        }
        None => false,
    }
}

/// True when no command before a redirect can change the working
/// directory. Only words in command position count: the first word of
/// each simple command, after `&&`, `||`, `;`, `|`, `&` or a newline and
/// after `NAME=value` prefixes. `ls .`, `grep env f` and `echo "(x)"` are
/// stable. Subshell, brace-group and backtick characters count only when
/// they may be unquoted: in a fully quoted token they are text. A token
/// with both quoted and bare parts is treated as if they were bare.
/// Unsure is unstable.
fn cwd_stable(prefix: &[String], quotes: &[Quote]) -> bool {
    let mut command_position = true;
    for (tok, quote) in prefix.iter().zip(quotes) {
        let may_be_bare = matches!(quote, Quote::None | Quote::Mixed);
        if may_be_bare && tok.contains(['(', ')', '{', '}', '`']) {
            return false;
        }
        if *quote == Quote::None && is_pipe_or_control(tok) {
            command_position = true;
            continue;
        }
        if !command_position {
            continue;
        }
        if *quote == Quote::None && is_assignment(tok) {
            continue;
        }
        if CWD_CHANGING_WORDS.contains(&tok.as_str()) {
            return false;
        }
        command_position = false;
    }
    true
}

/// Tokenize on whitespace, respecting single and double quotes, and
/// record how each token was quoted.
/// Backslash-escapes are NOT honored — we treat them as literal
/// characters (a quoted form is the common case, and getting backslash
/// semantics right requires the full shell grammar).
fn tokenize(line: &str) -> Vec<(String, Quote)> {
    fn kind(single: bool, double: bool) -> Quote {
        match (single, double) {
            (false, false) => Quote::None,
            (true, false) => Quote::Single,
            (false, true) => Quote::Double,
            (true, true) => Quote::Mixed,
        }
    }
    let mut out: Vec<(String, Quote)> = Vec::new();
    let mut cur = String::new();
    // Segments seen in the current token: quoted-single, quoted-double,
    // and bare (unquoted characters).
    let (mut saw_single, mut saw_double, mut saw_bare) = (false, false, false);
    let mut in_single = false;
    let mut in_double = false;
    let finish = |cur: &mut String,
                  out: &mut Vec<(String, Quote)>,
                  s: &mut bool,
                  d: &mut bool,
                  b: &mut bool| {
        if !cur.is_empty() {
            let q = if *b && (*s || *d) {
                Quote::Mixed
            } else {
                kind(*s, *d)
            };
            out.push((std::mem::take(cur), q));
        }
        *s = false;
        *d = false;
        *b = false;
    };
    for c in line.chars() {
        if c == '\'' && !in_double {
            in_single = !in_single;
            saw_single = true;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            saw_double = true;
            continue;
        }
        if c == '\n' && !in_single && !in_double {
            // A newline ends a simple command like `;` does.
            finish(
                &mut cur,
                &mut out,
                &mut saw_single,
                &mut saw_double,
                &mut saw_bare,
            );
            out.push((";".to_string(), Quote::None));
            continue;
        }
        if c.is_whitespace() && !in_single && !in_double {
            finish(
                &mut cur,
                &mut out,
                &mut saw_single,
                &mut saw_double,
                &mut saw_bare,
            );
            continue;
        }
        // Pipe / semicolon / ampersand break tokens too (so `cmd|tee`
        // becomes `cmd | tee`). Same for `&&` / `||` / `;` boundaries.
        if !in_single && !in_double && matches!(c, '|' | ';' | '&') {
            finish(
                &mut cur,
                &mut out,
                &mut saw_single,
                &mut saw_double,
                &mut saw_bare,
            );
            out.push((c.to_string(), Quote::None));
            continue;
        }
        if !in_single && !in_double {
            saw_bare = true;
        }
        cur.push(c);
    }
    finish(
        &mut cur,
        &mut out,
        &mut saw_single,
        &mut saw_double,
        &mut saw_bare,
    );
    out
}

fn is_pipe_or_control(tok: &str) -> bool {
    matches!(tok, "|" | ";" | "&" | "&&" | "||")
}

/// Paths the parser must never pre-stash.
fn is_special_path(p: &str) -> bool {
    if p == "/dev/null"
        || p == "/dev/zero"
        || p == "/dev/random"
        || p == "/dev/urandom"
        || p == "/dev/stdout"
        || p == "/dev/stderr"
        || p == "/dev/stdin"
    {
        return true;
    }
    if p.starts_with("/dev/tty") || p.starts_with("/dev/pts/") {
        return true;
    }
    if p.starts_with("/proc/") || p == "/proc" {
        return true;
    }
    if p.starts_with("/sys/") || p == "/sys" {
        return true;
    }
    // Process substitution leaves `/dev/fd/N` paths floating in argv
    // sometimes. Skip them too.
    if p.starts_with("/dev/fd/") {
        return true;
    }
    false
}

/// Reject `2>&1`-style fd-dup arguments (post-tokenization the `&1`
/// substring may travel with the path).
fn is_fd_dup_target(p: &str) -> bool {
    p.starts_with('&') && p[1..].chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Vec<RedirectTarget> {
        parse_redirects(line).targets
    }

    // ----- single redirects -----

    #[test]
    fn simple_truncate() {
        let t = parse("echo foo > out.txt");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::Truncate);
        assert_eq!(t[0].path, "out.txt");
    }

    #[test]
    fn append() {
        let t = parse("echo foo >> log");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::Append);
        assert_eq!(t[0].path, "log");
    }

    #[test]
    fn clobber_override() {
        let t = parse("echo foo >| out.txt");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::Truncate);
    }

    #[test]
    fn stderr_truncate() {
        let t = parse("cmd 2> err.log");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::Truncate);
        assert_eq!(t[0].path, "err.log");
    }

    #[test]
    fn stderr_append() {
        let t = parse("cmd 2>> err.log");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::Append);
    }

    #[test]
    fn combined_truncate() {
        let t = parse("cmd &> both.log");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::Truncate);
        assert_eq!(t[0].path, "both.log");
    }

    #[test]
    fn combined_append() {
        let t = parse("cmd &>> both.log");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::Append);
    }

    // ----- glued forms -----

    #[test]
    fn glued_truncate_no_space() {
        let t = parse("echo >out.txt");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::Truncate);
        assert_eq!(t[0].path, "out.txt");
    }

    #[test]
    fn glued_append_no_space() {
        let t = parse("echo >>log.txt");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::Append);
        assert_eq!(t[0].path, "log.txt");
    }

    // ----- multiple redirects -----

    #[test]
    fn multiple_targets_on_one_command() {
        let t = parse("cmd > out 2> err");
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].path, "out");
        assert_eq!(t[1].path, "err");
    }

    #[test]
    fn duplicate_targets_dedupe() {
        let t = parse("cmd > a > a");
        assert_eq!(t.len(), 1);
    }

    // ----- tee -----

    #[test]
    fn tee_truncate() {
        let t = parse("cmd | tee log.txt");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::TeeTruncate);
        assert_eq!(t[0].path, "log.txt");
    }

    #[test]
    fn tee_append() {
        let t = parse("cmd | tee -a log.txt");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::TeeAppend);
    }

    #[test]
    fn tee_append_long_flag() {
        let t = parse("cmd | tee --append log.txt");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::TeeAppend);
    }

    #[test]
    fn tee_multiple_files() {
        let t = parse("cmd | tee one.log two.log three.log");
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn tee_combined_with_redirect() {
        let t = parse("cmd | tee a.log > b.log");
        // `tee a.log` plus a `> b.log`.
        assert!(
            t.iter()
                .any(|x| x.op == RedirectOp::TeeTruncate && x.path == "a.log")
        );
        assert!(
            t.iter()
                .any(|x| x.op == RedirectOp::Truncate && x.path == "b.log")
        );
    }

    // ----- dd -----

    #[test]
    fn dd_of_truncate() {
        let t = parse("dd if=/etc/hosts of=/tmp/x bs=1M count=1");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].op, RedirectOp::DdOf);
        assert_eq!(t[0].path, "/tmp/x");
    }

    #[test]
    fn dd_without_of_does_not_match() {
        let t = parse("dd if=/etc/hosts bs=1M");
        assert!(t.is_empty());
    }

    // ----- special paths skipped -----

    #[test]
    fn dev_null_skipped() {
        for path in ["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"] {
            let t = parse(&format!("cmd > {path}"));
            assert!(t.is_empty(), "should skip {path}");
        }
    }

    #[test]
    fn proc_and_sys_writes_skipped() {
        assert!(parse("echo 1 > /proc/sys/vm/drop_caches").is_empty());
        assert!(parse("echo a > /sys/kernel/foo").is_empty());
    }

    #[test]
    fn dev_tty_and_pts_skipped() {
        assert!(parse("echo > /dev/tty").is_empty());
        assert!(parse("echo > /dev/pts/0").is_empty());
    }

    #[test]
    fn fd_dup_not_treated_as_path() {
        // The `2>&1` form: `>` is the operator, `&1` is the fd-dup
        // payload. Must not produce a target of `&1`.
        let t = parse("cmd 2>&1");
        // We tokenize `&` as a separator, so we'd see `2>` + `&` +
        // `1`. The `&` token alone gets seen by classify_redirect_token
        // as nothing. The `2>` then looks for a next token — which is
        // `&` — which isn't an fd-dup target by itself. Need to defend:
        // the `&` token isn't an fd-dup, so we'd capture `&` as a
        // "path" which would be wrong. Assert the parser doesn't do
        // that.
        assert!(t.is_empty(), "got {t:?}");
    }

    // ----- input redirects skipped -----

    #[test]
    fn input_redirect_skipped() {
        let t = parse("cmd < input.txt");
        assert!(t.is_empty());
    }

    #[test]
    fn heredoc_does_not_create_target() {
        let t = parse("cat <<EOF");
        assert!(t.is_empty());
    }

    // ----- quoting -----

    #[test]
    fn quoted_path_preserves_value() {
        let t = parse("echo 'hi' > 'spaced name.txt'");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].path, "spaced name.txt");
    }

    #[test]
    fn double_quoted_path_preserves_value() {
        let t = parse("echo > \"out with $var.txt\"");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].path, "out with $var.txt");
    }

    // ----- empty / weird -----

    #[test]
    fn empty_line_yields_empty_analysis() {
        assert!(parse_redirects("").is_empty());
        assert!(parse_redirects("   ").is_empty());
    }

    #[test]
    fn redirect_with_no_target_silently_drops() {
        let t = parse("echo >");
        assert!(t.is_empty());
    }

    #[test]
    fn unexpanded_path_with_dollar_var_preserved_verbatim() {
        let t = parse("echo > $LOG_PATH");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].path, "$LOG_PATH");
    }

    #[test]
    fn tilde_path_preserved_verbatim() {
        let t = parse("echo > ~/log.txt");
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].path, "~/log.txt");
    }

    // ----- quoting and cwd stability -----

    fn first(line: &str) -> RedirectTarget {
        parse(line).into_iter().next().expect("one target")
    }

    #[test]
    fn quote_kinds_are_recorded() {
        assert_eq!(first("echo > ~/x").quote, Quote::None);
        assert_eq!(first("echo > '~/x'").quote, Quote::Single);
        assert_eq!(first("echo > \"$HOME/x\"").quote, Quote::Double);
        assert_eq!(first("echo > 'a'\"b\"").quote, Quote::Mixed);
        assert_eq!(first("echo > 'a'b").quote, Quote::Mixed);
        assert_eq!(first("echo > 'notes (draft).txt'").quote, Quote::Single);
        // Glued form: the operator is bare text in the same token, so the
        // kind is the conservative Mixed (no expansion either way).
        assert_eq!(first("echo >'~/x'").quote, Quote::Mixed);
    }

    #[test]
    fn cwd_stable_until_something_can_change_it() {
        assert!(first("echo x > out").cwd_stable);
        assert!(first("make 2>&1 | tee out").cwd_stable);
        for line in [
            "cd sub && echo x > out",
            "pushd sub; echo x > out",
            "popd && echo x > out",
            "(cd sub; echo x) > out",
            "{ cd sub; echo x; } > out",
            "eval 'cd sub' && echo x > out",
            "source env.sh && echo x > out",
            "cd sub && dd if=a of=out",
            "cd sub && echo x | tee out",
            "echo $(cd sub; pwd) > out",
            "FOO=1 cd sub && echo x > out",
            "A=1 B=2 pushd sub; echo x > out",
            "true\ncd sub\necho x > out",
            "false || cd sub && echo x > out",
            "echo a | cd sub; echo x > out",
        ] {
            assert!(!first(line).cwd_stable, "{line}");
        }
    }

    #[test]
    fn words_outside_command_position_and_quoted_text_stay_stable() {
        for line in [
            "ls . > out.txt",
            "grep env f > o",
            "echo cd sub > out",
            "echo \"(x)\" > f",
            "echo '{a}' > f",
            "echo '`x`' > f",
            "FOO=1 make > log",
            "ls -l | grep source > out",
        ] {
            assert!(first(line).cwd_stable, "{line}");
        }
    }
}
