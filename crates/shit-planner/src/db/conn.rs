// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database CLI connection-string parsing (S19.2).
//!
//! Three engines, three argv shapes:
//!
//! | Engine    | Forms accepted                                        |
//! |-----------|-------------------------------------------------------|
//! | `psql`    | `postgres://user:pass@host:port/db?sslmode=...`       |
//! |           | `postgresql://...` (same scheme alias)                |
//! |           | libpq key-value: `host=db.example.com password=...`   |
//! |           | positional: `psql [options] DBNAME [USERNAME]`        |
//! | `mysql`   | `mysql://user:pass@host:port/db`                      |
//! |           | flags: `-h host -P port -u user -p[pass] DBNAME`      |
//! | `sqlite3` | `sqlite3 [options] PATH [STATEMENT...]`               |
//!
//! Passwords are **stripped at parse time**; the returned [`ConnInfo`]
//! never carries them. The capture pipeline only learns that a
//! password was present (via [`ConnInfo::password_present`]).
//!
//! We deliberately do *not* use a third-party connection-string crate
//! here — `libpq`'s own parser has corners we'd reproduce anyway,
//! and the dep blast radius isn't worth it for the subset we care
//! about (which is "extract enough to render in `shit show`").

use shit_proto::DbConnInfo;

#[derive(Debug, thiserror::Error)]
pub enum ConnParseError {
    #[error("empty argv")]
    EmptyArgv,
    #[error("invalid URI: {0}")]
    InvalidUri(String),
    #[error("unknown engine flag: {0}")]
    UnknownFlag(String),
    #[error("missing DBNAME for {0}")]
    MissingTarget(&'static str),
}

/// What we recover from a DB-CLI argv. The proto wire type
/// [`DbConnInfo`] is the same shape sans `password_present`; this
/// type exists so the planner can carry the boolean without bloating
/// the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnInfo {
    pub host: String,
    pub port: Option<u16>,
    pub user: String,
    pub target: String,
    pub password_present: bool,
}

impl ConnInfo {
    /// Convert to the wire-side info. The wire form deliberately
    /// drops `password_present` because the daemon doesn't need it
    /// — the redacted statement renderer does, and that's planner-side.
    pub fn to_wire(&self) -> DbConnInfo {
        DbConnInfo {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            target: self.target.clone(),
        }
    }
}

/// Parse a `psql ...` argv (after the `psql` token).
///
/// Returns whatever target info we can recover. Best-effort — if the
/// user typed `psql -h x` with no DBNAME, `target` is empty.
pub fn parse_psql_argv(args: &[String]) -> Result<ConnInfo, ConnParseError> {
    if args.is_empty() {
        return Err(ConnParseError::EmptyArgv);
    }
    let mut info = ConnInfo {
        host: String::new(),
        port: None,
        user: String::new(),
        target: String::new(),
        password_present: false,
    };

    // First pass: a URI argument outranks flags. `psql postgres://...`
    // is the canonical modern form.
    for a in args {
        if a.starts_with("postgres://") || a.starts_with("postgresql://") {
            parse_pg_uri(a, &mut info)?;
            return Ok(info);
        }
        if is_libpq_kv(a) {
            parse_libpq_kv(a, &mut info)?;
            return Ok(info);
        }
    }

    // Second pass: flag-driven. Accept the short and long forms psql
    // documents (-h/--host, -p/--port, -U/--username, -d/--dbname,
    // -W asks for password interactively, -w refuses; both mean
    // "password is present in the connection metadata even if we
    // don't see it").
    let mut iter = args.iter().peekable();
    let mut positional: Vec<String> = Vec::new();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-h" | "--host" => info.host = take_value(&mut iter, a)?,
            "-p" | "--port" => {
                let v = take_value(&mut iter, a)?;
                info.port = v.parse().ok();
            }
            "-U" | "--username" => info.user = take_value(&mut iter, a)?,
            "-d" | "--dbname" => info.target = take_value(&mut iter, a)?,
            "-W" | "--password" | "-w" | "--no-password" => info.password_present = true,
            // `--host=x` and `--port=5432` long-eq forms.
            x if x.starts_with("--host=") => info.host = x[7..].to_string(),
            x if x.starts_with("--port=") => info.port = x[7..].parse().ok(),
            x if x.starts_with("--username=") => info.user = x[11..].to_string(),
            x if x.starts_with("--dbname=") => info.target = x[9..].to_string(),
            // Everything else: skip unless it looks like a positional
            // (no leading dash + we haven't recorded DBNAME yet).
            x if !x.starts_with('-') => positional.push(x.to_string()),
            _ => {}
        }
    }
    // Positional fallthrough: psql DBNAME [USERNAME]
    if info.target.is_empty() && !positional.is_empty() {
        info.target = positional.remove(0);
    }
    if info.user.is_empty() && !positional.is_empty() {
        info.user = positional.remove(0);
    }
    Ok(info)
}

/// Parse a `mysql ...` argv (after the `mysql` token).
pub fn parse_mysql_argv(args: &[String]) -> Result<ConnInfo, ConnParseError> {
    if args.is_empty() {
        return Err(ConnParseError::EmptyArgv);
    }
    let mut info = ConnInfo {
        host: String::new(),
        port: None,
        user: String::new(),
        target: String::new(),
        password_present: false,
    };

    for a in args {
        if a.starts_with("mysql://") || a.starts_with("mariadb://") {
            parse_mysql_uri(a, &mut info)?;
            return Ok(info);
        }
    }

    let mut iter = args.iter().peekable();
    let mut positional: Vec<String> = Vec::new();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-h" | "--host" => info.host = take_value(&mut iter, a)?,
            "-P" | "--port" => {
                let v = take_value(&mut iter, a)?;
                info.port = v.parse().ok();
            }
            "-u" | "--user" => info.user = take_value(&mut iter, a)?,
            "-D" | "--database" => info.target = take_value(&mut iter, a)?,
            // -p is a special case: `-p<pass>` (no space) or `-p` (prompt).
            x if x == "-p" || x == "--password" => info.password_present = true,
            x if x.starts_with("-p") => info.password_present = true,
            x if x.starts_with("--password=") => info.password_present = true,
            x if x.starts_with("--host=") => info.host = x[7..].to_string(),
            x if x.starts_with("--port=") => info.port = x[7..].parse().ok(),
            x if x.starts_with("--user=") => info.user = x[7..].to_string(),
            x if x.starts_with("--database=") => info.target = x[11..].to_string(),
            x if !x.starts_with('-') => positional.push(x.to_string()),
            _ => {}
        }
    }
    if info.target.is_empty() && !positional.is_empty() {
        info.target = positional.remove(0);
    }
    Ok(info)
}

/// Parse a `sqlite3 ...` argv (after the `sqlite3` token).
///
/// First non-flag positional is the database file path.
pub fn parse_sqlite3_argv(args: &[String]) -> Result<ConnInfo, ConnParseError> {
    if args.is_empty() {
        return Err(ConnParseError::EmptyArgv);
    }
    let mut info = ConnInfo {
        host: String::new(),
        port: None,
        user: String::new(),
        target: String::new(),
        password_present: false,
    };
    // sqlite3's options are all `-flag`/`-flag value`. We scan once
    // and pick the first non-`-` token as the DB path.
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        if a.starts_with('-') {
            // The following sqlite3 flags consume a value:
            // -cmd CMD, -init FILE, -lookaside SIZE N, -mmap SIZE,
            // -newline SEP, -nullvalue STR, -pagecache SIZE N,
            // -separator SEP, -stats N, -table N
            match a.as_str() {
                "-cmd" | "--cmd" | "-init" | "--init" | "-mmap" | "-newline" | "-nullvalue"
                | "-separator" => {
                    iter.next();
                }
                "-lookaside" | "-pagecache" => {
                    iter.next();
                    iter.next();
                }
                _ => {}
            }
            continue;
        }
        // First positional is the DB path.
        info.target = a.to_string();
        break;
    }
    Ok(info)
}

fn parse_pg_uri(uri: &str, out: &mut ConnInfo) -> Result<(), ConnParseError> {
    let scheme_end = uri
        .find("://")
        .ok_or_else(|| ConnParseError::InvalidUri(format!("missing scheme separator in {uri}")))?;
    let after = &uri[scheme_end + 3..];
    // Split path (db) and query.
    let (authority_and_path, _query) = match after.find('?') {
        Some(q) => (&after[..q], Some(&after[q + 1..])),
        None => (after, None),
    };
    let (authority, path) = match authority_and_path.find('/') {
        Some(s) => (&authority_and_path[..s], Some(&authority_and_path[s + 1..])),
        None => (authority_and_path, None),
    };
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    if let Some(ui) = userinfo {
        if let Some(colon) = ui.find(':') {
            out.user = ui[..colon].to_string();
            out.password_present = !ui[colon + 1..].is_empty();
        } else {
            out.user = ui.to_string();
        }
    }
    if let Some(colon) = hostport.rfind(':') {
        // Could be a `host:port` or an IPv6 literal `[::1]:5432`. Reject
        // the trivial port-parse path for bracketed forms.
        if !hostport.starts_with('[') {
            out.host = hostport[..colon].to_string();
            out.port = hostport[colon + 1..].parse().ok();
        } else {
            out.host = hostport.to_string();
        }
    } else {
        out.host = hostport.to_string();
    }
    if let Some(p) = path {
        out.target = p.to_string();
    }
    Ok(())
}

fn parse_mysql_uri(uri: &str, out: &mut ConnInfo) -> Result<(), ConnParseError> {
    // Same shape as the postgres URI; reuse.
    parse_pg_uri(uri, out)
}

/// libpq key-value strings look like `host=x port=5432 user=y password=...`.
/// We accept this form as a single argv token; psql also accepts it
/// split across multiple tokens. Detected via "looks like `k=v`".
fn is_libpq_kv(s: &str) -> bool {
    s.contains('=') && !s.starts_with('-') && !s.contains("://")
}

fn parse_libpq_kv(s: &str, out: &mut ConnInfo) -> Result<(), ConnParseError> {
    for pair in s.split_whitespace() {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        match k {
            "host" | "hostaddr" => out.host = v.to_string(),
            "port" => out.port = v.parse().ok(),
            "user" => out.user = v.to_string(),
            "dbname" | "database" => out.target = v.to_string(),
            "password" => out.password_present = !v.is_empty(),
            _ => {}
        }
    }
    Ok(())
}

fn take_value(
    iter: &mut std::iter::Peekable<std::slice::Iter<String>>,
    flag: &str,
) -> Result<String, ConnParseError> {
    iter.next()
        .map(String::from)
        .ok_or_else(|| ConnParseError::UnknownFlag(format!("{flag} missing value")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn psql_uri_parses_host_user_db() {
        let info =
            parse_psql_argv(&v(&["postgres://alice:secret@db.example.com:5432/prod"])).unwrap();
        assert_eq!(info.host, "db.example.com");
        assert_eq!(info.port, Some(5432));
        assert_eq!(info.user, "alice");
        assert_eq!(info.target, "prod");
        assert!(info.password_present);
    }

    #[test]
    fn psql_uri_password_stripped() {
        let info = parse_psql_argv(&v(&["postgres://alice:hunter2@host/prod"])).unwrap();
        assert!(info.password_present);
        // Sanity: no field carries the password.
        assert!(!info.host.contains("hunter2"));
        assert!(!info.user.contains("hunter2"));
        assert!(!info.target.contains("hunter2"));
        // The Debug impl also should not leak it.
        assert!(!format!("{info:?}").contains("hunter2"));
    }

    #[test]
    fn psql_postgresql_scheme_alias() {
        let info = parse_psql_argv(&v(&["postgresql://alice@host/db"])).unwrap();
        assert_eq!(info.user, "alice");
        assert_eq!(info.target, "db");
        assert!(!info.password_present);
    }

    #[test]
    fn psql_flag_form() {
        let info = parse_psql_argv(&v(&[
            "-h",
            "db.example.com",
            "-p",
            "5432",
            "-U",
            "alice",
            "-d",
            "prod",
        ]))
        .unwrap();
        assert_eq!(info.host, "db.example.com");
        assert_eq!(info.port, Some(5432));
        assert_eq!(info.user, "alice");
        assert_eq!(info.target, "prod");
    }

    #[test]
    fn psql_long_eq_form() {
        let info = parse_psql_argv(&v(&[
            "--host=db.example.com",
            "--port=5432",
            "--username=alice",
            "--dbname=prod",
        ]))
        .unwrap();
        assert_eq!(info.host, "db.example.com");
        assert_eq!(info.port, Some(5432));
        assert_eq!(info.user, "alice");
        assert_eq!(info.target, "prod");
    }

    #[test]
    fn psql_libpq_kv_form() {
        let info = parse_psql_argv(&v(&[
            "host=db.example.com port=5432 user=alice dbname=prod password=hunter2",
        ]))
        .unwrap();
        assert_eq!(info.host, "db.example.com");
        assert_eq!(info.port, Some(5432));
        assert_eq!(info.user, "alice");
        assert_eq!(info.target, "prod");
        assert!(info.password_present);
    }

    #[test]
    fn psql_positional_dbname() {
        let info = parse_psql_argv(&v(&["mydb"])).unwrap();
        assert_eq!(info.target, "mydb");
    }

    #[test]
    fn psql_positional_dbname_and_username() {
        let info = parse_psql_argv(&v(&["mydb", "alice"])).unwrap();
        assert_eq!(info.target, "mydb");
        assert_eq!(info.user, "alice");
    }

    #[test]
    fn psql_password_present_via_minus_w_flag() {
        let info = parse_psql_argv(&v(&["-h", "x", "-W"])).unwrap();
        assert!(info.password_present);
    }

    #[test]
    fn psql_empty_argv_errors() {
        let err = parse_psql_argv(&[]).unwrap_err();
        assert!(matches!(err, ConnParseError::EmptyArgv));
    }

    #[test]
    fn mysql_uri_parses() {
        let info = parse_mysql_argv(&v(&["mysql://alice:secret@db:3306/prod"])).unwrap();
        assert_eq!(info.host, "db");
        assert_eq!(info.port, Some(3306));
        assert_eq!(info.user, "alice");
        assert_eq!(info.target, "prod");
        assert!(info.password_present);
    }

    #[test]
    fn mysql_flag_form_with_glued_password() {
        // `mysql -psecret -ualice -hdb prod` — `-p<pass>` glued, but
        // also `-u` and `-h` may be glued. We only handle the
        // documented split form here. The glued forms are caller's
        // responsibility (the wrapper should send normalized argv).
        // Verify the canonical form works:
        let info =
            parse_mysql_argv(&v(&["-h", "db", "-P", "3306", "-u", "alice", "-p", "prod"])).unwrap();
        assert_eq!(info.host, "db");
        assert_eq!(info.port, Some(3306));
        assert_eq!(info.user, "alice");
        assert_eq!(info.target, "prod");
        assert!(info.password_present);
    }

    #[test]
    fn mysql_minus_p_glued_password_is_present_without_leaking() {
        // `-phunter2` should mark password_present without recording
        // the password.
        let info = parse_mysql_argv(&v(&["-h", "db", "-uroot", "-phunter2", "prod"])).unwrap();
        assert!(info.password_present);
        assert!(!format!("{info:?}").contains("hunter2"));
    }

    #[test]
    fn sqlite3_path_is_target() {
        let info = parse_sqlite3_argv(&v(&["/tmp/test.db"])).unwrap();
        assert_eq!(info.target, "/tmp/test.db");
    }

    #[test]
    fn sqlite3_consumes_dash_init_value() {
        let info = parse_sqlite3_argv(&v(&["-init", "/etc/init.sql", "/tmp/test.db"])).unwrap();
        assert_eq!(info.target, "/tmp/test.db");
    }

    #[test]
    fn sqlite3_consumes_dash_lookaside_two_values() {
        let info = parse_sqlite3_argv(&v(&["-lookaside", "1024", "500", "/tmp/test.db"])).unwrap();
        assert_eq!(info.target, "/tmp/test.db");
    }

    #[test]
    fn sqlite3_empty_argv_errors() {
        let err = parse_sqlite3_argv(&[]).unwrap_err();
        assert!(matches!(err, ConnParseError::EmptyArgv));
    }

    #[test]
    fn to_wire_drops_password_present() {
        let info = parse_psql_argv(&v(&["postgres://alice:hunter2@db/prod"])).unwrap();
        let wire = info.to_wire();
        assert_eq!(wire.host, "db");
        assert_eq!(wire.user, "alice");
        assert_eq!(wire.target, "prod");
        // Wire form deliberately drops password_present (which the
        // executor reads from the planner-side ConnInfo, not the wire).
    }
}
