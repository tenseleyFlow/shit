// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pager wiring. `shit list` and `shit show` over N rows pipe through
//! `$PAGER` when stdout is a TTY.
//!
//! Stage-1 contract:
//! - **Only page when stdout is a TTY.** Piping into `cat` or `jq`
//!   shows the raw content; piping into the user's terminal pages.
//! - **Honor `$PAGER`.** Falls back to `less -R` (the `-R` lets ANSI
//!   colors through). If neither is available, write straight to
//!   stdout — no pager is better than a broken one.
//! - **Never page in `--json` mode.** Machine-parseable output stays
//!   single-shot.

use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

/// Display `content` either through `$PAGER` (when appropriate) or
/// straight to stdout.
///
/// `over_threshold` controls whether to page at all: callers typically
/// pass `body.lines().count() > 24` so short output skips the pager.
pub fn page_if_tty(content: &str, over_threshold: bool) -> std::io::Result<()> {
    if !over_threshold || !std::io::stdout().is_terminal() {
        std::io::stdout().write_all(content.as_bytes())?;
        return Ok(());
    }
    let pager_env = std::env::var("PAGER").ok();
    let (cmd, args): (String, Vec<String>) = match pager_env.as_deref() {
        Some("") | None => ("less".into(), vec!["-R".into()]),
        Some(s) => {
            // Allow `$PAGER` to carry args, like `less -FRX`. Split on
            // whitespace — simple and matches user expectation.
            let mut parts = s.split_whitespace();
            let head = parts.next().unwrap_or("less").to_string();
            let rest: Vec<String> = parts.map(|s| s.to_string()).collect();
            (head, rest)
        }
    };
    let mut child = match Command::new(&cmd).args(&args).stdin(Stdio::piped()).spawn() {
        Ok(c) => c,
        Err(_) => {
            // Pager spawn failed (binary not found, no exec perm, etc).
            // Fall back to plain stdout — better than dropping output.
            std::io::stdout().write_all(content.as_bytes())?;
            return Ok(());
        }
    };
    if let Some(stdin) = child.stdin.as_mut() {
        // Pager may quit early (user pressed q); ignore EPIPE.
        if let Err(e) = stdin.write_all(content.as_bytes()) {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                return Err(e);
            }
        }
    }
    let _ = child.wait();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In tests stdout isn't a TTY, so page_if_tty always falls back to
    /// plain stdout. We can't easily mock IsTerminal without an extra
    /// crate; this test just asserts the no-tty path doesn't error.
    #[test]
    fn no_tty_writes_directly() {
        // Cargo redirects stdout for tests, so the IsTerminal path is
        // false. The call should succeed.
        page_if_tty("hello\n", true).expect("page_if_tty");
    }

    #[test]
    fn below_threshold_writes_directly() {
        page_if_tty("short\n", false).expect("page_if_tty");
    }
}
