// SPDX-License-Identifier: AGPL-3.0-or-later

//! AR07.1 — refuse-list catalog.
//!
//! Maps a user's command line to a structured refusal when the
//! command class is fundamentally out-of-scope for `shit undo`.
//! Matched at plan-build time BEFORE per-event analysis runs, so the
//! plan contains a single `InverseOp::Refuse` node carrying the
//! user-facing reason + remediation, instead of a partial inverse
//! that pretends to do the right thing.
//!
//! ## What goes here
//!
//! Each entry encodes one command class. Initial catalog (AR07.1):
//!
//! - **remote-push** — `git push`, `docker push`, `npm publish`,
//!   `gh release upload` — we never observe the remote receiver.
//! - **history-rewrite** — `git rebase -i`, `git filter-branch`,
//!   `git commit --amend` (when push'd) — undo is reflog-driven by
//!   the user.
//! - **identity-generation** — `gpg --gen-key`, `ssh-keygen` — the
//!   key material is in the world; deleting the file doesn't
//!   un-distribute it.
//! - **power-state** — `shutdown`, `reboot`, `halt` — no inverse.
//! - **sandbox-escape** — `chroot`, `unshare` — semantics-wise the
//!   commands BEHIND the wall are what we'd need to undo, not the
//!   wall itself. Refuse instead of risk.
//! - **opaque-shell-mutation** — `source script.sh`, `. script.sh` —
//!   sourcing a script mutates the parent shell in arbitrary ways
//!   we don't introspect.
//! - **system-identity** — `useradd`, `userdel`, `groupadd`,
//!   `passwd` — PAM and shadow-file touching; reversal needs root
//!   semantics we don't trust ourselves with.
//!
//! ## Matching strategy
//!
//! Patterns match against the command's `cmd_string`. The match
//! shape is intentionally conservative: prefix-or-substring with
//! word-boundary checks, NOT a full shell parser. False positives
//! are worse than false negatives — a wrongly-refused command
//! denies the user undo; a missed refusal "just" produces the
//! same partial-undo behavior we have today (no regression).
//!
//! ## Adding entries
//!
//! New entries land here as `RefuseEntry` const-style values in
//! `CATALOG`. Each entry needs:
//!   - `class`: short identifier (kebab-case) for AR07.3 doctor
//!     surface + AR07.4 dry-run rendering.
//!   - `patterns`: one or more match patterns.
//!   - `reason`: one-line user-facing rationale.
//!   - `remediation`: optional next-best-step pointer.

/// A refusal entry — one command class shit explicitly will not undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefuseEntry {
    /// Stable kebab-case identifier. AR07.3 doctor surface keys on
    /// this; downstream tooling (CI gates, dashboards) may filter
    /// by class.
    pub class: &'static str,
    pub patterns: &'static [RefusePattern],
    pub reason: &'static str,
    pub remediation: Option<&'static str>,
}

/// One match pattern. Today only `WordPrefix` is implemented —
/// matches when the command's argv[0..n] equals `words`. The
/// extension surface stays open for argv-substring or regex if a
/// future entry needs it; keeping the enum narrow today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusePattern {
    /// Match commands whose tokenized argv starts with these words.
    /// Example: `&["git", "push"]` matches `git push origin main`
    /// AND `git push --force`.
    WordPrefix(&'static [&'static str]),
}

/// AR07.1 catalog. Order is documentation-only — `match_command`
/// returns the FIRST matching entry, so more specific patterns
/// should come before more general ones.
pub static CATALOG: &[RefuseEntry] = &[
    RefuseEntry {
        class: "remote-push",
        patterns: &[
            RefusePattern::WordPrefix(&["git", "push"]),
            RefusePattern::WordPrefix(&["docker", "push"]),
            RefusePattern::WordPrefix(&["podman", "push"]),
            RefusePattern::WordPrefix(&["npm", "publish"]),
            RefusePattern::WordPrefix(&["cargo", "publish"]),
            RefusePattern::WordPrefix(&["gh", "release", "upload"]),
        ],
        reason: "remote replication is outside our visibility; \
                 we capture only local-side state",
        remediation: Some(
            "revert the local working tree if needed; \
             the remote side is yours to roll back manually",
        ),
    },
    RefuseEntry {
        class: "history-rewrite",
        patterns: &[
            RefusePattern::WordPrefix(&["git", "rebase", "-i"]),
            RefusePattern::WordPrefix(&["git", "rebase", "--interactive"]),
            RefusePattern::WordPrefix(&["git", "filter-branch"]),
            RefusePattern::WordPrefix(&["git", "filter-repo"]),
        ],
        reason: "history-rewriting commands change ref topology in \
                 ways our event journal cannot mechanically reverse",
        remediation: Some(
            "git reflog (e.g. `git reset --hard HEAD@{1}`) is the \
             standard recovery path",
        ),
    },
    RefuseEntry {
        class: "identity-generation",
        patterns: &[
            RefusePattern::WordPrefix(&["gpg", "--gen-key"]),
            RefusePattern::WordPrefix(&["gpg", "--full-gen-key"]),
            RefusePattern::WordPrefix(&["gpg", "--full-generate-key"]),
            RefusePattern::WordPrefix(&["ssh-keygen"]),
        ],
        reason: "key material may already be distributed; deleting \
                 the file alone cannot un-publish a public key",
        remediation: Some(
            "delete the key file manually if you are sure it was \
             never shared; otherwise rotate / revoke through your \
             usual channel",
        ),
    },
    RefuseEntry {
        class: "power-state",
        patterns: &[
            RefusePattern::WordPrefix(&["shutdown"]),
            RefusePattern::WordPrefix(&["reboot"]),
            RefusePattern::WordPrefix(&["halt"]),
            RefusePattern::WordPrefix(&["poweroff"]),
        ],
        reason: "power-state changes have no inverse operation",
        remediation: None,
    },
    RefuseEntry {
        class: "sandbox-escape",
        patterns: &[
            RefusePattern::WordPrefix(&["chroot"]),
            RefusePattern::WordPrefix(&["unshare"]),
            RefusePattern::WordPrefix(&["nsenter"]),
        ],
        reason: "namespace / chroot transitions move execution into \
                 a context our capture tier can no longer observe",
        remediation: Some(
            "interactive transitions are reversible by exiting the \
             namespace shell; persistent ones (e.g. systemd-nspawn) \
             are out of v1 scope",
        ),
    },
    RefuseEntry {
        class: "opaque-shell-mutation",
        patterns: &[
            RefusePattern::WordPrefix(&["source"]),
            RefusePattern::WordPrefix(&["."]),
        ],
        reason: "sourcing a script mutates the parent shell in \
                 arbitrary ways our capture tier does not introspect",
        remediation: Some(
            "if the sourced script defines env vars / aliases / \
             functions, the AR06 shell-state diff (when complete) \
             will reverse them; today it does not",
        ),
    },
    RefuseEntry {
        class: "system-identity",
        patterns: &[
            RefusePattern::WordPrefix(&["useradd"]),
            RefusePattern::WordPrefix(&["userdel"]),
            RefusePattern::WordPrefix(&["usermod"]),
            RefusePattern::WordPrefix(&["groupadd"]),
            RefusePattern::WordPrefix(&["groupdel"]),
            RefusePattern::WordPrefix(&["passwd"]),
        ],
        reason: "PAM / shadow-file mutations touch system identity \
                 state we do not trust ourselves to roll back without \
                 explicit per-OS policy",
        remediation: Some(
            "use the matching inverse command directly (e.g. \
             `userdel`) once you've confirmed no side-effects (home \
             directory, sudoers entries, group memberships) need \
             special handling",
        ),
    },
];

/// Tokenize a shell command line for pattern matching. Whitespace-
/// split is deliberately the dumbest possible thing: a refuse
/// catalog match shouldn't depend on shell-quote nuance. Patterns
/// match against tokenized words, not the raw string, so
/// `git push --force` and `git   push` both match the
/// `[git, push]` prefix.
fn tokenize(cmd_string: &str) -> Vec<&str> {
    cmd_string.split_whitespace().collect()
}

/// Match a command string against the catalog. Returns the FIRST
/// matching entry's `(class, reason, remediation)`. `None` means
/// the command isn't refused.
pub fn match_command(cmd_string: &str) -> Option<&'static RefuseEntry> {
    let tokens = tokenize(cmd_string);
    if tokens.is_empty() {
        return None;
    }
    for entry in CATALOG {
        for pat in entry.patterns {
            if pattern_matches(pat, &tokens) {
                return Some(entry);
            }
        }
    }
    None
}

fn pattern_matches(pat: &RefusePattern, tokens: &[&str]) -> bool {
    match pat {
        RefusePattern::WordPrefix(words) => {
            if words.len() > tokens.len() {
                return false;
            }
            tokens.iter().zip(words.iter()).all(|(t, w)| t == w)
        }
    }
}

/// Stable identifiers of every class in the catalog. Doctor surface
/// (AR07.3) uses this to enumerate `refused_classes` without
/// duplicating the catalog.
pub fn catalog_classes() -> Vec<&'static str> {
    CATALOG.iter().map(|e| e.class).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_command_does_not_match() {
        assert!(match_command("").is_none());
        assert!(match_command("   ").is_none());
    }

    #[test]
    fn git_push_matches_remote_push() {
        let e = match_command("git push origin main").unwrap();
        assert_eq!(e.class, "remote-push");
    }

    #[test]
    fn git_push_force_matches_remote_push() {
        let e = match_command("git push --force origin main").unwrap();
        assert_eq!(e.class, "remote-push");
    }

    #[test]
    fn git_status_does_not_match() {
        assert!(match_command("git status").is_none());
    }

    #[test]
    fn git_rebase_i_matches_history_rewrite() {
        let e = match_command("git rebase -i HEAD~3").unwrap();
        assert_eq!(e.class, "history-rewrite");
    }

    #[test]
    fn git_rebase_without_interactive_does_not_match() {
        // Plain `git rebase main` is not on the refuse list (it's
        // reversible in principle via reflog; we don't refuse it
        // until the interactive flag is present).
        assert!(match_command("git rebase main").is_none());
    }

    #[test]
    fn ssh_keygen_matches_identity_generation() {
        let e = match_command("ssh-keygen -t ed25519 -f /tmp/k").unwrap();
        assert_eq!(e.class, "identity-generation");
    }

    #[test]
    fn shutdown_matches_power_state() {
        let e = match_command("shutdown -h now").unwrap();
        assert_eq!(e.class, "power-state");
    }

    #[test]
    fn dot_source_matches_opaque_shell_mutation() {
        let e = match_command(". /tmp/setup.sh").unwrap();
        assert_eq!(e.class, "opaque-shell-mutation");
    }

    #[test]
    fn source_keyword_matches_opaque_shell_mutation() {
        let e = match_command("source /tmp/setup.sh").unwrap();
        assert_eq!(e.class, "opaque-shell-mutation");
    }

    #[test]
    fn useradd_matches_system_identity() {
        let e = match_command("useradd -m alice").unwrap();
        assert_eq!(e.class, "system-identity");
    }

    #[test]
    fn extra_whitespace_does_not_break_match() {
        let e = match_command("  git   push    --force  ").unwrap();
        assert_eq!(e.class, "remote-push");
    }

    #[test]
    fn reason_and_remediation_populated() {
        let e = match_command("git push").unwrap();
        assert!(!e.reason.is_empty());
        assert!(e.remediation.is_some());
        // Power-state entries have no remediation by design (no
        // inverse exists).
        let p = match_command("reboot").unwrap();
        assert!(p.remediation.is_none());
    }

    #[test]
    fn catalog_classes_are_unique() {
        let classes = catalog_classes();
        let mut sorted = classes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            classes.len(),
            sorted.len(),
            "duplicate class identifiers in CATALOG"
        );
    }
}
