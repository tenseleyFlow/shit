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
//! - **cluster-release** — `helm install`, `helm upgrade`,
//!   `helm uninstall`, `helm delete`, `helm rollback` (global flags may
//!   precede the verb) — no release state is captured. Read-only verbs
//!   (`list`, `status`, `get`, `template`, `show`) are not refused.
//! - **firewalld** — `firewall-cmd` options that change state
//!   (`--add-*`, `--remove-*`, `--reload`, ...) — zone state is not
//!   captured. Query options (`--state`, `--list-*`, `--get-*`) pass.
//!
//! Leading `sudo`/`doas` (with options) and `env`/`NAME=value` prefixes
//! are stripped before matching, for every class.
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
    /// Match when the predicate returns true for the tokenized argv
    /// (after leading `sudo` / `env` wrappers are stripped). For tools
    /// where only some subcommands or options mutate state.
    Custom(fn(&[&str]) -> bool),
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
    RefuseEntry {
        class: "cluster-release",
        patterns: &[RefusePattern::Custom(is_helm_release_change)],
        reason: "helm releases live in the cluster and shit captures no \
                 release state, so an undo would report success while \
                 changing nothing",
        remediation: Some(
            "use `helm rollback <release> <revision>` or `helm uninstall \
             <release>` once you have checked `helm history <release>`",
        ),
    },
    RefuseEntry {
        class: "firewalld",
        patterns: &[RefusePattern::Custom(is_firewall_cmd_change)],
        reason: "firewalld keeps runtime and permanent zone state that \
                 shit does not capture, so an undo would report success \
                 while changing nothing",
        remediation: Some(
            "use the matching `firewall-cmd --remove-*` option, or \
             `firewall-cmd --reload` to drop runtime-only changes",
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
    let all = tokenize(cmd_string);
    let tokens = strip_wrappers(&all);
    if tokens.is_empty() {
        return None;
    }
    for entry in CATALOG {
        for pat in entry.patterns {
            if pattern_matches(pat, tokens) {
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
        RefusePattern::Custom(f) => f(tokens),
    }
}

/// Drop leading privilege and environment wrappers so `sudo helm ...`,
/// `sudo -u root firewall-cmd ...` and `env FOO=1 git push` match the
/// same entries as the bare command. Handles `sudo`/`doas` options
/// (those taking a value are skipped with it), `env` options and bare
/// `NAME=value` assignments.
fn strip_wrappers<'a, 'b>(tokens: &'b [&'a str]) -> &'b [&'a str] {
    const SUDO_VALUE_OPTS: &[&str] = &[
        "-u",
        "-g",
        "-h",
        "-p",
        "-C",
        "-D",
        "-R",
        "-T",
        "-U",
        "--user",
        "--group",
        "--host",
        "--prompt",
        "--chdir",
        "--chroot",
        "--close-from",
        "--command-timeout",
        "--other-user",
    ];
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i];
        if t == "sudo" || t == "doas" {
            i += 1;
            while i < tokens.len() && tokens[i].starts_with('-') && tokens[i] != "--" {
                let takes = SUDO_VALUE_OPTS.contains(&tokens[i]);
                i += 1;
                if takes {
                    i += 1;
                }
            }
            if i < tokens.len() && tokens[i] == "--" {
                i += 1;
            }
        } else if t == "env" {
            i += 1;
            while i < tokens.len() && (tokens[i].starts_with('-') || is_assignment(tokens[i])) {
                i += 1;
            }
        } else if is_assignment(t) {
            i += 1;
        } else {
            break;
        }
    }
    &tokens[i.min(tokens.len())..]
}

fn is_assignment(t: &str) -> bool {
    match t.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// helm global options that take a separate value argument.
const HELM_VALUE_FLAGS: &[&str] = &[
    "-n",
    "--namespace",
    "--kube-context",
    "--kubeconfig",
    "--kube-as-user",
    "--kube-as-group",
    "--kube-apiserver",
    "--kube-token",
    "--kube-ca-file",
    "--kube-tls-server-name",
    "--registry-config",
    "--repository-cache",
    "--repository-config",
    "--burst-limit",
    "--qps",
    "--content-cache",
    "--debug-addr",
];

/// True for `helm install|upgrade|uninstall|delete|rollback`, with
/// global flags allowed before the verb.
fn is_helm_release_change(tokens: &[&str]) -> bool {
    if tokens.first() != Some(&"helm") {
        return false;
    }
    let mut i = 1;
    while i < tokens.len() {
        let t = tokens[i];
        if t.starts_with('-') {
            i += if !t.contains('=') && HELM_VALUE_FLAGS.contains(&t) {
                2
            } else {
                1
            };
            continue;
        }
        return matches!(
            t,
            "install" | "upgrade" | "uninstall" | "delete" | "rollback"
        );
    }
    false
}

/// True when a `firewall-cmd` invocation changes state. Query options
/// (`--state`, `--list-*`, `--get-*`, `--query-*`, `--info-*`) alone are
/// not refused. `--permanent` only qualifies the other options, so it
/// counts as a change only when no query option accompanies it.
fn is_firewall_cmd_change(tokens: &[&str]) -> bool {
    if tokens.first() != Some(&"firewall-cmd") {
        return false;
    }
    const CHANGE_PREFIXES: &[&str] = &[
        "--add-",
        "--remove-",
        "--set-",
        "--new-",
        "--delete-",
        "--change-",
        "--enable-",
        "--disable-",
        "--reload",
        "--complete-reload",
        "--runtime-to-permanent",
        "--panic-on",
        "--panic-off",
        "--lockdown-on",
        "--lockdown-off",
        "--load-zone-defaults",
        "--reset-to-defaults",
    ];
    const QUERY_PREFIXES: &[&str] = &[
        "--state",
        "--list-",
        "--get-",
        "--query-",
        "--info-",
        "--check-config",
        "--version",
        "--help",
        "-h",
    ];
    let args = &tokens[1..];
    let is_query = |t: &&str| QUERY_PREFIXES.iter().any(|p| t.starts_with(p));
    if args
        .iter()
        .any(|t| !is_query(t) && CHANGE_PREFIXES.iter().any(|p| t.starts_with(p)))
    {
        return true;
    }
    args.contains(&"--permanent") && !args.iter().any(is_query)
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
    fn helm_release_verbs_match_cluster_release() {
        for cmd in [
            "helm install rel ./chart",
            "helm upgrade --install rel ./chart",
            "helm uninstall rel",
            "helm delete rel",
            "helm rollback rel 1",
        ] {
            let e = match_command(cmd).unwrap_or_else(|| panic!("{cmd} not refused"));
            assert_eq!(e.class, "cluster-release", "{cmd}");
        }
    }

    #[test]
    fn helm_read_only_verbs_do_not_match() {
        assert!(match_command("helm list").is_none());
        assert!(match_command("helm status rel").is_none());
        assert!(match_command("helm template rel ./chart").is_none());
    }

    #[test]
    fn firewall_cmd_matches_firewalld() {
        let e = match_command("firewall-cmd --add-port=8080/tcp").unwrap();
        assert_eq!(e.class, "firewalld");
    }

    #[test]
    fn helm_global_flags_before_verb_match() {
        for cmd in [
            "helm -n prod upgrade rel ./chart",
            "helm --namespace prod install rel ./chart",
            "helm --kube-context=x uninstall rel",
            "sudo helm install rel ./chart",
            "sudo -u root helm rollback rel 1",
            "env KUBECONFIG=/x helm upgrade rel ./chart",
        ] {
            let e = match_command(cmd).unwrap_or_else(|| panic!("{cmd} not refused"));
            assert_eq!(e.class, "cluster-release", "{cmd}");
        }
    }

    #[test]
    fn helm_read_only_with_global_flags_do_not_match() {
        for cmd in [
            "helm -n prod list",
            "helm --namespace install status rel",
            "sudo helm get values rel",
            "helm show chart ./c",
            "helm",
        ] {
            assert!(match_command(cmd).is_none(), "{cmd}");
        }
    }

    #[test]
    fn firewall_cmd_mutating_options_match() {
        for cmd in [
            "firewall-cmd --add-port=8080/tcp",
            "sudo firewall-cmd --add-port=8080/tcp",
            "sudo -n firewall-cmd --permanent --add-service=http",
            "firewall-cmd --remove-service=ssh",
            "firewall-cmd --set-default-zone=public",
            "firewall-cmd --new-zone=x",
            "firewall-cmd --delete-zone=x",
            "firewall-cmd --reload",
            "firewall-cmd --complete-reload",
            "firewall-cmd --runtime-to-permanent",
            "firewall-cmd --panic-on",
            "firewall-cmd --lockdown-on",
            "firewall-cmd --permanent",
        ] {
            let e = match_command(cmd).unwrap_or_else(|| panic!("{cmd} not refused"));
            assert_eq!(e.class, "firewalld", "{cmd}");
        }
    }

    #[test]
    fn firewall_cmd_queries_do_not_match() {
        for cmd in [
            "firewall-cmd --state",
            "firewall-cmd --list-all",
            "sudo firewall-cmd --get-active-zones",
            "firewall-cmd --query-port=80/tcp",
            "firewall-cmd --info-zone=public",
            "firewall-cmd --permanent --list-all",
            "firewall-cmd --permanent --get-zones",
        ] {
            assert!(match_command(cmd).is_none(), "{cmd}");
        }
    }

    #[test]
    fn wrappers_apply_to_other_classes() {
        assert_eq!(match_command("sudo git push").unwrap().class, "remote-push");
        assert_eq!(
            match_command("FOO=1 git push").unwrap().class,
            "remote-push"
        );
        assert!(match_command("sudo").is_none());
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
