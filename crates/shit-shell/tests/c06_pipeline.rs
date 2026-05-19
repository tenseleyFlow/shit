// SPDX-License-Identifier: AGPL-3.0-or-later

//! C06.9 — end-to-end integration tests for the C06 surface.
//!
//! Stitches the four pure-logic modules in this crate together as
//! the real shell hook will: parse the user's command line for
//! redirects, simulate pre + post shell-state snapshots, compute the
//! diff, render the per-shell undo snippet, and assert every step
//! against the realistic input.
//!
//! The planner-side `InverseOp::ShellStateRestore` /
//! `InverseOp::FileExtend` assembly lives in `shit-planner` (out of
//! this crate's reach), so the integration test stops at the
//! snippet text. The documented mapping `Truncate ⇒ RestoreContent`,
//! `Append ⇒ FileExtend`, etc. is exercised by the planner's own
//! tier-routing tests; here we lock in the **shell-side** half of
//! the contract.
//!
//! See the C06 sprint outcome doc for the full pipeline diagram.

use shit_shell::redirect::{RedirectOp, parse_redirects};
use shit_shell::snippet::{render_bash, render_fish, render_zsh};
use shit_shell::state::{Snapshot, compute_diff};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ---------- redirect classification → planner-tier mapping ----------

#[test]
fn truncate_classified_for_pre_stash_full_content_capture() {
    // `cat /etc/hosts > /tmp/log` truncates, then writes.
    // Planner-side: this becomes `InverseOp::RestoreContent` with the
    // full pre-content blob; the pre-stash captures the bytes
    // synchronously before the shell forks the child.
    let r = parse_redirects("cat /etc/hosts > /tmp/log");
    assert_eq!(r.targets.len(), 1);
    assert_eq!(r.targets[0].op, RedirectOp::Truncate);
    assert_eq!(r.targets[0].path, "/tmp/log");
}

#[test]
fn append_classified_for_pre_stash_size_only_capture() {
    // `echo bar >> /tmp/log` appends. Planner-side: this becomes
    // `InverseOp::FileExtend { truncate_to: pre_size }` — the
    // pre-stash captures only the size (one `stat` call) since the
    // original content stays untouched.
    let r = parse_redirects("echo bar >> /tmp/log");
    assert_eq!(r.targets.len(), 1);
    assert_eq!(r.targets[0].op, RedirectOp::Append);
}

#[test]
fn tee_truncate_and_dd_of_both_route_to_full_content_capture() {
    // Both `tee` (without -a) and `dd of=...` overwrite; planner
    // routes both to `RestoreContent`.
    let tee = parse_redirects("ps aux | tee /tmp/snap");
    let dd = parse_redirects("dd if=/etc/hosts of=/tmp/dd-out bs=1M count=1");
    assert!(tee.targets.iter().any(|t| t.op == RedirectOp::TeeTruncate));
    assert!(dd.targets.iter().any(|t| t.op == RedirectOp::DdOf));
}

#[test]
fn dev_null_skipped_at_parse_no_useless_pre_stash() {
    // /dev/null and friends must never trigger a pre-stash — the
    // pre-state is meaningless and the daemon round-trip is wasted.
    for line in [
        "echo > /dev/null",
        "cmd 2>> /dev/null",
        "cat /etc/hosts > /dev/stdout",
        "echo > /proc/sys/vm/drop_caches",
        "echo > /sys/kernel/foo",
    ] {
        assert!(
            parse_redirects(line).is_empty(),
            "expected no targets for `{line}`"
        );
    }
}

// ---------- redirect + state combined pipeline ----------

#[test]
fn shell_command_with_redirect_and_state_change_renders_complete_snippet() {
    // The user line:
    //
    //     cd /tmp && set -o errexit; cat /etc/hosts > /tmp/log
    //
    // produces:
    //   - one Truncate target at /tmp/log  (redirect parser)
    //   - pwd_changed from /home/u → /tmp  (state diff)
    //   - errexit off → on                  (option diff)
    //
    // The user-facing undo flow is:
    //   1. The daemon pre-stashes /tmp/log's bytes before the cat fork
    //      (planner emits `InverseOp::RestoreContent { blob: <hash> }`).
    //   2. The shell-state diff yields an `InverseOp::ShellStateRestore`
    //      whose rendered bash snippet re-cd's to /home/u and `set +o
    //      errexit`s.
    //
    // This test verifies the parse + diff + snippet halves; the
    // planner side has its own tier-routing tests.

    let r = parse_redirects("cat /etc/hosts > /tmp/log");
    assert_eq!(r.targets.len(), 1);
    assert_eq!(r.targets[0].path, "/tmp/log");

    let pre = Snapshot {
        pwd: PathBuf::from("/home/u"),
        set_opts: BTreeMap::from([("errexit".into(), "off".into())]),
        ..Default::default()
    };
    let post = Snapshot {
        pwd: PathBuf::from("/tmp"),
        set_opts: BTreeMap::from([("errexit".into(), "on".into())]),
        ..Default::default()
    };
    let d = compute_diff(&pre, &post);
    assert!(d.pwd_changed.is_some());
    assert_eq!(d.opts.len(), 1);

    let bash_snippet = render_bash(&d);
    assert!(bash_snippet.contains("cd '/home/u'"));
    assert!(bash_snippet.contains("set +o errexit"));
}

#[test]
fn append_workflow_pipelines_through_size_only_snapshot() {
    // `tail -f` users frequently `echo bar >> /tmp/log` from a side
    // shell. Verify the redirect parser identifies it as Append and
    // the planner-side mapping (Append → FileExtend) is documented.
    let r = parse_redirects("echo bar >> /tmp/log");
    assert_eq!(r.targets.len(), 1);
    assert_eq!(r.targets[0].op, RedirectOp::Append);
    // No state change accompanies an `echo`; diff stays empty.
    let s = Snapshot::default();
    let d = compute_diff(&s, &s);
    assert!(d.is_empty());
    // The bash snippet would be just the header (no real diff to
    // render); the file executor's `apply_file_extend` does the
    // real work. (Tested in the planner's executors::file::tests.)
    let snippet = render_bash(&d);
    assert_eq!(snippet.lines().count(), 1);
    assert!(snippet.starts_with("# C06:"));
}

#[test]
fn alias_added_and_function_added_during_command_render_correctly_per_shell() {
    let pre = Snapshot {
        pwd: PathBuf::from("/home/u"),
        ..Default::default()
    };
    let mut post = pre.clone();
    post.aliases.insert("g".into(), "git".into());
    post.functions
        .insert("greet".into(), "greet() { echo hi; }".into());
    let d = compute_diff(&pre, &post);

    let bash = render_bash(&d);
    assert!(bash.contains("unalias g 2>/dev/null || true"));
    assert!(bash.contains("unset -f greet 2>/dev/null || true"));

    let zsh = render_zsh(&d);
    assert!(zsh.contains("unalias g 2>/dev/null || true"));
    assert!(zsh.contains("unset -f greet 2>/dev/null || true"));

    let fish = render_fish(&d);
    // fish renders alias-removal as `functions -e`.
    assert!(fish.contains("functions -e g"));
    assert!(fish.contains("functions -e greet"));
}

#[test]
fn multi_redirect_one_command_captures_every_target() {
    // bash supports `cmd > out 2> err`; both targets need pre-stash.
    let r = parse_redirects("cmd > /tmp/out 2> /tmp/err");
    assert_eq!(r.targets.len(), 2);
    let paths: Vec<&str> = r.targets.iter().map(|t| t.path.as_str()).collect();
    assert!(paths.contains(&"/tmp/out"));
    assert!(paths.contains(&"/tmp/err"));
}

#[test]
fn quoting_keeps_redirect_destinations_intact() {
    let r = parse_redirects("echo > 'with spaces.log'");
    assert_eq!(r.targets.len(), 1);
    assert_eq!(r.targets[0].path, "with spaces.log");
}

#[test]
fn fd_dup_form_does_not_produce_phantom_target() {
    // `cmd 2>&1` is fd-dup; no file destination.
    let r = parse_redirects("cmd 2>&1");
    assert!(r.is_empty());
}

#[test]
fn snippet_quoting_round_trips_through_shell_safely() {
    // A pwd value with a single quote MUST round-trip through the
    // snippet without breaking the cd line. This is the most likely
    // injection point if quoting were wrong.
    let pre = Snapshot {
        pwd: PathBuf::from("/home/u/it's a project"),
        ..Default::default()
    };
    let post = Snapshot {
        pwd: PathBuf::from("/tmp"),
        ..Default::default()
    };
    let d = compute_diff(&pre, &post);
    let bash = render_bash(&d);
    // POSIX single-quote escape: `'\''`.
    assert!(bash.contains("'/home/u/it'\\''s a project'"));
}
