// SPDX-License-Identifier: AGPL-3.0-or-later

//! Process-tier executor (S18.7).
//!
//! Handles [`InverseOp::ProcessNote`]. Unlike the other executors,
//! this one **does not mutate live state** — processes are not files,
//! and we explicitly refuse to fork-exec a "replacement" and call it
//! a restoration (S18 design note: *no process resurrection*).
//!
//! What it produces instead is a renderable [`RestartSuggestion`].
//! Each call to `execute` appends a suggestion to a
//! [`SuggestionSink`] the orchestrator owns; the CLI's
//! `render::process` later consumes the sink and prints a
//! "Processes affected" section.
//!
//! ## Daemon cross-reference (Stage 1)
//!
//! If the killed process was managed by systemd/launchd, restarting
//! via the unit name is preferable to re-running the raw argv. Stage
//! 1 takes an injected [`DaemonCrossRef`] (a `BTreeMap` keyed by
//! `comm` or argv[0] leaf). The daemon will eventually populate this
//! from the S16 service-event log; see DR-51.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::events::SystemdScope;
use crate::executor::{ConflictPolicy, ExecutionOutcome, InverseOpExecutor};
use crate::executors::env::posix_single_quote;
use crate::inverse::InverseOp;

use std::cell::RefCell;

/// A unit reference recovered from the daemon's S16 recordings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRef {
    pub scope: SystemdScope,
    pub unit: String,
}

impl UnitRef {
    pub fn new(scope: SystemdScope, unit: impl Into<String>) -> Self {
        Self {
            scope,
            unit: unit.into(),
        }
    }
}

/// Cross-reference (DR-51): lookup by process key (typically `comm`
/// or the basename of argv[0]) → known unit. Populated from journaled
/// `SystemdOp` events via [`DaemonCrossRef::from_events`] so the CLI
/// can suggest `systemctl restart <unit>` instead of the raw argv
/// when the user killed something a service manager owns.
#[derive(Debug, Clone, Default)]
pub struct DaemonCrossRef {
    by_key: BTreeMap<String, UnitRef>,
}

impl DaemonCrossRef {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, key: impl Into<String>, unit: UnitRef) {
        self.by_key.insert(key.into(), unit);
    }
    pub fn lookup(&self, key: &str) -> Option<&UnitRef> {
        self.by_key.get(key)
    }
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Build the cross-ref by scanning an iterator of events for
    /// `SystemdOp` records. Each unit name is reduced to a process
    /// key via [`unit_to_process_key`] — `nginx.service` → `nginx`,
    /// `redis-server@instance.service` → `redis-server`.
    ///
    /// Later events overwrite earlier ones for the same key. That's
    /// usually what we want — if the user changed which unit manages
    /// a daemon, the latest record reflects the current truth.
    pub fn from_events<'a, I>(events: I) -> Self
    where
        I: IntoIterator<Item = &'a crate::events::CaptureEvent>,
    {
        use crate::events::CaptureEventKind;
        let mut out = Self::new();
        for ev in events {
            if let CaptureEventKind::SystemdOp { scope, unit, .. } = &ev.kind {
                let Some(key) = unit_to_process_key(unit) else {
                    continue;
                };
                out.insert(key, UnitRef::new(*scope, unit.clone()));
            }
        }
        out
    }
}

/// Reduce a service unit name to the process key the executor uses
/// for lookups: the comm / argv[0] basename.
///
/// Rules (systemd + launchd):
/// - Strip the `.service`, `.socket`, `.timer`, etc. suffix.
/// - For templated units `foo@instance.service`, strip the `@instance`
///   too — the live process's `comm` is the template name.
/// - launchd labels like `com.apple.nginx` are returned as-is; the
///   basename rule still maps to the underlying daemon name via the
///   final dot-component (`nginx`). We do that too.
/// - Returns `None` for an empty input or a name that's all
///   suffix (e.g., `.service`).
pub fn unit_to_process_key(unit: &str) -> Option<String> {
    if unit.is_empty() {
        return None;
    }
    // Strip a known suffix.
    const SUFFIXES: &[&str] = &[
        ".service", ".socket", ".timer", ".path", ".mount", ".target", ".slice",
    ];
    let mut base = unit;
    for suf in SUFFIXES {
        if let Some(stripped) = base.strip_suffix(suf) {
            base = stripped;
            break;
        }
    }
    // Strip @instance for templated systemd units.
    if let Some((tmpl, _instance)) = base.split_once('@') {
        base = tmpl;
    }
    // launchd labels: reverse-DNS → take last component.
    // (Has to come after suffix-strip; .service.com.apple.foo would
    // be exotic but harmless.)
    if base.contains('.') {
        base = base.rsplit('.').next().unwrap_or(base);
    }
    if base.is_empty() {
        return None;
    }
    Some(base.to_string())
}

/// Renderable suggestion for one killed process. Carried by the
/// sink; `shit show` formats it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartSuggestion {
    /// Original argv as captured. Useful for the "you killed:" line.
    pub original_argv: Vec<String>,
    /// CWD at capture time. Snippet prefixes a `cd` to this dir when
    /// `restart_argv` is the raw argv form.
    pub cwd: PathBuf,
    /// Filtered env summary (whitelist applied at capture). Snippet
    /// re-exports each entry before the restart argv.
    pub env_summary: BTreeMap<String, String>,
    /// Free-form message from the captured op (e.g., "killed by user").
    pub message: String,
    /// What we recommend running. One of:
    /// - [`RestartHint::SystemdUnit`] — preferred when daemon-cross-ref hit.
    /// - [`RestartHint::LaunchdUnit`] — preferred on macOS launchd hit.
    /// - [`RestartHint::RawArgv`] — fallback when no unit is known.
    pub hint: RestartHint,
}

/// What we recommend the user run to restart the killed process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartHint {
    /// `systemctl restart <unit>` (or `--user` for [`SystemdScope::User`]).
    SystemdUnit { scope: SystemdScope, unit: String },
    /// `launchctl kickstart -k <domain>/<unit>`. Restart-in-place
    /// when the unit is already bootstrapped, which is the
    /// MainPID-cross-ref case we hit here.
    LaunchdUnit { scope: SystemdScope, unit: String },
    /// Fallback: the original argv. The snippet form prefixes
    /// `cd <cwd>` and one `export` per env-summary entry. No `&` or
    /// `nohup` — we don't second-guess the original detach style.
    RawArgv,
}

/// Sink for suggestions the executor produces. Production uses
/// [`VecSuggestionSink`]; tests can implement their own.
pub trait SuggestionSink {
    fn push(&self, s: RestartSuggestion);
}

/// Default sink — collects suggestions in a `RefCell<Vec<_>>`.
/// Single-threaded by design (the orchestrator's executor runs
/// sequentially).
#[derive(Default, Debug)]
pub struct VecSuggestionSink {
    buf: RefCell<Vec<RestartSuggestion>>,
}

impl VecSuggestionSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn take(&self) -> Vec<RestartSuggestion> {
        std::mem::take(&mut *self.buf.borrow_mut())
    }
    pub fn len(&self) -> usize {
        self.buf.borrow().len()
    }
    pub fn is_empty(&self) -> bool {
        self.buf.borrow().is_empty()
    }
}

impl SuggestionSink for VecSuggestionSink {
    fn push(&self, s: RestartSuggestion) {
        self.buf.borrow_mut().push(s);
    }
}

pub struct ProcessExecutor<S: SuggestionSink> {
    sink: S,
    cross_ref: DaemonCrossRef,
}

impl<S: SuggestionSink> ProcessExecutor<S> {
    pub fn new(sink: S, cross_ref: DaemonCrossRef) -> Self {
        Self { sink, cross_ref }
    }
    pub fn sink(&self) -> &S {
        &self.sink
    }
    pub fn cross_ref(&self) -> &DaemonCrossRef {
        &self.cross_ref
    }
}

impl ProcessExecutor<VecSuggestionSink> {
    pub fn with_vec_sink(cross_ref: DaemonCrossRef) -> Self {
        Self::new(VecSuggestionSink::new(), cross_ref)
    }
}

impl<S: SuggestionSink> InverseOpExecutor for ProcessExecutor<S> {
    fn supports(&self, op: &InverseOp) -> bool {
        matches!(op, InverseOp::ProcessNote { .. })
    }

    fn execute(&self, op: &InverseOp, dry_run: bool, _policy: ConflictPolicy) -> ExecutionOutcome {
        let InverseOp::ProcessNote {
            argv,
            cwd,
            env_summary,
            message,
        } = op
        else {
            return ExecutionOutcome::Skipped {
                reason: "process executor reached non-process op".into(),
            };
        };
        if argv.is_empty() {
            return ExecutionOutcome::Skipped {
                reason: "process note has empty argv; nothing to suggest".into(),
            };
        }
        let suggestion = synthesize(&self.cross_ref, argv, cwd.as_path(), env_summary, message);
        if dry_run {
            return ExecutionOutcome::WouldApply;
        }
        self.sink.push(suggestion);
        ExecutionOutcome::Applied
    }
}

/// Pure synthesis: given the captured op and the cross-ref map,
/// produce a [`RestartSuggestion`]. Exposed for unit tests and for
/// the render layer to call directly when it has a note but no
/// orchestrator handy.
pub fn synthesize(
    cross_ref: &DaemonCrossRef,
    argv: &[String],
    cwd: &Path,
    env_summary: &BTreeMap<String, String>,
    message: &str,
) -> RestartSuggestion {
    let key = process_key(argv);
    let hint = match cross_ref.lookup(&key) {
        Some(u) => match u.scope {
            SystemdScope::LaunchdGui | SystemdScope::LaunchdSystem => RestartHint::LaunchdUnit {
                scope: u.scope,
                unit: u.unit.clone(),
            },
            SystemdScope::User | SystemdScope::System => RestartHint::SystemdUnit {
                scope: u.scope,
                unit: u.unit.clone(),
            },
            // FreeBSD rc.d uses `service <unit> restart` — render the
            // raw service-argv as a snippet rather than synthesizing a
            // systemd/launchd unit hint that doesn't apply.
            SystemdScope::RcBase => RestartHint::RawArgv,
        },
        None => RestartHint::RawArgv,
    };
    RestartSuggestion {
        original_argv: argv.to_vec(),
        cwd: cwd.to_path_buf(),
        env_summary: env_summary.clone(),
        message: message.to_string(),
        hint,
    }
}

/// Render the suggestion as a one-or-more-line shell snippet the user
/// can copy-paste. The orchestrator does *not* execute this; it's for
/// display only. Two shapes:
///
/// - **Unit hint** → a single line: `systemctl restart foo.service`
///   (or `--user`), or `launchctl kickstart -k gui/UID/foo`.
/// - **Raw argv** → `cd <cwd> && export A=B && ... && <argv>`. We
///   pick `&&` rather than `;` so a failed `cd` doesn't silently
///   blast the restart at the wrong CWD.
pub fn render_snippet(s: &RestartSuggestion) -> String {
    match &s.hint {
        RestartHint::SystemdUnit { scope, unit } => {
            let prefix: &str = match scope {
                SystemdScope::User => "systemctl --user",
                _ => "systemctl",
            };
            format!("{prefix} restart {unit}")
        }
        RestartHint::LaunchdUnit { scope, unit } => {
            let domain = match scope {
                SystemdScope::LaunchdSystem => "system".to_string(),
                SystemdScope::LaunchdGui => {
                    // SAFETY: getuid always succeeds.
                    let uid = unsafe { libc::getuid() };
                    format!("gui/{uid}")
                }
                _ => return format!("launchctl kickstart -k {unit}"),
            };
            format!("launchctl kickstart -k {domain}/{unit}")
        }
        RestartHint::RawArgv => render_raw_argv(s),
    }
}

fn render_raw_argv(s: &RestartSuggestion) -> String {
    const REDACTED_PREFIX: &str = "<redacted:";
    let mut out = String::new();
    out.push_str("cd ");
    out.push_str(&posix_single_quote(&s.cwd.to_string_lossy()));
    for (k, v) in &s.env_summary {
        // Redacted values are unrecoverable — exporting the literal
        // `<redacted:...>` marker would restore a useless string and
        // leak the capture-time hash. The "env:" line in the render
        // layer already tells the user *which* vars were redacted;
        // we silently omit them here.
        if v.starts_with(REDACTED_PREFIX) {
            continue;
        }
        out.push_str(" && export ");
        out.push_str(k);
        out.push('=');
        out.push_str(&posix_single_quote(v));
    }
    out.push_str(" && ");
    let mut first = true;
    for tok in &s.original_argv {
        if !first {
            out.push(' ');
        }
        first = false;
        out.push_str(&posix_single_quote(tok));
    }
    out
}

/// Cross-ref lookup key. Prefer comm (basename of argv[0]), since
/// the daemon's S16 events index unit MainPIDs by binary name.
fn process_key(argv: &[String]) -> String {
    let Some(first) = argv.first() else {
        return String::new();
    };
    std::path::Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CommandId;
    use crate::events::{CaptureEvent, CaptureEventKind, EventId, ServiceState};
    use crate::time::TimePoint;
    use uuid::Uuid;

    #[test]
    fn unit_to_process_key_strips_service_suffix() {
        assert_eq!(unit_to_process_key("nginx.service"), Some("nginx".into()));
    }

    #[test]
    fn unit_to_process_key_strips_template_instance() {
        assert_eq!(
            unit_to_process_key("redis-server@inst.service"),
            Some("redis-server".into())
        );
    }

    #[test]
    fn unit_to_process_key_handles_launchd_label() {
        // `com.apple.nginx` is the launchd label; the daemon's
        // process comm is "nginx" — last dot-component.
        assert_eq!(unit_to_process_key("com.apple.nginx"), Some("nginx".into()));
    }

    #[test]
    fn unit_to_process_key_strips_timer_socket_suffixes() {
        assert_eq!(unit_to_process_key("foo.socket"), Some("foo".into()));
        assert_eq!(unit_to_process_key("foo.timer"), Some("foo".into()));
        assert_eq!(unit_to_process_key("foo.target"), Some("foo".into()));
    }

    #[test]
    fn unit_to_process_key_returns_none_for_empty_or_suffix_only() {
        assert_eq!(unit_to_process_key(""), None);
        // ".service" → after strip "" → fail.
        assert_eq!(unit_to_process_key(".service"), None);
    }

    #[test]
    fn from_events_builds_cross_ref_from_systemd_ops() {
        let session = Uuid::nil();
        let mk = |unit: &str, scope: SystemdScope| CaptureEvent {
            id: EventId(0),
            command: CommandId { session, seq: 1 },
            ts: TimePoint::new(1, 1),
            partial: false,
            kind: CaptureEventKind::SystemdOp {
                scope,
                unit: unit.into(),
                before: ServiceState {
                    active: false,
                    enabled: false,
                    masked: false,
                    raw: String::new(),
                },
                after: ServiceState {
                    active: true,
                    enabled: true,
                    masked: false,
                    raw: String::new(),
                },
            },
        };
        let events = [
            mk("nginx.service", SystemdScope::System),
            mk("redis-server@inst.service", SystemdScope::User),
        ];
        let cr = DaemonCrossRef::from_events(events.iter());
        assert_eq!(cr.len(), 2);
        let nginx = cr.lookup("nginx").expect("nginx key present");
        assert_eq!(nginx.scope, SystemdScope::System);
        assert_eq!(nginx.unit, "nginx.service");
        let redis = cr.lookup("redis-server").expect("template key present");
        assert_eq!(redis.scope, SystemdScope::User);
    }

    #[test]
    fn from_events_ignores_non_systemd_events() {
        let session = Uuid::nil();
        let ev = CaptureEvent {
            id: EventId(0),
            command: CommandId { session, seq: 1 },
            ts: TimePoint::new(1, 1),
            partial: false,
            kind: CaptureEventKind::EnvDiff {
                added: Default::default(),
                removed: Default::default(),
                modified: Default::default(),
            },
        };
        let cr = DaemonCrossRef::from_events([ev].iter());
        assert!(cr.is_empty());
    }

    #[test]
    fn from_events_later_event_overwrites_earlier_for_same_key() {
        let session = Uuid::nil();
        let mk = |unit: &str, scope: SystemdScope, seq: u64| CaptureEvent {
            id: EventId(0),
            command: CommandId { session, seq },
            ts: TimePoint::new(seq, seq * 1000),
            partial: false,
            kind: CaptureEventKind::SystemdOp {
                scope,
                unit: unit.into(),
                before: ServiceState {
                    active: false,
                    enabled: false,
                    masked: false,
                    raw: String::new(),
                },
                after: ServiceState {
                    active: true,
                    enabled: true,
                    masked: false,
                    raw: String::new(),
                },
            },
        };
        // Same unit name, two scopes — last one wins.
        let cr = DaemonCrossRef::from_events(
            [
                mk("nginx.service", SystemdScope::User, 1),
                mk("nginx.service", SystemdScope::System, 2),
            ]
            .iter(),
        );
        assert_eq!(cr.lookup("nginx").unwrap().scope, SystemdScope::System);
    }

    fn note(argv: Vec<&str>, cwd: &str, env: &[(&str, &str)], msg: &str) -> InverseOp {
        InverseOp::ProcessNote {
            argv: argv.into_iter().map(String::from).collect(),
            cwd: PathBuf::from(cwd),
            env_summary: env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            message: msg.into(),
        }
    }

    #[test]
    fn dry_run_does_not_push() {
        let exec = ProcessExecutor::with_vec_sink(DaemonCrossRef::new());
        let op = note(vec!["sleep", "1000"], "/tmp", &[], "killed by user");
        let outcome = exec.execute(&op, true, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::WouldApply);
        assert!(exec.sink().is_empty());
    }

    #[test]
    fn applied_pushes_one_suggestion() {
        let exec = ProcessExecutor::with_vec_sink(DaemonCrossRef::new());
        let op = note(vec!["sleep", "1000"], "/tmp", &[], "killed by user");
        let outcome = exec.execute(&op, false, ConflictPolicy::Abort);
        assert_eq!(outcome, ExecutionOutcome::Applied);
        assert_eq!(exec.sink().len(), 1);
    }

    #[test]
    fn empty_argv_skips() {
        let exec = ProcessExecutor::with_vec_sink(DaemonCrossRef::new());
        let op = note(vec![], "/tmp", &[], "");
        let outcome = exec.execute(&op, false, ConflictPolicy::Abort);
        assert!(matches!(outcome, ExecutionOutcome::Skipped { .. }));
    }

    #[test]
    fn raw_argv_when_no_cross_ref() {
        let exec = ProcessExecutor::with_vec_sink(DaemonCrossRef::new());
        let op = note(vec!["/usr/bin/python3", "app.py"], "/srv", &[], "");
        exec.execute(&op, false, ConflictPolicy::Abort);
        let s = &exec.sink().take()[0];
        assert!(matches!(s.hint, RestartHint::RawArgv));
    }

    #[test]
    fn systemd_user_unit_picked_when_cross_ref_matches() {
        let mut cr = DaemonCrossRef::new();
        cr.insert("nginx", UnitRef::new(SystemdScope::User, "nginx.service"));
        let exec = ProcessExecutor::with_vec_sink(cr);
        let op = note(vec!["/usr/sbin/nginx", "-g", "daemon off;"], "/", &[], "");
        exec.execute(&op, false, ConflictPolicy::Abort);
        let s = &exec.sink().take()[0];
        match &s.hint {
            RestartHint::SystemdUnit { scope, unit } => {
                assert_eq!(*scope, SystemdScope::User);
                assert_eq!(unit, "nginx.service");
            }
            other => panic!("expected SystemdUnit, got {other:?}"),
        }
    }

    #[test]
    fn launchd_unit_picked_for_launchd_scope() {
        let mut cr = DaemonCrossRef::new();
        cr.insert(
            "com.example.foo",
            UnitRef::new(SystemdScope::LaunchdGui, "com.example.foo"),
        );
        let exec = ProcessExecutor::with_vec_sink(cr);
        let op = note(vec!["com.example.foo"], "/", &[], "");
        exec.execute(&op, false, ConflictPolicy::Abort);
        let s = &exec.sink().take()[0];
        assert!(matches!(s.hint, RestartHint::LaunchdUnit { .. }));
    }

    #[test]
    fn cross_ref_lookup_uses_basename_of_argv0() {
        let mut cr = DaemonCrossRef::new();
        cr.insert(
            "postgres",
            UnitRef::new(SystemdScope::System, "postgresql.service"),
        );
        let exec = ProcessExecutor::with_vec_sink(cr);
        // argv[0] is the full path; the lookup key is the basename.
        let op = note(vec!["/usr/lib/postgresql/16/bin/postgres"], "/", &[], "");
        exec.execute(&op, false, ConflictPolicy::Abort);
        let s = &exec.sink().take()[0];
        assert!(matches!(s.hint, RestartHint::SystemdUnit { .. }));
    }

    #[test]
    fn render_systemd_user_snippet() {
        let s = RestartSuggestion {
            original_argv: vec!["x".into()],
            cwd: PathBuf::from("/"),
            env_summary: BTreeMap::new(),
            message: String::new(),
            hint: RestartHint::SystemdUnit {
                scope: SystemdScope::User,
                unit: "foo.service".into(),
            },
        };
        assert_eq!(render_snippet(&s), "systemctl --user restart foo.service");
    }

    #[test]
    fn render_systemd_system_snippet() {
        let s = RestartSuggestion {
            original_argv: vec!["x".into()],
            cwd: PathBuf::from("/"),
            env_summary: BTreeMap::new(),
            message: String::new(),
            hint: RestartHint::SystemdUnit {
                scope: SystemdScope::System,
                unit: "nginx.service".into(),
            },
        };
        assert_eq!(render_snippet(&s), "systemctl restart nginx.service");
    }

    #[test]
    fn render_launchd_system_snippet() {
        let s = RestartSuggestion {
            original_argv: vec!["x".into()],
            cwd: PathBuf::from("/"),
            env_summary: BTreeMap::new(),
            message: String::new(),
            hint: RestartHint::LaunchdUnit {
                scope: SystemdScope::LaunchdSystem,
                unit: "com.example.foo".into(),
            },
        };
        assert_eq!(
            render_snippet(&s),
            "launchctl kickstart -k system/com.example.foo"
        );
    }

    #[test]
    fn render_raw_argv_quotes_and_chains_with_double_amp() {
        let s = synthesize(
            &DaemonCrossRef::new(),
            &["sleep".into(), "1000".into()],
            &PathBuf::from("/tmp/with space"),
            &BTreeMap::from([("FOO".into(), "bar".into())]),
            "",
        );
        let out = render_snippet(&s);
        assert!(out.starts_with("cd '/tmp/with space'"));
        assert!(out.contains("export FOO='bar'"));
        assert!(out.ends_with("'sleep' '1000'"));
        // && between sections, not ;
        assert!(out.contains(" && "));
        assert!(!out.contains(';'));
    }

    #[test]
    fn render_raw_argv_omits_redacted_env_exports() {
        let s = synthesize(
            &DaemonCrossRef::new(),
            &["app".into()],
            &PathBuf::from("/"),
            &BTreeMap::from([
                ("GITHUB_TOKEN".into(), "<redacted:deadbeef>".into()),
                ("WORKERS".into(), "4".into()),
            ]),
            "",
        );
        let out = render_snippet(&s);
        assert!(!out.contains("GITHUB_TOKEN"));
        assert!(!out.contains("deadbeef"));
        assert!(out.contains("export WORKERS='4'"));
    }

    #[test]
    fn render_raw_argv_quotes_embedded_single_quote_in_argv() {
        let s = synthesize(
            &DaemonCrossRef::new(),
            &["echo".into(), "it's".into()],
            &PathBuf::from("/"),
            &BTreeMap::new(),
            "",
        );
        let out = render_snippet(&s);
        assert!(out.contains(r"'it'\''s'"));
    }

    #[test]
    fn supports_only_process_note() {
        let exec = ProcessExecutor::with_vec_sink(DaemonCrossRef::new());
        let op = InverseOp::UnsetEnv { name: "X".into() };
        assert!(!exec.supports(&op));
        let p = note(vec!["x"], "/", &[], "");
        assert!(exec.supports(&p));
    }
}
