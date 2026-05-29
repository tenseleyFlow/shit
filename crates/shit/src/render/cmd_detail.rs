// SPDX-License-Identifier: AGPL-3.0-or-later

//! AU30 — `shit show <id>` human-readable renderer.
//!
//! Consumes [`shit_proto::CmdDetailBody`] and writes a multi-section
//! body to a `Write` sink:
//!
//! ```text
//! shit show <session>:<seq>
//!
//! cmd:      docker pull alpine:latest
//! cwd:      /home/u
//! shell:    bash (pid 12345)
//! started:  2026-05-29T20:17:34Z
//! ended:    2026-05-29T20:17:34Z (exit 0, 0.42s)
//!
//! plan: 1 node
//!   Container: 1
//!
//! events (2):
//!   [1] +0.001s ContainerOp
//!     {... json payload ...}
//!   [2] +0.012s FilePreImage
//!     /tmp/x  (... summary)
//! ```
//!
//! Per-event dispatch lives in `render_event` — each
//! `kind_label` gets a dedicated pretty branch (built out
//! incrementally) and unknown kinds fall through to indented JSON
//! so the data is visible even without a custom renderer.

use std::io::Write;

use shit_proto::{CmdDetailBody, CmdDetailEventWire, ShellKind};

/// Top-level entrypoint called from `cmd::show::run`. `exec` and
/// `shell_state` flag the optional sections — both still print
/// stage-1 deferral messages today; the data flow is in place so
/// they light up when the upstream wiring lands.
pub fn render(
    w: &mut dyn Write,
    body: &CmdDetailBody,
    exec: bool,
    shell_state: bool,
) -> std::io::Result<()> {
    writeln!(w, "shit show {}:{}", body.session, body.seq)?;
    writeln!(w)?;

    if let Some(cmd) = &body.cmd_string {
        writeln!(w, "cmd:      {cmd}")?;
    } else {
        // AU26 wires cmd_string from the shell hook; legacy /
        // pre-AU26 captures + hooks that don't ship --cmdline land
        // here. Keep the section header so output shape stays
        // predictable.
        writeln!(
            w,
            "cmd:      (not captured — pre-AU26 or shell hook lacked --cmdline)"
        )?;
    }
    writeln!(w, "cwd:      {}", body.cwd)?;
    writeln!(
        w,
        "shell:    {} (pid {})",
        shell_kind_label(body.shell_kind),
        body.pid
    )?;
    writeln!(
        w,
        "started:  {}",
        format_wallclock(body.started_at_unix_nanos)
    )?;
    match body.ended_at_unix_nanos {
        Some(end_ns) => {
            let dur_s = (end_ns.saturating_sub(body.started_at_unix_nanos)) as f64 / 1e9;
            let exit_part = body
                .exit_code
                .map(|c| format!("exit {c}"))
                .unwrap_or_else(|| "no exit".to_string());
            writeln!(
                w,
                "ended:    {} ({exit_part}, {dur_s:.3}s)",
                format_wallclock(end_ns)
            )?;
        }
        None => {
            writeln!(w, "ended:    (still open — no PostExec yet)")?;
        }
    }
    writeln!(w)?;

    // Plan summary section.
    writeln!(w, "plan: {} node(s)", body.plan_summary.total_nodes)?;
    for (tier, count) in &body.plan_summary.tier_counts {
        writeln!(w, "  {tier}: {count}")?;
    }
    if body.plan_summary.has_blocking_conflicts {
        writeln!(
            w,
            "  (blocking conflicts present — `shit undo` would refuse without --on-conflict=force)"
        )?;
    }
    if body.plan_summary.has_refused {
        writeln!(
            w,
            "  (plan includes a refuse-class node — `shit undo` will skip it; see `shit undo --explain`)"
        )?;
    }
    writeln!(w)?;

    // Events section.
    let shown = body.events.len();
    if body.events_total == shown {
        writeln!(w, "events ({shown}):")?;
    } else {
        writeln!(w, "events ({shown} of {}):", body.events_total)?;
    }
    let t0 = body.started_at_unix_nanos;
    for (idx, ev) in body.events.iter().enumerate() {
        let rel_s = (ev.ts_unix_nanos.saturating_sub(t0)) as f64 / 1e9;
        let partial_tag = if ev.partial { " [partial]" } else { "" };
        writeln!(
            w,
            "  [{}] +{rel_s:.3}s {}{partial_tag}",
            idx + 1,
            ev.kind_label
        )?;
        render_event(w, ev)?;
    }
    if let Some(cap) = body.truncated_at {
        let remaining = body.events_total.saturating_sub(cap);
        writeln!(
            w,
            "  ({remaining} more event(s) truncated — re-run with --events-limit N or --json for the full envelope)"
        )?;
    }

    if exec {
        writeln!(w)?;
        writeln!(
            w,
            "--exec: exec-log replay isn't wired through the ctl detail endpoint yet (planner has the API; the daemon needs to surface per-undo log paths). Skipping."
        )?;
    }
    if shell_state {
        writeln!(w)?;
        writeln!(
            w,
            "--shell-state: detailed shell-state diff section deferred until the precmd-queue dispatch (DR-CR-50) lands. The plan summary above counts ShellState ops."
        )?;
    }

    Ok(())
}

/// Pretty-renders a single event payload below its index line.
/// Dispatch by `kind_label`; falls back to indented JSON for
/// kinds without a dedicated branch yet. New variants land as
/// small additives in downstream sprints (AU23 adds the
/// ContainerOp Pull branch, etc).
pub fn render_event(w: &mut dyn Write, ev: &CmdDetailEventWire) -> std::io::Result<()> {
    match ev.kind_label.as_str() {
        "FilePreImage" => render_file_pre_image(w, &ev.kind_json),
        "FileAppendPreStash" => render_file_append_pre_stash(w, &ev.kind_json),
        "MetadataChange" => render_metadata_change(w, &ev.kind_json),
        "TreeOp" => render_tree_op(w, &ev.kind_json),
        "ContainerOp" => render_container_op(w, &ev.kind_json),
        "CaptureRefused" => render_capture_refused(w, &ev.kind_json),
        _ => render_json_fallback(w, &ev.kind_json),
    }
}

// === Per-kind renderers ===

fn render_file_pre_image(w: &mut dyn Write, kind_json: &str) -> std::io::Result<()> {
    // Strict-deser would couple us to the planner's field set;
    // freeform JSON lets future planner-side additions round-trip
    // without bumping the shit crate.
    let v: serde_json::Value = parse_or_fallback(w, kind_json)?;
    let Some(obj) = v.as_object() else {
        return render_json_fallback(w, kind_json);
    };
    let path = obj
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("(no path)");
    let blob = obj
        .get("blob")
        .and_then(|v| v.as_str())
        .map(short_hash)
        .unwrap_or_else(|| "?".to_string());
    let size = obj
        .get("meta")
        .and_then(|m| m.get("size"))
        .and_then(|v| v.as_u64());
    let size_part = match size {
        Some(s) => format!(", {} bytes", s),
        None => String::new(),
    };
    writeln!(w, "    path: {path}")?;
    writeln!(w, "    blob: {blob}{size_part}")?;
    if let Some(src) = obj.get("source").and_then(|v| v.as_str()) {
        writeln!(w, "    source: {src}")?;
    }
    Ok(())
}

fn render_file_append_pre_stash(w: &mut dyn Write, kind_json: &str) -> std::io::Result<()> {
    let v: serde_json::Value = parse_or_fallback(w, kind_json)?;
    let path = v
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("(no path)");
    let pre_size = v.get("pre_size").and_then(|v| v.as_u64()).unwrap_or(0);
    writeln!(w, "    path: {path}")?;
    writeln!(
        w,
        "    pre_size: {pre_size} bytes (truncate-target for undo)"
    )?;
    Ok(())
}

fn render_metadata_change(w: &mut dyn Write, kind_json: &str) -> std::io::Result<()> {
    let v: serde_json::Value = parse_or_fallback(w, kind_json)?;
    let path = v
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("(no path)");
    let before = v.get("before");
    let after = v.get("after");
    writeln!(w, "    path: {path}")?;
    if let (Some(b), Some(a)) = (before, after) {
        if let (Some(bm), Some(am)) = (
            b.get("mode").and_then(|v| v.as_u64()),
            a.get("mode").and_then(|v| v.as_u64()),
        ) && bm != am
        {
            writeln!(w, "    mode: {bm:o} → {am:o}")?;
        }
        if let (Some(bu), Some(au)) = (
            b.get("uid").and_then(|v| v.as_u64()),
            a.get("uid").and_then(|v| v.as_u64()),
        ) && bu != au
        {
            writeln!(w, "    uid: {bu} → {au}")?;
        }
        if let (Some(bg), Some(ag)) = (
            b.get("gid").and_then(|v| v.as_u64()),
            a.get("gid").and_then(|v| v.as_u64()),
        ) && bg != ag
        {
            writeln!(w, "    gid: {bg} → {ag}")?;
        }
    }
    Ok(())
}

fn render_tree_op(w: &mut dyn Write, kind_json: &str) -> std::io::Result<()> {
    // TreeOp wraps the variant directly; payload is the inner enum
    // serialized as { "Create": {...} } / { "Unlink": {...} } /
    // { "Rename": {...} } / { "Link": {...} } / etc. We surface the
    // variant tag + path(s) and defer further detail to the JSON
    // fallback for less common variants.
    let v: serde_json::Value = parse_or_fallback(w, kind_json)?;
    let Some(obj) = v.as_object() else {
        return render_json_fallback(w, kind_json);
    };
    if let Some((variant, inner)) = obj.iter().next() {
        match variant.as_str() {
            "Create" | "Unlink" | "SymlinkRemoved" => {
                let path = inner
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no path)");
                writeln!(w, "    {variant}: {path}")?;
            }
            "Rename" => {
                let from = inner
                    .get("old_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let to = inner
                    .get("new_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                writeln!(w, "    Rename: {from} → {to}")?;
            }
            "Link" | "Symlink" => {
                let source = inner
                    .get("source")
                    .or_else(|| inner.get("target"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let dest = inner
                    .get("link_path")
                    .or_else(|| inner.get("path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                writeln!(w, "    {variant}: {dest} → {source}")?;
            }
            _ => {
                // Unrecognized TreeOp sub-variant. Indent JSON.
                writeln!(w, "    {variant}:")?;
                render_indented_json(w, inner, 6)?;
            }
        }
    }
    Ok(())
}

fn render_container_op(w: &mut dyn Write, kind_json: &str) -> std::io::Result<()> {
    // ContainerOp wraps the planner's ContainerOp enum. Pretty
    // branches cover the destructive verbs that AR03 ships;
    // unrecognized variants (e.g. AU23's eventual Pull) fall to
    // the indented-JSON branch which the AU23 sprint will replace
    // with a dedicated renderer.
    let v: serde_json::Value = parse_or_fallback(w, kind_json)?;
    let Some(obj) = v.as_object() else {
        return render_json_fallback(w, kind_json);
    };
    // ContainerOp::ContainerOp wraps in `op` field per the
    // planner's CaptureEventKind shape: { runtime, op: { Rmi: {...} } }.
    let runtime = obj.get("runtime").and_then(|v| v.as_str()).unwrap_or("?");
    let op = obj.get("op");
    writeln!(w, "    runtime: {runtime}")?;
    if let Some(op_obj) = op.and_then(|v| v.as_object())
        && let Some((variant, inner)) = op_obj.iter().next()
    {
        match variant.as_str() {
            "Rmi" => {
                let image = inner.get("image").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(w, "    Rmi: {image}")?;
                if let Some(d) = inner.get("digest").and_then(|v| v.as_str()) {
                    writeln!(w, "    digest: {d}")?;
                }
            }
            "Rm" => {
                let name = inner
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(unnamed)");
                let id = inner.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(w, "    Rm: {name} (id {id})")?;
            }
            "VolumeRm" => {
                let name = inner.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(w, "    VolumeRm: {name}")?;
            }
            "NetworkRm" => {
                let name = inner.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(w, "    NetworkRm: {name}")?;
            }
            "ComposeDown" => {
                let project = inner.get("project").and_then(|v| v.as_str()).unwrap_or("?");
                writeln!(w, "    ComposeDown: project {project}")?;
            }
            _ => {
                writeln!(w, "    {variant}:")?;
                render_indented_json(w, inner, 6)?;
            }
        }
    }
    Ok(())
}

fn render_capture_refused(w: &mut dyn Write, kind_json: &str) -> std::io::Result<()> {
    let v: serde_json::Value = parse_or_fallback(w, kind_json)?;
    let class = v.get("class").and_then(|v| v.as_str()).unwrap_or("?");
    let detail = v
        .get("detail")
        .and_then(|v| v.as_str())
        .unwrap_or("(no detail)");
    let path = v.get("path").and_then(|v| v.as_str());
    writeln!(w, "    class: {class}")?;
    if let Some(p) = path {
        writeln!(w, "    path: {p}")?;
    }
    writeln!(w, "    detail: {detail}")?;
    Ok(())
}

fn render_json_fallback(w: &mut dyn Write, kind_json: &str) -> std::io::Result<()> {
    match serde_json::from_str::<serde_json::Value>(kind_json) {
        Ok(v) => render_indented_json(w, &v, 4),
        Err(_) => writeln!(w, "    {kind_json}"),
    }
}

// === Helpers ===

fn parse_or_fallback(w: &mut dyn Write, kind_json: &str) -> std::io::Result<serde_json::Value> {
    match serde_json::from_str::<serde_json::Value>(kind_json) {
        Ok(v) => Ok(v),
        Err(_) => {
            // Malformed JSON — emit the raw string + a Value::Null
            // so the caller's `as_object()` short-circuits to the
            // safe path.
            writeln!(w, "    (failed to parse event payload as JSON)")?;
            writeln!(w, "    {kind_json}")?;
            Ok(serde_json::Value::Null)
        }
    }
}

fn render_indented_json(
    w: &mut dyn Write,
    v: &serde_json::Value,
    indent: usize,
) -> std::io::Result<()> {
    let pretty = serde_json::to_string_pretty(v).unwrap_or_else(|_| "null".to_string());
    let prefix = " ".repeat(indent);
    for line in pretty.lines() {
        writeln!(w, "{prefix}{line}")?;
    }
    Ok(())
}

fn shell_kind_label(k: ShellKind) -> &'static str {
    match k {
        ShellKind::Bash => "bash",
        ShellKind::Zsh => "zsh",
        ShellKind::Fish => "fish",
        ShellKind::Unknown => "unknown",
    }
}

fn format_wallclock(ns: i64) -> String {
    // Avoid a chrono dep; humans see seconds + the raw nanos for
    // precise correlation with the daemon's structured logs.
    let secs = ns / 1_000_000_000;
    let sub_ms = (ns % 1_000_000_000) / 1_000_000;
    format!("unix-secs={secs}.{sub_ms:03}")
}

fn short_hash(full: &str) -> String {
    if full.len() <= 16 {
        full.to_string()
    } else {
        format!("{}…", &full[..12])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_body() -> CmdDetailBody {
        CmdDetailBody {
            session: uuid::Uuid::nil(),
            seq: 1,
            cmd_string: Some("echo hi".into()),
            cwd: "/tmp".into(),
            pid: 1234,
            shell_kind: ShellKind::Bash,
            exit_code: Some(0),
            started_at_unix_nanos: 1_700_000_000_000_000_000,
            ended_at_unix_nanos: Some(1_700_000_001_000_000_000),
            events: vec![],
            events_total: 0,
            truncated_at: None,
            plan_summary: shit_proto::CmdDetailPlanSummary::default(),
        }
    }

    fn capture_render(body: &CmdDetailBody) -> String {
        let mut buf: Vec<u8> = Vec::new();
        render(&mut buf, body, false, false).expect("render ok");
        String::from_utf8(buf).expect("utf8")
    }

    #[test]
    fn header_renders_cmd_cwd_shell() {
        let body = empty_body();
        let out = capture_render(&body);
        assert!(out.contains("shit show 00000000-0000-0000-0000-000000000000:1"));
        assert!(out.contains("cmd:      echo hi"));
        assert!(out.contains("cwd:      /tmp"));
        assert!(out.contains("shell:    bash (pid 1234)"));
        assert!(out.contains("exit 0"));
        assert!(out.contains("plan: 0 node(s)"));
        assert!(out.contains("events (0):"));
    }

    #[test]
    fn missing_cmd_string_renders_placeholder() {
        let mut body = empty_body();
        body.cmd_string = None;
        let out = capture_render(&body);
        assert!(
            out.contains("(not captured"),
            "expected placeholder note; got: {out}"
        );
    }

    #[test]
    fn truncation_note_appears_when_capped() {
        let mut body = empty_body();
        body.events_total = 500;
        body.truncated_at = Some(200);
        // Add two synthetic events so the header line shows "2 of 500".
        for i in 0..2 {
            body.events.push(CmdDetailEventWire {
                id: i,
                ts_unix_nanos: body.started_at_unix_nanos,
                kind_label: "FilePreImage".into(),
                kind_json:
                    r#"{"path":"/tmp/x","blob":"deadbeef0123456789abcdef","meta":{"size":42}}"#
                        .into(),
                partial: false,
            });
        }
        let out = capture_render(&body);
        assert!(
            out.contains("events (2 of 500)"),
            "expected events header to show truncation; got: {out}"
        );
        assert!(
            out.contains("300 more event"),
            "expected truncation note; got: {out}"
        );
    }

    #[test]
    fn file_pre_image_renders_path_and_short_blob() {
        let mut body = empty_body();
        body.events.push(CmdDetailEventWire {
            id: 1,
            ts_unix_nanos: body.started_at_unix_nanos,
            kind_label: "FilePreImage".into(),
            kind_json: r#"{"path":"/tmp/foo","blob":"deadbeefcafebabe1234","meta":{"size":42}}"#
                .into(),
            partial: false,
        });
        body.events_total = 1;
        let out = capture_render(&body);
        assert!(out.contains("path: /tmp/foo"));
        assert!(out.contains("deadbeefcafe"));
        assert!(out.contains("42 bytes"));
    }

    #[test]
    fn unknown_kind_falls_back_to_json() {
        let mut body = empty_body();
        body.events.push(CmdDetailEventWire {
            id: 1,
            ts_unix_nanos: body.started_at_unix_nanos,
            kind_label: "FutureKindThatDoesNotExist".into(),
            kind_json: r#"{"some_field":"some_value"}"#.into(),
            partial: false,
        });
        body.events_total = 1;
        let out = capture_render(&body);
        assert!(out.contains("FutureKindThatDoesNotExist"));
        assert!(out.contains("\"some_field\""));
        assert!(out.contains("\"some_value\""));
    }

    #[test]
    fn partial_events_tagged() {
        let mut body = empty_body();
        body.events.push(CmdDetailEventWire {
            id: 1,
            ts_unix_nanos: body.started_at_unix_nanos,
            kind_label: "TreeOp".into(),
            kind_json: r#"{"Create":{"path":"/tmp/race-loss"}}"#.into(),
            partial: true,
        });
        body.events_total = 1;
        let out = capture_render(&body);
        assert!(out.contains("[partial]"));
    }
}
