// SPDX-License-Identifier: AGPL-3.0-or-later

//! HD-01 — renderer-coverage drift catcher.
//!
//! `shit show <id>` renders each event in a `CmdDetail` via a
//! per-kind dispatch in `crates/shit/src/render/cmd_detail.rs`.
//! New `CaptureEventKind` (and nested `TreeOp`) variants added to
//! the planner can silently fall through to a JSON-only fallback,
//! degrading the UX without any compile-time signal.
//!
//! This test fails the build when:
//!
//! - A new variant lands without either a render branch in
//!   `render_event` / `render_tree_op` OR an explicit entry on the
//!   `JSON_ONLY_*` allowlists below.
//! - A variant is removed but its render branch / allowlist entry
//!   stays — surfaces dead code.
//!
//! The allowlists are deliberate, not forgotten — each entry
//! carries a one-line comment explaining why human-readable
//! rendering would be redundant or misleading for that variant.
//!
//! Adding a new event kind without a renderer? Pick one:
//! 1. Add a `"<Variant>" => render_<variant>(w, &ev.kind_json)` arm.
//! 2. Add the variant name to the matching JSON_ONLY allowlist with
//!    a `// rationale: ...` comment.
//!
//! Neither = build fails here. By design.

use shit_planner::events::{CaptureEventKindDiscriminants, TreeOpDiscriminants};
use strum::IntoEnumIterator;

/// Variants of `CaptureEventKind` that intentionally render via the
/// JSON fallback. Each entry needs a rationale.
const JSON_ONLY_CAPTURE_EVENT_KINDS: &[&str] = &[
    // rationale: EnvDiff is a structured before/after map; the JSON
    // fallback is more readable than a hand-rolled table at the
    // current usage volume. Promote to a dedicated renderer if a
    // user-facing sprint scopes shell-state rendering.
    "EnvDiff",
    // rationale: ShellStateDiff is similar to EnvDiff — structured
    // pwd/opts/aliases/funcs diff. Same as above.
    "ShellStateDiff",
    // rationale: PackageOp's most informative field is the
    // {before,after} version map; the JSON fallback shows it
    // compactly. Promote when we ship the AR-package-undo
    // rendering polish.
    "PackageOp",
    // rationale: NetworkOp carries raw before/after iptables/nft
    // state as Vec<u8>; the bytes are line-oriented but binary by
    // type. JSON fallback hex-escapes safely; a dedicated
    // renderer would need tool-specific decoders.
    "NetworkOp",
    // rationale: SystemdOp's before/after ServiceState is a small
    // struct — JSON fallback fits in two lines. Promote on user
    // demand.
    "SystemdOp",
    // rationale: ProcessOp is informational-only at undo time (we
    // don't reanimate killed processes); the JSON fallback's full
    // argv + pid surface is appropriate for the diagnostic use.
    "ProcessOp",
    // rationale: DbOp's statements list is opaque SQL; rendering as
    // bullet-pointed lines would just reformat what the JSON
    // fallback already shows.
    "DbOp",
    // rationale: TerraformOp / KubectlOp / GhOp carry tool-specific
    // captured-state blobs. Dedicated renderers belong with the
    // tool-undo UX sprints (AR04 polish), not here.
    "TerraformOp",
    "KubectlOp",
    "GhOp",
];

/// Subvariants of `TreeOp` that intentionally render via the JSON
/// fallback in `render_tree_op`. Empty at HD-01 land time — every
/// TreeOp shape today has an explicit human-readable arm.
const JSON_ONLY_TREE_OPS: &[&str] = &[];

/// Names of `CaptureEventKind` variants that `render_event` has a
/// dedicated arm for. Source of truth: the `match ev.kind_label`
/// block in `crates/shit/src/render/cmd_detail.rs::render_event`.
/// Update this list when adding a new render arm.
const RENDERED_CAPTURE_EVENT_KINDS: &[&str] = &[
    "FilePreImage",
    "FileAppendPreStash",
    "MetadataChange",
    "TreeOp",
    "ContainerOp",
    "CaptureRefused",
];

/// Names of `TreeOp` subvariants that `render_tree_op` has a
/// dedicated arm for. Source of truth: the `match outer.as_str()`
/// block in `render_tree_op`.
const RENDERED_TREE_OPS: &[&str] = &[
    "Create",
    "Unlink",
    "Rename",
    "Link",
    "Symlink",
    "SymlinkRemoved",
];

#[test]
fn no_variant_appears_in_both_capture_lists() {
    // Catches the drift where a render arm is added without
    // removing the previous JSON-fallback allowlist entry. Both
    // pass individual checks (rendered + still allowlisted) but
    // the allowlist's rationale is now stale.
    let dupes: Vec<&&str> = RENDERED_CAPTURE_EVENT_KINDS
        .iter()
        .filter(|v| JSON_ONLY_CAPTURE_EVENT_KINDS.contains(v))
        .collect();
    assert!(
        dupes.is_empty(),
        "CaptureEventKind variants appear in both \
         RENDERED_CAPTURE_EVENT_KINDS and JSON_ONLY_CAPTURE_EVENT_KINDS: \
         {dupes:?}. Pick one — if a render arm was added, drop the \
         allowlist entry; if the allowlist is canonical, drop the \
         render arm.",
    );
}

#[test]
fn no_subvariant_appears_in_both_tree_lists() {
    let dupes: Vec<&&str> = RENDERED_TREE_OPS
        .iter()
        .filter(|v| JSON_ONLY_TREE_OPS.contains(v))
        .collect();
    assert!(
        dupes.is_empty(),
        "TreeOp subvariants appear in both RENDERED_TREE_OPS and \
         JSON_ONLY_TREE_OPS: {dupes:?}.",
    );
}

#[test]
fn every_capture_event_kind_has_renderer_or_allowlist() {
    let all: Vec<&'static str> = CaptureEventKindDiscriminants::iter()
        .map(<CaptureEventKindDiscriminants as Into<&'static str>>::into)
        .collect();

    let missing: Vec<&&'static str> = all
        .iter()
        .filter(|v| {
            !RENDERED_CAPTURE_EVENT_KINDS.contains(v) && !JSON_ONLY_CAPTURE_EVENT_KINDS.contains(v)
        })
        .collect();

    assert!(
        missing.is_empty(),
        "CaptureEventKind variants without a render branch AND not on \
         JSON_ONLY_CAPTURE_EVENT_KINDS: {missing:?}\n\
         Either add a branch in \
         `crates/shit/src/render/cmd_detail.rs::render_event` OR add \
         the variant name to JSON_ONLY_CAPTURE_EVENT_KINDS in \
         `crates/shit/tests/render_cmd_detail_coverage.rs` with a \
         `// rationale: ...` comment.",
    );

    let stale_render: Vec<&&str> = RENDERED_CAPTURE_EVENT_KINDS
        .iter()
        .filter(|name| !all.contains(name))
        .collect();
    assert!(
        stale_render.is_empty(),
        "RENDERED_CAPTURE_EVENT_KINDS references variants that no \
         longer exist in CaptureEventKind: {stale_render:?}. Drop \
         the obsolete render arm and update this list.",
    );

    let stale_allowlist: Vec<&&str> = JSON_ONLY_CAPTURE_EVENT_KINDS
        .iter()
        .filter(|name| !all.contains(name))
        .collect();
    assert!(
        stale_allowlist.is_empty(),
        "JSON_ONLY_CAPTURE_EVENT_KINDS references variants that no \
         longer exist in CaptureEventKind: {stale_allowlist:?}. Drop \
         the obsolete allowlist entry.",
    );
}

#[test]
fn every_tree_op_subvariant_has_renderer_or_allowlist() {
    let all: Vec<&'static str> = TreeOpDiscriminants::iter()
        .map(<TreeOpDiscriminants as Into<&'static str>>::into)
        .collect();

    let missing: Vec<&&'static str> = all
        .iter()
        .filter(|v| !RENDERED_TREE_OPS.contains(v) && !JSON_ONLY_TREE_OPS.contains(v))
        .collect();

    assert!(
        missing.is_empty(),
        "TreeOp subvariants without a render branch AND not on \
         JSON_ONLY_TREE_OPS: {missing:?}\n\
         Either add a branch in \
         `crates/shit/src/render/cmd_detail.rs::render_tree_op` OR \
         add the subvariant name to JSON_ONLY_TREE_OPS in \
         `crates/shit/tests/render_cmd_detail_coverage.rs` with a \
         `// rationale: ...` comment.",
    );

    let stale_render: Vec<&&str> = RENDERED_TREE_OPS
        .iter()
        .filter(|name| !all.contains(name))
        .collect();
    assert!(
        stale_render.is_empty(),
        "RENDERED_TREE_OPS references subvariants that no longer \
         exist in TreeOp: {stale_render:?}.",
    );

    let stale_allowlist: Vec<&&str> = JSON_ONLY_TREE_OPS
        .iter()
        .filter(|name| !all.contains(name))
        .collect();
    assert!(
        stale_allowlist.is_empty(),
        "JSON_ONLY_TREE_OPS references subvariants that no longer \
         exist in TreeOp: {stale_allowlist:?}.",
    );
}
