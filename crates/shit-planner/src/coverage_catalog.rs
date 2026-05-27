// SPDX-License-Identifier: AGPL-3.0-or-later

//! AU02 — single source of truth for the `arbitrary_undo_coverage`
//! surface. Replaces the hand-typed literal that used to live in
//! `crates/shit/src/doctor/mod.rs::collect_arbitrary_undo_coverage`.
//!
//! Each [`CoverageClass`] describes one capability shit claims to
//! undo (or to refuse with intent). The class's `representative_smoke`
//! field is the canonical end-to-end test that exercises the
//! capability; the AU14 CI driver cross-references it against the
//! green-smoke matrix and stamps `coverage-snapshot.json` accordingly.
//!
//! Three kinds of classes:
//!
//! - **Covered** — shit undoes commands of this kind. Backed by a
//!   green smoke in CI.
//! - **Pending** — shit knows about commands of this kind but doesn't
//!   yet have full coverage (partial implementation, missing tier).
//!   Surfaces in `pending_classes` so users see what's in flight.
//! - **Refused** — enumerated in [`crate::refuse::CATALOG`]; shit
//!   explicitly says it won't undo. Not in this catalog (it lives in
//!   `refuse.rs`).
//!
//! The `coverage_pct` field on the doctor JSON envelope was DROPPED
//! in AU02 — a percentage over a fictitious denominator is worse than
//! the three lists. See `crates/shit/src/doctor/json.rs` for the
//! current shape.

/// One row in the coverage catalog. Constructed only as a `const` in
/// [`COVERAGE_CATALOG`] below — no instances at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageClass {
    /// Stable identifier shown in the doctor JSON envelope.
    pub id: &'static str,
    /// One smoke filename that exercises this class end-to-end. The
    /// AU14 driver verifies this exists in `tests/smoke/` and that
    /// it ran green on the trunk commit a snapshot was stamped on.
    pub representative_smoke: &'static str,
    /// Sprint identifier where this class landed. Tracks lineage; not
    /// surfaced in doctor JSON today.
    pub since_sprint: &'static str,
}

/// Classes shit currently undoes, with their representative smoke.
/// Ordering: alphabetical-by-id so diffs are easy to eyeball.
pub const COVERAGE_CATALOG: &[CoverageClass] = &[
    CoverageClass {
        id: "container-compose",
        representative_smoke: "docker-compose-down-undo-linux.sh",
        since_sprint: "AR03.6",
    },
    CoverageClass {
        id: "container-network",
        representative_smoke: "docker-network-rm-undo-linux.sh",
        since_sprint: "AR03.4",
    },
    CoverageClass {
        id: "container-rm",
        representative_smoke: "docker-rm-undo-linux.sh",
        since_sprint: "AR03.1",
    },
    CoverageClass {
        id: "container-rmi",
        representative_smoke: "docker-rmi-undo-linux.sh",
        since_sprint: "AR03.2",
    },
    CoverageClass {
        id: "container-volume",
        representative_smoke: "docker-volume-rm-undo-linux.sh",
        since_sprint: "AR03.3",
    },
    CoverageClass {
        id: "fs-content-restore",
        representative_smoke: "edit-undo-linux.sh",
        since_sprint: "L02",
    },
    CoverageClass {
        id: "fs-metadata",
        representative_smoke: "chmod-undo-linux.sh",
        since_sprint: "L03",
    },
    CoverageClass {
        id: "fs-rename",
        representative_smoke: "mv-undo-linux.sh",
        since_sprint: "L03",
    },
    CoverageClass {
        id: "fs-tree",
        representative_smoke: "rm-undo-linux.sh",
        since_sprint: "L02",
    },
    CoverageClass {
        id: "kubectl-delete",
        representative_smoke: "kubectl-delete-undo-linux.sh",
        since_sprint: "AR04.3",
    },
    CoverageClass {
        id: "package-apt",
        representative_smoke: "apt-pkg.sh",
        since_sprint: "AR02.1",
    },
    CoverageClass {
        id: "package-brew",
        representative_smoke: "brew-pkg.sh",
        since_sprint: "DR-22",
    },
    CoverageClass {
        id: "package-dnf",
        representative_smoke: "dnf-history-undo-linux.sh",
        since_sprint: "AR02.2",
    },
    CoverageClass {
        id: "preload-install",
        representative_smoke: "make-install-undo-linux.sh",
        since_sprint: "AR05.1",
    },
    CoverageClass {
        id: "process-note",
        representative_smoke: "kill-proc.sh",
        since_sprint: "S18",
    },
    CoverageClass {
        id: "redirect-truncate",
        representative_smoke: "redirect-race-undo-linux.sh",
        since_sprint: "AR06.5",
    },
    CoverageClass {
        id: "service-systemctl",
        representative_smoke: "systemctl-svc.sh",
        since_sprint: "S16",
    },
    CoverageClass {
        id: "shell-state",
        representative_smoke: "cd-undo-linux.sh",
        since_sprint: "AR06.1",
    },
    CoverageClass {
        id: "tool-gh",
        representative_smoke: "gh-release-delete-undo-linux.sh",
        since_sprint: "AR04.4",
    },
    CoverageClass {
        id: "tool-network",
        representative_smoke: "iptables-net.sh",
        since_sprint: "AR08.2",
    },
    CoverageClass {
        id: "tool-terraform",
        representative_smoke: "terraform-apply-undo-linux.sh",
        since_sprint: "AR04.1",
    },
];

/// Classes we know about and partially support, but don't claim full
/// coverage for. Users see these in `pending_classes` so the doctor
/// surface admits "we're working on it" rather than implying
/// either complete coverage or refusal.
///
/// Definition of "pending": there is design work or partial
/// implementation in the tree, but the representative smoke isn't
/// stable green AND the class isn't in [`crate::refuse::CATALOG`].
pub const PENDING_CATALOG: &[CoverageClass] = &[
    CoverageClass {
        // BSD shim default-on at install — sprint AU07. Once landed,
        // promote to COVERAGE_CATALOG with a representative smoke.
        id: "bsd-shim-default",
        representative_smoke: "(none — AU07 pending)",
        since_sprint: "AU07",
    },
    CoverageClass {
        // Linux capability preservation across cargo rebuilds — AU08
        // shipped dev-loop tooling but the install-path postinst
        // verification is L06 territory.
        id: "linux-cap-install-verify",
        representative_smoke: "(none — L06 pending)",
        since_sprint: "AU08",
    },
];

/// Enumerate just the class IDs in [`COVERAGE_CATALOG`].
pub fn covered_class_ids() -> Vec<&'static str> {
    COVERAGE_CATALOG.iter().map(|c| c.id).collect()
}

/// Enumerate just the class IDs in [`PENDING_CATALOG`].
pub fn pending_class_ids() -> Vec<&'static str> {
    PENDING_CATALOG.iter().map(|c| c.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covered_ids_are_unique_and_sorted() {
        let ids = covered_class_ids();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(
            ids, sorted,
            "COVERAGE_CATALOG must stay alphabetically sorted by id"
        );
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "duplicate id in COVERAGE_CATALOG");
    }

    #[test]
    fn pending_ids_are_unique() {
        let ids = pending_class_ids();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "duplicate id in PENDING_CATALOG");
    }

    #[test]
    fn covered_and_pending_are_disjoint() {
        let covered: std::collections::HashSet<_> = covered_class_ids().into_iter().collect();
        let pending: std::collections::HashSet<_> = pending_class_ids().into_iter().collect();
        let overlap: Vec<_> = covered.intersection(&pending).collect();
        assert!(
            overlap.is_empty(),
            "class IDs must be in EITHER covered OR pending, not both: {overlap:?}"
        );
    }

    #[test]
    fn every_covered_class_has_a_representative_smoke() {
        for cls in COVERAGE_CATALOG {
            assert!(
                !cls.representative_smoke.is_empty(),
                "{} missing representative_smoke",
                cls.id
            );
            assert!(
                cls.representative_smoke.ends_with(".sh"),
                "{} representative_smoke must be a .sh file (got {:?})",
                cls.id,
                cls.representative_smoke
            );
        }
    }
}
