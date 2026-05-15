// SPDX-License-Identifier: AGPL-3.0-or-later

//! Undo planner and inverse-op DAG for `shit`.
//!
//! Spec lives in `.docs/sprints/S03-undo-planner-spec.md`. The executor and
//! per-tier executors land in S11.

#[cfg(test)]
mod tests {
    #[test]
    fn crate_wires_up() {
        assert_eq!(2 + 2, 4);
    }
}
