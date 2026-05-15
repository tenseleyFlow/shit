// SPDX-License-Identifier: AGPL-3.0-or-later

//! Copy-on-write capture engine and filesystem-watcher abstractions for `shit`.
//!
//! Spec lives in `.docs/sprints/S05-cow-engine.md`. Per-OS watcher implementations
//! land in S07 (macOS EndpointSecurity), S08 (Linux fanotify), S09 (Linux eBPF-LSM),
//! and S10 (BSD kqueue).

#[cfg(test)]
mod tests {
    #[test]
    fn crate_wires_up() {
        assert_eq!(2 + 2, 4);
    }
}
