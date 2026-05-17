// SPDX-License-Identifier: AGPL-3.0-or-later

//! Package-manager hook integration (S14).
//!
//! The transient `shit-helper pkg-event <manager> <phase>` mode lives
//! here. It does not enter the sidecar runtime: it reads package
//! state via the requested manager's CLI tools, ships a `PkgEventReq`
//! to the daemon over the ctl socket, and exits.
//!
//! The per-manager inspectors land in S14.4..S14.8. This file owns
//! the entrypoint that the subcommand dispatcher calls.

/// Dispatch a `pkg-event` invocation. The dispatcher (in `main.rs`)
/// hands us the manager/phase strings as parsed by clap; we validate
/// and route from here.
///
/// S14.2 lands the entrypoint with a placeholder body. S14.3 fills
/// in the trait + dispatch; S14.4..S14.8 fill in the per-manager
/// inspectors.
pub async fn run_event(
    manager: &str,
    phase: &str,
    _ctl_sock: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    tracing::info!(
        manager,
        phase,
        "pkg-event invocation (S14.2 stub; S14.3 wires real dispatch)"
    );
    // Stage-1 short-circuit: pkg-event must never break the package
    // manager's transaction. Until S14.3..S14.9 land, we log and
    // succeed unconditionally. Real failure modes (helper unreachable,
    // unknown manager, etc.) are S14.9's problem.
    Ok(())
}
