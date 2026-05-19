// SPDX-License-Identifier: AGPL-3.0-or-later

// C03 cloud-tier capture (kubectl/gh/aws/terraform). Each submodule
// owns the per-tool snapshot logic that runs from a PATH-prepend
// wrapper (installed via `shit cloud-hooks install`). The capture
// hook invokes `shit-helper cloud-event <tool> <pre|post>`; the
// daemon-side binding to a captured command window is gated on the
// same capture-runtime work as DR-25 / DR-32 / DR-36 (pkg/env/svc).
//
// Stage 1 ships the parsers + argv classifiers; wiring the helper
// CLI subcommand and the daemon ctl-handler is DR-CR-06.
#![allow(dead_code)]

pub mod kubectl;

#[allow(unused_imports)]
pub use kubectl::{KubectlVerb, classify_kubectl_argv};
