// SPDX-License-Identifier: AGPL-3.0-or-later

//! BPF-LSM tier — userspace loader side (S09 stage 2 scaffold).
//!
//! **Status:** dependency wired, types defined, `EbpfLoader::load`
//! returns `Err(NotImplemented)` deliberately. Stage 3 (a future PR)
//! adds the program crate + bpf-linker toolchain + real load logic.
//!
//! Why this halfway-house ships now:
//!   - Compile errors that would only surface on Linux are caught
//!     early via the `aya` dep being part of the build graph.
//!   - The tier-decision plumbing (`main.rs::pick_linux_tier`) can
//!     call `EbpfLoader::probe` to check whether load is even worth
//!     attempting, without anything kernel-side happening.
//!   - When stage 3 fills in `load()`, the call sites don't move.
//!
//! Safety invariants (encoded here so a future change can't quietly
//! violate them):
//!   1. `load()` must never attach a program until the helper has
//!      proven a clean detach in a sandboxed environment.
//!   2. Any program ever attached must have a hard runtime budget and
//!      a watchdog that detaches on overrun.
//!   3. LSM hooks that can return non-zero (deny) require explicit
//!      review per `.docs/audits/helper-protocol.md` standing rules.
//!   4. Tracepoint programs (read-only observers) are the safer entry
//!      point; LSM programs come after tracepoints are proven.

pub mod error;
pub mod loader;

pub use error::EbpfError;
pub use loader::{EbpfLoader, ProbeOutcome};
