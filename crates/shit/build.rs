// SPDX-License-Identifier: AGPL-3.0-or-later

use vergen_gitcl::{BuildBuilder, CargoBuilder, Emitter, GitclBuilder, RustcBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let build = BuildBuilder::default().build_timestamp(true).build()?;
    let cargo = CargoBuilder::default().target_triple(true).build()?;
    let git = GitclBuilder::default().sha(true).build()?;
    let rustc = RustcBuilder::default().semver(true).build()?;
    Emitter::default()
        .quiet()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        .add_instructions(&git)?
        .add_instructions(&rustc)?
        .emit()?;
    // AU02 — coverage snapshot is include_str!'d into doctor::coverage_snapshot.
    // Trigger a rebuild on snapshot changes so the embedded data stays
    // current with what's in-tree. The default cargo rebuild detection
    // covers source files; the snapshot lives outside src/ so we need
    // the explicit rerun-if-changed.
    println!("cargo:rerun-if-changed=../../tools/audit/coverage-snapshot.json");
    Ok(())
}
