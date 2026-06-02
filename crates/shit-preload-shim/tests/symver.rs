// SPDX-License-Identifier: AGPL-3.0-or-later

//! W06.A.2 regression test — verify the cdylib exports each libc
//! interposer at the version(s) FreeBSD libc exposes it at.
//!
//! Why this exists: the `.symver` inline-asm + `shim.ver` + per-
//! package `strip = "debuginfo"` combination is fragile. If
//! anything in that stack regresses (a future Rust edition
//! changes how cdylib symbols are mangled, a build.rs gets
//! reverted, etc.), the shim's interposers silently stop binding
//! against FreeBSD base utilities — make-install undo goes back
//! to "applied=0, files remain on disk." This test catches that
//! statically.
//!
//! The test is FreeBSD-only (the `.symver` block is cfg-gated to
//! BSD and Linux doesn't need versioned exports), and runs at
//! `cargo test --release -p shit-preload-shim --test symver`.

#![cfg(target_os = "freebsd")]

use std::process::Command;

/// Expected (symbol, version) pairs the shim must export. Sourced
/// from `objdump -T /lib/libc.so.7` on FreeBSD 14.4 — if a future
/// FreeBSD adds a new version for any of these, this list needs
/// extending AND the `.symver` block in `lib.rs` needs matching
/// entries.
const EXPECTED_VERSIONED_EXPORTS: &[(&str, &str)] = &[
    ("open", "FBSD_1.0"),
    ("unlink", "FBSD_1.0"),
    ("rename", "FBSD_1.0"),
    ("truncate", "FBSD_1.0"),
    ("ftruncate", "FBSD_1.0"),
    ("pwrite", "FBSD_1.0"),
    ("mmap", "FBSD_1.0"),
    // W09.10.1 — mkfifo is the only libc version (FBSD_1.0).
    ("mkfifo", "FBSD_1.0"),
    // B08 — link/linkat shim parity (mirrors macOS PR #175).
    // `link` is at FBSD_1.0; `linkat` is at FBSD_1.1.
    ("link", "FBSD_1.0"),
    // *at variants are at FBSD_1.1 in libc. openat also exists
    // at FBSD_1.2 but lld won't let us tag the same source
    // symbol twice (multiple-versions error when rlib links
    // into the bin), so we cover FBSD_1.1 only — see the
    // .symver block in lib.rs for the tradeoff.
    ("openat", "FBSD_1.1"),
    ("unlinkat", "FBSD_1.1"),
    ("renameat", "FBSD_1.1"),
    ("mkfifoat", "FBSD_1.1"),
    ("linkat", "FBSD_1.1"),
];

/// Locate the built `.so`. cargo provides `CARGO_BIN_EXE_<name>`
/// for bin targets but not for cdylibs. `cargo test` builds the
/// test binary + its rlib dependency but does NOT produce the
/// cdylib output, so we trigger a `cargo build -p
/// shit-preload-shim` as a fallback to ensure the artifact
/// exists before the regression check.
///
/// Probes Cargo's standard layout — both debug and release —
/// so the test works after either `cargo build` or `cargo build
/// --release`.
fn shim_so_path() -> std::path::PathBuf {
    // Release paths first — debug builds default to many codegen
    // units which silently drops `.symver` aliases (see the
    // fallback-build comment below). Probing release first means
    // we validate the artifact that actually ships, even when a
    // stale debug build exists alongside.
    let candidates = [
        // Crate-rooted (default `cargo test -p shit-preload-shim`)
        "../../target/release/libshit_preload_shim.so",
        // Workspace-rooted (CI `cargo test --workspace`)
        "target/release/libshit_preload_shim.so",
    ];
    if let Some(p) = candidates
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
    {
        return p.canonicalize().unwrap_or(p);
    }
    // Fallback: trigger a RELEASE build of the cdylib and re-probe.
    // `cargo test --workspace` doesn't auto-build cdylib outputs,
    // so the artifact may not yet exist when this test runs.
    //
    // Why `--release` specifically: debug builds default to many
    // codegen units, which causes the `.symver` directives in
    // `core::arch::global_asm!` to land in a different codegen
    // unit than the function they alias. The linker doesn't
    // associate the alias and the dynsym ends up without
    // version tags. Release uses `codegen-units = 1` (workspace
    // setting), keeping the assembly and the function in one
    // unit so the `.symver` actually sticks. The shim only ever
    // ships its release artifact, so validating release is the
    // load-bearing check.
    eprintln!(
        "symver test: cdylib not yet built; running `cargo build --release -p shit-preload-shim`"
    );
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "shit-preload-shim"])
        .status()
        .expect("`cargo` must be on PATH");
    assert!(status.success(), "fallback `cargo build --release` failed");
    candidates
        .iter()
        .map(std::path::PathBuf::from)
        .find(|p| p.exists())
        .map(|p| p.canonicalize().unwrap_or(p))
        .unwrap_or_else(|| {
            panic!("cdylib still not present after fallback build; tried: {candidates:?}")
        })
}

/// Parse `objdump -T` output for `(VERSION) NAME` pairs from
/// FUNC lines in the `.text` section. Returns a sorted Vec for
/// stable diffs.
fn parse_versioned_exports(objdump_output: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = objdump_output
        .lines()
        .filter_map(|line| {
            // Format: ADDR g    DF .text  SIZE  (VERSION)   NAME
            // We anchor on " DF .text" and `(...)` for the version.
            if !line.contains(" DF .text") {
                return None;
            }
            let open = line.find('(')?;
            let close = line[open + 1..].find(')')?;
            let version = &line[open + 1..open + 1 + close];
            let rest = line[open + 1 + close + 1..].trim();
            // `rest` is the symbol name (possibly followed by more
            // whitespace). Take the first token.
            let name = rest.split_whitespace().next()?;
            Some((name.to_string(), version.to_string()))
        })
        .collect();
    out.sort();
    out
}

#[test]
fn shim_exports_all_expected_versioned_symbols() {
    let so = shim_so_path();
    let output = Command::new("objdump")
        .arg("-T")
        .arg(&so)
        .output()
        .expect("objdump must be on PATH");
    assert!(
        output.status.success(),
        "objdump -T {} failed: stderr={}",
        so.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed = parse_versioned_exports(&String::from_utf8_lossy(&output.stdout));

    let mut missing: Vec<(&str, &str)> = Vec::new();
    for &(name, version) in EXPECTED_VERSIONED_EXPORTS {
        let found = parsed.iter().any(|(n, v)| n == name && v == version);
        if !found {
            missing.push((name, version));
        }
    }

    assert!(
        missing.is_empty(),
        "shim is missing versioned exports: {missing:?}\n\
         parsed exports: {parsed:?}\n\
         If FreeBSD libc has added new versions for any of these symbols, \
         update both the `.symver` block in src/lib.rs AND the EXPECTED_VERSIONED_EXPORTS \
         table here.",
    );
}

#[test]
fn parse_versioned_exports_extracts_objdump_format() {
    // Excerpt from a real `objdump -T libshit_preload_shim.so`.
    let sample = "\
0000000000026264 g    DF .text\t0000000000000140 (FBSD_1.0)   open\n\
00000000000263a4 g    DF .text\t0000000000000150 (FBSD_1.1)   openat\n\
0000000000026a58 g    DF .text\t0000000000000004              shit_preload_unlink\n\
0000000000000000      DF *UND*\t0000000000000000 (FBSD_1.0)   __cxa_finalize\n\
";
    let parsed = parse_versioned_exports(sample);
    // Expect only the two .text-section lines; the UND line is
    // filtered, the unversioned shit_preload_unlink is filtered.
    assert_eq!(
        parsed,
        vec![
            ("open".to_string(), "FBSD_1.0".to_string()),
            ("openat".to_string(), "FBSD_1.1".to_string()),
        ],
    );
}
