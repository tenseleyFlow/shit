// SPDX-License-Identifier: AGPL-3.0-or-later

//! Build script for `shit-preload-shim`.
//!
//! On FreeBSD (and the other BSDs we ship the LD_PRELOAD path for),
//! base utilities link against libc with versioned symbol imports
//! — `open@FBSD_1.0`, `unlink@FBSD_1.0`, etc. The rtld resolver
//! looks up the SPECIFIC versioned symbol when binding the PLT.
//!
//! The shim's `src/lib.rs` emits `.symver name, name@FBSD_1.0`
//! directives via `core::arch::global_asm!` for each interposed
//! libc symbol. lld emits versioned aliases but refuses to link
//! unless a `FBSD_1.0` version *definition* exists in the
//! resulting `.gnu.version_d` section. This build script attaches
//! a minimal version script declaring that version name.
//!
//! Linux is unaffected — glibc's versioning (`GLIBC_2.x`) is more
//! permissive about LD_PRELOAD substitution and the shim's
//! unversioned exports already work there.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let bsd = matches!(
        target_os.as_str(),
        "freebsd" | "netbsd" | "openbsd" | "dragonfly"
    );
    if !bsd {
        return;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let ver_script = format!("{manifest_dir}/shim.ver");
    println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={ver_script}");
    println!("cargo:rerun-if-changed=shim.ver");
}
