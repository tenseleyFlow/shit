// SPDX-License-Identifier: AGPL-3.0-or-later

//! C05.9: end-to-end pipeline integration tests for the install-shim
//! Rust surface.
//!
//! The cdylib interpose layer (dlsym RTLD_NEXT) lives on a separate
//! branch (S24.D on trunk). What this file exercises is the
//! **decision pipeline** that the interpose layer calls — every
//! pure-logic module composed together as the real shim will compose
//! them:
//!
//!     install_pattern::classify_install_argv
//!         │  (does the shell hook activate the shim?)
//!         ▼
//!     install_config::load_str → resolve  → Vec<String> of prefixes
//!         │  (the daemon resolves the prefix set at startup)
//!         ▼
//!     prefix_match::PrefixSet::new(prefixes)
//!         │  (the cdylib caches this in static storage)
//!         ▼
//!     runtime + dispatch::should_capture(path, prefix_set)
//!         │  (the per-syscall gate)
//!         ▼
//!     bool   (true ⇒ notify daemon then call real libc;
//!              false ⇒ call real libc directly)
//!
//! Each test sets the runtime env vars explicitly (sharing the same
//! lock the unit tests use to keep `std::env` mutations serial) and
//! asserts the dispatch decision for realistic argv + path
//! combinations.

use shit_preload_shim::dispatch::should_capture;
use shit_preload_shim::install_config::{Config, PrefixEntry, load_str, resolve};
use shit_preload_shim::install_pattern::{InstallPattern, classify_install_argv};
use shit_preload_shim::prefix_match::PrefixSet;
use shit_preload_shim::runtime::{SHIT_PRELOAD_ACTIVE_ENV, SHIT_PRELOAD_DEPTH_ENV};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Shared with the unit tests' env lock — `std::env` is process-wide
/// and integration tests run in their own binary, so we use a fresh
/// `Mutex` here rather than crate-internal `TEST_ENV_LOCK` (which is
/// `pub(crate)`).
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn set_active(on: bool) {
    unsafe {
        if on {
            std::env::set_var(SHIT_PRELOAD_ACTIVE_ENV, "1");
        } else {
            std::env::remove_var(SHIT_PRELOAD_ACTIVE_ENV);
        }
    }
}

fn set_depth(d: Option<&str>) {
    unsafe {
        match d {
            Some(v) => std::env::set_var(SHIT_PRELOAD_DEPTH_ENV, v),
            None => std::env::remove_var(SHIT_PRELOAD_DEPTH_ENV),
        }
    }
}

fn argv(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

/// Realistic "/usr/local + /opt" prefix set, used by most tests.
fn standard_prefix_set() -> PrefixSet {
    PrefixSet::new(["/usr/local", "/opt", "/home/u/.local", "/home/u/.cargo/bin"])
}

// ----- pattern + decision composition -----

#[test]
fn make_install_writing_into_usr_local_captures() {
    let _g = ENV_LOCK.lock().unwrap();
    set_active(true);
    set_depth(None);

    // 1. The shell hook would have noticed this argv:
    assert_eq!(
        classify_install_argv(&argv(&["make", "install"])),
        Some(InstallPattern::Make)
    );

    // 2. The daemon-resolved prefix set is in place:
    let prefixes = standard_prefix_set();

    // 3. The shim sees a write under /usr/local — capture.
    assert!(should_capture(Path::new("/usr/local/bin/foo"), &prefixes));
    assert!(should_capture(
        Path::new("/usr/local/share/doc/foo.1.gz"),
        &prefixes
    ));

    set_active(false);
}

#[test]
fn cargo_install_path_writing_into_cargo_bin_captures() {
    let _g = ENV_LOCK.lock().unwrap();
    set_active(true);
    set_depth(None);

    assert_eq!(
        classify_install_argv(&argv(&["cargo", "install", "--path", ".", "--locked"])),
        Some(InstallPattern::CargoInstall)
    );
    let prefixes = standard_prefix_set();
    assert!(should_capture(
        Path::new("/home/u/.cargo/bin/ripgrep"),
        &prefixes
    ));

    set_active(false);
}

#[test]
fn writes_outside_any_prefix_dont_capture() {
    let _g = ENV_LOCK.lock().unwrap();
    set_active(true);
    set_depth(None);

    let prefixes = standard_prefix_set();
    // Build's own intermediate files in /tmp/cargo-XXX/, /var/tmp/,
    // ${CARGO_TARGET_DIR}/... — none should trigger capture.
    assert!(!should_capture(
        Path::new("/tmp/cargo-build/release/foo.o"),
        &prefixes
    ));
    assert!(!should_capture(
        Path::new("/var/lib/dpkg/status"),
        &prefixes
    ));
    assert!(!should_capture(Path::new("/etc/passwd"), &prefixes));

    set_active(false);
}

#[test]
fn shim_inactive_means_no_capture_anywhere() {
    let _g = ENV_LOCK.lock().unwrap();
    set_active(false);
    set_depth(None);

    let prefixes = standard_prefix_set();
    // Even paths squarely under an install prefix don't capture
    // unless SHIT_PRELOAD_ACTIVE=1.
    assert!(!should_capture(Path::new("/usr/local/bin/foo"), &prefixes));
    assert!(!should_capture(Path::new("/opt/local/share"), &prefixes));
}

#[test]
fn recursion_guard_blocks_capture_at_depth_one() {
    let _g = ENV_LOCK.lock().unwrap();
    set_active(true);
    set_depth(Some("1"));

    let prefixes = standard_prefix_set();
    // A wrapped `make install` that internally invokes a wrapped
    // `cp` must NOT double-capture. The inner depth=1 falls through.
    assert!(!should_capture(Path::new("/usr/local/bin/foo"), &prefixes));

    set_active(false);
    set_depth(None);
}

#[test]
fn non_install_argv_does_not_trigger_pattern_classifier() {
    let _g = ENV_LOCK.lock().unwrap();
    // The classifier path runs in the shell hook BEFORE any env
    // mutation; it doesn't care about runtime gates. Asserting both
    // here documents the layering: the shim never gets activated for
    // a non-install command.
    assert!(classify_install_argv(&argv(&["cd", "/tmp"])).is_none());
    assert!(classify_install_argv(&argv(&["git", "commit"])).is_none());
    assert!(classify_install_argv(&argv(&["ls", "-la"])).is_none());
    // The unhooked command would run with active=false anyway.
    set_active(false);
    let prefixes = standard_prefix_set();
    assert!(!should_capture(Path::new("/usr/local/bin/foo"), &prefixes));
}

// ----- config → prefix-set composition -----

#[test]
fn user_config_with_replace_drops_builtins_and_uses_only_user_entries() {
    let toml = r#"
replace = true

[[prefix]]
path = "/opt/me"
"#;
    let cfg: Config = load_str(toml).expect("parse");
    let resolved = resolve(&cfg, Path::new("/home/u"), |_| true).expect("resolve");
    assert_eq!(resolved, vec!["/opt/me".to_string()]);

    let prefixes = PrefixSet::new(resolved);
    let _g = ENV_LOCK.lock().unwrap();
    set_active(true);
    set_depth(None);

    // /opt/me is captured; the built-ins are NOT.
    assert!(should_capture(Path::new("/opt/me/bin/x"), &prefixes));
    assert!(!should_capture(Path::new("/usr/local/bin/x"), &prefixes));

    set_active(false);
}

#[test]
fn user_config_appends_to_builtins_when_replace_false() {
    let toml = r#"
[[prefix]]
path = "~/.dotfiles/bin"
optional = true
"#;
    let cfg: Config = load_str(toml).expect("parse");
    let resolved = resolve(&cfg, Path::new("/home/u"), |_| true).expect("resolve");
    // Built-ins (some count) + 1 user entry.
    assert!(resolved.iter().any(|p| p == "/usr/local"));
    assert!(resolved.iter().any(|p| p == "/home/u/.dotfiles/bin"));

    let prefixes = PrefixSet::new(resolved);
    let _g = ENV_LOCK.lock().unwrap();
    set_active(true);
    set_depth(None);
    assert!(should_capture(
        Path::new("/home/u/.dotfiles/bin/install.sh"),
        &prefixes
    ));
    assert!(should_capture(Path::new("/usr/local/bin/foo"), &prefixes));
    set_active(false);
}

#[test]
fn required_missing_prefix_errors_at_config_load() {
    let cfg = Config {
        replace: true,
        prefixes: vec![PrefixEntry {
            path: "/opt/typo".into(),
            optional: false,
        }],
    };
    let err =
        resolve(&cfg, Path::new("/home/u"), |_| false).expect_err("required + missing must error");
    assert!(format!("{err}").contains("/opt/typo"));
}

// ----- realistic-fixture sanity -----

#[test]
fn fake_installer_writes_to_tempdir_prefix_captures() {
    // A real installer would write a file under its `--prefix`. This
    // test simulates that flow: configure the prefix set to point at
    // a tempdir, then assert paths inside the tempdir are captured.
    let tmp = tempfile::tempdir().unwrap();
    let prefix_path = tmp.path().to_path_buf();
    // realpath-resolve via canonicalize so symlinks (macOS /tmp →
    // /private/tmp) match the way the shim's interpose layer would
    // see them.
    let canonical_prefix: PathBuf = prefix_path.canonicalize().unwrap();
    let prefixes = PrefixSet::new([canonical_prefix.to_string_lossy().into_owned()]);

    let _g = ENV_LOCK.lock().unwrap();
    set_active(true);
    set_depth(None);

    let under = canonical_prefix.join("bin/fake-installer");
    let above = canonical_prefix.parent().unwrap().join("not-under-prefix");

    assert!(should_capture(&under, &prefixes), "path under prefix");
    assert!(
        !should_capture(&above, &prefixes),
        "sibling of prefix must NOT match"
    );

    set_active(false);
}
