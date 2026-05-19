// SPDX-License-Identifier: AGPL-3.0-or-later

//! Install-command pattern matcher (C05.2).
//!
//! The shell preexec hook calls [`classify_install_argv`] on every
//! about-to-run command. If the argv matches one of the recognised
//! install patterns, the hook wraps that single command with the
//! shim's `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` env-vars set; the
//! shim then captures pre-state at every install-prefix-touching
//! syscall. If the argv doesn't match, no env-vars are set and the
//! command runs unhooked — the cost is one Rust call per shell
//! command, not one per file operation.
//!
//! The matcher is intentionally **pure** (no I/O, no allocations
//! beyond the input argv borrow) so it can run inside the shell hook
//! with ~zero overhead and live alongside the prefix matcher in the
//! same `cdylib` + `rlib` crate.
//!
//! ## What we match
//!
//! - `make install`, `make -C dir install`, `make all install`
//! - `cmake --install <dir>`
//! - `ninja install`
//! - `cargo install --path …`, `cargo install --force …`,
//!   `cargo install --root …`
//! - `pip install --user …` / `pip3 install --user …`
//! - `python -m pip install --user …` (and `python3 -m pip …`)
//! - `python setup.py install` / `python3 setup.py install`
//! - `python -m installer …`
//! - `meson install`
//!
//! ## What we don't match
//!
//! Sudo-prefixed forms (`sudo make install`) — those would inherit
//! the shim only if the user explicitly preserves `LD_PRELOAD` via
//! `sudo --preserve-env=LD_PRELOAD,SHIT_PRELOAD_ACTIVE,SHIT_DAEMON_SOCK`.
//! The matcher does not peek past `sudo`; the user's responsibility is
//! to set up sudo correctly (documented; see DR-CR-37).
//!
//! Plain `cargo install <pkg>` (no `--path`/`--force`/`--root`) — that
//! downloads from crates.io and installs to `$CARGO_HOME/bin` which
//! IS an install prefix; but the spec deliberately scopes capture to
//! the explicit-source forms (`--path .`, `--force`) to avoid noise
//! from routine package installs. Users who want capture for plain
//! `cargo install` can wrap the command in `shit install ...`.

/// Which install pattern matched. Drives the renderer in `shit log`
/// ("make install of <projectname>") and is returned to the shell hook
/// so it can include the kind in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallPattern {
    /// `make install`.
    Make,
    /// `cmake --install <dir>`.
    CmakeInstall,
    /// `ninja install`.
    NinjaInstall,
    /// `cargo install` with one of `--path`, `--force`, `--root`.
    CargoInstall,
    /// `pip install --user` (any of `pip`, `pip3`, `python -m pip`).
    PipUserInstall,
    /// `python setup.py install` (deprecated upstream but still
    /// pervasive in legacy / vendored builds).
    PythonSetupPyInstall,
    /// `python -m installer` — the modern PEP 517 install backend.
    PythonInstaller,
    /// `meson install`.
    MesonInstall,
}

impl InstallPattern {
    /// Short human-readable label for diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Make => "make-install",
            Self::CmakeInstall => "cmake-install",
            Self::NinjaInstall => "ninja-install",
            Self::CargoInstall => "cargo-install",
            Self::PipUserInstall => "pip-install-user",
            Self::PythonSetupPyInstall => "python-setup-py-install",
            Self::PythonInstaller => "python-installer",
            Self::MesonInstall => "meson-install",
        }
    }
}

/// Classify an argv. Returns `Some(pattern)` if the command matches
/// a known install-time pattern, `None` otherwise.
pub fn classify_install_argv(argv: &[String]) -> Option<InstallPattern> {
    let head = argv.first().map(String::as_str)?;

    // Normalize basenames: a shell may invoke `make`, `/usr/bin/make`,
    // or `gmake` (BSD). We only match the basename's final component
    // since pip3 / python3 / gmake are common aliases.
    let head = basename(head);

    match head {
        "make" | "gmake" | "remake" => {
            if has_token(&argv[1..], "install") {
                Some(InstallPattern::Make)
            } else {
                None
            }
        }
        "cmake" => {
            if has_token(&argv[1..], "--install") {
                Some(InstallPattern::CmakeInstall)
            } else {
                None
            }
        }
        "ninja" => {
            if has_token(&argv[1..], "install") {
                Some(InstallPattern::NinjaInstall)
            } else {
                None
            }
        }
        "meson" => {
            if has_token(&argv[1..], "install") {
                Some(InstallPattern::MesonInstall)
            } else {
                None
            }
        }
        "cargo" => classify_cargo(&argv[1..]),
        "pip" | "pip3" => classify_pip(&argv[1..]),
        "python" | "python2" | "python3" => classify_python(&argv[1..]),
        _ => None,
    }
}

fn classify_cargo(rest: &[String]) -> Option<InstallPattern> {
    if rest.first().map(String::as_str) != Some("install") {
        return None;
    }
    // Require one of --path / --force / --root to opt-into capture.
    // Plain `cargo install <crate>` is noisy and the user can wrap it
    // explicitly in `shit install ...` if they want it captured.
    let opts = &rest[1..];
    if has_any_flag(opts, &["--path", "--force", "--root"]) {
        Some(InstallPattern::CargoInstall)
    } else {
        None
    }
}

fn classify_pip(rest: &[String]) -> Option<InstallPattern> {
    if rest.first().map(String::as_str) != Some("install") {
        return None;
    }
    if has_token(&rest[1..], "--user") {
        Some(InstallPattern::PipUserInstall)
    } else {
        None
    }
}

fn classify_python(rest: &[String]) -> Option<InstallPattern> {
    match rest.first().map(String::as_str) {
        Some("-m") => match rest.get(1).map(String::as_str) {
            Some("pip") => {
                // python -m pip install --user
                if rest.get(2).map(String::as_str) == Some("install")
                    && has_token(&rest[3..], "--user")
                {
                    Some(InstallPattern::PipUserInstall)
                } else {
                    None
                }
            }
            Some("installer") => Some(InstallPattern::PythonInstaller),
            _ => None,
        },
        Some("setup.py") => {
            if rest.get(1).map(String::as_str) == Some("install") {
                Some(InstallPattern::PythonSetupPyInstall)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Whether any of `tokens` appears as a standalone argv element.
fn has_token(argv: &[String], tok: &str) -> bool {
    argv.iter().any(|t| t == tok)
}

/// Whether any flag in `flags` appears in argv, accepting both the
/// bare form (`--path`) and the equals form (`--path=…`).
fn has_any_flag(argv: &[String], flags: &[&str]) -> bool {
    argv.iter().any(|t| {
        flags
            .iter()
            .any(|f| t == f || (t.starts_with(f) && t.as_bytes().get(f.len()) == Some(&b'=')))
    })
}

fn basename(p: &str) -> &str {
    if let Some(idx) = p.rfind('/') {
        &p[idx + 1..]
    } else {
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    // ----- make -----

    #[test]
    fn make_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["make", "install"])),
            Some(InstallPattern::Make)
        );
    }

    #[test]
    fn make_with_dir_and_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["make", "-C", "build", "install"])),
            Some(InstallPattern::Make)
        );
    }

    #[test]
    fn make_all_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["make", "all", "install"])),
            Some(InstallPattern::Make)
        );
    }

    #[test]
    fn make_check_does_not_classify() {
        assert!(classify_install_argv(&argv(&["make", "check"])).is_none());
        assert!(classify_install_argv(&argv(&["make"])).is_none());
    }

    #[test]
    fn gmake_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["gmake", "install"])),
            Some(InstallPattern::Make)
        );
    }

    #[test]
    fn full_path_make_classifies_via_basename() {
        assert_eq!(
            classify_install_argv(&argv(&["/usr/bin/make", "install"])),
            Some(InstallPattern::Make)
        );
    }

    // ----- cmake -----

    #[test]
    fn cmake_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["cmake", "--install", "build"])),
            Some(InstallPattern::CmakeInstall)
        );
    }

    #[test]
    fn cmake_build_does_not_classify() {
        assert!(classify_install_argv(&argv(&["cmake", "--build", "build"])).is_none());
    }

    // ----- ninja / meson -----

    #[test]
    fn ninja_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["ninja", "install"])),
            Some(InstallPattern::NinjaInstall)
        );
    }

    #[test]
    fn ninja_without_install_does_not_classify() {
        assert!(classify_install_argv(&argv(&["ninja"])).is_none());
    }

    #[test]
    fn meson_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["meson", "install"])),
            Some(InstallPattern::MesonInstall)
        );
    }

    // ----- cargo -----

    #[test]
    fn cargo_install_path_dot_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["cargo", "install", "--path", "."])),
            Some(InstallPattern::CargoInstall)
        );
    }

    #[test]
    fn cargo_install_force_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["cargo", "install", "--force", "ripgrep"])),
            Some(InstallPattern::CargoInstall)
        );
    }

    #[test]
    fn cargo_install_root_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["cargo", "install", "--root", "/tmp/x", "ripgrep"])),
            Some(InstallPattern::CargoInstall)
        );
    }

    #[test]
    fn cargo_install_equals_form_path_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["cargo", "install", "--path=./crate"])),
            Some(InstallPattern::CargoInstall)
        );
    }

    #[test]
    fn cargo_install_bare_does_not_classify() {
        // Plain `cargo install <crate>` is deliberately out — see the
        // module doc. Users who want capture wrap explicitly.
        assert!(classify_install_argv(&argv(&["cargo", "install", "ripgrep"])).is_none());
    }

    #[test]
    fn cargo_other_subcommand_does_not_classify() {
        assert!(classify_install_argv(&argv(&["cargo", "build"])).is_none());
        assert!(classify_install_argv(&argv(&["cargo", "test", "--release"])).is_none());
    }

    // ----- pip / pip3 -----

    #[test]
    fn pip_user_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["pip", "install", "--user", "requests"])),
            Some(InstallPattern::PipUserInstall)
        );
    }

    #[test]
    fn pip3_user_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["pip3", "install", "--user", "numpy"])),
            Some(InstallPattern::PipUserInstall)
        );
    }

    #[test]
    fn pip_install_without_user_does_not_classify() {
        // System-wide pip install hits /usr; kernel-tier captures.
        // The shim is opt-in for the user-scope path.
        assert!(classify_install_argv(&argv(&["pip", "install", "requests"])).is_none());
    }

    // ----- python -m pip -----

    #[test]
    fn python_m_pip_user_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&[
                "python", "-m", "pip", "install", "--user", "wheel"
            ])),
            Some(InstallPattern::PipUserInstall)
        );
    }

    #[test]
    fn python3_m_pip_user_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&[
                "python3", "-m", "pip", "install", "--user", "wheel"
            ])),
            Some(InstallPattern::PipUserInstall)
        );
    }

    #[test]
    fn python_m_pip_without_user_does_not_classify() {
        assert!(
            classify_install_argv(&argv(&["python", "-m", "pip", "install", "wheel"])).is_none()
        );
    }

    // ----- python setup.py -----

    #[test]
    fn python_setup_py_install_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["python", "setup.py", "install"])),
            Some(InstallPattern::PythonSetupPyInstall)
        );
    }

    #[test]
    fn python_setup_py_test_does_not_classify() {
        assert!(classify_install_argv(&argv(&["python", "setup.py", "test"])).is_none());
    }

    // ----- python -m installer -----

    #[test]
    fn python_m_installer_classifies() {
        assert_eq!(
            classify_install_argv(&argv(&["python", "-m", "installer", "wheel.whl"])),
            Some(InstallPattern::PythonInstaller)
        );
    }

    // ----- non-install commands -----

    #[test]
    fn cd_does_not_classify() {
        assert!(classify_install_argv(&argv(&["cd", "/tmp"])).is_none());
    }

    #[test]
    fn empty_argv_does_not_classify() {
        let empty: Vec<String> = vec![];
        assert!(classify_install_argv(&empty).is_none());
    }

    #[test]
    fn sudo_prefixed_make_install_does_not_classify_by_design() {
        // Documented: sudo strips LD_PRELOAD by default; the matcher
        // does not unwrap sudo so the user explicitly opts in via
        // `sudo --preserve-env=...` (DR-CR-37). Asserting the
        // negative protects future contributors from "fixing" this in
        // a way that breaks the doc contract.
        assert!(classify_install_argv(&argv(&["sudo", "make", "install"])).is_none());
    }

    #[test]
    fn as_str_labels_are_kebab_case_and_unique() {
        let all = [
            InstallPattern::Make,
            InstallPattern::CmakeInstall,
            InstallPattern::NinjaInstall,
            InstallPattern::CargoInstall,
            InstallPattern::PipUserInstall,
            InstallPattern::PythonSetupPyInstall,
            InstallPattern::PythonInstaller,
            InstallPattern::MesonInstall,
        ];
        let mut seen = std::collections::HashSet::new();
        for p in all {
            let s = p.as_str();
            assert!(s.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
            assert!(seen.insert(s), "duplicate label: {s}");
        }
    }
}
