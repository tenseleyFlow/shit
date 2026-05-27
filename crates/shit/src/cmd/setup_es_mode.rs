// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit setup-es-mode` — power-user EndpointSecurity setup helper
//! (M03.x.POWER-USER.2).
//!
//! Apple denied the EndpointSecurity entitlement for general
//! distribution (see `.docs/audits/apple-entitlement.md`), so the
//! only way to get ES-tier pre-image capture on a stock Mac is for
//! the user to explicitly disable SIP + AuthRoot, set the AMFI
//! bypass boot-arg, and codesign the helper with the entitlement
//! plist embedded. This subcommand turns the doctor's structured
//! `es_blockers` list into a user-facing setup flow:
//!
//! - `shit setup-es-mode --check` — runs the doctor probes, prints
//!   a green/yellow/red status line per prereq. Exit code 0 iff
//!   `es_capable = true`.
//! - `shit setup-es-mode --print` — prints the exact recovery-mode
//!   commands + the local codesign step + a clear enumeration of
//!   the security trade-offs. Output is copy-pasteable verbatim.
//! - `shit setup-es-mode --apply` — runs the LOCAL-MACHINE pieces
//!   (codesign the helper). Recovery-mode pieces (csrutil) stay
//!   manual — we cannot script Recovery boot from running macOS by
//!   design. Requires `--i-understand-the-tradeoffs` for the
//!   AMFI-bypass step (nvram boot-args) because AMFI weakening is
//!   the security tradeoff most users will under-appreciate.

#![cfg(target_os = "macos")]

use clap::Args;
use std::path::PathBuf;
use std::process::Command;

use crate::doctor::json::EsBlocker;
use crate::doctor::probes::macos;
use crate::exitcode::{CliError, GENERIC_FAILURE};

#[derive(Debug, Clone, Args)]
pub struct SetupEsModeArgs {
    /// Run the doctor probes + print a per-prereq status line.
    /// Exit code 0 iff every prereq passes.
    #[arg(long, conflicts_with_all = ["print", "apply"])]
    pub check: bool,

    /// Print the exact setup commands the user needs to run, plus a
    /// clear enumeration of what they trade for the elevated capture.
    /// Output is copy-pasteable verbatim.
    #[arg(long, conflicts_with_all = ["check", "apply"])]
    pub print: bool,

    /// Apply the local-machine setup steps (codesign the helper with
    /// the entitlement plist embedded). Recovery-mode steps (csrutil)
    /// stay manual — Recovery boot can't be scripted from running
    /// macOS. The AMFI-bypass step (nvram boot-args) requires
    /// `--i-understand-the-tradeoffs`.
    #[arg(long, conflicts_with_all = ["check", "print"])]
    pub apply: bool,

    /// Acknowledge the AMFI-weakening security tradeoff. Required
    /// for the `--apply` path to run the `nvram boot-args` setup.
    /// Has no effect for `--check` or `--print`.
    #[arg(long)]
    pub i_understand_the_tradeoffs: bool,

    /// Override the helper binary path for the codesign step.
    /// Defaults to the same path the daemon would spawn (env
    /// `SHIT_HELPER_BIN` → `target/release/shit-helper` →
    /// `/usr/local/bin/shit-helper` → `/opt/homebrew/bin/shit-helper`).
    #[arg(long, value_name = "PATH")]
    pub helper_bin: Option<PathBuf>,

    /// Override the entitlement plist path for the codesign step.
    /// Defaults to the plist shipped in the release tarball under
    /// `packaging/codesign/macos-entitlements.plist`.
    #[arg(long, value_name = "PATH")]
    pub entitlement_plist: Option<PathBuf>,
}

pub fn run(args: SetupEsModeArgs) -> Result<(), CliError> {
    let modes = [args.check, args.print, args.apply];
    if !modes.iter().any(|x| *x) {
        return Err(CliError::fail(
            GENERIC_FAILURE,
            "shit setup-es-mode: pick one of --check / --print / --apply",
        ));
    }
    let sip = macos::probe_sip_state();
    let mut es = macos::probe_endpoint_security();
    es.helper_has_es_entitlement =
        macos::probe_helper_has_es_entitlement(args.helper_bin.as_deref());
    let (capable, blockers) = macos::compose_es_capable(&sip, &es);

    if args.check {
        return run_check(capable, &blockers);
    }
    if args.print {
        return run_print(capable, &blockers);
    }
    if args.apply {
        return run_apply(&args, capable, &blockers);
    }
    unreachable!("mode flag handled above")
}

fn run_check(capable: bool, blockers: &[EsBlocker]) -> Result<(), CliError> {
    println!("shit setup-es-mode: prereq check");
    println!();
    for (component, label) in &[
        ("sip", "SIP disabled                "),
        ("authenticated_root", "AuthRoot disabled           "),
        ("amfi_bypass", "AMFI bypass boot-arg set    "),
        ("helper_entitlement", "Helper carries ES entitlement"),
    ] {
        let pass = !blockers.iter().any(|b| b.component == *component);
        let symbol = if pass { "✓ pass" } else { "✗ FAIL" };
        println!("  [{symbol}] {label}");
    }
    println!();
    if capable {
        println!("Result: es_capable = TRUE. Power-user ES mode is live.");
        Ok(())
    } else {
        println!(
            "Result: es_capable = FALSE. Run `shit setup-es-mode --print` for the setup commands."
        );
        Err(CliError::fail(
            GENERIC_FAILURE,
            "one or more ES prereqs failed",
        ))
    }
}

fn run_print(capable: bool, blockers: &[EsBlocker]) -> Result<(), CliError> {
    if capable {
        println!("shit setup-es-mode: nothing to do — es_capable already TRUE.");
        return Ok(());
    }

    print_warnings_header();

    println!("# 1. Recovery-mode steps (manual)");
    println!("#");
    println!("# Boot into Recovery: power on while holding the power button (Apple Silicon)");
    println!("# or Cmd+R (Intel). Open Terminal from the menu bar, then run:");
    println!("#");
    let mut recovery_count = 0;
    for b in blockers.iter().filter(|b| b.recovery_mode) {
        recovery_count += 1;
        println!("#   # {}", b.reason);
        if let Some(cmd) = &b.fix_command {
            println!("    {cmd}");
        }
    }
    if recovery_count == 0 {
        println!("#   (Recovery already configured — skip to step 2.)");
    }
    println!();
    println!("# 2. Reboot, then back in macOS run the running-system steps:");
    println!("#");
    let mut running_count = 0;
    for b in blockers.iter().filter(|b| !b.recovery_mode) {
        running_count += 1;
        println!("#   # {}", b.reason);
        if let Some(cmd) = &b.fix_command {
            println!("    {cmd}");
        }
    }
    if running_count == 0 {
        println!("#   (no running-system steps needed)");
    }
    println!();
    println!("# 3. Verify:");
    println!("    shit setup-es-mode --check");
    println!();
    println!("# To REVERT later (restore SIP + AuthRoot + remove the AMFI bypass):");
    println!("#   - Boot into Recovery again, run:");
    println!("        csrutil enable");
    println!("        csrutil authenticated-root enable");
    println!("#   - Back in macOS:");
    println!("        sudo nvram -d boot-args");
    println!("#   - Reboot.");
    Ok(())
}

fn print_warnings_header() {
    println!("# ╔══════════════════════════════════════════════════════════════════╗");
    println!("# ║                  ⚠  YOU ARE ABOUT TO WEAKEN macOS SECURITY  ⚠       ║");
    println!("# ╠══════════════════════════════════════════════════════════════════╣");
    println!("# ║  These steps disable System Integrity Protection, the Apple        ║");
    println!("# ║  Silicon System volume seal, and the AMFI entitlement-check.       ║");
    println!("# ║  After running them:                                                ║");
    println!("# ║    • Gatekeeper signature verification is weakened                 ║");
    println!("# ║    • Kernel extension loading is less restricted                   ║");
    println!("# ║    • AppleCare may push back if you ever bring the Mac in          ║");
    println!("# ║    • Many enterprise compliance baselines (MDM) are violated       ║");
    println!("# ║                                                                    ║");
    println!("# ║  You gain: full arbitrary-command undo on this machine — `shit`    ║");
    println!("# ║  captures pre-image bytes for any syscall family ES covers.        ║");
    println!("# ║                                                                    ║");
    println!("# ║  This is appropriate for kernel developers, security researchers,  ║");
    println!("# ║  AI/ML environments that already load custom kexts, and similar    ║");
    println!("# ║  power-user setups. It is NOT appropriate for a primary work       ║");
    println!("# ║  machine that holds confidential corporate data.                   ║");
    println!("# ╚══════════════════════════════════════════════════════════════════╝");
    println!();
}

fn run_apply(
    args: &SetupEsModeArgs,
    capable: bool,
    blockers: &[EsBlocker],
) -> Result<(), CliError> {
    if capable {
        println!("shit setup-es-mode: nothing to do — es_capable already TRUE.");
        return Ok(());
    }

    // Recovery-mode pieces cannot be applied from running macOS.
    let recovery_blockers: Vec<&EsBlocker> = blockers.iter().filter(|b| b.recovery_mode).collect();
    if !recovery_blockers.is_empty() {
        println!("shit setup-es-mode --apply: pre-flight refusal.");
        println!();
        println!("The following prereqs require booting into Recovery and CANNOT be");
        println!("applied from running macOS:");
        for b in &recovery_blockers {
            println!(
                "  - {}: `{}`",
                b.component,
                b.fix_command.as_deref().unwrap_or("")
            );
        }
        println!();
        println!("Run `shit setup-es-mode --print` for the full step-by-step guide,");
        println!("then re-run `--apply` after Recovery + reboot has completed those steps.");
        return Err(CliError::fail(
            GENERIC_FAILURE,
            "recovery-mode steps remain; apply aborted",
        ));
    }

    // We have only running-system steps to apply. Each requires its
    // own opt-in flag because they have distinct security postures.
    for b in blockers {
        match b.component.as_str() {
            "amfi_bypass" => {
                if !args.i_understand_the_tradeoffs {
                    return Err(CliError::fail(
                        GENERIC_FAILURE,
                        "setting amfi_get_out_of_my_way requires --i-understand-the-tradeoffs",
                    ));
                }
                apply_amfi_bypass()?;
            }
            "helper_entitlement" => {
                apply_helper_codesign(args)?;
            }
            other => {
                return Err(CliError::fail(
                    GENERIC_FAILURE,
                    format!(
                        "unrecognized blocker component `{other}` in --apply path; please run --print"
                    ),
                ));
            }
        }
    }

    println!();
    println!("shit setup-es-mode --apply: done.");
    println!("Re-run `shit setup-es-mode --check` to verify (a reboot may be required");
    println!("for nvram boot-args changes to take effect).");
    Ok(())
}

fn apply_amfi_bypass() -> Result<(), CliError> {
    println!("→ setting nvram boot-args=\"amfi_get_out_of_my_way=0x1\" (sudo)");
    let status = Command::new("sudo")
        .args(["nvram", "boot-args=amfi_get_out_of_my_way=0x1"])
        .status()
        .map_err(|e| {
            CliError::fail(
                GENERIC_FAILURE,
                format!("spawn `sudo nvram boot-args=...`: {e}"),
            )
        })?;
    if !status.success() {
        return Err(CliError::fail(
            GENERIC_FAILURE,
            "sudo nvram boot-args=... returned non-zero",
        ));
    }
    println!("  ✓ boot-args set. Reboot required for AMFI to honor the change.");
    Ok(())
}

fn apply_helper_codesign(args: &SetupEsModeArgs) -> Result<(), CliError> {
    let helper = args
        .helper_bin
        .clone()
        .or_else(default_helper_path)
        .ok_or_else(|| {
            CliError::fail(
                GENERIC_FAILURE,
                "couldn't find shit-helper; pass --helper-bin",
            )
        })?;
    let plist = args
        .entitlement_plist
        .clone()
        .or_else(default_entitlement_plist)
        .ok_or_else(|| {
            CliError::fail(
                GENERIC_FAILURE,
                "couldn't find entitlement plist; pass --entitlement-plist",
            )
        })?;
    if !helper.exists() {
        return Err(CliError::fail(
            GENERIC_FAILURE,
            format!("helper path {} does not exist", helper.display()),
        ));
    }
    if !plist.exists() {
        return Err(CliError::fail(
            GENERIC_FAILURE,
            format!("entitlement plist {} does not exist", plist.display()),
        ));
    }
    println!(
        "→ codesigning {} with entitlement plist {} (sudo)",
        helper.display(),
        plist.display()
    );
    let status = Command::new("sudo")
        .args([
            "codesign",
            "--force",
            "--options",
            "runtime",
            "--entitlements",
        ])
        .arg(&plist)
        .args(["--sign", "-"])
        .arg(&helper)
        .status()
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("spawn `sudo codesign`: {e}")))?;
    if !status.success() {
        return Err(CliError::fail(
            GENERIC_FAILURE,
            "sudo codesign returned non-zero",
        ));
    }
    println!("  ✓ helper codesigned. Verify with `shit setup-es-mode --check`.");
    Ok(())
}

fn default_helper_path() -> Option<PathBuf> {
    if let Some(env) = std::env::var_os("SHIT_HELPER_BIN") {
        let p = PathBuf::from(env);
        if p.exists() {
            return Some(p);
        }
    }
    for candidate in [
        "target/release/shit-helper",
        "/usr/local/bin/shit-helper",
        "/opt/homebrew/bin/shit-helper",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn default_entitlement_plist() -> Option<PathBuf> {
    // Repo-relative for dev installs; an install-time copy lives at
    // the standard packaging path for release tarballs.
    for candidate in [
        "packaging/codesign/macos-entitlements.plist",
        "/usr/local/share/shit/macos-entitlements.plist",
        "/opt/homebrew/share/shit/macos-entitlements.plist",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_default_state_requires_mode_pick() {
        // Default args (no --check / --print / --apply) should refuse
        // in run() with the "pick one of" error.
        let args = SetupEsModeArgs {
            check: false,
            print: false,
            apply: false,
            i_understand_the_tradeoffs: false,
            helper_bin: None,
            entitlement_plist: None,
        };
        let err = run(args).unwrap_err();
        assert!(format!("{err:?}").contains("pick one of"));
    }
}
