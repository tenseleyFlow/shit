// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code)]

//! Interactive confirmation prompts (S12.3).
//!
//! Three contracts:
//! 1. **Non-TTY stdin refuses to prompt.** A user piping into `shit` or
//!    invoking from a non-interactive shell must pass `--yes`; we don't
//!    silently hang on `read_line`.
//! 2. **The default answer is risk-aware.** Low-risk plans default to
//!    `Y` (uppercase = default); risky plans default to `N`. Callers
//!    classify their plan and pass the appropriate `Risk`.
//! 3. **The five-option Apply prompt** (`y/N/d/e/q`) is the standard
//!    surface for `shit undo`. `d` shows details, `e` enters the
//!    partial-undo picker (stage-2 work — DR-17), `q` cancels.
//!
//! Stage 1: dialoguer isn't a dep yet. We use `std::io::stdin` directly
//! for simple y/n; the `Apply` prompt and the partial-undo picker
//! return a stage-1 stub that defers to `--yes`. Adding dialoguer when
//! we wire the actual interactive picker is a one-line change here.

use std::io::{IsTerminal, Write};

/// How "destructive" the operation is. Drives the default answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Common case — a file restore in the user's own home.
    Low,
    /// Touches files outside the user's home, system paths, or a
    /// large number of files. Forces explicit `y`.
    High,
}

#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    #[error("non-interactive stdin: refusing to prompt; pass --yes to confirm")]
    NotInteractive,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("user cancelled")]
    Cancelled,
}

/// User's decision on the `Apply?` prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyDecision {
    /// Apply the plan as-is.
    Apply,
    /// Render full details and re-prompt (caller responsible for the loop).
    ShowDetails,
    /// Enter the partial-undo picker. **Stage 1**: surfaces a clear
    /// "not yet implemented" message; for now, treat as ShowDetails.
    EditSelection,
    /// Cancel.
    Cancel,
}

/// Simple yes/no confirm. Returns the bool the user picked, or
/// `PromptError::NotInteractive` if stdin isn't a TTY.
pub fn confirm(question: &str, risk: Risk) -> Result<bool, PromptError> {
    if !std::io::stdin().is_terminal() {
        return Err(PromptError::NotInteractive);
    }
    // Default answer per risk.
    let default = matches!(risk, Risk::Low);
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    eprint!("{question} {suffix} ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(parse_yes_no(line.trim(), default))
}

/// Five-option Apply prompt. Caller already rendered the plan summary;
/// this just reads the keypress and returns the decision.
pub fn apply_prompt(risk: Risk) -> Result<ApplyDecision, PromptError> {
    if !std::io::stdin().is_terminal() {
        return Err(PromptError::NotInteractive);
    }
    let default_marker = if matches!(risk, Risk::Low) { "Y" } else { "N" };
    // Lowercase non-default options.
    let prompt = match risk {
        Risk::Low => format!("Apply? [{default_marker}/n/d/e/q] "),
        Risk::High => format!("Apply? [y/{default_marker}/d/e/q] "),
    };
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(parse_apply_response(line.trim(), risk))
}

fn parse_yes_no(input: &str, default: bool) -> bool {
    if input.is_empty() {
        return default;
    }
    matches!(input.to_lowercase().as_str(), "y" | "yes")
}

fn parse_apply_response(input: &str, risk: Risk) -> ApplyDecision {
    let default = match risk {
        Risk::Low => ApplyDecision::Apply,
        Risk::High => ApplyDecision::Cancel,
    };
    match input.to_lowercase().as_str() {
        "" => default,
        "y" | "yes" => ApplyDecision::Apply,
        "n" | "no" => ApplyDecision::Cancel,
        "d" | "details" => ApplyDecision::ShowDetails,
        "e" | "edit" => ApplyDecision::EditSelection,
        "q" | "quit" | "cancel" => ApplyDecision::Cancel,
        // Unknown input: safest fallback is the default for the risk.
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_no_default_applied_on_empty() {
        assert!(parse_yes_no("", true));
        assert!(!parse_yes_no("", false));
    }

    #[test]
    fn yes_no_recognizes_common_forms() {
        assert!(parse_yes_no("y", false));
        assert!(parse_yes_no("Y", false));
        assert!(parse_yes_no("yes", false));
        assert!(parse_yes_no("YES", false));
        assert!(!parse_yes_no("n", true));
        assert!(!parse_yes_no("no", true));
    }

    #[test]
    fn apply_default_low_is_apply() {
        assert_eq!(parse_apply_response("", Risk::Low), ApplyDecision::Apply);
    }

    #[test]
    fn apply_default_high_is_cancel() {
        assert_eq!(parse_apply_response("", Risk::High), ApplyDecision::Cancel);
    }

    #[test]
    fn apply_recognizes_all_five() {
        assert_eq!(parse_apply_response("y", Risk::High), ApplyDecision::Apply);
        assert_eq!(parse_apply_response("n", Risk::Low), ApplyDecision::Cancel);
        assert_eq!(
            parse_apply_response("d", Risk::Low),
            ApplyDecision::ShowDetails
        );
        assert_eq!(
            parse_apply_response("e", Risk::Low),
            ApplyDecision::EditSelection
        );
        assert_eq!(parse_apply_response("q", Risk::Low), ApplyDecision::Cancel);
    }

    #[test]
    fn apply_unknown_input_falls_back_to_default() {
        assert_eq!(parse_apply_response("zzz", Risk::Low), ApplyDecision::Apply);
        assert_eq!(
            parse_apply_response("zzz", Risk::High),
            ApplyDecision::Cancel
        );
    }
}
