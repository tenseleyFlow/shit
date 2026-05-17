// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable CLI exit codes. **API-shaped** — scripts depend on these.
//!
//! Spec lives in S12 sprint plan. The man pages (S12.9) reference this
//! module as the source of truth; if you add a code, document it
//! there in the same commit.
//!
//! ## Why codes are an API
//!
//! Users will write shell pipelines like:
//!
//! ```sh
//! shit undo --yes || case $? in
//!   2) echo "conflict — re-run with --on-conflict=skip" ;;
//!   3) echo "daemon down" ;;
//!   *) echo "other failure" ;;
//! esac
//! ```
//!
//! Stable codes let those pipelines keep working across versions. The
//! contract: codes are append-only. Once shipped, a code's meaning
//! never changes; new failure classes get new codes.

use std::process::ExitCode;

/// 0 — success.
pub const SUCCESS: u8 = 0;
/// 1 — generic failure (user error, unexpected I/O, parse error, etc.).
/// Avoid using this for cases that match a more specific code below.
pub const GENERIC_FAILURE: u8 = 1;
/// 2 — conflict requiring user attention. Live state diverged from
/// captured state and no `--on-conflict` policy resolved it.
pub const CONFLICT: u8 = 2;
/// 3 — daemon unavailable. The CLI tried to reach `shitd` and could
/// not (no socket, refused connection, handshake failed).
pub const DAEMON_UNAVAILABLE: u8 = 3;
/// 4 — helper unavailable or running degraded. Kernel-tier capture is
/// off; commands that require it are refused.
pub const HELPER_UNAVAILABLE: u8 = 4;
/// 5 — capture protection denied a command (hard-fail). Used by the
/// shell hook integration, not the CLI subcommands directly; surfaced
/// here so the man page can name it.
pub const CAPTURE_DENIED: u8 = 5;

/// Convert a numeric code to a `process::ExitCode`. Just a wrapper to
/// keep call sites tidy.
pub fn exit(code: u8) -> ExitCode {
    ExitCode::from(code)
}

/// Typed error carrying an exit code. `main()` maps these to the
/// process exit; subcommand functions return
/// `Result<(), CliError>` so the code is part of the type system.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// User-facing message; rendered to stderr; exit code from
    /// `code()` below.
    #[error("{message}")]
    Failed { code: u8, message: String },

    /// Underlying I/O. Maps to GENERIC_FAILURE unless the caller
    /// remaps via `.map_err(CliError::with_code)`.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Anything anyhow's chain produces. Same default mapping as Io.
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl CliError {
    pub fn code(&self) -> u8 {
        match self {
            Self::Failed { code, .. } => *code,
            Self::Io(_) | Self::Other(_) => GENERIC_FAILURE,
        }
    }

    /// Convenience constructor for the common case.
    pub fn fail(code: u8, message: impl Into<String>) -> Self {
        Self::Failed {
            code,
            message: message.into(),
        }
    }
}

/// Run a `Result<(), CliError>` and translate to a process exit code,
/// printing the error message to stderr on failure.
pub fn run<F>(f: F) -> ExitCode
where
    F: FnOnce() -> Result<(), CliError>,
{
    match f() {
        Ok(()) => exit(SUCCESS),
        Err(e) => {
            eprintln!("shit: {e}");
            exit(e.code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_code_overrides_default() {
        let e = CliError::fail(CONFLICT, "test conflict");
        assert_eq!(e.code(), CONFLICT);
    }

    #[test]
    fn io_error_maps_to_generic() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "x");
        let e: CliError = io_err.into();
        assert_eq!(e.code(), GENERIC_FAILURE);
    }

    #[test]
    fn anyhow_maps_to_generic() {
        let e: CliError = anyhow::anyhow!("boom").into();
        assert_eq!(e.code(), GENERIC_FAILURE);
    }

    #[test]
    fn codes_are_distinct() {
        // Catches accidental duplicate assignment.
        let codes = [
            SUCCESS,
            GENERIC_FAILURE,
            CONFLICT,
            DAEMON_UNAVAILABLE,
            HELPER_UNAVAILABLE,
            CAPTURE_DENIED,
        ];
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a, b, "duplicate exit code");
            }
        }
    }
}
