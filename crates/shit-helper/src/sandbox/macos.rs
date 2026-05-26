// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS sandbox entry via `sandbox_init_with_parameters(3)`.
//!
//! M01 ships an `(allow default)` profile with targeted network denies.
//! This is intentionally conservative: the helper needs read-everywhere
//! to capture pre-images and Mach lookups for FSEvents (M01) +
//! EndpointSecurity (M03) + SecurityServer (M07 codesign verify), and
//! Apple's SBPL is undocumented enough that a `(deny default)` profile
//! at this stage risks helper crashes on syscalls we haven't enumerated.
//!
//! Tightening to `(deny default)` with an enumerated allow-list is M03
//! territory — by then the ES bus access is the only Mach lookup the
//! steady-state hot path needs, and the surface to whitelist is fully
//! known.
//!
//! M01 lock-down posture:
//! - `(deny network-outbound (remote ip))` — no outbound IP. Block
//!   accidental network calls; unix-domain sockets (the daemon UDS,
//!   the FSEvents-IPC FD passing) are unaffected.
//! - `(deny network-bind)` — helper never listens on a socket.
//! - `(allow default)` — everything else.
//!
//! `sandbox_init_with_parameters` is technically deprecated by Apple
//! but still functional; every privileged helper on macOS uses it
//! (Apple's own `mDNSResponder`, `cfprefsd`, etc.). The documented
//! replacement is App Sandbox via codesign entitlements, which is
//! for App-Store apps, not privileged helpers — wrong tool here.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::ptr;

unsafe extern "C" {
    /// `int sandbox_init_with_parameters(const char *profile, uint64_t flags,`
    /// `                                 const char *const parameters[],`
    /// `                                 char **errorbuf);`
    ///
    /// Returns 0 on success. On failure returns -1 and populates
    /// `*errorbuf` with a malloc'd C string the caller must free via
    /// [`sandbox_free_error`].
    fn sandbox_init_with_parameters(
        profile: *const c_char,
        flags: u64,
        parameters: *const *const c_char,
        errorbuf: *mut *mut c_char,
    ) -> c_int;

    /// Free an error buffer returned by `sandbox_init_with_parameters`.
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// SBPL (sandbox profile language) source. Apple's SBPL is Scheme-like
/// and undocumented; this profile is a deliberately small surface that
/// can be extended in M03 without rewriting.
///
/// `(param "STATE_DIR")` is substituted at load time from the parameter
/// array passed to `sandbox_init_with_parameters`. Currently unused in
/// M01's `(allow default)` posture but kept for the M03 transition.
const PROFILE: &str = r#"(version 1)
(allow default)
(deny network-outbound (remote ip))
(deny network-bind)
"#;

pub fn enter(state_dir: &Path) -> anyhow::Result<()> {
    let profile = CString::new(PROFILE)
        .map_err(|e| anyhow::anyhow!("profile contains interior NUL: {e}"))?;

    // The STATE_DIR parameter is unused by the M01 profile body but
    // we still pass it so the parameter-array shape matches what M03
    // will need. `sandbox_init_with_parameters` accepts a NULL-
    // terminated array of `key, value, key, value, ..., NULL`.
    let state_dir_str = state_dir.to_string_lossy();
    let key = CString::new("STATE_DIR")?;
    let value = CString::new(state_dir_str.as_ref())
        .map_err(|e| anyhow::anyhow!("state_dir contains interior NUL: {e}"))?;
    let params: [*const c_char; 3] = [key.as_ptr(), value.as_ptr(), ptr::null()];

    let mut errbuf: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        sandbox_init_with_parameters(profile.as_ptr(), 0, params.as_ptr(), &mut errbuf)
    };

    if rc != 0 {
        let msg = if errbuf.is_null() {
            "sandbox_init_with_parameters failed (no error message)".to_string()
        } else {
            let s = unsafe { CStr::from_ptr(errbuf) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandbox_free_error(errbuf) };
            s
        };
        // Conservative posture: warn and continue rather than refuse
        // to start. A misconfigured profile shouldn't brick the
        // helper — better to run un-sandboxed and log loudly.
        // M03 will tighten this to hard-fail once the profile is
        // exercised by integration tests.
        tracing::warn!(
            error = %msg,
            "sandbox_init_with_parameters failed; helper continues unsandboxed"
        );
        return Ok(());
    }

    tracing::info!(
        state_dir = %state_dir.display(),
        "macos sandbox profile installed (allow-default + network-outbound IP deny)"
    );
    Ok(())
}
