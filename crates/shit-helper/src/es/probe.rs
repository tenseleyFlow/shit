// SPDX-License-Identifier: AGPL-3.0-or-later

//! ES client-creation probe (M03.1.B).
//!
//! Asks the kernel "can this binary subscribe to ES?" by calling
//! `es_new_client` with a no-op global block handler, then
//! immediately tearing down via `es_delete_client`. Returns the
//! kernel's verdict as a [`ProbeResult`] enum.
//!
//! This is what M02's `probe_endpoint_security` stub becomes once
//! wired (M03.1.C) — the doctor surface uses this to flip the
//! `endpoint_security.entitlement_present` JSON field truthful.
//!
//! ## What the probe is safe for
//!
//! - Calling on any macOS box: SIP-on stock Mac, SIP-disabled VM,
//!   notarized release build — the probe correctly reports each.
//! - Calling repeatedly: each invocation is independent; no
//!   accumulated state.
//! - Calling unprivileged: returns `NotPrivileged` instead of
//!   crashing.
//!
//! ## What it is NOT
//!
//! - A subscription. We never call `es_subscribe`. Nothing gets
//!   delivered to our handler; the kernel doesn't queue events for
//!   our client. The handler is required by the C API contract
//!   only.
//! - A long-lived client. We tear down within milliseconds.

#![cfg(target_os = "macos")]

use std::ffi::c_void;
use std::ptr;

use super::sys;

/// Result of asking the kernel "can this binary subscribe?"
///
/// Maps from `es_new_client_result_t`. The doctor surface (M03.1.C)
/// collapses these into bool fields plus a remediation string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// `es_new_client` returned SUCCESS. Binary is entitled + FDA
    /// granted (or SIP is off, which bypasses both checks). The
    /// runtime ES tier is operational.
    Success,
    /// Binary lacks the `com.apple.developer.endpoint-security.client`
    /// entitlement AND SIP isn't disabled. This is the default
    /// state on stock macOS for any binary we haven't signed +
    /// notarized with the entitlement.
    NotEntitled,
    /// Binary has the entitlement but TCC hasn't granted Full Disk
    /// Access. User-fixable via System Settings → Privacy & Security
    /// → Full Disk Access.
    NotPermitted,
    /// Binary not running as root. Some ES paths require root even
    /// after entitlement; this surfaces the gap.
    NotPrivileged,
    /// `es_new_client` returned ERR_INVALID_ARGUMENT. Indicates a
    /// bug on our side (typically a null handler block). The probe
    /// passes a valid global block so this should never fire in
    /// practice.
    InvalidArgument,
    /// ES subsystem internal error. Surfaces ES-runtime issues
    /// (host-side problems beyond our control). Rare.
    InternalError,
    /// System hit the per-host ES client limit.
    TooManyClients,
    /// `es_new_client` returned a discriminant we don't know about.
    /// Carries the raw u32 for diagnostic purposes — Apple may add
    /// new error codes in future macOS releases.
    UnknownResult(u32),
}

impl ProbeResult {
    /// True iff a real ES client could be created right now.
    /// Used by future M03 slices that gate on "ES is real" — the
    /// M03.1.C doctor wiring uses pattern-matching instead of this
    /// helper. `#[cfg_attr(not(test), ...)]` keeps dead-code quiet
    /// until then.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_success(&self) -> bool {
        matches!(self, ProbeResult::Success)
    }

    /// One-line human-facing label. Used by future probe-CLI dump
    /// code and by tests; `cfg_attr` for the same dead-code reason.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn label(&self) -> &'static str {
        match self {
            ProbeResult::Success => "ES client created successfully",
            ProbeResult::NotEntitled => {
                "missing com.apple.developer.endpoint-security.client entitlement \
                 (or SIP is not disabled for dev)"
            }
            ProbeResult::NotPermitted => "TCC has not granted Full Disk Access to the helper",
            ProbeResult::NotPrivileged => "helper not running as root",
            ProbeResult::InvalidArgument => "ES rejected our handler block (probe bug)",
            ProbeResult::InternalError => "ES subsystem internal error",
            ProbeResult::TooManyClients => "host has too many active ES clients",
            ProbeResult::UnknownResult(_) => "unknown es_new_client_result_t value",
        }
    }
}

/// Attempt to create + immediately destroy an ES client. Returns the
/// kernel's verdict as a [`ProbeResult`].
///
/// Safe: the unsafe FFI is contained; the static `NOOP_HANDLER`
/// global block is valid for the lifetime of the program; we tear
/// down on every path (drop scope or explicit `es_delete_client`).
pub fn probe_client_creation() -> ProbeResult {
    let mut client: *mut sys::es_client_t = ptr::null_mut();
    // SAFETY: `&mut client` is valid; `&sys::NOOP_HANDLER` lives in
    // BSS for the program's lifetime; both are required by ES.
    let result = unsafe {
        sys::es_new_client(
            &mut client as *mut *mut sys::es_client_t,
            &sys::NOOP_HANDLER as *const _ as *const c_void,
        )
    };

    match result {
        sys::es_new_client_result_t::SUCCESS => {
            // Got a client; tear it down immediately.
            if !client.is_null() {
                // SAFETY: `client` is the valid pointer ES just gave
                // us; we delete on the same thread that created it
                // (Apple's documented requirement).
                let _ = unsafe { sys::es_delete_client(client) };
            }
            ProbeResult::Success
        }
        sys::es_new_client_result_t::ERR_NOT_ENTITLED => ProbeResult::NotEntitled,
        sys::es_new_client_result_t::ERR_NOT_PERMITTED => ProbeResult::NotPermitted,
        sys::es_new_client_result_t::ERR_NOT_PRIVILEGED => ProbeResult::NotPrivileged,
        sys::es_new_client_result_t::ERR_INVALID_ARGUMENT => ProbeResult::InvalidArgument,
        sys::es_new_client_result_t::ERR_INTERNAL => ProbeResult::InternalError,
        sys::es_new_client_result_t::ERR_TOO_MANY_CLIENTS => ProbeResult::TooManyClients,
        sys::es_new_client_result_t(raw) => ProbeResult::UnknownResult(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_strings_are_non_empty() {
        for r in [
            ProbeResult::Success,
            ProbeResult::NotEntitled,
            ProbeResult::NotPermitted,
            ProbeResult::NotPrivileged,
            ProbeResult::InvalidArgument,
            ProbeResult::InternalError,
            ProbeResult::TooManyClients,
            ProbeResult::UnknownResult(99),
        ] {
            assert!(!r.label().is_empty(), "label empty for {r:?}");
        }
    }

    #[test]
    fn is_success_only_true_for_success() {
        assert!(ProbeResult::Success.is_success());
        for r in [
            ProbeResult::NotEntitled,
            ProbeResult::NotPermitted,
            ProbeResult::NotPrivileged,
            ProbeResult::InvalidArgument,
            ProbeResult::InternalError,
            ProbeResult::TooManyClients,
            ProbeResult::UnknownResult(99),
        ] {
            assert!(!r.is_success(), "is_success() should be false for {r:?}");
        }
    }

    /// End-to-end against the local machine. On the dev Mac (SIP-on,
    /// no entitlement) we expect `NotEntitled`. On the SIP-disabled
    /// Tart VM we expect `Success`. Either way the call must not
    /// crash.
    #[test]
    fn probe_returns_a_known_result_on_this_host() {
        let r = probe_client_creation();
        // We don't pin to a specific value — host environment
        // determines it. We just verify the FFI works + we get a
        // ProbeResult variant we understand.
        match r {
            ProbeResult::Success
            | ProbeResult::NotEntitled
            | ProbeResult::NotPermitted
            | ProbeResult::NotPrivileged
            | ProbeResult::InvalidArgument
            | ProbeResult::InternalError
            | ProbeResult::TooManyClients => {
                eprintln!("probe outcome on this host: {} ({:?})", r.label(), r);
            }
            ProbeResult::UnknownResult(raw) => {
                eprintln!("probe returned unknown discriminant {raw}; investigate");
            }
        }
    }
}
