// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vendored EndpointSecurity FFI surface for M03.
//!
//! Mirrors the relevant subset of `<EndpointSecurity/EndpointSecurity.h>`
//! and `<EndpointSecurity/ESClient.h>`. Modeled on
//! `HarfangLab/endpoint-sec/endpoint-sec-sys` (cloned at
//! `.docs/refs/endpoint-sec` for reference; MIT-licensed) but
//! vendored inline to match the project's "own the FFI" pattern
//! (`shit-capture/src/cow/clonefile_macos.rs`, raw kqueue via libc
//! on BSD, the FSEvents bindings in `src/fsevents.rs`).
//!
//! ## Why an Apple Block, not a plain extern "C" fn
//!
//! ES message handlers are typed as
//! `void (^)(es_client_t *, es_message_t *)` — an Apple Block, not a
//! C function pointer. Blocks have a fixed binary layout (Apple's
//! block-ABI spec) that we vendor below.
//!
//! For the probe slice (M03.1.A) we only need a no-op *global*
//! block (stateless, no captures, lives in BSS). That's the simplest
//! Block variant: a static `Block` literal with `BLOCK_IS_GLOBAL`
//! set + an invoke trampoline that ignores its args.
//!
//! Subsequent M03 slices that actually consume `es_message_t` will
//! either:
//! - Extend this to a *stack* Block carrying captured state (the
//!   pump's mpsc Sender), OR
//! - Build a small heap-block-allocator helper here.
//!
//! ## Subset vendored (M03.1.A scope only)
//!
//! - `es_client_t` (opaque)
//! - `es_new_client_result_t` enum
//! - `es_return_t` enum
//! - `es_new_client` / `es_delete_client` extern fns
//! - Minimal `Block` literal + descriptor + `_NSConcreteGlobalBlock`
//!   external symbol
//! - `noop_handler_block` — pre-built static global Block for the
//!   probe
//!
//! Subsequent slices add: `es_message_t`, `es_event_type_t`,
//! `es_auth_result_t`, `es_subscribe`, `es_respond_auth_result`,
//! `es_mute_path`, `audit_token_t`, message field accessors, ...

#![allow(non_camel_case_types)]

use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::raw::{c_int, c_ulong};

// ─────────────────────────────────────────────────────────────────────
// Event type discriminants (mirror `es_event_type_t` from
// <EndpointSecurity/types.h>)
// ─────────────────────────────────────────────────────────────────────
//
// Only the variants M03 actually subscribes to land here. Adding a
// variant is a 1-line edit; we deliberately don't paste the full
// enum (~120 events) since unused entries are dead code by default.

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct es_event_type_t(pub u32);

impl es_event_type_t {
    /// NOTIFY events — no response required, just informational.
    /// M03.1.E subscribes to this for the subscribe-deliver smoke.
    /// AUTH_OPEN/AUTH_RENAME/AUTH_UNLINK/NOTIFY_FORK/NOTIFY_EXIT
    /// get added back here when M03.1.F+ slices land.
    pub const NOTIFY_EXEC: Self = Self(9);
}

// ─────────────────────────────────────────────────────────────────────
// Result enums (mirror C enum values from <EndpointSecurity/types.h>)
// ─────────────────────────────────────────────────────────────────────

/// `es_new_client_result_t` — discriminated by C enum values 0..=6.
///
/// Stable since macOS 10.15.0; `ERR_TOO_MANY_CLIENTS = 6` added in
/// 10.15.1 (we accept it on all macOS we care about — 13+).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct es_new_client_result_t(pub u32);

impl es_new_client_result_t {
    /// Success — caller holds a valid `*mut es_client_t`.
    pub const SUCCESS: Self = Self(0);
    /// `es_new_client` got malformed input (typically a null handler).
    pub const ERR_INVALID_ARGUMENT: Self = Self(1);
    /// ES subsystem comms error.
    pub const ERR_INTERNAL: Self = Self(2);
    /// Binary lacks `com.apple.developer.endpoint-security.client`
    /// entitlement (the M03 production path) AND SIP isn't disabled
    /// (the M03 dev path).
    pub const ERR_NOT_ENTITLED: Self = Self(3);
    /// Caller doesn't have Full Disk Access. Entitlement may be
    /// present; this is the TCC gate.
    pub const ERR_NOT_PERMITTED: Self = Self(4);
    /// Caller isn't root.
    pub const ERR_NOT_PRIVILEGED: Self = Self(5);
    /// Too many active ES clients on the system.
    pub const ERR_TOO_MANY_CLIENTS: Self = Self(6);
}

/// `es_return_t` — generic 2-state success/error return for ES APIs.
/// Used by `es_delete_client` and (in M03.1.D+) `es_subscribe`,
/// `es_respond_auth_result`, etc. The constants here are read by
/// callers we haven't built yet; `#[cfg_attr(not(test), ...)]` keeps
/// the bin-target dead-code lint quiet until then.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct es_return_t(pub u32);

impl es_return_t {
    #[cfg_attr(not(test), allow(dead_code))]
    pub const SUCCESS: Self = Self(0);
    #[cfg_attr(not(test), allow(dead_code))]
    pub const ERROR: Self = Self(1);
}

// ─────────────────────────────────────────────────────────────────────
// Opaque client handle
// ─────────────────────────────────────────────────────────────────────

/// Opaque ES client. Neither `Send` nor `Sync` per Apple's doc —
/// `es_delete_client` must run on the same thread that created the
/// client. The probe creates + deletes on the calling thread; longer-
/// lived clients (M03.1.B+ slices) keep the value local to a worker
/// thread.
#[repr(transparent)]
pub struct es_client_t(u8, PhantomData<*mut u8>);

// ─────────────────────────────────────────────────────────────────────
// Apple Block ABI — minimal global-block subset
// ─────────────────────────────────────────────────────────────────────
//
// Reference: https://clang.llvm.org/docs/Block-ABI-Apple.html
//
// A "global block" lives in static storage with `BLOCK_IS_GLOBAL`
// flag set; the runtime never copies or refcounts it. That's the
// simplest variant and what we need for a stateless probe handler.

/// Flags bits in `Block_literal.flags`. Only `BLOCK_IS_GLOBAL` is
/// relevant for the M03.1.A probe.
const BLOCK_IS_GLOBAL: c_int = 1 << 28;

#[repr(C)]
struct BlockDescriptor {
    reserved: c_ulong,
    /// Total size of the Block_literal (must match `Block::size_of_self()`).
    size: c_ulong,
}

/// Layout-compatible with `struct Block_literal_1` from the
/// block-ABI spec. We don't include the optional copy/dispose
/// helpers — global blocks don't use them.
#[repr(C)]
pub struct Block<F: 'static> {
    /// Set to `&_NSConcreteGlobalBlock` so the runtime recognizes
    /// the layout.
    isa: *const c_void,
    flags: c_int,
    reserved: c_int,
    /// Trampoline that calls our Rust handler. First arg is always
    /// `*const Block<F>` (block-ABI convention).
    invoke: *const c_void,
    descriptor: *const BlockDescriptor,
    /// Marker so the compiler can carry F's variance through.
    _phantom: PhantomData<F>,
}

// Apple guarantees global blocks are immutable + thread-safe — every
// invocation reads the same static memory.
unsafe impl<F: 'static> Sync for Block<F> {}
unsafe impl<F: 'static> Send for Block<F> {}

#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    /// Block class for global (static) blocks. The runtime checks
    /// `block->isa == _NSConcreteGlobalBlock` to skip copy/dispose.
    static _NSConcreteGlobalBlock: c_void;
}

// ─────────────────────────────────────────────────────────────────────
// Probe handler — no-op block
// ─────────────────────────────────────────────────────────────────────

/// The C signature ES will invoke against our handler:
/// `void(es_client_t *client, es_message_t *message)`
///
/// Block-ABI prepends an implicit `*const Block` first arg.
/// Used by the `block_invoke_signature_is_callable` compile-only
/// test; gated for the bin-target dead-code lint.
#[cfg_attr(not(test), allow(dead_code))]
type BlockInvoke =
    extern "C" fn(block: *const Block<()>, client: *mut es_client_t, message: *const c_void);

/// Trampoline for the probe's no-op handler. ES will never call this
/// in the probe path (we tear down before subscribing) but the API
/// requires a non-null handler.
extern "C" fn noop_invoke(
    _block: *const Block<()>,
    _client: *mut es_client_t,
    _message: *const c_void,
) {
}

static NOOP_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: core::mem::size_of::<Block<()>>() as c_ulong,
};

/// Pre-built global Block we pass to `es_new_client` in the probe.
/// Lives in BSS; `BLOCK_IS_GLOBAL` makes the runtime treat it as
/// immutable + thread-safe.
pub static NOOP_HANDLER: Block<()> = Block {
    isa: unsafe { &_NSConcreteGlobalBlock as *const _ },
    flags: BLOCK_IS_GLOBAL,
    reserved: 0,
    invoke: noop_invoke as *const c_void,
    descriptor: &NOOP_DESCRIPTOR,
    _phantom: PhantomData,
};

// ─────────────────────────────────────────────────────────────────────
// Counter handler — increments a static atomic for every delivered
// message. Used by M03.1.E to prove the subscribe→deliver loop works
// (counter > 0 after subscribing to a high-frequency NOTIFY event).
// ─────────────────────────────────────────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

/// Global event counter. Single-shared because we only have one
/// EsClient per process. Reads + writes via atomics — the ES
/// callback runs on a kernel thread Apple owns.
pub static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

extern "C" fn counter_invoke(
    _block: *const Block<()>,
    _client: *mut es_client_t,
    _message: *const c_void,
) {
    EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
}

static COUNTER_DESCRIPTOR: BlockDescriptor = BlockDescriptor {
    reserved: 0,
    size: core::mem::size_of::<Block<()>>() as c_ulong,
};

/// Pre-built global Block that increments [`EVENT_COUNTER`] on every
/// delivery. Used by M03.1.E's subscribe-deliver smoke test. Does
/// NOT call `es_respond_auth_result` — only safe to use with NOTIFY
/// events that don't require a response.
pub static COUNTER_HANDLER: Block<()> = Block {
    isa: unsafe { &_NSConcreteGlobalBlock as *const _ },
    flags: BLOCK_IS_GLOBAL,
    reserved: 0,
    invoke: counter_invoke as *const c_void,
    descriptor: &COUNTER_DESCRIPTOR,
    _phantom: PhantomData,
};

// ─────────────────────────────────────────────────────────────────────
// ES extern fns
// ─────────────────────────────────────────────────────────────────────

#[link(name = "EndpointSecurity", kind = "dylib")]
unsafe extern "C" {
    /// `es_new_client_result_t es_new_client(es_client_t **client,`
    /// `                                     es_handler_block_t handler);`
    ///
    /// On `SUCCESS` writes a non-NULL `*mut es_client_t` to `*client`.
    /// `handler` is an Apple Block (see `Block<F>` above).
    pub fn es_new_client(
        client: *mut *mut es_client_t,
        handler: *const c_void,
    ) -> es_new_client_result_t;

    /// `es_return_t es_delete_client(es_client_t *client);`
    ///
    /// Must run on the same thread that called `es_new_client`.
    pub fn es_delete_client(client: *mut es_client_t) -> es_return_t;

    /// `es_return_t es_subscribe(es_client_t *client,`
    /// `                         const es_event_type_t *events,`
    /// `                         uint32_t event_count);`
    ///
    /// Subscribe an existing client to a set of event types.
    /// Subscriptions are additive — calling again with new types
    /// extends the subscription set rather than replacing it.
    pub fn es_subscribe(
        client: *mut es_client_t,
        events: *const es_event_type_t,
        event_count: u32,
    ) -> es_return_t;
}

// ─────────────────────────────────────────────────────────────────────
// Tests — pure compile-checks for now (real probe smoke is in M03.1.B
// + the doctor surface in M03.1.C).
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn result_enum_discriminants_match_apple() {
        // Sanity: ensure the constants match Apple's header values
        // exactly. If Apple ever renumbers these (they haven't since
        // 10.15) this catches the drift.
        assert_eq!(es_new_client_result_t::SUCCESS.0, 0);
        assert_eq!(es_new_client_result_t::ERR_INVALID_ARGUMENT.0, 1);
        assert_eq!(es_new_client_result_t::ERR_INTERNAL.0, 2);
        assert_eq!(es_new_client_result_t::ERR_NOT_ENTITLED.0, 3);
        assert_eq!(es_new_client_result_t::ERR_NOT_PERMITTED.0, 4);
        assert_eq!(es_new_client_result_t::ERR_NOT_PRIVILEGED.0, 5);
        assert_eq!(es_new_client_result_t::ERR_TOO_MANY_CLIENTS.0, 6);
        // es_return_t — same drift-check for the generic enum.
        assert_eq!(es_return_t::SUCCESS.0, 0);
        assert_eq!(es_return_t::ERROR.0, 1);
    }

    #[test]
    fn noop_handler_has_global_block_flag() {
        // Verifies the static-init produced a global block with the
        // right flag bit. If this ever flips off, the runtime would
        // try to refcount / dispose our static block.
        assert_eq!(NOOP_HANDLER.flags & BLOCK_IS_GLOBAL, BLOCK_IS_GLOBAL);
        assert_eq!(
            NOOP_HANDLER.descriptor as usize,
            &NOOP_DESCRIPTOR as *const _ as usize
        );
    }

    #[test]
    fn block_invoke_signature_is_callable() {
        // Compile-only check: NOOP_HANDLER.invoke must be the right
        // function-pointer type. If the type ever drifts, this stops
        // compiling.
        let _checked: BlockInvoke = noop_invoke;
    }
}
