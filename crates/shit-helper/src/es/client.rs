// SPDX-License-Identifier: AGPL-3.0-or-later

//! Long-lived ES client (M03.1.E).
//!
//! Wraps `es_new_client` + `es_subscribe` + (in later slices)
//! `es_respond_auth_result` in a safe Rust API that owns the client
//! lifetime + the static event sink the kernel callback uses.
//!
//! ## Slice 1 (M03.1.E) — counter-only
//!
//! `EsClient::new_counting()` subscribes to NOTIFY_EXEC with the
//! [`super::sys::COUNTER_HANDLER`] global block. Each delivered
//! message increments `super::sys::EVENT_COUNTER`. No response
//! required (NOTIFY events are informational), no message decode,
//! no capture. Just proves the kernel→helper loop is alive.
//!
//! ## Single-client constraint
//!
//! Apple's ES allows multiple clients per process, but we share one
//! static counter + one static handler block. Holding more than one
//! `EsClient` at a time is allowed but its events mix into the
//! shared counter. The helper process only ever runs one ES
//! subscription, so this is fine in practice.
//!
//! ## Later slices
//!
//! - M03.1.F adds `EsClient::new_for_capture(sink)` taking a
//!   `Sender<EsRecord>`. The handler decodes `es_message_t` and
//!   pipes the record to the worker thread for capture-and-respond.
//! - M03.1.G adds the AUTH_OPEN/UNLINK/RENAME etc. subscription set
//!   + the `es_respond_auth_result` ALLOW path.
//! - M03.1.H adds the ring buffer between the kernel callback and
//!   the capture worker, with a watchdog for the 5-s auth timeout.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::Ordering;

use super::sys;

#[derive(Debug, thiserror::Error)]
pub enum EsClientError {
    #[error("es_new_client failed: {0:?}")]
    NewClient(sys::es_new_client_result_t),
    #[error("es_subscribe failed: {0:?}")]
    Subscribe(sys::es_return_t),
}

/// Long-lived ES client wrapping an `*mut es_client_t`.
///
/// Drop tears down via `es_delete_client`. Apple documents that
/// `es_delete_client` must run on the same thread as `es_new_client`
/// — `EsClient` is `!Send` to enforce this at compile time.
pub struct EsClient {
    client: *mut sys::es_client_t,
    /// Starting value of `EVENT_COUNTER` at construction; lets
    /// callers ask "how many events have I received?" without being
    /// affected by counter state from previous clients.
    start_count: u64,
    /// Prevents Send/Sync — the kernel thread that runs the callback
    /// is owned by Apple; we don't move the client across threads.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl EsClient {
    /// Subscribe to NOTIFY_EXEC with the counter handler. This is
    /// the Slice-1 smoke shape — every process exec on the system
    /// bumps [`super::sys::EVENT_COUNTER`].
    ///
    /// Requires the binary to be ad-hoc-signed with the ES
    /// entitlement embedded (see
    /// `packaging/codesign/macos-entitlements.plist`) AND running
    /// in an env where AMFI accepts that claim (SIP+AuthRoot+AMFI-
    /// bypassed VM, or production signed-and-notarized + Apple
    /// paperwork landed).
    pub fn new_counting() -> Result<Self, EsClientError> {
        let mut client: *mut sys::es_client_t = ptr::null_mut();
        let result = unsafe {
            sys::es_new_client(
                &mut client as *mut *mut sys::es_client_t,
                &sys::COUNTER_HANDLER as *const _ as *const c_void,
            )
        };
        if result != sys::es_new_client_result_t::SUCCESS {
            return Err(EsClientError::NewClient(result));
        }

        let start_count = sys::EVENT_COUNTER.load(Ordering::Relaxed);

        let events = [sys::es_event_type_t::NOTIFY_EXEC];
        let sub = unsafe { sys::es_subscribe(client, events.as_ptr(), events.len() as u32) };
        if sub != sys::es_return_t::SUCCESS {
            // Best-effort teardown if subscribe failed; ignore the
            // delete-client error (the client may be in a partial
            // state, but we have no recovery beyond logging).
            unsafe {
                let _ = sys::es_delete_client(client);
            }
            return Err(EsClientError::Subscribe(sub));
        }

        Ok(Self {
            client,
            start_count,
            _not_send: std::marker::PhantomData,
        })
    }

    /// Subscribe to AUTH_UNLINK with the ALLOW-and-count handler.
    /// This is Slice 2 (M03.1.F) — every `unlink` syscall on the
    /// system is delivered to our handler, which responds ALLOW
    /// immediately + bumps [`super::sys::EVENT_COUNTER`].
    ///
    /// Same env requirements as [`Self::new_counting`] (signed +
    /// AMFI-bypassed VM, or production entitlement).
    ///
    /// Holding this client briefly affects every unlink on the
    /// host (kernel waits for our ALLOW). The response is inline
    /// in the callback so latency is microseconds — fine for a
    /// smoke. Don't hold it long-term on a busy host without
    /// understanding the trade-off; M03.1.H+ adds the worker-
    /// thread + ring buffer architecture that decouples response
    /// from capture work.
    pub fn new_auth_counting() -> Result<Self, EsClientError> {
        let mut client: *mut sys::es_client_t = ptr::null_mut();
        let result = unsafe {
            sys::es_new_client(
                &mut client as *mut *mut sys::es_client_t,
                &sys::ALLOW_COUNTER_HANDLER as *const _ as *const c_void,
            )
        };
        if result != sys::es_new_client_result_t::SUCCESS {
            return Err(EsClientError::NewClient(result));
        }

        let start_count = sys::EVENT_COUNTER.load(Ordering::Relaxed);

        let events = [sys::es_event_type_t::AUTH_UNLINK];
        let sub = unsafe { sys::es_subscribe(client, events.as_ptr(), events.len() as u32) };
        if sub != sys::es_return_t::SUCCESS {
            unsafe {
                let _ = sys::es_delete_client(client);
            }
            return Err(EsClientError::Subscribe(sub));
        }

        Ok(Self {
            client,
            start_count,
            _not_send: std::marker::PhantomData,
        })
    }

    /// Subscribe to AUTH_UNLINK with the path-logging handler
    /// (M03.1.G). Same response posture as
    /// [`Self::new_auth_counting`] but also decodes each message
    /// and records the unlink target path in
    /// [`super::sys::LAST_UNLINK_PATHS`]. Drain via
    /// [`Self::drain_logged_paths`] after the smoke window.
    pub fn new_path_logging() -> Result<Self, EsClientError> {
        let mut client: *mut sys::es_client_t = ptr::null_mut();
        let result = unsafe {
            sys::es_new_client(
                &mut client as *mut *mut sys::es_client_t,
                &sys::PATH_LOG_HANDLER as *const _ as *const c_void,
            )
        };
        if result != sys::es_new_client_result_t::SUCCESS {
            return Err(EsClientError::NewClient(result));
        }

        let start_count = sys::EVENT_COUNTER.load(Ordering::Relaxed);

        let events = [sys::es_event_type_t::AUTH_UNLINK];
        let sub = unsafe { sys::es_subscribe(client, events.as_ptr(), events.len() as u32) };
        if sub != sys::es_return_t::SUCCESS {
            unsafe {
                let _ = sys::es_delete_client(client);
            }
            return Err(EsClientError::Subscribe(sub));
        }

        Ok(Self {
            client,
            start_count,
            _not_send: std::marker::PhantomData,
        })
    }

    /// Drain the path-logging buffer (M03.1.G). Returns and clears
    /// the recorded paths. Safe to call from any thread but
    /// typically used by the calling thread after teardown to
    /// dump the smoke results.
    pub fn drain_logged_paths(&self) -> Vec<std::path::PathBuf> {
        match sys::LAST_UNLINK_PATHS.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(_) => Vec::new(),
        }
    }

    /// Subscribe to AUTH_UNLINK with the tree-filter handler
    /// (M03.1.H). Pre-seeds [`super::sys::TRACKED_TOKENS`] with
    /// `audit_token_self()` so unlinks from THIS process pass the
    /// filter; unlinks from other host processes are ALLOW'd but
    /// not recorded.
    ///
    /// Demonstrates the audit_token-based filter primitive that the
    /// producer integration (M03.1.I) layers on top — production
    /// seeds via WatchTree dispatches from the daemon instead of
    /// self.
    pub fn new_tree_filtered() -> Result<Self, EsClientError> {
        // Seed tracked-tokens with self FIRST so any events arriving
        // before es_subscribe returns (rare but possible) are still
        // filtered correctly.
        if let Some(self_token) = super::message::audit_token_self()
            && let Ok(mut g) = sys::TRACKED_TOKENS.lock()
        {
            let set = g.get_or_insert_with(Default::default);
            set.insert(self_token);
        }

        let mut client: *mut sys::es_client_t = ptr::null_mut();
        let result = unsafe {
            sys::es_new_client(
                &mut client as *mut *mut sys::es_client_t,
                &sys::TREE_FILTER_HANDLER as *const _ as *const c_void,
            )
        };
        if result != sys::es_new_client_result_t::SUCCESS {
            return Err(EsClientError::NewClient(result));
        }

        let start_count = sys::EVENT_COUNTER.load(Ordering::Relaxed);

        let events = [sys::es_event_type_t::AUTH_UNLINK];
        let sub = unsafe { sys::es_subscribe(client, events.as_ptr(), events.len() as u32) };
        if sub != sys::es_return_t::SUCCESS {
            unsafe {
                let _ = sys::es_delete_client(client);
            }
            return Err(EsClientError::Subscribe(sub));
        }

        Ok(Self {
            client,
            start_count,
            _not_send: std::marker::PhantomData,
        })
    }

    /// Events delivered to the counter handler since this client
    /// was constructed.
    pub fn events_received(&self) -> u64 {
        sys::EVENT_COUNTER
            .load(Ordering::Relaxed)
            .saturating_sub(self.start_count)
    }
}

impl Drop for EsClient {
    fn drop(&mut self) {
        if !self.client.is_null() {
            unsafe {
                let _ = sys::es_delete_client(self.client);
            }
            self.client = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This test only succeeds in an ES-enabled environment:
    /// SIP+AuthRoot+AMFI-bypassed VM + ad-hoc-signed-with-entitlement
    /// test binary + run with sudo. On any other host the constructor
    /// returns NotEntitled / NotPrivileged and the test is skipped
    /// via early return (we don't want CI flakiness on unprivileged
    /// hosts).
    ///
    /// On the VM:
    ///   tools/macos-tart-vm/build-signed.sh --test
    ///   tools/macos-tart-vm/ssh.sh 'sudo <signed-test-bin> \
    ///     es::client::tests::counter_handler_observes_execs -- --nocapture'
    #[test]
    fn counter_handler_observes_execs() {
        let client = match EsClient::new_counting() {
            Ok(c) => c,
            Err(EsClientError::NewClient(sys::es_new_client_result_t::ERR_NOT_ENTITLED)) => {
                eprintln!(
                    "skip: ES not entitled here — run on SIP+AuthRoot+AMFI-bypassed VM \
                     with signed binary"
                );
                return;
            }
            Err(EsClientError::NewClient(sys::es_new_client_result_t::ERR_NOT_PRIVILEGED)) => {
                eprintln!("skip: run with sudo");
                return;
            }
            Err(other) => panic!("EsClient::new_counting failed: {other:?}"),
        };

        // Trigger some execs from inside the test process so we
        // don't rely on whatever else is happening on the host.
        // Each Command::new spawn does an exec(2) the kernel will
        // route to our handler.
        for _ in 0..5 {
            let _ = std::process::Command::new("/usr/bin/true").status();
        }

        // Give the ES delivery thread a beat to dispatch — Apple's
        // ES typically delivers within microseconds, but 100ms is
        // generous and stays under the auth-timeout budget by a
        // wide margin.
        std::thread::sleep(std::time::Duration::from_millis(100));

        let n = client.events_received();
        eprintln!("events received since EsClient creation: {n}");
        assert!(
            n > 0,
            "expected NOTIFY_EXEC events from /usr/bin/true spawns; got 0 \
             (subscription not delivering)"
        );
        // Drop tears down via es_delete_client; verified by absence
        // of a kernel-side warning on the next test run.
    }
}
