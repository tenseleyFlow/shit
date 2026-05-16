// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Shared, lock-light counters the ctl handler reads to render `shit status`.
#[derive(Debug)]
pub struct Stats {
    pub started_at: Instant,
    pub last_activity: Mutex<Instant>,
    pub hook_msgs: AtomicU64,
    pub hook_decode_errors: AtomicU64,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            started_at: now,
            last_activity: Mutex::new(now),
            hook_msgs: AtomicU64::new(0),
            hook_decode_errors: AtomicU64::new(0),
        })
    }

    pub fn note_hook_msg(&self) {
        self.hook_msgs.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.last_activity.lock() {
            *g = Instant::now();
        }
    }

    pub fn note_decode_error(&self) {
        self.hook_decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn idle_for(&self) -> std::time::Duration {
        match self.last_activity.lock() {
            Ok(g) => g.elapsed(),
            Err(_) => std::time::Duration::ZERO,
        }
    }
}
