// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bidirectional heartbeat. Each side pings the other every
//! [`PING_INTERVAL`]; if no matching pong arrives within
//! [`PONG_TIMEOUT`], we treat the peer as dead.
//!
//! The full async loop is driven by the helper's event loop in S07+.
//! This module provides the bookkeeping types and a pure-function
//! check the loop can call on each tick.

use std::time::{Duration, Instant};

#[allow(dead_code)]
pub const PING_INTERVAL: Duration = Duration::from_secs(5);
#[allow(dead_code)]
pub const PONG_TIMEOUT: Duration = Duration::from_secs(2);

/// Tracks outstanding ping nonces and decides when the peer is dead.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Heartbeat {
    last_ping_nonce: u64,
    last_ping_sent_at: Option<Instant>,
    last_pong_nonce: Option<u64>,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl Heartbeat {
    pub const fn new() -> Self {
        Self {
            last_ping_nonce: 0,
            last_ping_sent_at: None,
            last_pong_nonce: None,
        }
    }

    /// Allocate the next nonce and record the send time. The caller is
    /// responsible for sending the actual `Ping` over the wire.
    pub fn next_ping_nonce(&mut self) -> u64 {
        self.last_ping_nonce = self.last_ping_nonce.wrapping_add(1);
        self.last_ping_sent_at = Some(Instant::now());
        self.last_ping_nonce
    }

    /// Record an incoming pong. Returns true when it matched the last
    /// outstanding ping; false on a stale or unknown nonce (which the
    /// caller may want to log but not treat as fatal — pong reordering
    /// is fine in practice but unexpected on SEQPACKET).
    pub fn observe_pong(&mut self, nonce: u64) -> bool {
        self.last_pong_nonce = Some(nonce);
        nonce == self.last_ping_nonce
    }

    /// True when we have a ping outstanding and `PONG_TIMEOUT` has
    /// elapsed since we sent it without a matching pong.
    pub fn peer_dead(&self, now: Instant) -> bool {
        let Some(sent) = self.last_ping_sent_at else {
            return false;
        };
        if self.last_pong_nonce == Some(self.last_ping_nonce) {
            return false;
        }
        now.duration_since(sent) > PONG_TIMEOUT
    }

    #[allow(dead_code)]
    pub fn last_pong_nonce(&self) -> Option<u64> {
        self.last_pong_nonce
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn fresh_heartbeat_says_peer_not_dead() {
        let hb = Heartbeat::new();
        assert!(!hb.peer_dead(Instant::now()));
    }

    #[test]
    fn unanswered_ping_eventually_marks_dead() {
        let mut hb = Heartbeat::new();
        let _nonce = hb.next_ping_nonce();
        sleep(Duration::from_millis(5));
        // Without bumping time forward we just check the math: peer_dead
        // is `elapsed > PONG_TIMEOUT`. Construct a fake "now" 3s ahead.
        let later = Instant::now() + Duration::from_secs(3);
        assert!(hb.peer_dead(later));
    }

    #[test]
    fn answered_ping_clears_outstanding() {
        let mut hb = Heartbeat::new();
        let n = hb.next_ping_nonce();
        let matched = hb.observe_pong(n);
        assert!(matched);
        let later = Instant::now() + Duration::from_secs(10);
        assert!(!hb.peer_dead(later));
    }

    #[test]
    fn stale_pong_does_not_match() {
        let mut hb = Heartbeat::new();
        let _ = hb.next_ping_nonce(); // n=1
        let _ = hb.next_ping_nonce(); // n=2
        // Pong for older nonce — does not match the latest ping.
        let matched = hb.observe_pong(1);
        assert!(!matched);
        // And we still consider the peer suspect once timeout elapses.
        let later = Instant::now() + Duration::from_secs(3);
        assert!(hb.peer_dead(later));
    }
}
