// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bidirectional heartbeat. Full implementation in S06.8.

use std::time::Duration;

#[allow(dead_code)]
pub const PING_INTERVAL: Duration = Duration::from_secs(5);
#[allow(dead_code)]
pub const PONG_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct Heartbeat {
    pub last_pong_nonce: Option<u64>,
}
