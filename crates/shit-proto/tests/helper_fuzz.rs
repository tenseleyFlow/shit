// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property-based fuzz-equivalent for the helper IPC decoder.
//!
//! Real cargo-fuzz harness is deferred to S21 (perf + observability
//! sprint) where the CI runners can afford the nightly-toolchain
//! overhead and the 5-minute-per-target budget. For S06 we exercise
//! the decode surface against random bytes via proptest, which catches
//! the same classes of bugs (panics, infinite loops, oversize-frame
//! escape) on stable.

use proptest::prelude::*;
use shit_proto::{HelperRequest, HelperResponse, MAX_HELPER_FRAME_SIZE, decode_frame};

proptest! {
    /// Random byte soup must never panic the request decoder.
    #[test]
    fn random_bytes_do_not_panic_request_decoder(
        bytes in prop::collection::vec(any::<u8>(), 0..MAX_HELPER_FRAME_SIZE)
    ) {
        let _ = decode_frame::<HelperRequest>(&bytes);
    }

    /// Same for the response decoder.
    #[test]
    fn random_bytes_do_not_panic_response_decoder(
        bytes in prop::collection::vec(any::<u8>(), 0..MAX_HELPER_FRAME_SIZE)
    ) {
        let _ = decode_frame::<HelperResponse>(&bytes);
    }

    /// Frames declaring a body larger than MAX must be rejected; never
    /// allocate the declared size.
    #[test]
    fn oversize_declared_length_rejected(
        body_len in (MAX_HELPER_FRAME_SIZE as u32 + 1)..(u32::MAX / 2)
    ) {
        let mut frame = Vec::with_capacity(8);
        frame.extend_from_slice(&body_len.to_be_bytes());
        frame.push(shit_proto::WIRE_VERSION);
        frame.push(0xAA); // garbage payload byte
        let res = decode_frame::<HelperRequest>(&frame);
        prop_assert!(res.is_err(), "oversize {body_len} should reject; got {res:?}");
    }
}
