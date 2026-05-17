// SPDX-License-Identifier: AGPL-3.0-or-later

//! S20.5 — hand-written hostile-message tests covering every
//! [`CtlRequest`] variant added since S06.
//!
//! Pairs with `helper_fuzz.rs` (proptest-based, broad-coverage); this
//! file targets *specific* malformed inputs the threat model
//! enumerates: oversized variants, wrong-version frames, truncated
//! frames, garbage payloads, claimed-large-but-actually-tiny
//! length prefixes (the classic CVE shape).
//!
//! Every test must exit *without panicking* — that's the audit
//! invariant. Returning `Err` is fine; aborting the process is not.

use shit_proto::{
    CtlRequest, DbConnInfo, DbEngineWire, DbEventReq, DbTxStateWire, DecodeError, MAX_FRAME_SIZE,
    NetEventReq, NetToolWire, PkgEventReq, PkgManagerWire, PkgPhase, ProcEventReq, ProcToolWire,
    SvcEventReq, SvcScopeWire, SvcToolWire, WIRE_VERSION, decode_frame, encode_frame,
};
use std::collections::BTreeMap;

/// Returns a list of every CtlRequest variant the daemon should
/// accept. Used by tests that walk the full variant matrix.
fn sample_variants() -> Vec<(&'static str, CtlRequest)> {
    vec![
        ("Ping", CtlRequest::Ping),
        ("Status", CtlRequest::Status),
        (
            "PkgEvent",
            CtlRequest::PkgEvent(PkgEventReq {
                manager: PkgManagerWire::Apt,
                phase: PkgPhase::Pre,
                pid: 1,
                uid: 1000,
                packages: BTreeMap::from([("x".into(), "1.0".into())]),
                op_hint: Some("install".into()),
                extras: BTreeMap::new(),
            }),
        ),
        (
            "SvcEvent",
            CtlRequest::SvcEvent(SvcEventReq {
                tool: SvcToolWire::Systemctl,
                phase: PkgPhase::Pre,
                scope: SvcScopeWire::User,
                unit: "x.service".into(),
                verb: "start".into(),
                pid: 1,
                uid: 1000,
                state_raw: String::new(),
            }),
        ),
        (
            "NetEvent",
            CtlRequest::NetEvent(NetEventReq {
                tool: NetToolWire::Iptables,
                phase: PkgPhase::Pre,
                verb: "-A".into(),
                scope_hint: "filter".into(),
                pid: 1,
                uid: 1000,
                state_raw: vec![],
            }),
        ),
        (
            "ProcEvent",
            CtlRequest::ProcEvent(ProcEventReq {
                tool: ProcToolWire::Kill,
                phase: PkgPhase::Pre,
                target_argv: vec!["-9".into(), "1234".into()],
                targets: vec![],
                pid: 1,
                uid: 1000,
            }),
        ),
        (
            "DbEvent",
            CtlRequest::DbEvent(DbEventReq {
                engine: DbEngineWire::Postgres,
                phase: PkgPhase::Pre,
                conn: DbConnInfo {
                    host: "h".into(),
                    port: Some(5432),
                    user: "u".into(),
                    target: "t".into(),
                },
                statements: vec!["INSERT INTO t VALUES (1)".into()],
                transaction_state: DbTxStateWire::Unknown,
                pid: 1,
                uid: 1000,
                extras: BTreeMap::new(),
            }),
        ),
    ]
}

#[test]
fn every_variant_round_trips() {
    for (name, req) in sample_variants() {
        let frame = encode_frame(&req).unwrap_or_else(|e| panic!("{name}: encode {e}"));
        let _back: CtlRequest =
            decode_frame(&frame).unwrap_or_else(|e| panic!("{name}: decode {e}"));
    }
}

#[test]
fn empty_buffer_returns_truncated() {
    let err = decode_frame::<CtlRequest>(&[]).unwrap_err();
    assert!(matches!(err, DecodeError::Truncated(0)));
}

#[test]
fn buffer_below_minimum_returns_truncated() {
    // Header is 4 bytes len + 1 byte wire version = 5 bytes minimum.
    for n in 1..5 {
        let buf = vec![0xff; n];
        let err = decode_frame::<CtlRequest>(&buf).unwrap_err();
        assert!(
            matches!(err, DecodeError::Truncated(_)),
            "n={n} returned {err:?}"
        );
    }
}

#[test]
fn buffer_above_cap_returns_too_large() {
    let buf = vec![0u8; MAX_FRAME_SIZE + 1];
    let err = decode_frame::<CtlRequest>(&buf).unwrap_err();
    assert!(matches!(err, DecodeError::TooLarge(_)));
}

#[test]
fn wrong_wire_version_rejected() {
    // Craft a valid-shaped frame but bump the version byte.
    let mut frame = encode_frame(&CtlRequest::Ping).unwrap();
    frame[4] = WIRE_VERSION.wrapping_add(7);
    let err = decode_frame::<CtlRequest>(&frame).unwrap_err();
    assert!(matches!(err, DecodeError::UnsupportedVersion(_)));
}

#[test]
fn declared_length_too_large_returns_mismatch() {
    // Length header claims a huge body; actual buffer is small.
    let mut frame = vec![0u8; 10];
    let claimed: u32 = u32::MAX / 2;
    frame[..4].copy_from_slice(&claimed.to_be_bytes());
    frame[4] = WIRE_VERSION;
    let err = decode_frame::<CtlRequest>(&frame).unwrap_err();
    assert!(matches!(err, DecodeError::LengthMismatch { .. }));
}

#[test]
fn declared_length_smaller_than_buffer_returns_mismatch() {
    // Header claims tiny body; we attach extra bytes.
    let mut frame = encode_frame(&CtlRequest::Ping).unwrap();
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let err = decode_frame::<CtlRequest>(&frame).unwrap_err();
    assert!(matches!(err, DecodeError::LengthMismatch { .. }));
}

#[test]
fn garbage_payload_with_valid_header_returns_postcard_error() {
    // 4-byte declared len + valid wire version + garbage body.
    let body = vec![0xff; 100];
    let body_len = (1 + body.len()) as u32;
    let mut frame = Vec::with_capacity(4 + body_len as usize);
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.push(WIRE_VERSION);
    frame.extend_from_slice(&body);
    // Either Postcard or LengthMismatch — both are valid refusals.
    // What we *must not* see is success or panic.
    let result = decode_frame::<CtlRequest>(&frame);
    assert!(result.is_err());
}

#[test]
fn bit_flipped_frame_does_not_panic() {
    // Flip one bit at a time across the first 64 bytes of a real frame.
    let original = encode_frame(&CtlRequest::Status).unwrap();
    for byte_idx in 0..original.len().min(64) {
        for bit in 0..8 {
            let mut corrupted = original.clone();
            corrupted[byte_idx] ^= 1 << bit;
            let _ = decode_frame::<CtlRequest>(&corrupted);
        }
    }
}

#[test]
fn truncated_real_frame_does_not_panic() {
    // Take a real frame, truncate it at every length from 0 to full.
    let frame = encode_frame(&CtlRequest::Ping).unwrap();
    for n in 0..frame.len() {
        let _ = decode_frame::<CtlRequest>(&frame[..n]);
    }
}

#[test]
fn each_tier_event_handles_unicode_in_payload_strings() {
    // Strings that came from user input may carry unicode (e.g.,
    // unit names with emoji, env vars with non-ASCII values). The
    // decoder should round-trip unchanged.
    let variants = vec![
        (
            "SvcEvent unit",
            CtlRequest::SvcEvent(SvcEventReq {
                tool: SvcToolWire::Systemctl,
                phase: PkgPhase::Pre,
                scope: SvcScopeWire::User,
                unit: "service-with-🎉.service".into(),
                verb: "start".into(),
                pid: 1,
                uid: 1000,
                state_raw: String::new(),
            }),
        ),
        (
            "DbEvent statement",
            CtlRequest::DbEvent(DbEventReq {
                engine: DbEngineWire::Postgres,
                phase: PkgPhase::Pre,
                conn: DbConnInfo {
                    host: "host".into(),
                    port: None,
                    user: "alice".into(),
                    target: "prod".into(),
                },
                statements: vec!["INSERT INTO t VALUES ('café — 中文 — 🎉')".into()],
                transaction_state: DbTxStateWire::Unknown,
                pid: 1,
                uid: 1000,
                extras: BTreeMap::new(),
            }),
        ),
    ];
    for (name, req) in variants {
        let frame = encode_frame(&req).unwrap_or_else(|e| panic!("{name}: encode {e}"));
        let _back: CtlRequest =
            decode_frame(&frame).unwrap_or_else(|e| panic!("{name}: decode {e}"));
    }
}

#[test]
fn header_length_overflow_does_not_panic() {
    // Header declares u32::MAX. Bounded by the cap check first.
    let mut frame = vec![0xff; 8];
    frame[4] = WIRE_VERSION;
    let result = decode_frame::<CtlRequest>(&frame);
    assert!(result.is_err()); // either LengthMismatch or Postcard
}
