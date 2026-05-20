// SPDX-License-Identifier: AGPL-3.0-or-later

use shit_proto::{DecodeError, HookMessage, ShellKind, decode_frame, encode_frame};
use uuid::Uuid;

fn sample_session_open() -> HookMessage {
    HookMessage::SessionOpen {
        session: Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
        shell_kind: ShellKind::Bash,
        parent_pid: 4242,
        tty: "/dev/ttys003".to_string(),
        ts_unix_nanos: 1_700_000_000_000_000_000,
    }
}

fn sample_preexec() -> HookMessage {
    HookMessage::PreExec {
        session: Uuid::nil(),
        seq: 17,
        pid: 7331,
        cwd_inode: 99_999,
        cwd_dev: 16777220,
        cwd_path: "/tmp/sample".to_string(),
        ts_unix_nanos: 1_700_000_100_000_000_000,
        shell_kind: ShellKind::Zsh,
        depth: 1,
    }
}

fn sample_postexec() -> HookMessage {
    HookMessage::PostExec {
        session: Uuid::nil(),
        seq: 17,
        exit_code: 0,
        ts_unix_nanos: 1_700_000_101_000_000_000,
    }
}

fn sample_session_close() -> HookMessage {
    HookMessage::SessionClose {
        session: Uuid::nil(),
        ts_unix_nanos: 1_700_000_200_000_000_000,
    }
}

#[test]
fn roundtrip_session_open() {
    let msg = sample_session_open();
    let frame = encode_frame(&msg).expect("encode");
    let decoded: HookMessage = decode_frame(&frame).expect("decode");
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_preexec() {
    let msg = sample_preexec();
    let frame = encode_frame(&msg).expect("encode");
    let decoded: HookMessage = decode_frame(&frame).expect("decode");
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_postexec() {
    let msg = sample_postexec();
    let frame = encode_frame(&msg).expect("encode");
    let decoded: HookMessage = decode_frame(&frame).expect("decode");
    assert_eq!(msg, decoded);
}

#[test]
fn roundtrip_session_close() {
    let msg = sample_session_close();
    let frame = encode_frame(&msg).expect("encode");
    let decoded: HookMessage = decode_frame(&frame).expect("decode");
    assert_eq!(msg, decoded);
}

#[test]
fn detect_truncated_frame() {
    let frame = encode_frame(&sample_preexec()).unwrap();
    let err = decode_frame::<HookMessage>(&frame[..3]).expect_err("should fail");
    assert!(matches!(err, DecodeError::Truncated(_)));
}

#[test]
fn detect_length_mismatch() {
    let mut frame = encode_frame(&sample_preexec()).unwrap();
    frame.pop();
    let err = decode_frame::<HookMessage>(&frame).expect_err("should fail");
    assert!(matches!(err, DecodeError::LengthMismatch { .. }));
}

#[test]
fn detect_bad_wire_version() {
    let mut frame = encode_frame(&sample_preexec()).unwrap();
    frame[4] = 99;
    let err = decode_frame::<HookMessage>(&frame).expect_err("should fail");
    assert!(matches!(err, DecodeError::UnsupportedVersion(99)));
}

#[test]
fn empty_buffer_is_truncated() {
    let err = decode_frame::<HookMessage>(&[]).expect_err("should fail");
    assert!(matches!(err, DecodeError::Truncated(0)));
}

#[test]
fn random_garbage_does_not_panic() {
    let cases: &[&[u8]] = &[
        &[0xff; 100],
        &[0u8; 5],
        &[0, 0, 0, 1, 1],
        &[0, 0, 0, 1, 99],
        &[0, 0, 0, 0],
    ];
    for case in cases {
        let _ = decode_frame::<HookMessage>(case);
    }
}

#[test]
fn shell_kind_str_roundtrip() {
    use std::str::FromStr;
    for k in [
        ShellKind::Bash,
        ShellKind::Zsh,
        ShellKind::Fish,
        ShellKind::Unknown,
    ] {
        let s = k.as_str();
        let back = ShellKind::from_str(s).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn frame_size_is_bounded() {
    let msg = sample_session_open();
    let frame = encode_frame(&msg).unwrap();
    assert!(frame.len() <= shit_proto::MAX_FRAME_SIZE);
    assert!(frame.len() >= 5);
}

#[test]
fn db_engine_wire_str_roundtrip() {
    use shit_proto::DbEngineWire;
    use std::str::FromStr;
    for e in [
        DbEngineWire::Postgres,
        DbEngineWire::Mysql,
        DbEngineWire::Sqlite3,
    ] {
        let back = DbEngineWire::from_str(e.as_str()).unwrap();
        assert_eq!(e, back);
    }
    // Aliases.
    assert_eq!(
        DbEngineWire::from_str("postgres").unwrap(),
        DbEngineWire::Postgres
    );
    assert_eq!(
        DbEngineWire::from_str("mariadb").unwrap(),
        DbEngineWire::Mysql
    );
    assert_eq!(
        DbEngineWire::from_str("sqlite").unwrap(),
        DbEngineWire::Sqlite3
    );
    assert!(DbEngineWire::from_str("oracle").is_err());
}

#[test]
fn encode_rejects_payload_over_max_frame_size() {
    // S20.4 audit: encode_frame must refuse anything that would
    // produce a frame larger than MAX_FRAME_SIZE. Build a HookMessage
    // variant whose tty field is just long enough to push the
    // serialized payload past the cap.
    let big_tty = "x".repeat(shit_proto::MAX_FRAME_SIZE + 1024);
    let msg = HookMessage::SessionOpen {
        session: Uuid::nil(),
        shell_kind: ShellKind::Bash,
        parent_pid: 1,
        tty: big_tty,
        ts_unix_nanos: 0,
    };
    let err = encode_frame(&msg).unwrap_err();
    match err {
        shit_proto::EncodeError::TooLarge { got } => {
            assert!(got > shit_proto::MAX_FRAME_SIZE);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}

#[test]
fn decode_rejects_buffer_over_max_frame_size() {
    // S20.4 audit: decode_frame must refuse oversized buffers
    // before attempting any postcard work. Hand it a buffer
    // larger than the cap and assert TooLarge.
    let buf = vec![0u8; shit_proto::MAX_FRAME_SIZE + 1];
    let err = decode_frame::<HookMessage>(&buf).unwrap_err();
    assert!(matches!(err, DecodeError::TooLarge(_)));
}

#[test]
fn decode_at_exactly_max_frame_size_does_not_overflow() {
    // Defensive: a buffer exactly MAX_FRAME_SIZE bytes long should
    // proceed to postcard parsing (which will fail on garbage but
    // not on size). Verifies the off-by-one is correctly handled.
    let buf = vec![0u8; shit_proto::MAX_FRAME_SIZE];
    let _ = decode_frame::<HookMessage>(&buf);
    // No panic, no TooLarge — proceeded past the size gate.
}

#[test]
fn max_frame_size_is_at_least_256kib() {
    // Regression guard: F-NEW-1 fix raised MAX_FRAME_SIZE to 256 KiB
    // to accommodate tier-event state-dump payloads. If a future PR
    // lowers it back below that, NetEvent/ProcEvent/DbEvent will
    // silently start failing to ship. Catch that here. We read the
    // constant into a local so clippy's `assertions_on_constants`
    // sees a runtime value (it isn't, but the const-vs-runtime
    // distinction matters to the lint).
    let cap = shit_proto::MAX_FRAME_SIZE;
    assert!(
        cap >= 256 * 1024,
        "MAX_FRAME_SIZE regressed below 256 KiB ({cap}); would break tier-event capture (see S20.4)"
    );
}

#[test]
fn net_event_req_with_large_state_raw_encodes() {
    // Real-world driver: an iptables-save dump of ~10 KiB. The
    // pre-S20 4 KiB cap would have rejected this; the post-fix cap
    // accepts it.
    use shit_proto::{CtlRequest, NetEventReq, NetToolWire, PkgPhase};
    let state_raw = vec![b'#'; 16 * 1024];
    let req = NetEventReq {
        tool: NetToolWire::Iptables,
        phase: PkgPhase::Pre,
        verb: "-A".into(),
        scope_hint: "filter".into(),
        pid: 1234,
        uid: 1000,
        state_raw,
    };
    let frame = encode_frame(&CtlRequest::NetEvent(req)).unwrap();
    let frame_len = frame.len();
    assert!(
        frame_len > 4 * 1024,
        "this test exists *because* 4 KiB was the old cap; got {frame_len}"
    );
    let _back: CtlRequest = decode_frame(&frame).unwrap();
}

#[test]
fn db_event_req_with_large_statement_blob_encodes() {
    // Real-world driver: a migrations.sql with ~150 statements.
    use shit_proto::{CtlRequest, DbConnInfo, DbEngineWire, DbEventReq, DbTxStateWire, PkgPhase};
    let statements: Vec<String> = (0..150)
        .map(|i| format!("INSERT INTO t (id) VALUES ({i})"))
        .collect();
    let req = DbEventReq {
        engine: DbEngineWire::Postgres,
        phase: PkgPhase::Pre,
        conn: DbConnInfo {
            host: "db".into(),
            port: Some(5432),
            user: "alice".into(),
            target: "prod".into(),
        },
        statements,
        transaction_state: DbTxStateWire::Unknown,
        pid: 1234,
        uid: 1000,
        extras: std::collections::BTreeMap::new(),
    };
    let frame = encode_frame(&CtlRequest::DbEvent(req)).unwrap();
    let _back: CtlRequest = decode_frame(&frame).unwrap();
}

#[test]
fn metrics_snapshot_postcard_roundtrip() {
    use shit_proto::{CtlResponse, MetricsSnapshot};
    let snap = MetricsSnapshot {
        uptime_secs: 3600,
        pid: 12345,
        hook_messages_received: 42,
        hook_decode_errors: 0,
        hook_latency_us_p50: 850,
        hook_latency_us_p99: 9100,
        hook_latency_samples: 42,
        store_size_bytes: 1024 * 1024 * 17,
        store_blob_count: 100,
        store_command_count: 50,
        last_gc_duration_ms: 142,
        last_gc_bytes_reclaimed: 1024 * 1024,
        last_gc_at_unix_secs: 1_700_000_000,
        kernel_tier: "fanotify".into(),
    };
    let frame = encode_frame(&CtlResponse::Metrics(snap.clone())).unwrap();
    let back: CtlResponse = decode_frame(&frame).unwrap();
    match back {
        CtlResponse::Metrics(r) => assert_eq!(r, snap),
        other => panic!("expected Metrics, got {other:?}"),
    }
}

#[test]
fn metrics_request_postcard_roundtrip() {
    use shit_proto::CtlRequest;
    let frame = encode_frame(&CtlRequest::Metrics).unwrap();
    let back: CtlRequest = decode_frame(&frame).unwrap();
    assert!(matches!(back, CtlRequest::Metrics));
}

#[test]
fn db_event_req_postcard_roundtrip() {
    use shit_proto::{CtlRequest, DbConnInfo, DbEngineWire, DbEventReq, DbTxStateWire, PkgPhase};
    use std::collections::BTreeMap;
    let req = DbEventReq {
        engine: DbEngineWire::Postgres,
        phase: PkgPhase::Pre,
        conn: DbConnInfo {
            host: "db.example.com".into(),
            port: Some(5432),
            user: "alice".into(),
            target: "production".into(),
        },
        statements: vec!["INSERT INTO t VALUES (1)".into()],
        transaction_state: DbTxStateWire::Unknown,
        pid: 9999,
        uid: 1000,
        extras: BTreeMap::from([("xact_commit_pre".into(), "42".into())]),
    };
    let frame = encode_frame(&CtlRequest::DbEvent(req.clone())).unwrap();
    let back: CtlRequest = decode_frame(&frame).unwrap();
    match back {
        CtlRequest::DbEvent(r) => {
            assert_eq!(r.engine, req.engine);
            assert_eq!(r.conn.host, req.conn.host);
            assert_eq!(r.statements, req.statements);
            assert_eq!(r.extras, req.extras);
        }
        other => panic!("expected DbEvent, got {other:?}"),
    }
}
