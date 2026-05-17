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
