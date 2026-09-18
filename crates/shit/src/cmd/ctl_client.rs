// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic daemon ctl-socket client used by gc / pin / forget / list.
//!
//! `shit status` predates this and has its own copy; refactoring it to
//! share this helper is a tidy-up follow-up that doesn't change
//! behavior. Until then, two implementations is the lesser cost.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use shit_proto::{CtlRequest, CtlResponse, MAX_FRAME_SIZE, decode_frame, encode_frame};

use crate::exitcode::{CliError, DAEMON_UNAVAILABLE, GENERIC_FAILURE};

const TIMEOUT: Duration = Duration::from_secs(60);

/// Send one CtlRequest, wait one CtlResponse. Maps connection errors
/// to `CliError::Failed { code: DAEMON_UNAVAILABLE }` so the CLI
/// exit-code contract holds.
pub fn call(path: &Path, req: &CtlRequest) -> Result<CtlResponse, CliError> {
    let mut stream = UnixStream::connect(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => CliError::fail(
            DAEMON_UNAVAILABLE,
            format!("daemon not running (no ctl socket at {})", path.display()),
        ),
        _ => CliError::fail(GENERIC_FAILURE, format!("connect ctl: {e}")),
    })?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let bytes =
        encode_frame(req).map_err(|e| CliError::fail(GENERIC_FAILURE, format!("encode: {e}")))?;
    stream
        .write_all(&bytes)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("write: {e}")))?;
    read_response(&mut stream)
}

/// Read one length-prefixed ctl response from a stream.
///
/// A Unix stream read is allowed to return fewer bytes than requested even
/// when the peer wrote the whole frame in one call. Reading into a fixed
/// buffer once therefore truncated larger undo reports in practice. Read the
/// four-byte prefix first, validate it before allocating, then read the exact
/// body promised by that prefix.
fn read_response(stream: &mut impl Read) -> Result<CtlResponse, CliError> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("read response header: {e}")))?;

    let body_len = u32::from_be_bytes(header) as usize;
    let total_len = 4usize
        .checked_add(body_len)
        .ok_or_else(|| CliError::fail(GENERIC_FAILURE, "response frame length overflow"))?;
    if total_len > MAX_FRAME_SIZE {
        return Err(CliError::fail(
            GENERIC_FAILURE,
            format!("response frame too large: {total_len} bytes"),
        ));
    }

    let mut frame = vec![0u8; total_len];
    frame[..4].copy_from_slice(&header);
    stream
        .read_exact(&mut frame[4..])
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("read response body: {e}")))?;

    decode_frame(&frame).map_err(|e| CliError::fail(GENERIC_FAILURE, format!("decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChunkedReader {
        bytes: std::io::Cursor<Vec<u8>>,
        max_chunk: usize,
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let limit = buf.len().min(self.max_chunk);
            self.bytes.read(&mut buf[..limit])
        }
    }

    #[test]
    fn reads_response_body_across_partial_stream_reads() {
        let message = "x".repeat(30_000);
        let frame = encode_frame(&CtlResponse::Error(message.clone())).unwrap();
        let mut stream = ChunkedReader {
            bytes: std::io::Cursor::new(frame),
            max_chunk: 8_188,
        };

        let response = read_response(&mut stream).unwrap();
        match response {
            CtlResponse::Error(actual) => assert_eq!(actual, message),
            other => panic!("expected error response, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_response_before_allocating_body() {
        let oversized_body = u32::try_from(MAX_FRAME_SIZE).unwrap();
        let mut stream = std::io::Cursor::new(oversized_body.to_be_bytes());

        let err = read_response(&mut stream).unwrap_err();
        assert!(err.to_string().contains("response frame too large"));
    }
}
