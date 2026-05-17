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

use shit_proto::{CtlRequest, CtlResponse, decode_frame, encode_frame};

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
    let mut buf = vec![0u8; 64 * 1024];
    let n = stream
        .read(&mut buf)
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("read: {e}")))?;
    let resp: CtlResponse = decode_frame(&buf[..n])
        .map_err(|e| CliError::fail(GENERIC_FAILURE, format!("decode: {e}")))?;
    Ok(resp)
}
