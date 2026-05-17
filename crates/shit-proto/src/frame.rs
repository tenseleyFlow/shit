// SPDX-License-Identifier: AGPL-3.0-or-later

use serde::Serialize;
use serde::de::DeserializeOwned;

pub const WIRE_VERSION: u8 = 1;

/// Maximum frame size (including length prefix). Frames over this are
/// rejected on the decode side and never produced on the encode side.
///
/// **S20 audit (F-NEW-1):** the original 4 KiB cap was sized for the
/// shell-hook UDS datagram surface (small `HookMessage` payloads).
/// Tier-event messages added in S14–S19 (`CtlRequest::PkgEvent`,
/// `SvcEvent`, `NetEvent`, `ProcEvent`, `DbEvent`) carry raw
/// state-dump bytes — `iptables-save -c` output, `/proc` snapshots,
/// SQL statement blobs — that routinely exceed 4 KiB. The helper's
/// own read buffers are 256 KiB; the encode-side cap was the choke
/// point. Raising it to match keeps both sides honest.
///
/// The `HookMessage` (shell-hook) payload remains small by design;
/// the daemon's `server::serve` validates its own bounds against
/// the same constant. A malicious same-UID attacker can now send up
/// to 256 KiB per request — that's bounded, and the per-connection
/// reader is one-shot (no streaming), so total memory cost is one
/// buffer per concurrent connection.
pub const MAX_FRAME_SIZE: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("postcard serialization failed: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("encoded frame too large: {got} bytes")]
    TooLarge { got: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("frame truncated: need at least 5 bytes, got {0}")]
    Truncated(usize),
    #[error("frame length mismatch: header says {declared}, buffer has {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("unsupported wire version: {0}")]
    UnsupportedVersion(u8),
    #[error("postcard deserialization failed: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
}

/// Encode any postcard-serializable message into the on-wire framing:
///
/// ```text
/// | u32 BE body_len | u8 wire_version | postcard payload |
/// ```
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, EncodeError> {
    let payload = postcard::to_allocvec(msg)?;
    let body_len = 1 + payload.len();
    let total_len = 4 + body_len;
    if total_len > MAX_FRAME_SIZE {
        return Err(EncodeError::TooLarge { got: total_len });
    }
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(
        &u32::try_from(body_len)
            .expect("checked above")
            .to_be_bytes(),
    );
    frame.push(WIRE_VERSION);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode any postcard-deserializable message from a complete frame.
pub fn decode_frame<T: DeserializeOwned>(buf: &[u8]) -> Result<T, DecodeError> {
    if buf.len() < 5 {
        return Err(DecodeError::Truncated(buf.len()));
    }
    if buf.len() > MAX_FRAME_SIZE {
        return Err(DecodeError::TooLarge(buf.len()));
    }
    let declared = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let actual_body = buf.len() - 4;
    if declared != actual_body {
        return Err(DecodeError::LengthMismatch {
            declared,
            actual: actual_body,
        });
    }
    let version = buf[4];
    if version != WIRE_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let payload = &buf[5..];
    let msg = postcard::from_bytes(payload)?;
    Ok(msg)
}
