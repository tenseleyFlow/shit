// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper-side IPC. Full SEQPACKET framing + handshake lands in S06.4;
//! this scaffold provides the `Conn` handle and a stub `connect()` so
//! the rest of the binary compiles.

use std::path::Path;

/// Opaque IPC connection handle. S06.4 swaps in the real SEQPACKET fd
/// + framing layer.
#[derive(Debug)]
pub struct Conn {
    _placeholder: (),
}

#[derive(Debug, thiserror::Error)]
pub enum ConnError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon socket missing at {0}")]
    Missing(String),
}

/// Connect to the daemon's SEQPACKET socket. S06.3 placeholder: only
/// confirms the path exists.
pub async fn connect(path: &Path) -> Result<Conn, ConnError> {
    if !path.exists() {
        return Err(ConnError::Missing(path.display().to_string()));
    }
    Ok(Conn { _placeholder: () })
}
