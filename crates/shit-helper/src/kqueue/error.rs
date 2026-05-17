// SPDX-License-Identifier: AGPL-3.0-or-later

//! Errors surfaced by the kqueue layer.

#![cfg(any(
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]

#[derive(Debug, thiserror::Error)]
pub enum KqueueError {
    #[error("kqueue(2): {0}")]
    Kqueue(std::io::Error),
    #[error("kevent(2): {0}")]
    Kevent(std::io::Error),
    #[error("open({path:?}): {source}")]
    Open {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("not implemented in stage 1: {0}")]
    NotImplemented(&'static str),
}
