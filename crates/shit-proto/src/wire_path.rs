// SPDX-License-Identifier: AGPL-3.0-or-later

//! #211: filesystem paths in `String` fields, byte for byte.
//!
//! The helper and hook wires carry paths as `String`. A Unix path is
//! any byte string without NUL, so a name that is not UTF-8 (a Latin-1
//! directory, say) used to cross as a lossy string with U+FFFD in it,
//! and undo restored into a sibling spelled that way.
//!
//! [`encode`] passes a UTF-8 path through unchanged, so every existing
//! frame and stored row reads the same. Any other path becomes a NUL
//! byte, `x`, and the lowercase hex of its bytes. No real path starts
//! with NUL, so the two forms cannot collide, and [`decode`] reverses
//! either. A reader that forgets to decode hands the kernel a path with
//! a NUL in it, which every path syscall rejects: the mistake fails
//! loudly instead of landing at a look-alike name.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const MARK: &str = "\0x";

/// `path` as a wire string; see the module docs.
pub fn encode(path: impl AsRef<Path>) -> String {
    let bytes = path.as_ref().as_os_str().as_bytes();
    match std::str::from_utf8(bytes) {
        Ok(s) if !s.starts_with('\0') => s.to_owned(),
        _ => {
            let mut out = String::with_capacity(MARK.len() + bytes.len() * 2);
            out.push_str(MARK);
            for b in bytes {
                out.push_str(&format!("{b:02x}"));
            }
            out
        }
    }
}

/// The path a wire string from [`encode`] names. A string that is not
/// in the hex form is taken as the path itself.
pub fn decode(s: &str) -> PathBuf {
    if let Some(hex) = s.strip_prefix(MARK)
        && hex.len() % 2 == 0
        && let Some(bytes) = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()
    {
        return PathBuf::from(OsString::from_vec(bytes));
    }
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_paths_pass_through_unchanged() {
        for p in ["/home/u/caf\u{e9}/victim", "", "relative/x", "/t\u{fffd}"] {
            assert_eq!(encode(p), p);
            assert_eq!(decode(p), PathBuf::from(p));
        }
    }

    #[test]
    fn latin1_bytes_round_trip_exactly() {
        let raw = PathBuf::from(OsString::from_vec(b"/tmp/caf\xe9/victim".to_vec()));
        let wire = encode(&raw);
        assert!(wire.starts_with('\0'), "{wire:?}");
        assert!(!wire.contains('\u{fffd}'));
        assert_eq!(decode(&wire), raw);
        assert_eq!(decode(&wire).as_os_str().as_bytes(), b"/tmp/caf\xe9/victim");
    }

    #[test]
    fn malformed_hex_is_taken_literally() {
        assert_eq!(decode("\0xzz"), PathBuf::from("\0xzz"));
        assert_eq!(decode("\0x1"), PathBuf::from("\0x1"));
    }
}
