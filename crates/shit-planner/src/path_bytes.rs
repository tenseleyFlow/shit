// SPDX-License-Identifier: AGPL-3.0-or-later

//! #211: serde for a `PathBuf` that keeps every byte.
//!
//! serde's own `Path` impl refuses a path that is not UTF-8, so a
//! journaled event for a Latin-1 name could not be stored at all, and
//! the wire fed it a lossy U+FFFD spelling instead. Here a UTF-8 path
//! serializes as a string, exactly as before, and any other path as
//! its raw bytes. postcard writes both as a length and the bytes, so
//! rows stored before this change decode unchanged and no migration is
//! needed. A self-describing format (JSON) gets a string or a byte
//! array; deserializing accepts either.
//!
//! Use as `#[serde(with = "crate::path_bytes")]`, or
//! `crate::path_bytes::option` for `Option<PathBuf>`.

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::Serializer;
use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

pub fn serialize<S: Serializer>(path: &Path, s: S) -> Result<S::Ok, S::Error> {
    match path.to_str() {
        Some(utf8) => s.serialize_str(utf8),
        None => s.serialize_bytes(path.as_os_str().as_bytes()),
    }
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PathBuf, D::Error> {
    d.deserialize_byte_buf(PathVisitor)
}

struct PathVisitor;

impl<'de> Visitor<'de> for PathVisitor {
    type Value = PathBuf;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a path as a string or bytes")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<PathBuf, E> {
        Ok(PathBuf::from(v))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<PathBuf, E> {
        Ok(PathBuf::from(v))
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<PathBuf, E> {
        Ok(PathBuf::from(OsString::from_vec(v.to_vec())))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<PathBuf, E> {
        Ok(PathBuf::from(OsString::from_vec(v)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<PathBuf, A::Error> {
        let mut v = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(b) = seq.next_element::<u8>()? {
            v.push(b);
        }
        Ok(PathBuf::from(OsString::from_vec(v)))
    }
}

/// The same for `Option<PathBuf>`.
pub mod option {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct Wrap(#[serde(with = "super")] PathBuf);

    pub fn serialize<S: Serializer>(path: &Option<PathBuf>, s: S) -> Result<S::Ok, S::Error> {
        match path {
            Some(p) => s.serialize_some(&Wrap(p.clone())),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<PathBuf>, D::Error> {
        Ok(Option::<Wrap>::deserialize(d)?.map(|w| w.0))
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::PathBuf;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct New {
        #[serde(with = "super")]
        p: PathBuf,
        #[serde(with = "super::option")]
        o: Option<PathBuf>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Old {
        p: PathBuf,
        o: Option<PathBuf>,
    }

    fn latin1() -> PathBuf {
        PathBuf::from(OsString::from_vec(b"/tmp/caf\xe9/victim".to_vec()))
    }

    #[test]
    fn non_utf8_round_trips_through_postcard() {
        let v = New {
            p: latin1(),
            o: Some(latin1()),
        };
        let bytes = postcard::to_allocvec(&v).unwrap();
        let back: New = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.p.as_os_str().as_bytes(), b"/tmp/caf\xe9/victim");
        assert_eq!(back, v);
    }

    #[test]
    fn rows_written_with_default_serde_still_decode() {
        let old = Old {
            p: PathBuf::from("/tmp/x"),
            o: None,
        };
        let bytes = postcard::to_allocvec(&old).unwrap();
        let new: New = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(new.p, old.p);
        assert_eq!(new.o, None);
        // And the new encoding of a UTF-8 path is byte-identical.
        let again = postcard::to_allocvec(&New {
            p: PathBuf::from("/tmp/x"),
            o: None,
        })
        .unwrap();
        assert_eq!(again, bytes);
    }

    #[test]
    fn json_takes_a_string_or_a_byte_array() {
        let s: New = serde_json::from_str(r#"{"p":"/a","o":null}"#).unwrap();
        assert_eq!(s.p, PathBuf::from("/a"));
        let json = serde_json::to_string(&New {
            p: latin1(),
            o: None,
        })
        .unwrap();
        let back: New = serde_json::from_str(&json).unwrap();
        assert_eq!(back.p, latin1());
    }
}
