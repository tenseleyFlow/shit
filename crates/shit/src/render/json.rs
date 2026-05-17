// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code)]

//! JSON output. Schema-versioned.
//!
//! Every `--json` mode emits a top-level object with `schema_version`
//! (currently 1) so consumers can refuse unknown majors. The schema
//! itself is documented in `.docs/audits/json-schema.md` (lands as
//! part of S12.4 when we stub the first commands that emit it).
//!
//! Stage 1 ships the wire-shape helpers; the per-command DTOs land
//! alongside their respective subcommands.

use std::io::Write;

#[derive(Debug, thiserror::Error)]
pub enum JsonError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde_json: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Schema version baked into every emitted document.
pub const SCHEMA_VERSION: u32 = 1;

/// Write a serializable value as a top-level JSON object with the
/// project's schema-version header. Always followed by a newline so
/// `shit ... --json | jq` works cleanly.
///
/// The header shape is non-negotiable: `{ "schema_version": N, "data":
/// <body> }`. Adding sibling fields is allowed (forward-compatible
/// extension); changing the top-level shape would be a major bump.
pub fn write_json<T, W>(out: &mut W, body: &T) -> Result<(), JsonError>
where
    T: serde::Serialize,
    W: Write,
{
    #[derive(serde::Serialize)]
    struct Envelope<'a, T: serde::Serialize> {
        schema_version: u32,
        data: &'a T,
    }
    let env = Envelope {
        schema_version: SCHEMA_VERSION,
        data: body,
    };
    serde_json::to_writer(&mut *out, &env)?;
    out.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Serialize)]
    struct Sample {
        message: &'static str,
        count: u32,
    }

    #[test]
    fn envelope_includes_schema_version_and_data() {
        let mut buf: Vec<u8> = Vec::new();
        write_json(
            &mut buf,
            &Sample {
                message: "hi",
                count: 3,
            },
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        // Order isn't guaranteed by serde_json but in practice is
        // insertion order; check both keys present.
        assert!(s.contains(r#""schema_version":1"#), "{s}");
        assert!(s.contains(r#""data":{"#), "{s}");
        assert!(s.contains(r#""message":"hi""#), "{s}");
        assert!(s.contains(r#""count":3"#), "{s}");
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn writes_compact_single_line() {
        let mut buf: Vec<u8> = Vec::new();
        write_json(
            &mut buf,
            &Sample {
                message: "x",
                count: 1,
            },
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        // One line of body + one trailing newline. The body itself must
        // contain no embedded LFs — `jq` and friends parse line-by-line.
        assert_eq!(s.matches('\n').count(), 1);
    }
}
