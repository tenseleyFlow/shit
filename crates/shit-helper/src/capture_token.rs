// SPDX-License-Identifier: AGPL-3.0-or-later

//! L4b - capture tokens: the helper's own evidence for a privileged
//! apply. Linux-only, like the device-node restore that uses them.
//!
//! Any local user can run the helper, and its peer (shitd) runs as that
//! user, so every field of an apply request is attacker-controlled. The
//! helper therefore restores a block/char device node only when the
//! request carries a token this helper process issued when it saw that
//! node unlinked through a held fd.
//!
//! A token is HMAC-SHA256 over the captured facts (kind, rdev, mode,
//! uid, gid, dev, ino, absolute path, session, command seq) under a key
//! drawn from the kernel RNG at helper start. The key lives only in this
//! process's memory and is never sent, logged or written. A setcap
//! helper is non-dumpable, so the same user cannot ptrace it or read its
//! memory through /proc; [`ensure_non_dumpable`] makes that hold for
//! every start, setcap or not. A restarted helper has a new key and a
//! new id, so old tokens fail, and the id lets it say why.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use shit_proto::CaptureToken;
use std::sync::OnceLock;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Domain separation for the MAC input, versioned with its layout.
const DOMAIN: &[u8] = b"shit-helper device-node capture v1\0";

/// The facts a device-node token covers. Built from the held fd's
/// `fstat` at capture, and from the request at apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceFacts<'a> {
    /// Full `st_mode`; the kind is `mode & S_IFMT`.
    pub mode: u32,
    pub rdev: u64,
    pub uid: u32,
    pub gid: u32,
    /// `st_dev` / `st_ino` of the node that was removed.
    pub dev: u64,
    pub ino: u64,
    /// Absolute path the node was removed from.
    pub path: &'a str,
    /// The command that removed it.
    pub session: Uuid,
    pub seq: u64,
}

/// Why a token was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Issued by another helper process (normally: this helper was
    /// restarted since the capture).
    OtherHelper,
    /// Issued by this helper, but not for these facts.
    Mismatch,
}

impl TokenError {
    pub fn reason(self) -> &'static str {
        match self {
            TokenError::OtherHelper => "capture evidence expired: helper restarted",
            TokenError::Mismatch => "capture evidence does not match the request",
        }
    }
}

/// One helper process's token key and id.
pub struct TokenKey {
    id: [u8; 16],
    key: [u8; 32],
}

impl TokenKey {
    /// Fresh key and id from the kernel RNG. `None` if the RNG is
    /// unavailable; the helper then issues no tokens and every device
    /// restore is refused.
    pub fn generate() -> Option<Self> {
        let mut buf = [0u8; 48];
        fill_random(&mut buf)?;
        let mut id = [0u8; 16];
        let mut key = [0u8; 32];
        id.copy_from_slice(&buf[..16]);
        key.copy_from_slice(&buf[16..]);
        Some(Self { id, key })
    }

    fn mac(&self, f: &DeviceFacts<'_>) -> HmacSha256 {
        let mut m = HmacSha256::new_from_slice(&self.key).expect("HMAC takes any key length");
        m.update(DOMAIN);
        m.update(&self.id);
        m.update(&(f.mode & 0o170000).to_le_bytes());
        m.update(&f.rdev.to_le_bytes());
        m.update(&f.mode.to_le_bytes());
        m.update(&f.uid.to_le_bytes());
        m.update(&f.gid.to_le_bytes());
        m.update(&f.dev.to_le_bytes());
        m.update(&f.ino.to_le_bytes());
        m.update(&(f.path.len() as u64).to_le_bytes());
        m.update(f.path.as_bytes());
        m.update(f.session.as_bytes());
        m.update(&f.seq.to_le_bytes());
        m
    }

    pub fn issue(&self, f: &DeviceFacts<'_>) -> CaptureToken {
        CaptureToken {
            helper: self.id,
            mac: self.mac(f).finalize().into_bytes().into(),
        }
    }

    /// Constant-time check of `token` against `f`.
    pub fn verify(&self, f: &DeviceFacts<'_>, token: &CaptureToken) -> Result<(), TokenError> {
        if token.helper != self.id {
            return Err(TokenError::OtherHelper);
        }
        self.mac(f)
            .verify_slice(&token.mac)
            .map_err(|_| TokenError::Mismatch)
    }
}

static PROCESS_KEY: OnceLock<Option<TokenKey>> = OnceLock::new();

/// This process's key, generated on first use. `main` calls it before
/// the sandbox goes up so the RNG read happens at start.
pub fn process_key() -> Option<&'static TokenKey> {
    PROCESS_KEY.get_or_init(TokenKey::generate).as_ref()
}

fn fill_random(buf: &mut [u8]) -> Option<()> {
    let mut done = 0;
    while done < buf.len() {
        let rc = unsafe { libc::getrandom(buf[done..].as_mut_ptr().cast(), buf.len() - done, 0) };
        if rc < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return None;
        }
        done += rc as usize;
    }
    Some(())
}

/// Make sure the helper is not dumpable, and report what the kernel
/// says. The kernel already clears the flag when it execs a binary with
/// file capabilities; this covers a helper started some other way
/// (root, tests) and checks nothing in the process turned it back on.
/// Returns the value read back with `PR_GET_DUMPABLE` (0 is the goal).
pub fn ensure_non_dumpable() -> i32 {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(path: &str) -> DeviceFacts<'_> {
        DeviceFacts {
            mode: 0o020640,
            rdev: 0x103,
            uid: 1000,
            gid: 1000,
            dev: 0x803,
            ino: 42,
            path,
            session: Uuid::from_u128(7),
            seq: 3,
        }
    }

    #[test]
    fn token_verifies_only_for_the_facts_it_was_issued_for() {
        let k = TokenKey::generate().unwrap();
        let f = facts("/w/null");
        let t = k.issue(&f);
        assert_eq!(k.verify(&f, &t), Ok(()));
        let variants = [
            DeviceFacts {
                mode: 0o060640,
                ..f
            },
            DeviceFacts {
                mode: 0o020666,
                ..f
            },
            DeviceFacts { rdev: 0x105, ..f },
            DeviceFacts { uid: 0, ..f },
            DeviceFacts { gid: 0, ..f },
            DeviceFacts { dev: 0x804, ..f },
            DeviceFacts { ino: 43, ..f },
            DeviceFacts {
                path: "/w/null2",
                ..f
            },
            DeviceFacts {
                session: Uuid::from_u128(8),
                ..f
            },
            DeviceFacts { seq: 4, ..f },
        ];
        for v in variants {
            assert_eq!(k.verify(&v, &t), Err(TokenError::Mismatch), "{v:?}");
        }
        let mut bad = t;
        bad.mac[0] ^= 1;
        assert_eq!(k.verify(&f, &bad), Err(TokenError::Mismatch));
    }

    #[test]
    fn token_from_another_helper_process_is_refused_as_expired() {
        let old = TokenKey::generate().unwrap();
        let new = TokenKey::generate().unwrap();
        let f = facts("/w/null");
        let t = old.issue(&f);
        assert_eq!(new.verify(&f, &t), Err(TokenError::OtherHelper));
        assert_eq!(
            TokenError::OtherHelper.reason(),
            "capture evidence expired: helper restarted"
        );
        // Same id with another key (forged id) still fails the MAC.
        let forged = CaptureToken {
            helper: new.id,
            mac: t.mac,
        };
        assert_eq!(new.verify(&f, &forged), Err(TokenError::Mismatch));
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_case_2() {
        let mut m = HmacSha256::new_from_slice(b"Jefe").unwrap();
        m.update(b"what do ya want for nothing?");
        let out: [u8; 32] = m.finalize().into_bytes().into();
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
