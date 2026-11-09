// SPDX-License-Identifier: AGPL-3.0-or-later

//! L4b - capture tokens: the helper's own evidence for a privileged
//! apply. Linux-only, like the device-node and ownership (#227) restores
//! that use them.
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

/// Domain separation for the MAC input, versioned with its layout. Each
/// kind of evidence has its own, so a token for one kind never verifies
/// as another.
const DEVICE_DOMAIN: &[u8] = b"shit-helper device-node capture v1\0";
const OWNER_DOMAIN: &[u8] = b"shit-helper owner capture v1\0";

/// Captured facts a token can cover.
pub trait Facts {
    /// Domain-separation prefix for this kind of evidence.
    fn domain(&self) -> &'static [u8];
    /// Feed the facts into the MAC, in a fixed layout.
    fn feed(&self, m: &mut HmacSha256);
}

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

impl Facts for DeviceFacts<'_> {
    fn domain(&self) -> &'static [u8] {
        DEVICE_DOMAIN
    }
    fn feed(&self, m: &mut HmacSha256) {
        m.update(&(self.mode & 0o170000).to_le_bytes());
        m.update(&self.rdev.to_le_bytes());
        m.update(&self.mode.to_le_bytes());
        m.update(&self.uid.to_le_bytes());
        m.update(&self.gid.to_le_bytes());
        m.update(&self.dev.to_le_bytes());
        m.update(&self.ino.to_le_bytes());
        m.update(&(self.path.len() as u64).to_le_bytes());
        m.update(self.path.as_bytes());
        m.update(self.session.as_bytes());
        m.update(&self.seq.to_le_bytes());
    }
}

/// #227 - the facts an ownership token covers: the file's identity
/// (`st_dev`, `st_ino`, absolute path) and its owner at capture, which
/// is the owner an `ApplyChown` may give back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerFacts<'a> {
    pub uid: u32,
    pub gid: u32,
    pub dev: u64,
    pub ino: u64,
    pub path: &'a str,
    /// The command that changed the owner.
    pub session: Uuid,
    pub seq: u64,
}

impl Facts for OwnerFacts<'_> {
    fn domain(&self) -> &'static [u8] {
        OWNER_DOMAIN
    }
    fn feed(&self, m: &mut HmacSha256) {
        m.update(&self.uid.to_le_bytes());
        m.update(&self.gid.to_le_bytes());
        m.update(&self.dev.to_le_bytes());
        m.update(&self.ino.to_le_bytes());
        m.update(&(self.path.len() as u64).to_le_bytes());
        m.update(self.path.as_bytes());
        m.update(self.session.as_bytes());
        m.update(&self.seq.to_le_bytes());
    }
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

    fn mac(&self, f: &impl Facts) -> HmacSha256 {
        let mut m = HmacSha256::new_from_slice(&self.key).expect("HMAC takes any key length");
        m.update(f.domain());
        m.update(&self.id);
        f.feed(&mut m);
        m
    }

    pub fn issue(&self, f: &impl Facts) -> CaptureToken {
        CaptureToken {
            helper: self.id,
            mac: self.mac(f).finalize().into_bytes().into(),
        }
    }

    /// Constant-time check of `token` against `f`.
    pub fn verify(&self, f: &impl Facts, token: &CaptureToken) -> Result<(), TokenError> {
        if token.helper != self.id {
            return Err(TokenError::OtherHelper);
        }
        self.mac(f)
            .verify_slice(&token.mac)
            .map_err(|_| TokenError::Mismatch)
    }
}

/// True when the filesystem holding `fd` is mounted `nodev` (FUSE
/// always is). Such a filesystem can report any rdev and owner, so a
/// device node seen there proves nothing about what may be made on a
/// filesystem that honors device nodes. Works on an O_PATH fd.
pub fn fs_is_nodev(fd: std::os::fd::RawFd) -> std::io::Result<bool> {
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatvfs(fd, &mut sv) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(sv.f_flag & libc::ST_NODEV != 0)
}

/// Why the helper will not vouch for a device node held by `fd`: its
/// filesystem is `nodev`, or `fstatvfs` failed so the helper cannot
/// tell. `None` when the filesystem honors device nodes.
pub fn untrusted_source(fd: std::os::fd::RawFd) -> Option<shit_proto::UntrustedSource> {
    classify_source(fs_is_nodev(fd))
}

/// [`untrusted_source`] on a `fs_is_nodev` result (split out so the
/// error case can be tested).
pub fn classify_source(nodev: std::io::Result<bool>) -> Option<shit_proto::UntrustedSource> {
    match nodev {
        Ok(false) => None,
        Ok(true) => Some(shit_proto::UntrustedSource::Nodev),
        Err(_) => Some(shit_proto::UntrustedSource::Unknown),
    }
}

/// The token for a device-node capture, or none when the source
/// filesystem is untrusted (`nodev`, or its flags unknown): the helper
/// does not vouch for what such a filesystem reports.
pub fn device_token(
    key: &TokenKey,
    facts: &DeviceFacts<'_>,
    untrusted: bool,
) -> Option<CaptureToken> {
    (!untrusted).then(|| key.issue(facts))
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

    /// Review round 2, item 1: no token for a node on a `nodev`
    /// filesystem. /dev/shm is mounted nodev on the usual Linux setups;
    /// the test skips the real-mount half where it is not.
    #[test]
    fn no_token_for_a_nodev_source() {
        let k = TokenKey::generate().unwrap();
        let f = facts("/w/null");
        assert!(device_token(&k, &f, true).is_none());
        assert_eq!(device_token(&k, &f, false), Some(k.issue(&f)));
        // A real nodev mount, where /proc/mounts lists one at /dev/shm.
        use std::os::fd::AsRawFd;
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        let shm_nodev = mounts.lines().any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.get(1) == Some(&"/dev/shm")
                && f.get(3).is_some_and(|o| o.split(',').any(|x| x == "nodev"))
        });
        if shm_nodev {
            let fd = std::fs::File::open("/dev/shm").unwrap();
            assert!(fs_is_nodev(fd.as_raw_fd()).unwrap());
        }
    }

    /// Review round 3, item 4: an fstatvfs error is its own reason, not
    /// "nodev".
    #[test]
    fn statvfs_error_is_unknown_not_nodev() {
        use shit_proto::UntrustedSource;
        assert_eq!(classify_source(Ok(false)), None);
        assert_eq!(classify_source(Ok(true)), Some(UntrustedSource::Nodev));
        assert_eq!(
            classify_source(Err(std::io::Error::from_raw_os_error(libc::EBADF))),
            Some(UntrustedSource::Unknown)
        );
        assert_eq!(untrusted_source(-1), Some(UntrustedSource::Unknown));
    }

    fn owner(path: &str) -> OwnerFacts<'_> {
        OwnerFacts {
            uid: 0,
            gid: 0,
            dev: 0x803,
            ino: 42,
            path,
            session: Uuid::from_u128(7),
            seq: 3,
        }
    }

    /// #227: an ownership token binds owner, identity, path and command.
    #[test]
    fn owner_token_verifies_only_for_the_facts_it_was_issued_for() {
        let k = TokenKey::generate().unwrap();
        let f = owner("/etc/x");
        let t = k.issue(&f);
        assert_eq!(k.verify(&f, &t), Ok(()));
        let variants = [
            OwnerFacts { uid: 1000, ..f },
            OwnerFacts { gid: 1000, ..f },
            OwnerFacts { dev: 0x804, ..f },
            OwnerFacts { ino: 43, ..f },
            OwnerFacts {
                path: "/etc/y",
                ..f
            },
            OwnerFacts {
                session: Uuid::from_u128(8),
                ..f
            },
            OwnerFacts { seq: 4, ..f },
        ];
        for v in variants {
            assert_eq!(k.verify(&v, &t), Err(TokenError::Mismatch), "{v:?}");
        }
        let other = TokenKey::generate().unwrap();
        assert_eq!(other.verify(&f, &t), Err(TokenError::OtherHelper));
    }

    /// A device token never passes as an ownership token for the same
    /// identity and owner, and the other way round.
    #[test]
    fn device_and_owner_tokens_do_not_cross_verify() {
        let k = TokenKey::generate().unwrap();
        let d = facts("/w/null");
        let o = OwnerFacts {
            uid: d.uid,
            gid: d.gid,
            dev: d.dev,
            ino: d.ino,
            path: d.path,
            session: d.session,
            seq: d.seq,
        };
        assert_eq!(k.verify(&o, &k.issue(&d)), Err(TokenError::Mismatch));
        assert_eq!(k.verify(&d, &k.issue(&o)), Err(TokenError::Mismatch));
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
