// SPDX-License-Identifier: AGPL-3.0-or-later

//! `shit doctor` JSON envelope (B03).
//!
//! Versioned schema for CI / external tooling consumption. The
//! `--json` flag on `shit doctor` emits a `DoctorReport` serialized
//! as JSON; keep this schema strictly additive so consumers pinned
//! to `schema_version: 1` keep working.
//!
//! ## Compatibility rules
//!
//! - **DO** add new optional fields (`Option<T>` or `Vec<T>` that
//!   may be empty). Old consumers ignore unknown keys.
//! - **DO** add new variants to per-platform sub-reports (BsdReport,
//!   LinuxReport, MacReport). Each lives behind a top-level
//!   `Option<…>` so platforms-not-present serialize to `null`.
//! - **DO NOT** rename existing fields, remove fields, or change a
//!   field's serialized type without bumping `schema_version`.
//! - **DO NOT** rely on field ordering in serialized JSON — consumers
//!   should use object access by key.
//!
//! Bump `schema_version` to 2+ only for genuinely-breaking changes;
//! document the migration in `.docs/audits/doctor-json-schema.md`.

use serde::{Deserialize, Serialize};

/// Top-level envelope. Serialized by `shit doctor --json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Schema version. Currently `1`. Consumers SHOULD assert this
    /// equals (or is at least) the version they're coded against.
    pub schema_version: u32,
    pub host: HostInfo,
    /// Present on FreeBSD/NetBSD/OpenBSD/DragonFly. `None` elsewhere.
    pub bsd: Option<BsdReport>,
    /// Present on Linux (filled by L05). `None` elsewhere.
    pub linux: Option<LinuxReport>,
    /// Present on macOS (filled by future mac campaign). `None`
    /// elsewhere.
    pub macos: Option<MacReport>,
    /// Cross-platform: COW tier per probed mount point.
    pub mounts: Vec<MountReport>,
}

/// Host identification — OS family, version, arch. Always present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// `freebsd`, `linux`, `macos`, `netbsd`, `openbsd`, `dragonfly`.
    pub os: String,
    /// OS release string. FreeBSD: `14.4-RELEASE-p3`. Linux:
    /// kernel version (`6.5.0-25-generic`). macOS: Darwin release.
    pub os_release: String,
    /// `x86_64`, `aarch64`, etc.
    pub arch: String,
}

/// BSD-family report. Filled by `probes::bsd`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BsdReport {
    /// Stable string identifying the active runtime tier. One of:
    /// `"kqueue+preload"`, `"kqueue-only"`, `"degraded"`.
    pub runtime_capture: String,
    /// True iff the live `kqueue(2)` functional probe succeeded —
    /// we opened a kqueue, registered EVFILT_VNODE on a tempfile,
    /// wrote to it, and drained the NOTE_WRITE event in <100ms.
    pub kqueue_functional: bool,
    /// True iff `cap_getmode(2)` returned 0 (the syscall is wired
    /// in the kernel — doesn't matter whether we're IN cap mode).
    /// FreeBSD-only field; absent (or false) on other BSDs.
    pub capsicum_available: bool,
    /// True iff the helper will enter `cap_enter(2)` on startup with
    /// the current environment. B05 default-on: this is true when
    /// `capsicum_available` is true AND `SHIT_CAPSICUM != "0"`.
    /// Users can verify sandbox status without spawning the helper.
    pub capsicum_default_on: bool,
    /// Names of ZFS datasets discovered via `zfs list -H -o name`.
    /// Empty if zfs is not installed or no pools imported.
    pub zfs_datasets: Vec<String>,
    /// Live helper handshake probe result.
    pub helper_handshake: HelperHandshakeReport,
    /// True iff the LD_PRELOAD shim is installed at the expected
    /// path (`/usr/local/lib/shit/libshit_preload.so`).
    pub preload_shim_installed: bool,
}

/// Result of spawning `shit-helper handshake-probe --daemon-sock
/// <path>` and waiting for its one-line JSON reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperHandshakeReport {
    /// `true` iff the helper successfully exchanged a Handshake /
    /// HandshakeAck with the daemon at `daemon_sock`.
    pub ok: bool,
    /// Wall-clock round-trip time in milliseconds. 0 when `ok=false`.
    pub latency_ms: u32,
    /// Version string the helper reported (e.g. `"shit-helper 0.1.0"`).
    /// `None` when the handshake failed before the helper could reply.
    pub helper_version: Option<String>,
    /// Capture tier label the helper picked
    /// (`"kqueue"`, `"fanotify"`, etc.). `None` on handshake failure.
    pub kernel_tier: Option<String>,
    /// Connection / handshake error message when `ok=false`. `None`
    /// on success.
    pub error: Option<String>,
}

/// Linux-family report. Populated by L05 (the Linux doctor uplift).
/// Empty here so the JSON envelope stays stable while L05 is in
/// flight; the schema permits adding fields later without bumping
/// `schema_version`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinuxReport {}

/// macOS-family report. Populated by the future mac campaign.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MacReport {}

/// One probed mount point. Mirrors the existing table's columns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountReport {
    /// Path that was probed (e.g. `/home/user`, `/etc`).
    pub path: String,
    /// Filesystem family classification (e.g. `ufs`, `ext4`, `apfs`).
    pub fs_kind: String,
    /// COW tier the executor would pick for this path. `None` when
    /// no tier is viable (capture would refuse / hard-fail).
    pub picked_cow_tier: Option<String>,
    /// Human-readable caveats associated with this mount + tier
    /// (synthetic-fs warning, network-fs warning, etc.).
    pub caveats: Vec<String>,
}

/// Current schema version. Consumers MAY pin this; we only bump
/// it for breaking changes.
pub const SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_report() -> DoctorReport {
        DoctorReport {
            schema_version: SCHEMA_VERSION,
            host: HostInfo {
                os: "freebsd".into(),
                os_release: "14.4-RELEASE".into(),
                arch: "aarch64".into(),
            },
            bsd: Some(BsdReport {
                runtime_capture: "kqueue-only".into(),
                kqueue_functional: true,
                capsicum_available: true,
                capsicum_default_on: true,
                zfs_datasets: vec![],
                helper_handshake: HelperHandshakeReport {
                    ok: false,
                    latency_ms: 0,
                    helper_version: None,
                    kernel_tier: None,
                    error: Some("no daemon running".into()),
                },
                preload_shim_installed: false,
            }),
            linux: None,
            macos: None,
            mounts: vec![],
        }
    }

    #[test]
    fn schema_version_is_one() {
        // Bumping this is a deliberate API break — make sure it's
        // intentional. If you're seeing this test fail and you
        // intentionally bumped the version, update the assertion
        // here AND publish the migration note in
        // `.docs/audits/doctor-json-schema.md`.
        assert_eq!(SCHEMA_VERSION, 1);
    }

    #[test]
    fn report_serializes_to_json() {
        let r = empty_report();
        let s = serde_json::to_string(&r).expect("serialize");
        assert!(s.contains("\"schema_version\":1"));
        assert!(s.contains("\"os\":\"freebsd\""));
        assert!(s.contains("\"runtime_capture\":\"kqueue-only\""));
    }

    #[test]
    fn report_round_trips_through_json() {
        let r = empty_report();
        let s = serde_json::to_string(&r).expect("serialize");
        let r2: DoctorReport = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(r2.schema_version, r.schema_version);
        assert_eq!(r2.host.os, r.host.os);
        assert!(r2.bsd.is_some());
        assert!(r2.linux.is_none());
        assert!(r2.macos.is_none());
    }

    #[test]
    fn unknown_fields_in_input_ignored() {
        // Forward compat: consumers running schema v1 reading an
        // envelope from a v1-extended-with-new-fields server should
        // gracefully drop the unknown keys. serde's default behavior
        // does this.
        let extended = r#"{
            "schema_version": 1,
            "host": {"os":"freebsd","os_release":"14.4","arch":"aarch64"},
            "bsd": null,
            "linux": null,
            "macos": null,
            "mounts": [],
            "future_field_we_dont_know_about": "ignore me"
        }"#;
        let r: DoctorReport = serde_json::from_str(extended).expect("ignore unknown");
        assert_eq!(r.schema_version, 1);
    }
}
