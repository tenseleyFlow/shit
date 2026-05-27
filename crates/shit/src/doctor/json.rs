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
    /// AR07.3 — coverage manifest. What `shit undo` does and does
    /// not claim to reverse. Cross-platform: `refused_classes` is
    /// constant per build (the planner refuse-list catalog);
    /// `covered_classes` may shift per OS as tiers light up.
    /// `serde(default)` so older `shit doctor --json` consumers
    /// round-trip clean envelopes from new daemons.
    #[serde(default)]
    pub arbitrary_undo_coverage: ArbitraryUndoCoverage,
}

/// AR07.3 coverage manifest. Tells the user (and CI) what
/// `shit undo` honestly claims to do.
///
/// The catalog of refused classes lives in
/// [`shit_planner::refuse::CATALOG`] and is enumerated here via
/// [`shit_planner::refuse::catalog_classes`] so the two never
/// drift.
///
/// `covered_classes` is the inventory of capture-tier-supported
/// classes shit currently undoes. Sourced from the AR08.1
/// coverage audit; today it's a hand-curated list per OS. A
/// future sprint may derive it programmatically from
/// `InverseTier` + per-class smoke status, but the AR07.3 surface
/// freezes the contract first.
///
/// `coverage_pct` is a rough rollup for the human-facing doctor
/// summary, computed as `covered / (covered + refused)` rounded
/// to whole percent. It's a guide, not a contract.
///
/// `last_validated_at` is set by CI when it writes a fresh
/// doctor JSON snapshot; defaults to the empty string when no
/// validation has been recorded.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArbitraryUndoCoverage {
    pub covered_classes: Vec<String>,
    pub refused_classes: Vec<String>,
    pub coverage_pct: u32,
    pub last_validated_at: String,
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
///
/// `Default` is the "no daemon was probed" value — all-false /
/// all-None with an empty `error`. Used by [`LinuxReport`]'s
/// `Default` derive so the schema's neutral state is well-defined.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
///
/// All fields are filled in by `crate::doctor::probes::linux`. A
/// probe that can't determine its value emits the neutral default
/// (`false`, empty Vec, `None`) so the JSON envelope still
/// serializes cleanly even on broken hosts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinuxReport {
    /// Stable string identifying the active runtime tier. One of
    /// `"ebpf-lsm"`, `"fanotify-perm"`, `"degraded"`. Matches the
    /// strings emitted by `shit-helper`'s `pick_linux_tier`.
    pub runtime_capture: String,
    /// True iff a live fanotify-perm functional probe succeeded —
    /// helper opened a fanotify-perm fd, marked a tmpfs path, wrote
    /// a probe file, drained one perm event in <100ms.
    pub fanotify_functional: bool,
    /// True iff the eBPF-LSM prerequisite probe succeeded — kernel
    /// ≥5.7, CONFIG_BPF_LSM=y, `bpf` in /sys/kernel/security/lsm,
    /// helper has CAP_BPF + CAP_PERFMON.
    pub ebpf_lsm_functional: bool,
    /// Capability state for the helper binary on disk plus the
    /// caller's own effective caps.
    pub capabilities: CapsReport,
    /// systemd --user status for `shit.service`.
    pub systemd_user_unit: SystemdUnitReport,
    /// Contents of `/sys/kernel/security/lsm` (comma-split into a
    /// list). Empty when unreadable.
    pub kernel_lsm_list: Vec<String>,
    /// Helper handshake probe — shared with `BsdReport`. Same wire,
    /// same semantics (helper spawned, daemon handshake exchanged).
    pub helper_handshake: HelperHandshakeReport,
}

/// Capability state — split into caller-side (the `shit` CLI's
/// effective caps via `/proc/self/status`) and helper-binary-side
/// (file caps via `getcap` shell-out).
///
/// Doctor caller and helper binary may have different cap sets.
/// The helper's file caps are what matter for runtime; the
/// caller's caps matter for whether the in-process fanotify probe
/// is viable (CAP_SYS_ADMIN is required).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapsReport {
    /// Helper binary file caps from `getcap <helper-path>`.
    pub helper_binary: HelperBinaryCaps,
    /// Effective caps of the `shit` doctor process itself.
    pub caller_effective: CallerEffectiveCaps,
    /// If any helper-binary cap is missing, the exact `setcap`
    /// invocation to fix it. `None` when all required caps are
    /// present.
    pub setcap_remediation: Option<String>,
}

/// Caps the helper binary holds as file caps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HelperBinaryCaps {
    pub cap_sys_admin: bool,
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
    /// True iff we could resolve a helper-bin path and read its
    /// file caps. False when the helper isn't installed where we
    /// can find it (typical fresh-checkout case).
    pub readable: bool,
    /// AU08 — true when caps existed previously (sentinel file present)
    /// but the helper binary mtime is newer than the sentinel, i.e. a
    /// rebuild has stripped the caps since the last apply. Distinguishes
    /// a fresh checkout (never had caps; sentinel absent → false) from a
    /// post-rebuild state (had caps; cargo stripped them → true). When
    /// true, `shit doctor --fix` (or re-running with SHIT_AUTO_SETCAP=1)
    /// is the targeted remediation.
    #[serde(default)]
    pub caps_stale: bool,
}

/// Effective caps of the calling process (the `shit` CLI). Read
/// from `/proc/self/status` `CapEff`. Relevant because the in-
/// process fanotify probe requires CAP_SYS_ADMIN — if the doctor
/// caller lacks it, the probe is skipped and noted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallerEffectiveCaps {
    pub cap_sys_admin: bool,
    pub cap_bpf: bool,
    pub cap_perfmon: bool,
}

/// `systemctl --user is-{active,enabled}` status for the daemon
/// user unit, plus a present-on-disk check for the unit file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemdUnitReport {
    /// `~/.config/systemd/user/shit.service` exists.
    pub user_unit_present: bool,
    /// `systemctl --user is-active shit.service` returned "active".
    pub user_unit_active: bool,
    /// `systemctl --user is-enabled shit.service` returned
    /// "enabled" or "static".
    pub user_unit_enabled: bool,
    /// True iff `systemctl --user` is reachable at all. SSH non-
    /// interactive sessions may not have `XDG_RUNTIME_DIR` set; in
    /// that case all the active/enabled bits are false and this
    /// field tells the operator why.
    pub user_manager_reachable: bool,
}

/// macOS-family report. Populated by `probes::macos` (M02).
///
/// `runtime_capture` is the stable enum string identifying the
/// active capture tier:
/// - `"endpoint-security"` — ES tier active (M03; entitled + FDA granted)
/// - `"fsevents-degraded"` — M01 fallback (no entitlement or no FDA)
/// - `"unknown"` — could not determine (probe failures)
///
/// Each sub-report has its own `Default` so a probe that can't run
/// (missing tool, EPERM, etc.) emits the neutral value and the
/// JSON envelope still serializes cleanly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MacReport {
    pub runtime_capture: String,
    pub endpoint_security: EndpointSecurityReport,
    pub fsevents: FsEventsProbeReport,
    pub codesign: CodesignReport,
    pub sip: SipReport,
    pub sandbox: SandboxReport,
    /// Helper handshake — shared shape with [`BsdReport`] /
    /// [`LinuxReport`]. Same wire, same semantics.
    pub helper_handshake: HelperHandshakeReport,
    /// M03.x.POWER-USER — composed view: is this system in a state
    /// where ES will actually run? True iff SIP-disabled (or custom
    /// w/ filesystem protection off), authenticated-root disabled,
    /// AMFI bypass boot-arg set, and the installed helper carries
    /// the ES entitlement. Drives the doctor's "tier=endpoint-
    /// security vs tier=fsevents-degraded" remediation surface.
    #[serde(default)]
    pub es_capable: bool,
    /// M03.x.POWER-USER — when `es_capable = false`, each blocker
    /// names a specific prereq the user can fix + the command to
    /// fix it. Empty when es_capable = true. Stable JSON so the
    /// CLI's `shit setup-es-mode --print` can format the same data.
    #[serde(default)]
    pub es_blockers: Vec<EsBlocker>,
}

/// EndpointSecurity probe result.
///
/// M02 stages this — `entitlement_present` + `client_can_subscribe`
/// remain false until M03 lands the real ES FFI. The `notes` field
/// surfaces "M03 not yet implemented" until then.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EndpointSecurityReport {
    /// True iff `es_new_client` returns SUCCESS (entitlement
    /// granted by Apple AND embedded in the binary's codesign).
    pub entitlement_present: bool,
    /// True iff Full Disk Access has been granted to the helper.
    /// Detected via stat against known-FDA-protected paths
    /// (~/Library/Mail/V*/MailData/Envelope Index, with TCC.db
    /// fallback). EPERM → false; ENOENT-on-all-paths → false
    /// (indeterminate, conservative); success → true.
    pub fda_granted: bool,
    /// True iff the helper can actually subscribe an ES client.
    /// Encompasses entitlement_present + fda_granted plus any
    /// sandbox/runtime constraints. M02 stub: always false.
    pub client_can_subscribe: bool,
    /// Subscribed event kinds when `client_can_subscribe = true`.
    /// Empty otherwise.
    pub subscribed_event_kinds: Vec<String>,
    /// Probe-internal notes the doctor can surface in table mode
    /// (e.g. "FDA indeterminate: Mail.app never used; TCC.db fallback
    /// also unreachable" or "M03 not yet implemented"). Empty in the
    /// nominal case.
    pub notes: Vec<String>,
    /// M03.x.POWER-USER — true iff the installed `shit-helper`
    /// binary carries `com.apple.developer.endpoint-security.client`
    /// in its embedded entitlements. Read via
    /// `codesign -d --entitlements - <helper>` — independent of
    /// whether AMFI is currently accepting the claim (that's
    /// `entitlement_present`). The user opts into power-user mode
    /// by running the install-time codesign script that flips this
    /// from false to true.
    #[serde(default)]
    pub helper_has_es_entitlement: bool,
}

/// FSEvents functional probe result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FsEventsProbeReport {
    /// True iff the probe successfully started a stream, observed
    /// one event for a touched file, and tore down — all inside
    /// the latency budget.
    pub functional: bool,
    /// Wall-clock time from FSEventStreamCreate to first event in
    /// milliseconds. 0 when `functional = false`.
    pub latency_probe_ms: u32,
}

/// Codesign verification result.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CodesignReport {
    /// Apple Developer Team ID (e.g. `"Q6JHJ53S9C"`). `None` when
    /// the binary is ad-hoc-signed or unsigned.
    pub team_id: Option<String>,
    /// Stable string: `"developer-id-application"`, `"ad-hoc"`,
    /// `"unsigned"`, or `"unknown"`.
    pub signature_kind: String,
    /// True iff the binary is notarized (stapler ticket present).
    pub notarized: bool,
    /// True iff the notary ticket is stapled to the binary.
    pub stapled: bool,
}

/// SIP (System Integrity Protection) state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SipReport {
    /// `"enabled"`, `"disabled"`, `"custom"`, or `"unknown"`.
    pub state: String,
    /// M03.x.POWER-USER — `csrutil authenticated-root status` parse.
    /// Apple Silicon machines have a System volume seal that's
    /// independent of SIP itself. AMFI's entitlement-bypass path
    /// requires BOTH SIP disabled AND auth-root disabled; just
    /// disabling SIP isn't enough. `"disabled"` / `"enabled"` /
    /// `"unknown"` (csrutil not present or output unrecognized).
    #[serde(default)]
    pub authenticated_root: String,
    /// M03.x.POWER-USER — `nvram boot-args` parse for
    /// `amfi_get_out_of_my_way=0x1`. When set, AMFI accepts
    /// entitlement claims from ad-hoc-signed binaries — the
    /// mechanism the M03.x.POWER-USER install relies on.
    #[serde(default)]
    pub amfi_bypass: bool,
}

/// M03.x.POWER-USER — one entry per ES-mode prerequisite the user's
/// current system fails. The doctor surfaces these as a numbered
/// remediation checklist; `shit setup-es-mode --print` formats the
/// same data into a user-facing setup script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsBlocker {
    /// Stable identifier the CLI/UX layer keys on: `"sip"`,
    /// `"authenticated_root"`, `"amfi_bypass"`, `"helper_entitlement"`.
    pub component: String,
    /// Human-readable description of what's wrong.
    pub reason: String,
    /// Concrete shell command (Recovery-mode for SIP/auth-root,
    /// running-macOS for AMFI/codesign) that fixes this blocker.
    /// `None` when the fix isn't a one-command runner (e.g. needs a
    /// full reboot after a sequence).
    pub fix_command: Option<String>,
    /// True iff the fix requires booting into Recovery (csrutil
    /// commands). The doctor's text mode prepends "(Recovery)" to
    /// these so users know they can't just run them from a terminal.
    #[serde(default)]
    pub recovery_mode: bool,
}

/// Sandbox profile verification.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SandboxReport {
    /// True iff the M01 sandbox profile is actually loaded for
    /// the helper. Verified via `sandbox_check(pid, ...)`.
    pub profile_loaded: bool,
    /// True iff `file-write*` outside the state dir is permitted
    /// (a regression — the M01 profile should deny this).
    pub write_allowed_outside_state_dir: bool,
}

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
            arbitrary_undo_coverage: ArbitraryUndoCoverage::default(),
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
    fn arbitrary_undo_coverage_serializes_with_all_fields() {
        let mut r = empty_report();
        r.arbitrary_undo_coverage = ArbitraryUndoCoverage {
            covered_classes: vec!["fs-content-restore".to_string()],
            refused_classes: vec!["remote-push".to_string(), "power-state".to_string()],
            coverage_pct: 33,
            last_validated_at: "2026-05-26T00:00:00Z".to_string(),
        };
        let s = serde_json::to_string(&r).expect("serialize");
        // Field present even when other coverage fields are empty.
        assert!(s.contains("\"arbitrary_undo_coverage\""));
        assert!(s.contains("\"covered_classes\":[\"fs-content-restore\"]"));
        assert!(
            s.contains("\"refused_classes\":[\"remote-push\",\"power-state\"]"),
            "refused_classes list missing or in unexpected order: {s}"
        );
        assert!(s.contains("\"coverage_pct\":33"));
        assert!(s.contains("\"last_validated_at\":\"2026-05-26T00:00:00Z\""));
    }

    #[test]
    fn arbitrary_undo_coverage_default_round_trips_clean() {
        let r = empty_report();
        let s = serde_json::to_string(&r).expect("serialize");
        let r2: DoctorReport = serde_json::from_str(&s).expect("deserialize");
        assert!(r2.arbitrary_undo_coverage.covered_classes.is_empty());
        assert!(r2.arbitrary_undo_coverage.refused_classes.is_empty());
        assert_eq!(r2.arbitrary_undo_coverage.coverage_pct, 0);
        assert!(r2.arbitrary_undo_coverage.last_validated_at.is_empty());
    }

    #[test]
    fn older_envelope_without_coverage_field_round_trips_via_serde_default() {
        // Forward-compat sanity: an envelope from a build that
        // predates AR07.3 (no arbitrary_undo_coverage key in the
        // JSON) deserializes cleanly, populating the field with
        // ArbitraryUndoCoverage::default(). The schema_version
        // stays at 1 because the field is additive.
        let legacy = r#"{
            "schema_version": 1,
            "host": {"os":"linux","os_release":"6.5.0","arch":"x86_64"},
            "bsd": null,
            "linux": null,
            "macos": null,
            "mounts": []
        }"#;
        let r: DoctorReport = serde_json::from_str(legacy).expect("deserialize");
        assert_eq!(r.schema_version, 1);
        assert!(r.arbitrary_undo_coverage.covered_classes.is_empty());
        assert!(r.arbitrary_undo_coverage.refused_classes.is_empty());
    }

    #[test]
    fn macos_report_round_trips() {
        let mut r = empty_report();
        r.host.os = "macos".into();
        r.host.os_release = "Darwin 25.4.0".into();
        r.bsd = None;
        r.macos = Some(MacReport {
            runtime_capture: "fsevents-degraded".into(),
            endpoint_security: EndpointSecurityReport {
                entitlement_present: false,
                fda_granted: false,
                client_can_subscribe: false,
                subscribed_event_kinds: vec![],
                notes: vec!["M03 not yet implemented".into()],
                helper_has_es_entitlement: false,
            },
            fsevents: FsEventsProbeReport {
                functional: true,
                latency_probe_ms: 47,
            },
            codesign: CodesignReport {
                team_id: Some("Q6JHJ53S9C".into()),
                signature_kind: "ad-hoc".into(),
                notarized: false,
                stapled: false,
            },
            sip: SipReport {
                state: "enabled".into(),
                authenticated_root: "enabled".into(),
                amfi_bypass: false,
            },
            sandbox: SandboxReport {
                profile_loaded: true,
                write_allowed_outside_state_dir: false,
            },
            helper_handshake: HelperHandshakeReport {
                ok: true,
                latency_ms: 12,
                helper_version: Some("0.1.0".into()),
                kernel_tier: Some("fsevents-degraded".into()),
                error: None,
            },
            es_capable: false,
            es_blockers: vec![],
        });
        let s = serde_json::to_string(&r).expect("serialize");
        assert!(s.contains("\"runtime_capture\":\"fsevents-degraded\""));
        assert!(s.contains("\"signature_kind\":\"ad-hoc\""));
        assert!(s.contains("\"team_id\":\"Q6JHJ53S9C\""));
        assert!(s.contains("\"state\":\"enabled\""));
        let r2: DoctorReport = serde_json::from_str(&s).expect("deserialize");
        let mac = r2.macos.expect("macos report present");
        assert_eq!(mac.runtime_capture, "fsevents-degraded");
        assert_eq!(mac.fsevents.latency_probe_ms, 47);
        assert!(mac.sandbox.profile_loaded);
        assert!(!mac.sandbox.write_allowed_outside_state_dir);
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
