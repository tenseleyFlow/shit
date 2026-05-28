// SPDX-License-Identifier: AGPL-3.0-or-later

//! AU12 — scan a watched path for binaries whose mutations bypass the
//! LD_PRELOAD / DYLD_INSERT_LIBRARIES shim, so doctor can warn the
//! user about lost coverage.
//!
//! ## Scope
//!
//! Two bypass classes detected today:
//!
//! 1. **setuid** — `stat(2)` checks the S_ISUID bit. setuid binaries
//!    strip `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` on `execve(2)` per
//!    `rtld(1)` / `dyld(1)` documented behavior.
//! 2. **statically linked** — ELF without `PT_INTERP`, or Mach-O
//!    without `LC_LOAD_DYLINKER`. The kernel never invokes a dynamic
//!    linker on these, so the shim has no entry point.
//!
//! In both cases the mutations are post-hoc-only via the kernel tier
//! (LSM on Linux, ZFS-clone on FreeBSD where set up; nothing on macOS
//! without an EndpointSecurity entitlement).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Hard cap on files visited per `scan_path` call. Beyond this the
/// scan returns what it has + sets `truncated=true`; the user gets
/// "at least N" rather than an exhaustive list. Doctor is a fast
/// path, not a forensic tool.
const SCAN_FILE_CAP: usize = 500;

/// Max directory-recursion depth. Doctor scans the user's cwd plus
/// one level (e.g. `./bin/`, `./target/`); deeper recursion turns
/// the doctor into a `find(1)` substitute and burns time on each
/// invocation.
const SCAN_MAX_DEPTH: usize = 2;

/// JSON-serializable visibility report. Populated by
/// `shit doctor --visibility <path>`; `None` on the default
/// doctor invocation so the envelope stays small.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisibilityReport {
    /// Root of the scan (the path the user passed).
    pub watched_path: PathBuf,
    /// Total executable-bit files visited. Bounded by
    /// `SCAN_FILE_CAP`.
    pub executables_scanned: u32,
    /// Count of setuid binaries found. The user-facing signal that
    /// "at least one of your binaries here is shim-invisible."
    pub setuid_bypassing_shim: u32,
    /// AU12.A — count of statically-linked binaries (ELF without
    /// PT_INTERP / Mach-O without LC_LOAD_DYLINKER). `#[serde(default)]`
    /// keeps older `shit doctor --json` consumers round-tripping
    /// envelopes without this field.
    #[serde(default)]
    pub static_bypassing_shim: u32,
    /// First N bypass entries for the user to inspect (cap small
    /// to keep JSON tight). Sorted by path.
    #[serde(default)]
    pub details: Vec<BypassEntry>,
    /// True iff the scan hit `SCAN_FILE_CAP` and stopped early.
    /// JSON consumers should treat `setuid_bypassing_shim` as a
    /// lower bound in that case.
    pub truncated: bool,
}

/// One bypass binary's path + classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BypassEntry {
    pub path: PathBuf,
    pub kind: BypassKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BypassKind {
    /// `mode & S_ISUID != 0`.
    Setuid,
    /// AU12.A — ELF without `PT_INTERP` or Mach-O without
    /// `LC_LOAD_DYLINKER`. The kernel never invokes a dynamic linker
    /// on these, so neither LD_PRELOAD nor DYLD_INSERT_LIBRARIES can
    /// attach.
    Static,
}

/// True iff `path` has the setuid bit set. Returns `false` for
/// missing / unreadable / non-file paths; the doctor never fails
/// hard on a permission denied during the walk.
///
/// `scan_path` doesn't call this — it works off the metadata it
/// already has from the directory walk so it doesn't re-stat. This
/// is part of the public API for callers (and AU12.A) that have a
/// single path in hand and don't need a tree walk.
#[allow(dead_code)]
pub fn is_setuid(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(md) if md.is_file() => (md.mode() & 0o4000) != 0,
        _ => false,
    }
}

/// Read up to this many bytes when sniffing an executable for static-
/// linkage. ELF program headers + Mach-O load commands almost always
/// fit in 32 KiB; binaries that don't are exotic enough that doctor
/// can give up cleanly (returning `None`).
const STATIC_SNIFF_CAP: u64 = 32 * 1024;

/// Inspect `path` and decide whether it's a statically-linked
/// executable.
///
/// Return values:
///
/// - `Some(true)` — recognized executable AND no dynamic linker
///   reference (ELF lacks `PT_INTERP`, Mach-O lacks
///   `LC_LOAD_DYLINKER`).
/// - `Some(false)` — recognized executable WITH a dynamic linker.
/// - `None` — not a recognized executable (script, archive, raw
///   data, unreadable, parse error). The visibility scan treats
///   this as "uncountable" — neither setuid nor static, just an
///   ordinary file the shim path doesn't worry about.
///
/// Reads at most `STATIC_SNIFF_CAP` bytes from `path`. Pure inspection
/// — never executes the binary.
pub fn is_statically_linked(path: &Path) -> Option<bool> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(STATIC_SNIFF_CAP as usize);
    f.take(STATIC_SNIFF_CAP).read_to_end(&mut buf).ok()?;
    classify_bytes(&buf)
}

/// Pure byte-level classifier. Split out for testability: the unit
/// tests feed it synthetic ELF + Mach-O blobs without touching the
/// filesystem.
///
/// Dispatches via magic-byte sniffing so we don't need goblin's PE
/// support pulled in just to reach `Object::parse`.
fn classify_bytes(bytes: &[u8]) -> Option<bool> {
    if bytes.len() < 4 {
        return None;
    }
    match &bytes[0..4] {
        [0x7f, b'E', b'L', b'F'] => classify_elf(bytes),
        // Mach-O magic in both endians + 32/64-bit. The first byte
        // tells us the byte order; goblin's parser handles either.
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xcf, 0xfa, 0xed, 0xfe]
        | [0xca, 0xfe, 0xba, 0xbe] => classify_macho(bytes),
        _ => None,
    }
}

fn classify_elf(bytes: &[u8]) -> Option<bool> {
    let elf = goblin::elf::Elf::parse(bytes).ok()?;
    let has_interp = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == goblin::elf::program_header::PT_INTERP);
    if has_interp {
        return Some(false);
    }
    // No interp — static IF it's an executable. ET_EXEC = 2 is the
    // classic static-exec case; ET_DYN (3) without interp is ambiguous
    // (could be a .so OR a fully-PIE static), so we return None there
    // rather than over-claim.
    const ET_EXEC: u16 = 2;
    if elf.header.e_type == ET_EXEC {
        Some(true)
    } else {
        None
    }
}

fn classify_macho(bytes: &[u8]) -> Option<bool> {
    const LC_LOAD_DYLINKER: u32 = 0x0e;
    let mach = goblin::mach::Mach::parse(bytes).ok()?;
    let lc_has_dylinker = |lcs: &[goblin::mach::load_command::LoadCommand]| -> bool {
        lcs.iter().any(|lc| lc.command.cmd() == LC_LOAD_DYLINKER)
    };
    match mach {
        goblin::mach::Mach::Binary(macho) => Some(!lc_has_dylinker(&macho.load_commands)),
        // Fat / universal — every slice in our usage carries the
        // same linkage shape. Inspect the first slice.
        goblin::mach::Mach::Fat(fat) => {
            fat.into_iter()
                .next()
                .and_then(|res| res.ok())
                .and_then(|slice| match slice {
                    goblin::mach::SingleArch::MachO(macho) => {
                        Some(!lc_has_dylinker(&macho.load_commands))
                    }
                    _ => None,
                })
        }
    }
}

/// Walk `root` up to `SCAN_MAX_DEPTH` levels deep, collecting setuid
/// executables. Honors `SCAN_FILE_CAP`. Symlinks are followed via
/// `std::fs::metadata` (vs. `symlink_metadata`) since the visibility
/// question is about the file the user-facing binary actually
/// resolves to.
///
/// Returns Ok even when the root is missing — the report just shows
/// zero scanned files. The CLI's `--visibility` handler is responsible
/// for bailing on user-facing "no such path" before calling this.
pub fn scan_path(root: &Path) -> std::io::Result<VisibilityReport> {
    let mut report = VisibilityReport {
        watched_path: root.to_path_buf(),
        executables_scanned: 0,
        setuid_bypassing_shim: 0,
        static_bypassing_shim: 0,
        details: Vec::new(),
        truncated: false,
    };
    if !root.exists() {
        return Ok(report);
    }
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            // Unreadable dir — skip silently. The user pointed doctor
            // at the parent; us bailing on a single inaccessible
            // subdir would be more confusing than the empty result.
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            if report.executables_scanned as usize >= SCAN_FILE_CAP {
                report.truncated = true;
                stack.clear();
                break;
            }
            let path = entry.path();
            let md = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if md.is_dir() {
                if depth < SCAN_MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !md.is_file() {
                continue;
            }
            use std::os::unix::fs::MetadataExt;
            let mode = md.mode();
            // Only count files that are executable by *someone*. A
            // setuid-bit on a non-executable file is meaningless
            // (kernel only honors the bit on exec(2)).
            if mode & 0o111 == 0 {
                continue;
            }
            report.executables_scanned += 1;
            // A file can be BOTH setuid and statically linked — e.g.,
            // /usr/local/bin/static-sudo. Count + record both so the
            // text-mode warning reports the worst-case category for
            // each path independently.
            if mode & 0o4000 != 0 {
                report.setuid_bypassing_shim += 1;
                report.details.push(BypassEntry {
                    path: path.clone(),
                    kind: BypassKind::Setuid,
                });
            }
            // Static-link check: read up to 32 KiB. The sniff is bounded
            // and per-file, so worst-case scan cost stays in tens of MB
            // for the SCAN_FILE_CAP=500 ceiling — well inside the
            // <2s doctor-overhead budget.
            if matches!(is_statically_linked(&path), Some(true)) {
                report.static_bypassing_shim += 1;
                report.details.push(BypassEntry {
                    path,
                    kind: BypassKind::Static,
                });
            }
        }
    }
    report.details.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn touch(path: &Path, mode: u32) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn is_setuid_detects_bit() {
        let tmp = tempfile::tempdir().unwrap();
        let suid = tmp.path().join("sudo-fake");
        let plain = tmp.path().join("ls-fake");
        touch(&suid, 0o4755);
        touch(&plain, 0o755);
        assert!(is_setuid(&suid));
        assert!(!is_setuid(&plain));
    }

    #[test]
    fn is_setuid_false_for_nonfile() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        std::fs::create_dir(&dir).unwrap();
        // Even though directories can have the sticky/setuid bits
        // set on some unices, the bypass question doesn't apply —
        // exec(2) doesn't fire on a directory.
        let mut perm = std::fs::metadata(&dir).unwrap().permissions();
        perm.set_mode(0o4755);
        std::fs::set_permissions(&dir, perm).unwrap();
        assert!(!is_setuid(&dir));
        assert!(!is_setuid(&tmp.path().join("missing")));
    }

    #[test]
    fn scan_finds_one_setuid() {
        let tmp = tempfile::tempdir().unwrap();
        touch(&tmp.path().join("a"), 0o755);
        touch(&tmp.path().join("b-setuid"), 0o4755);
        touch(&tmp.path().join("c"), 0o644); // not executable — skipped
        let r = scan_path(tmp.path()).unwrap();
        assert_eq!(r.executables_scanned, 2);
        assert_eq!(r.setuid_bypassing_shim, 1);
        assert_eq!(r.details.len(), 1);
        assert_eq!(r.details[0].kind, BypassKind::Setuid);
        assert!(r.details[0].path.ends_with("b-setuid"));
        assert!(!r.truncated);
    }

    #[test]
    fn scan_honors_max_depth() {
        let tmp = tempfile::tempdir().unwrap();
        // depth 0 (root)
        touch(&tmp.path().join("root-bin"), 0o4755);
        let d1 = tmp.path().join("sub");
        std::fs::create_dir(&d1).unwrap();
        // depth 1
        touch(&d1.join("sub-bin"), 0o4755);
        let d2 = d1.join("sub2");
        std::fs::create_dir(&d2).unwrap();
        // depth 2
        touch(&d2.join("d2-bin"), 0o4755);
        let d3 = d2.join("sub3");
        std::fs::create_dir(&d3).unwrap();
        // depth 3 — should NOT be visited
        touch(&d3.join("d3-bin"), 0o4755);
        let r = scan_path(tmp.path()).unwrap();
        // Three setuid files at depths 0, 1, 2; the depth-3 one is
        // skipped because the walker bumps depth before pushing the
        // dir and refuses to push at SCAN_MAX_DEPTH.
        assert_eq!(r.setuid_bypassing_shim, 3);
    }

    #[test]
    fn scan_handles_missing_root() {
        let r = scan_path(Path::new("/nonexistent-au12-au12")).unwrap();
        assert_eq!(r.executables_scanned, 0);
        assert_eq!(r.setuid_bypassing_shim, 0);
    }

    #[test]
    fn scan_skips_nonexecutable_setuid() {
        // S_ISUID on a non-executable file is meaningless — exec(2)
        // never reads it. Don't pollute the count.
        let tmp = tempfile::tempdir().unwrap();
        touch(&tmp.path().join("weird"), 0o4644);
        let r = scan_path(tmp.path()).unwrap();
        assert_eq!(r.executables_scanned, 0);
        assert_eq!(r.setuid_bypassing_shim, 0);
        assert_eq!(r.static_bypassing_shim, 0);
    }

    // ----- AU12.A — static-linkage classifier tests -----
    //
    // The tests below feed `classify_bytes` synthetic ELF + Mach-O
    // headers rather than relying on the host shipping a statically-
    // linked binary at a known path. The byte-level synthesis means
    // these tests run identically on macOS (no static binaries by
    // default), Linux (where /bin/busybox MIGHT be static), and any
    // CI runner — no environment assumption.

    /// Build a minimal valid ELF64 byte sequence with exactly one
    /// program header. `with_interp = true` adds a PT_INTERP segment
    /// (so we expect classify → Some(false)); `with_interp = false`
    /// leaves only a PT_LOAD-style segment (classify → Some(true) when
    /// e_type=ET_EXEC).
    fn make_minimal_elf64(with_interp: bool) -> Vec<u8> {
        // ELF64 header is 64 bytes; program header is 56 bytes per
        // entry. We emit one ph entry, so total = 64 + 56 = 120.
        let ph_off: u64 = 64;
        let ph_count: u16 = 1;
        let mut buf = vec![0u8; 64 + 56];

        // EI_MAG
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // EI_CLASS = ELFCLASS64
        buf[5] = 1; // EI_DATA = ELFDATA2LSB (little-endian)
        buf[6] = 1; // EI_VERSION
        // e_type @ offset 16 (u16). 2 = ET_EXEC.
        buf[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine @ 18 (u16). 0x3e = EM_X86_64 (arbitrary).
        buf[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        // e_version @ 20 (u32) = 1.
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry @ 24 (u64) = 0x400000 (canonical).
        buf[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        // e_phoff @ 32 (u64).
        buf[32..40].copy_from_slice(&ph_off.to_le_bytes());
        // e_shoff @ 40 (u64) = 0 (no section headers).
        // e_flags @ 48 (u32) = 0.
        // e_ehsize @ 52 (u16) = 64.
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // e_phentsize @ 54 (u16) = 56.
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        // e_phnum @ 56 (u16).
        buf[56..58].copy_from_slice(&ph_count.to_le_bytes());
        // e_shentsize @ 58 (u16) = 0.
        // e_shnum @ 60 (u16) = 0.
        // e_shstrndx @ 62 (u16) = 0.

        // Program header at offset 64. Format (ELF64):
        //   p_type   (u32) @ +0
        //   p_flags  (u32) @ +4
        //   p_offset (u64) @ +8
        //   p_vaddr  (u64) @ +16
        //   p_paddr  (u64) @ +24
        //   p_filesz (u64) @ +32
        //   p_memsz  (u64) @ +40
        //   p_align  (u64) @ +48
        let p_type: u32 = if with_interp {
            3 /* PT_INTERP */
        } else {
            1 /* PT_LOAD */
        };
        buf[64..68].copy_from_slice(&p_type.to_le_bytes());
        // Other fields zero — goblin accepts the header structurally.

        buf
    }

    /// Build a minimal 32-bit Mach-O binary with optionally a
    /// LC_LOAD_DYLINKER load command. Always emits exactly one load
    /// command — goblin's parser fails on an LC-less Mach-O even
    /// though the spec arguably permits it — so we vary the command
    /// type (LC_LOAD_DYLINKER vs LC_UUID) rather than the count.
    fn make_minimal_macho_32(with_dylinker: bool) -> Vec<u8> {
        // Mach-O 32-bit magic = 0xfeedface. Header layout:
        //   magic        u32 @ 0
        //   cputype      u32 @ 4
        //   cpusubtype   u32 @ 8
        //   filetype     u32 @ 12
        //   ncmds        u32 @ 16
        //   sizeofcmds   u32 @ 20
        //   flags        u32 @ 24
        let mut buf = vec![0u8; 28];
        buf[0..4].copy_from_slice(&0xfeedfaceu32.to_le_bytes());
        buf[4..8].copy_from_slice(&0x7u32.to_le_bytes()); // CPU_TYPE_X86 (any plausible)
        buf[8..12].copy_from_slice(&0x3u32.to_le_bytes()); // generic subtype
        buf[12..16].copy_from_slice(&0x2u32.to_le_bytes()); // MH_EXECUTE = 2

        let (cmd, cmdsize, body) = if with_dylinker {
            // LC_LOAD_DYLINKER = 0x0e. Layout:
            //   cmd      u32
            //   cmdsize  u32
            //   name     u32 (offset of the string within the cmd)
            //   <string payload>
            let mut body = vec![0u8; 12]; // 12 bytes payload (after the 8-byte cmd/cmdsize header)
            body[0..4].copy_from_slice(&12u32.to_le_bytes()); // name.offset = 12 (right after the lc_str field)
            body[4..12].copy_from_slice(b"/dyld\0\0\0");
            (0x0eu32, 20u32, body)
        } else {
            // LC_UUID = 0x1b. Layout: cmd, cmdsize, uuid[16] = 24 bytes total.
            let body = vec![0u8; 16]; // uuid (all zeros — fine for parsing)
            (0x1bu32, 24u32, body)
        };
        let mut lc = Vec::with_capacity(cmdsize as usize);
        lc.extend_from_slice(&cmd.to_le_bytes());
        lc.extend_from_slice(&cmdsize.to_le_bytes());
        lc.extend_from_slice(&body);

        buf[16..20].copy_from_slice(&1u32.to_le_bytes()); // ncmds = 1
        buf[20..24].copy_from_slice(&cmdsize.to_le_bytes()); // sizeofcmds
        buf.extend_from_slice(&lc);

        buf
    }

    #[test]
    fn classify_bytes_elf_with_interp_is_dynamic() {
        let bytes = make_minimal_elf64(true);
        assert_eq!(classify_bytes(&bytes), Some(false));
    }

    #[test]
    fn classify_bytes_elf_without_interp_is_static() {
        let bytes = make_minimal_elf64(false);
        assert_eq!(classify_bytes(&bytes), Some(true));
    }

    #[test]
    fn classify_bytes_macho_with_dylinker_is_dynamic() {
        let bytes = make_minimal_macho_32(true);
        assert_eq!(classify_bytes(&bytes), Some(false));
    }

    #[test]
    fn classify_bytes_macho_without_dylinker_is_static() {
        let bytes = make_minimal_macho_32(false);
        assert_eq!(classify_bytes(&bytes), Some(true));
    }

    #[test]
    fn classify_bytes_shell_script_is_none() {
        // Scripts have no ELF / Mach-O magic; the classifier returns
        // None so they don't pollute either bypass count. The smoke
        // path counts them as ordinary "executables_scanned" entries.
        let bytes = b"#!/bin/sh\necho hi\n";
        assert_eq!(classify_bytes(bytes), None);
    }

    #[test]
    fn classify_bytes_garbage_is_none() {
        let bytes = b"\x00\x01\x02\x03not an executable";
        assert_eq!(classify_bytes(bytes), None);
    }

    #[test]
    fn is_statically_linked_on_disk_roundtrip() {
        // Validates the file-IO path: write a synthetic static ELF
        // to a tempfile, point is_statically_linked at it, expect
        // Some(true).
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("fake-static");
        std::fs::write(&p, make_minimal_elf64(false)).unwrap();
        assert_eq!(is_statically_linked(&p), Some(true));
    }

    #[test]
    fn scan_finds_static_via_synthetic_elf() {
        let tmp = tempfile::tempdir().unwrap();
        // One plain script (not counted as bypass).
        touch(&tmp.path().join("a-script"), 0o755);
        // One synthetic static ELF, chmod +x.
        let elf = tmp.path().join("b-static-elf");
        std::fs::write(&elf, make_minimal_elf64(false)).unwrap();
        std::fs::set_permissions(&elf, std::fs::Permissions::from_mode(0o755)).unwrap();
        // One synthetic dynamic ELF.
        let dyn_ = tmp.path().join("c-dynamic-elf");
        std::fs::write(&dyn_, make_minimal_elf64(true)).unwrap();
        std::fs::set_permissions(&dyn_, std::fs::Permissions::from_mode(0o755)).unwrap();

        let r = scan_path(tmp.path()).unwrap();
        assert_eq!(r.executables_scanned, 3);
        assert_eq!(r.setuid_bypassing_shim, 0);
        assert_eq!(r.static_bypassing_shim, 1);
        assert_eq!(r.details.len(), 1);
        assert_eq!(r.details[0].kind, BypassKind::Static);
        assert!(r.details[0].path.ends_with("b-static-elf"));
    }

    #[test]
    fn scan_double_counts_setuid_and_static() {
        // A binary that's BOTH setuid and statically linked appears
        // in details twice — once per axis. The counts reflect
        // independent classifications.
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("setuid-static");
        std::fs::write(&p, make_minimal_elf64(false)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let r = scan_path(tmp.path()).unwrap();
        assert_eq!(r.executables_scanned, 1);
        assert_eq!(r.setuid_bypassing_shim, 1);
        assert_eq!(r.static_bypassing_shim, 1);
        assert_eq!(r.details.len(), 2);
        let kinds: Vec<BypassKind> = r.details.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&BypassKind::Setuid));
        assert!(kinds.contains(&BypassKind::Static));
    }
}
