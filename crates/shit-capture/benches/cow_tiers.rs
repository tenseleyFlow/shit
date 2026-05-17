// SPDX-License-Identifier: AGPL-3.0-or-later

//! Microbench for COW tiers. We deliberately don't use criterion: this
//! is a regression smoke-bench, not a publication-grade benchmark. It
//! prints a markdown-flavored table that we paste into
//! `.docs/audits/cow-bench-S05.md`.
//!
//! Run with `cargo bench -p shit-capture`. Skip 1GiB with
//! `SHIT_BENCH_SKIP_GIANT=1`.

use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::time::Instant;

#[cfg(target_os = "macos")]
use shit_capture::cow::clonefile_macos::capture_clonefile;
use shit_capture::cow::hardlink::capture_hardlink;
use shit_capture::cow::streaming::capture_streaming;

const SIZES: &[(&str, usize)] = &[
    ("4K", 4 * 1024),
    ("64K", 64 * 1024),
    ("1M", 1024 * 1024),
    ("100M", 100 * 1024 * 1024),
];

const ITERS: u32 = 5;

fn main() {
    let include_giant = std::env::var_os("SHIT_BENCH_SKIP_GIANT").is_none();
    let mut sizes: Vec<(&str, usize)> = SIZES.to_vec();
    if include_giant {
        sizes.push(("1G", 1024 * 1024 * 1024));
    }

    println!("# COW tier microbench\n");
    println!("(median of {ITERS} runs, in microseconds)\n");
    println!("| size | streaming | hardlink | clonefile |");
    println!("|------|-----------|----------|-----------|");

    for (label, size) in sizes {
        let streaming = run_streaming(size);
        let hardlink = run_hardlink(size);
        let clonefile = run_clonefile(size);

        println!(
            "| {label} | {} | {} | {} |",
            fmt_us(streaming),
            fmt_us(hardlink),
            fmt_us(clonefile),
        );
    }
}

fn run_streaming(size: usize) -> Option<u128> {
    bench_n(ITERS, || {
        let tmp = tempfile::tempdir().unwrap();
        let src = make_file(tmp.path(), size);
        let f = File::open(&src).unwrap();
        let started = Instant::now();
        capture_streaming(f.as_raw_fd(), &src, tmp.path()).unwrap();
        started.elapsed().as_micros()
    })
}

fn run_hardlink(size: usize) -> Option<u128> {
    bench_n(ITERS, || {
        let tmp = tempfile::tempdir().unwrap();
        let src = make_file(tmp.path(), size);
        let f = File::open(&src).unwrap();
        let started = Instant::now();
        capture_hardlink(f.as_raw_fd(), &src, tmp.path(), true).unwrap();
        started.elapsed().as_micros()
    })
}

#[cfg(target_os = "macos")]
fn run_clonefile(size: usize) -> Option<u128> {
    bench_n(ITERS, || {
        let tmp = tempfile::tempdir().unwrap();
        let src = make_file(tmp.path(), size);
        let f = File::open(&src).unwrap();
        let started = Instant::now();
        capture_clonefile(f.as_raw_fd(), &src, tmp.path()).unwrap();
        started.elapsed().as_micros()
    })
}

#[cfg(not(target_os = "macos"))]
fn run_clonefile(_size: usize) -> Option<u128> {
    None
}

fn bench_n(iters: u32, mut f: impl FnMut() -> u128) -> Option<u128> {
    let mut samples: Vec<u128> = (0..iters).map(|_| f()).collect();
    samples.sort_unstable();
    Some(samples[samples.len() / 2])
}

fn make_file(dir: &std::path::Path, size: usize) -> std::path::PathBuf {
    let path = dir.join("bench-input.bin");
    let mut f = File::create(&path).unwrap();
    // Pseudo-random-ish content via a counter pattern so the hasher
    // sees varied data rather than a long run of zeros (which some
    // filesystems compress aggressively).
    let chunk: Vec<u8> = (0..4096u32).map(|i| (i & 0xFF) as u8).collect();
    let mut written = 0;
    while written < size {
        let take = (size - written).min(chunk.len());
        f.write_all(&chunk[..take]).unwrap();
        written += take;
    }
    f.flush().unwrap();
    path
}

fn fmt_us(o: Option<u128>) -> String {
    match o {
        Some(n) => format!("{n}us"),
        None => "n/a".to_string(),
    }
}
