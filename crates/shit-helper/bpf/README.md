# shit-helper BPF programs

This directory contains the eBPF programs that ship with `shit-helper`.

## Layout

- `src/*.bpf.c` — source. LSM programs use the checked-in
  `include/vmlinux.h` plus libbpf's helper headers for CO-RE reads.
- `build/*.bpf.o` — compiled output, **committed to the repo**. The
  consuming Rust code embeds these via `include_bytes!`.
- `Makefile` — builds the .o files. Run on a Linux box with `clang`
  ≥ 14 that has BPF target support (macOS Apple clang does *not*).

## Why check in the .o?

Three reasons:

1. **Reproducibility.** Downstream builds don't need clang or BPF
   toolchain. Reviewing the diff of a .bpf.o regen is reviewable —
   the disassembly is short and stable.
2. **CI portability.** Most cloud CI builders don't have BPF clang
   set up. With pre-built .o, our regular `cargo build` works
   everywhere.
3. **Security posture.** The shipped artifact is the one we
   reviewed and tested. A producer-consumer split between
   "compile from source on the build machine" and "ship binary
   to the user" is the boundary we want.

## Regenerating

```sh
make -C crates/shit-helper/bpf clean all
make -C crates/shit-helper/bpf inspect    # disassembly + section table
```

After regenerating, commit both the `.bpf.c` source and the
`.bpf.o` binary in the same commit.

## Programs

| File | Section | Type | Returns | Risk |
|------|---------|------|---------|------|
| `noop_tracepoint.bpf.c` | `tracepoint/sched/sched_process_exec` | TRACEPOINT | always 0 | observation only — **cannot deny syscalls** |
| `inode_*.bpf.c`, `file_*.bpf.c` | `lsm/*` | BPF LSM | always 0 | system-wide observation; verifier and load behavior require HP-18 review |

Each LSM object owns a private `ringbuf_loss_count` one-element BPF array.
If `bpf_ringbuf_reserve` fails, the hook still returns 0 but atomically
increments that counter. The userspace reader polls it independently of the
full ring buffer and emits `CaptureRefused` for every command active when a
delta is observed. Because the lost record contains the only exact pid/path
identity, narrower attribution is not truthful.

The `file_open` and `file_release` hooks emit only writable regular-file
events. Writable pipes, sockets, devices, and anonymous inodes cannot carry a
replayable filesystem pre-image and are filtered before ring-buffer reserve.

## License

Programs are AGPL-3.0-or-later like the rest of the project. The
license symbol embedded in each `.o` is `GPL` because the Linux
kernel rejects non-GPL BPF programs from most helper APIs.
