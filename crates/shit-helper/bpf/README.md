# shit-helper BPF programs

This directory contains the eBPF programs that ship with `shit-helper`.

## Layout

- `src/*.bpf.c` — source. Written in C with **no header dependencies**
  so the build is portable across kernel versions and distros.
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

LSM hooks are deliberately not yet present; per the standing rule in
`.docs/audits/helper-protocol.md` (HP-18), any hook that *can* return
non-zero requires explicit isolation review before introduction.

## License

Programs are AGPL-3.0-or-later like the rest of the project. The
license symbol embedded in each `.o` is `GPL` because the Linux
kernel rejects non-GPL BPF programs from most helper APIs.
