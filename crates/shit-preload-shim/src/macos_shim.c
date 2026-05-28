// SPDX-License-Identifier: AGPL-3.0-or-later
//
// macOS interpose trampolines for variadic libc symbols.
//
// Why this exists: Apple AArch64 splits the calling convention
// between fixed args (passed in registers) and variadic args
// (passed on the stack). libc's `open(const char *, int, ...)`
// has the mode arg in the variadic slot. A Rust-side fixed-arity
// replacement `fn(*const c_char, c_int, c_uint)` reads the third
// arg from a REGISTER while callers pushed it on the STACK —
// the register holds garbage and the kernel creates files with
// nonsense mode bits (cargo's Cargo.lock created with mode 0o540
// instead of 0o644, etc.).
//
// The C trampoline below is the same shape as libc's declaration
// — it accepts the variadic arg correctly via va_arg(ap, int).
// Then it forwards to a fixed-arity Rust function that does the
// notify + libc::open(_, _, mode_as_int). On the Rust side
// libc-rs declares open as variadic; the Rust→libc::open call
// emits the correct varargs-out ABI.
//
// Only `open` and `openat` need this trampoline; `unlink`,
// `rename`, `mkdir`, etc. have fixed signatures and the Rust
// interposers work directly.

#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>

// Defined in macos.rs.
extern int rust_shim_open(const char *path, int flags, unsigned int mode);
extern int rust_shim_openat(int dirfd, const char *path, int flags, unsigned int mode);

// Public symbol names: `macos_shim_open` / `macos_shim_openat`.
// The Rust side puts these (as function pointers) in the
// `__DATA,__interpose` table.

int macos_shim_open(const char *path, int flags, ...) {
    unsigned int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        // POSIX: `mode_t` promoted to int through varargs.
        mode = (unsigned int)va_arg(ap, int);
        va_end(ap);
    }
    return rust_shim_open(path, flags, mode);
}

int macos_shim_openat(int dirfd, const char *path, int flags, ...) {
    unsigned int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (unsigned int)va_arg(ap, int);
        va_end(ap);
    }
    return rust_shim_openat(dirfd, path, flags, mode);
}
