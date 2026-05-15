# shit

magic undo for the command line

You just made a mistake on the command line — an edit, a botched `mv`, a `rm` that took more than you meant — and you want to undo its *effects*. `shit` watches the right kernel surfaces, captures pre-images cheaply via your filesystem's native copy-on-write, and produces an approvable undo plan.

## Status

Pre-1.0. APIs, wire formats, and on-disk layouts are unstable.

## Install

Coming soon: `brew install tenseleyFlow/tap/shit`, AUR (`shit-bin`), FreeBSD ports, and a signed `curl … | sh`.

## Dev quickstart

```sh
git clone https://github.com/tenseleyFlow/shit
cd shit
make dev    # cargo build --workspace
make test   # cargo test --workspace
make lint   # cargo clippy
make ci     # everything CI runs
```

## How it works

`shit` is three binaries plus shell glue:

- **`shit`** — the CLI: `shit undo`, `shit redo`, `shit list`, `shit show`, `shit pin`, `shit doctor`, …
- **`shitd`** — a per-user daemon that owns the snapshot store, the sqlite index, the IPC sockets, and the undo planner.
- **`shit-helper`** — a privileged helper that drives kernel-level capture: EndpointSecurity on macOS, fanotify-perm + eBPF-LSM on Linux, kqueue + an optional LD_PRELOAD shim on BSD.
- **shell hooks** (bash, zsh, fish) that bracket each command with metadata events sent over a persistent Unix-domain-socket fd.

When a command writes, renames, unlinks, or otherwise mutates a file inside a tracked process subtree, the helper captures the pre-image *before* the kernel allows the syscall to complete — using `clonefile` (APFS), `reflink` (btrfs/XFS), `zfs clone` (ZFS), hardlink, or streaming copy, picking the cheapest tier the underlying filesystem supports. Blobs land in a content-addressed store (blake3 + zstd) under `$XDG_STATE_HOME/shit/`.

When you run `shit undo`, the daemon's planner walks the captured events, computes an inverse-op DAG, shows you exactly what it'll do, and applies it on your `y`.

## Coverage

Beyond files, `shit` also captures:

- File metadata (perms, ACLs, xattrs).
- Tree operations (create/delete/rename/link).
- Environment-variable mutations (per-shell).
- Package-manager operations (apt, dpkg, pacman, dnf, brew, FreeBSD pkg) via each manager's native hook system.
- systemd / launchd unit operations (via CLI wrappers).
- Network / firewall / routing changes (iptables, nft, ufw, pfctl, ip, networksetup).
- Process lifecycle (best-effort; `shit show` produces a restart suggestion you can confirm).

What's *not* undoable is documented honestly in each tier's design notes — we'd rather say "this was unrecoverable" than lie about it.

## License

AGPLv3. See [LICENSE](./LICENSE).
