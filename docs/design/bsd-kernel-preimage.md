# Kernel-side pre-images on FreeBSD (spike B5)

Status: design spike, measured on the FreeBSD 14.4-RELEASE-p11 amd64 VM
(8 vCPU, 8 GB, UFS root) on 2026-11-10. Prototypes and raw output live
under `spike/bsd-kernel-preimage/` on branch `b5-kernel-preimage-spike`.
Nothing here changes shipped code.

## Problem

FreeBSD capture today is the kqueue helper plus the preload shim. kqueue
reports a vnode change after it has happened, so a pre-image exists only
if the shim copied it first or a baseline walk already holds it. A
static binary, a setuid binary, or any process started without the shim
writes before anything copies. The question for this spike was whether
a kernel facility can hold or copy the old contents before the change
lands, and at what cost.

Four candidates were tried: a loadable MAC policy, audit(4) through
auditpipe(4), DTrace, and (as a cross-cutting constraint) how each one
behaves under jails and Capsicum.

## Recommendation

Build a MAC policy module as an opt-in FreeBSD tier, with the copy done
inside the hook by the kernel. Do not use audit or DTrace as a pre-image
source.

The MAC prototype captured every pre-image a static binary destroyed
(unlink, O_TRUNC open, in-place write, rename over an existing file,
shared mmap write) and reported the old mode before a chmod. Its overhead
on the two file-heavy workloads was within the run-to-run noise of the
shared VM. Audit and DTrace both failed every pre-image trial: their
records arrive after the syscall body has run.

The MAC approach works only if the kernel does the preserving. A design
in which the hook parks the syscall and waits for a userspace helper to
copy the file does not work, because the parked thread holds the vnode
locks the helper needs (see "Parking the syscall for userspace" below).

This PR is a draft and is not meant to be merged. If a record on trunk is
wanted, merge this memo alone; `spike/` stays on the branch.

## MAC policy module (`mac_shitpre`)

### What the prototype does

`spike/bsd-kernel-preimage/mac_shitpre/mac_shitpre.c` registers these
hooks: `vnode_check_unlink`, `rename_from`, `rename_to`, `open` (write
or O_TRUNC intent), `write`, `mmap` (PROT_WRITE with MAP_SHARED),
`setmode`, `setowner`, `setflags` and `setutimes`. Every hook returns 0,
so the policy never denies anything. A hook does work only when the
calling process is the configured root pid
(`security.mac.shitpre.root_pid`) or one of its descendants. Otherwise it
returns after one atomic load.

The kernel-to-user channel is a character device, `/dev/shitpre`. It
allows one opener, has `read(2)` for fixed-size event records and
`poll(2)` readiness, and takes four ioctls. A kqueue filter on the
device would be about 30 more lines; the prototype helper polls.

In mode 1 (capture) the module preserves content two ways:

- Unlink, and rename over an existing file: the hook takes a vnode
  reference (`vref`) on the victim. The file's blocks stay allocated
  after the name is gone, the same as an open descriptor on an unlinked
  file. Later the helper calls `SHITPRE_CLAIM`, and the module opens the
  vnode read-only and installs a descriptor in the helper (the same
  sequence as `kern_fhopen`). The syscall never waits for the helper.
- Open for write, write, truncate and shared mmap: the hook already
  holds the vnode lock, so it reads the whole file into kernel memory
  with `vn_rdwr(IO_NODELOCKED | IO_RANGELOCKED)`. It does this once per
  (fsid, fileid) per watch, and only up to `copy_cap` (16 MiB in the
  prototype). The helper collects the bytes with `SHITPRE_FETCH`.
  `IO_RANGELOCKED` matters: the writer may already hold a write
  rangelock on the file, and asking for a read rangelock would deadlock.

The event record carries the old size, mode, owner, flags and link
count from `VOP_GETATTR`, plus pid, jail id, comm, and file handles for
the vnode and (for unlink and rename) its parent directory with the
component name. It carries no path (see "Incident" below). The helper
turns handles into paths with `fhopen(2)` and `fcntl(F_KINFO)` while
holding no kernel locks.

### Evidence

`evidence/functional-mode1.txt`, from a static mutator
(`helper/mut.c`, linked `-static`, so LD_PRELOAD never applies):

| Operation | Hook time | Pre-image |
|---|---|---|
| `unlink` (14 KB) | 2.4 us | captured by pin, byte-equal |
| `open(O_TRUNC)` (30 KB) | 19 us | copied in kernel, byte-equal |
| `pwrite` in place (39 KB) | 36 us | copied at open, byte-equal |
| `rename` over target (48 KB) | 0.5 us | captured by pin, byte-equal |
| shared `mmap` write (65 KB) | 30 us at open | copied at open, byte-equal |
| `chmod 600` | 0.9 us | old mode 644 in the event |

The hook time includes the copy. The in-kernel copy cost for 30 to 65 KB
files was 19 to 36 us.

`evidence/capture-counters.txt` covers the two bench workloads in
capture mode. Untarring 6942 entries produced 20826 events with nothing
to copy: every file was new, and the first write to a new file marks it
seen. Five `git checkout` round trips (105 files each way) produced 2165
events, 1045 pinned unlinks and 1061 captured pre-images (15 MB staged),
with no events dropped.

### Parking the syscall for userspace (mode 2) does not work

Mode 2 queues the event and sleeps in the hook for up to `wait_ms` until
the helper acks it. The helper starts a userspace copier on the path and
acks once the copier finishes or half the timeout has passed. From
`evidence/wait-mode2.txt`:

| Operation | Copier result |
|---|---|
| unlink | blocked until the ack, then ENOENT |
| open(O_TRUNC) | blocked until the ack, then read the 4-byte post-image |
| in-place write | blocked until the ack, then read the post-image |
| rename | blocked until the ack, then ENOENT |
| chmod | blocked until the ack |

All five copiers blocked. The reason is in the kernel sources: `unlink`
calls `mac_vnode_check_unlink` with the parent directory and the file
both locked (`LOCKPARENT | LOCKLEAF`, `kern/vfs_syscalls.c`). The write
paths call `check_open` and `check_write` with the file locked. A
userspace lookup of the same path needs those locks. Any MAC design in
which the kernel waits for userspace to read the file is therefore a
self-inflicted deadlock, bounded only by the timeout. The copy has to
happen in the hook, by the thread that already holds the lock.

### Incident: `vn_fullpath` under the vnode lock

The first prototype called `vn_fullpath()` in the hook to put a path in
each event. During the untar bench, an `open(O_CREAT)` hook ran on a new
file the name cache had not seen. `vn_fullpath` fell through to
`vn_vptocnp`, which asks for a shared lock on the vnode this thread
already held exclusively. lockmgr returned EDEADLK, and
`_vn_lock_fallback` retries with `LK_RETRY` forever. The result was an
unkillable `bsdtar` spinning at 100% of one CPU inside the kernel. The
policy could not be unloaded either: the spinning thread held the MAC
policy read lock, and `kldunload` would have waited on it. The VM needed
a hard reset.

The fix is to resolve no path inside a hook. The module now records
file handles (`VOP_VPTOFH`, which takes no locks) and the helper
resolves them afterward. `bench/create_smoke.sh` is the regression
check (200 new files plus 3 created by redirection under watch). The
lesson for any production module is to treat every helper called from a
vnode hook as suspect until its locking is read, and to stress-test with
a WITNESS and INVARIANTS kernel before the module goes near a user.

### Overhead

`bench/run_all.sh` interleaves conditions in each round, for 11 rounds:
the module unloaded, loaded with no watch, loaded watching the workload
in observe mode, and the same in capture mode. The workloads are `tar -x`
of a 218 MB, 6942-entry slice of `/usr/src/sys`, and five round trips of
`git checkout v5.3.6` and back to `v5.4.6` in a Lua clone. Timing comes
from `/usr/bin/time -p` (10 ms resolution). The ratio column is the
median over rounds of condition time divided by that round's unloaded
time (`bench/paired.py`, `evidence/bench-mac.txt`):

| Workload | Condition | Median | Paired ratio (min to max) |
|---|---|---|---|
| untar | unloaded | 0.42 s | 1.00 |
| untar | loaded, unwatched | 0.44 s | 1.07 (0.84 to 1.35) |
| untar | observe | 0.48 s | 1.06 (0.90 to 1.66) |
| untar | capture | 0.46 s | 1.14 (0.79 to 1.74) |
| checkout x5 | unloaded | 0.36 s | 1.00 |
| checkout x5 | loaded, unwatched | 0.37 s | 0.97 (0.86 to 1.12) |
| checkout x5 | observe | 0.37 s | 1.00 (0.82 to 1.16) |
| checkout x5 | capture | 0.37 s | 0.97 (0.69 to 1.18) |

The spread within one condition is wider than the gap between
conditions. The VM is shared with lane B6, and other lanes load the
host. What these numbers support is that the overhead is under about
15% on these workloads and not resolvable at this precision. They do
not support a smaller figure. A follow-up should measure on an idle host
with `hwpmc` or many more rounds.

The cost model is easy to read off the code. Unwatched, each hooked
check is a function call and an atomic load. Watched, each hook adds a
`VOP_GETATTR`, a hash lookup, a malloc, and one event (about 1.4 KB),
and the first write-intent per file adds a full read of that file under
its lock. That read stalls other readers of the file and the writer
itself for the length of the copy. That is fine at 64 KB and not fine at
4 GB, which is why `copy_cap` exists.

### Costs of shipping it

- A kernel module is C in the kernel. A bug panics or wedges the
  machine, as the incident above showed on a spike that had been
  reviewed line by line. It needs its own review standard (WITNESS and
  INVARIANTS stress runs, a fuzzed ioctl surface, lock-order notes per
  hook) before it ships to anyone.
- Packaging: a port using `USES=kmod`, built against the kernel sources
  of each supported release. FreeBSD keeps the KBI stable within a
  branch, but kmod packages are still published per minor release, so CI
  needs one build per supported 14.x and 15.x minor. Building needs
  `/usr/src/sys` (the spike fetched `src.txz`, about 200 MB).
- Loading: `kld_list="mac_shitpre"` in `rc.conf`, or
  `mac_shitpre_load="YES"` in `loader.conf`. kldload is refused once
  securelevel is 1 or higher, so the module has to load at boot on
  hardened hosts. The policy uses no label slots, so loading late is
  safe and unloading is allowed (`MPC_LOADTIME_FLAG_UNLOADOK`), as long
  as no hook is stuck.
- Exposure: the device hands out read descriptors on deleted files and
  copies of any file a watched process writes, so the consumer must be
  root, single, and not jailed (see "Jails" below). Pinned vnodes keep
  deleted data allocated until claimed, so disk space can run out if the
  helper stalls. The queue is bounded and counts drops, and production
  needs the same loss ledger the eBPF tier has.
- Coverage gaps in the prototype: extended attributes
  (`setextattr`, `deleteextattr`), ACLs, hard-link count changes,
  `copy_file_range` beyond `check_write`, and files over `copy_cap`. ZFS
  and tmpfs were not exercised, because the ZFS pool belongs to lane B6.
- Scoping: the prototype finds descendants by walking `p_pptr` under
  `proctree_lock` from inside a hook that holds vnode locks. No deadlock
  showed up in testing, but the lock order is unreviewed. Production
  should keep a watched-pid set maintained by `process_fork` and
  `process_exit` event handlers and consult it without `proctree_lock`.

## audit(4) and auditpipe(4)

`audit/auditpipe_reader.c` opens `/dev/auditpipe` in local preselection
mode for classes `fw,fd,fm,fc`, for attributable and non-attributable
events alike. For each record it `lstat`s the first path at receipt. The
kernel generates records only while an audit trail is enabled
(`audit_syscalls_enabled_update` in `security/audit/audit.c`), so
auditd has to run.

What it reports: the event type, the paths the syscall resolved,
subject credentials and the return value. `write(2)`, `pwrite(2)` and
`mmap(2)` are in class `no` in `/etc/security/audit_event`, so audit
never reports a write to a descriptor that is already open.

Is it ever pre-change? No. A record is committed at syscall exit
(`audit_syscall_exit`), after the work is done.
`evidence/audit-preimage.txt`, 20 trials each with the static mutator:

| Trial | Records | Pre-image still present at receipt |
|---|---|---|
| unlink | 20 | 0 |
| open(O_WRONLY or O_TRUNC) then write | 20 | 0 (all post-image size) |

Latency from the record's header time to receipt was 10.7 to 14.7 ms
for the records shown in the evidence file. Over the whole run,
including unrelated system records, the average was 50.7 ms and the
maximum 100 ms. The header time has 1 ms resolution.

Under the untar and checkout workloads the pipe dropped between 30865
and 39461 records per round, which is 75 to 92% of what the kernel
generated, even with the queue limit raised to
`AUDITPIPE_GET_QLIMIT_MAX` (`evidence/audit-pipe-summaries.txt`). A
source that silently loses most of its events under a tar extract cannot
serve as an event source, let alone a pre-image source. Paired overhead with
auditd and the reader running was 1.30 on untar (1.02 to 1.59) and 1.14
on checkout (0.82 to 1.33). That is the largest of the three
mechanisms, and it applies system-wide whenever a trail is enabled.

## DTrace

DTrace needs `dtraceall` loaded (the spike unloaded it after each run).

`dtrace/stop_test.d` calls the destructive `stop()` at entry to
`unlink`, `unlinkat` and `openat` for the static mutator, and runs a
copier through `system()`. The copier records what the file looks like
and then sends SIGCONT. `dtrace/chill_test.d` instead spins the thread in
probe context with `chill()` for 200 ms or 450 ms (the cap is 500 ms per
second per CPU), before `namei` has taken any lock, while the copier
runs. From `evidence/dtrace-preimage.txt`, 10 unlink and 10 truncate
trials each:

| Script | Unlink: file present | Truncate: full size |
|---|---|---|
| `stop()` | 0/10 | 0/10 (size 0 every time) |
| `chill(200 ms)` | 0/10 | 0/10 |
| `chill(450 ms)` | 0/10 | 0/10 |

`stop()` takes effect when the thread returns to user mode, after the
syscall body. Every copier found the mutator already in state T and the
file already gone or truncated. In the chill runs the copier started
after the mutator had exited in 20 of 20 trials at 200 ms. The consumer
did not see the probe record until the chill ended. The likely cause,
not verified here, is that the consumer's buffer switch needs a
cross-call into the spinning CPU, which runs probe context with
interrupts off. Either way, chill opens no window a consumer can use.

As an event source, non-destructive tracing of the file mutators
(`dtrace/trace_mutators.d`) cost a paired 1.10 on untar (0.89 to 1.22)
and 0.96 on checkout (`evidence/bench-dtrace.txt`). In an earlier run
that was aborted (its output was not kept), `copyinstr` of an `openat`
path at syscall entry failed with "invalid address". That happens when
the user page holding the path is not resident, so events can lose their
paths.

DTrace is not usable outside a debugging context for this purpose. Its
destructive actions need `-w`. `stop()` and `chill()` change scheduling
system-wide. The consumer is a large userspace library that cannot run
in capability mode. And none of it reaches a pre-image.

## Jails

`jail/jail_probe.sh` runs a static mutator inside a jail
(`path=/`, so it shares the host's `/dev`, which is the worst case),
with the host helper watching the `jail(8)` invocation.

- MAC: hooks fire for jailed threads. Events carry the jail id (1 and 3
  in the two runs), and both pre-images were captured on the host
  (`evidence/jail-probe-*.txt`). In the first run, root inside the jail
  could open `/dev/shitpre`, which would have made it the consumer for
  every host pre-image. The module now refuses opens from jailed
  credentials (`jailed(td->td_ucred)` in `d_open`), and the second run
  shows the open denied. A normal jail with devfs ruleset 4 hides the
  node anyway; the check covers jails that unhide it.
- audit: root inside this jail could open and configure
  `/dev/auditpipe`. Whether it then receives host records was not
  tested. Jails with the default devfs ruleset do not see the node.
- DTrace: opening `/dev/dtrace/dtrace` inside the jail was denied, and
  `dtrace -n BEGIN` failed.

In every option the helper runs on the host and watches into jails. A
helper running inside a jail cannot kldload, cannot see the MAC device,
and cannot run DTrace.

## Capsicum

The helper enters capability mode by default on FreeBSD.
`jail/cap_probe` checks what still works after `cap_enter()`:

| Operation after cap_enter | Result |
|---|---|
| `fhopen` of a directory handle | not permitted in capability mode |
| `open("/dev/shitpre")` | not permitted |
| `open("/dev/auditpipe")` | not permitted |
| `open("/dev/dtrace/dtrace")` | not permitted |
| `ioctl` on an auditpipe fd opened before `cap_enter` | ok |

The MAC channel fits Capsicum if the helper opens `/dev/shitpre` before
`cap_enter` and limits it with `cap_ioctls_limit`. The prototype's
handle-to-path step uses `fhopen`, which capability mode forbids. In
production the kernel should return descriptors instead: the parent
directory for unlink and rename, and the file itself for writes. They
would come back through the same `CLAIM` ioctl that already works on an
fd opened before `cap_enter`. The helper then names files with
`fcntl(F_KINFO)` or `openat` relative to those descriptors. auditpipe
also works from a descriptor opened beforehand. DTrace does not.

## Follow-up lane (sized)

Lane "BSD-MAC tier", about two lane-weeks, split in two so the kernel
work can be reviewed before anything depends on it.

Part 1, kernel module hardening (about 1 week):

- Watched-pid set from `process_fork` and `process_exit` event handlers
  in place of the `p_pptr` walk. Per-command ids in events.
- `CLAIM` returns parent-directory and file descriptors. Drop
  `fhopen` from the helper path. Add `cap_ioctls_limit` on the device.
- Streaming copy for files over `copy_cap`: the hook hands the helper
  chunks through the device while it holds the lock, with a hard time
  budget, and on overrun marks the event lost instead of blocking.
- Hooks for extattr, ACL and link changes. Drop counters wired to a loss
  ledger. `d_kqfilter`.
- Test kernel with WITNESS and INVARIANTS. A stress run of
  untar, checkout and parallel `rm -rf` under watch on UFS, ZFS and
  tmpfs. An ioctl fuzzer. Load and unload under load.
- Exit criterion: zero WITNESS warnings, zero panics in 1000 stress
  iterations, and byte-equal pre-images in every smoke class.

Part 2, integration (about 1 week):

- A `shit-helper` capture source behind
  `#[cfg(target_os = "freebsd")]` that reads `/dev/shitpre` and emits
  the existing `CapturedPreImage` wire with the descriptors as
  `SCM_RIGHTS`.
- Tier selection and `shit doctor` reporting
  `kqueue+mac` when the module is loaded, falling back to the current
  shim tier otherwise.
- Port skeleton under `packaging/` (`USES=kmod`), plus rc.conf and
  loader.conf docs.
- Smokes on both FreeBSD legs with a static mutator: rm, truncate,
  in-place write, mv over, mmap write, chmod. Each one fails on the
  kqueue+shim tier and passes on `kqueue+mac`. The CI VM fetches
  `src.txz` to build the module.

Out of scope for that lane: making the module the default, NetBSD,
OpenBSD and DragonFly (no MAC framework of this kind), and any use of
audit or DTrace.
