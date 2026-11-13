/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Non-destructive DTrace view of file mutators, system-wide. This is the
 * overhead baseline for "DTrace as an event source": it records the
 * syscall and path at entry and never blocks the caller.
 *
 *   dtrace -q -s trace_mutators.d -o out.txt
 */
#pragma D option bufsize=16m
#pragma D option switchrate=100hz
#pragma D option dynvarsize=16m

syscall::unlink:entry, syscall::rmdir:entry, syscall::truncate:entry,
syscall::chmod:entry, syscall::lchmod:entry, syscall::chown:entry
{
	printf("%d %s %s %s\n", pid, execname, probefunc, copyinstr(arg0));
}

syscall::unlinkat:entry, syscall::fchmodat:entry, syscall::fchownat:entry,
syscall::funlinkat:entry
{
	printf("%d %s %s %s\n", pid, execname, probefunc, copyinstr(arg1));
}

syscall::rename:entry
{
	printf("%d %s %s %s -> %s\n", pid, execname, probefunc,
	    copyinstr(arg0), copyinstr(arg1));
}

syscall::renameat:entry
{
	printf("%d %s %s %s -> %s\n", pid, execname, probefunc,
	    copyinstr(arg1), copyinstr(arg3));
}

/* O_WRONLY 0x1, O_RDWR 0x2, O_TRUNC 0x400 */
syscall::openat:entry
/(arg2 & 0x403) != 0/
{
	printf("%d %s %s %s flags=%x\n", pid, execname, probefunc,
	    copyinstr(arg1), arg2);
}

syscall::write:entry, syscall::pwrite:entry, syscall::writev:entry,
syscall::ftruncate:entry
{
	@writes[probefunc] = count();
}
