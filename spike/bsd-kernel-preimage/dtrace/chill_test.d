/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Destructive: chill() spins the CPU inside the syscall entry probe,
 * before namei() takes any vnode lock, while the consumer runs a
 * userspace copier through system(). Tests whether busy-waiting at entry
 * opens a window for a pre-image copy. Needs dtrace -w.
 *
 *   dtrace -w -q -s chill_test.d -x switchrate=1000hz \
 *       '"/path/to/copier.sh"' CHILL_NS
 *
 * dtrace caps chill at dtrace_chill_max (500 ms) per
 * dtrace_chill_interval (1 s) per CPU. Scoped to execname "mut".
 */
syscall::unlink:entry
/execname == "mut"/
{
	system("%s %d %s %s", $$1, pid, probefunc, copyinstr(arg0));
	chill($2);
}

syscall::unlinkat:entry, syscall::openat:entry
/execname == "mut"/
{
	system("%s %d %s %s", $$1, pid, probefunc, copyinstr(arg1));
	chill($2);
}
