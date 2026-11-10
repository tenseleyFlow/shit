/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Destructive: stop() the mutating process at syscall entry and run a
 * userspace copier, then SIGCONT it. Tests whether stop() parks the
 * thread before the syscall body runs. Needs dtrace -w.
 *
 *   dtrace -w -q -s stop_test.d -x switchrate=1000hz \
 *       '"/path/to/copier.sh"'
 *
 * Scoped to execname "mut" (the spike's static mutator).
 */
syscall::unlink:entry
/execname == "mut"/
{
	stop();
	system("%s %d %s %s", $$1, pid, probefunc, copyinstr(arg0));
}

syscall::unlinkat:entry, syscall::openat:entry
/execname == "mut"/
{
	stop();
	system("%s %d %s %s", $$1, pid, probefunc, copyinstr(arg1));
}
