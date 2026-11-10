/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Which kernel-side capture channels survive cap_enter(2)?
 *
 *   cap_probe DIR
 *
 * Before cap_enter: getfh(DIR), open /dev/auditpipe. After: try each
 * operation a helper would need and print the result. The shit helper
 * enters capability mode by default on FreeBSD (SHIT_CAPSICUM=0 opts
 * out), so a channel that needs a global namespace after cap_enter must
 * be opened before it or brokered by an uncapsicumed parent.
 */
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <security/audit/audit_ioctl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void
report(const char *what, int rc)
{
	printf("%-48s %s\n", what, rc < 0 ? strerror(errno) : "ok");
}

int
main(int argc, char **argv)
{
	fhandle_t fh;
	u_int qlen;
	int ap, fd, rc;

	if (argc < 2)
		errx(2, "usage: cap_probe DIR");
	if (getfh(argv[1], &fh) != 0)
		err(1, "getfh");
	ap = open("/dev/auditpipe", O_RDONLY);
	report("before: open /dev/auditpipe", ap);
	if (cap_enter() != 0)
		err(1, "cap_enter");

	fd = fhopen(&fh, O_RDONLY | O_DIRECTORY);
	report("after: fhopen(dir handle)", fd);
	fd = open("/dev/shitpre", O_RDONLY);
	report("after: open /dev/shitpre", fd);
	fd = open("/dev/auditpipe", O_RDONLY);
	report("after: open /dev/auditpipe", fd);
	fd = open("/dev/dtrace/dtrace", O_RDWR);
	report("after: open /dev/dtrace/dtrace", fd);
	if (ap >= 0) {
		rc = ioctl(ap, AUDITPIPE_GET_QLEN, &qlen);
		report("after: ioctl on auditpipe fd opened before", rc);
	}
	return (0);
}
