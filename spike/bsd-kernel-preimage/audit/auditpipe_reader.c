/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * auditpipe(4) reader for the spike.
 *
 *   auditpipe_reader [-q] [-o file] [-c classes]
 *
 * Opens /dev/auditpipe in local preselection mode for the given classes
 * (default fw,fd,fm,fc), for attributable and non-attributable events,
 * and for each record prints: event name, first path token, the record
 * header time, the delay from header time to receipt, and whether the
 * path still exists (lstat) at receipt. auditd must be running: the
 * kernel only generates records while an audit trail is enabled.
 *
 * On SIGINT prints a summary.
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <security/audit/audit_ioctl.h>
#include <bsm/libbsm.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop;

static void
onint(int sig)
{
	(void)sig;
	stop = 1;
}

static au_class_t
classes_mask(const char *list)
{
	au_mask_t m = { 0, 0 };
	char copy[256];

	/* getauditflagsbin() tokenizes its argument in place. */
	strlcpy(copy, list, sizeof(copy));
	if (getauditflagsbin(copy, &m) != 0)
		errx(1, "bad class list %s", list);
	return (m.am_success | m.am_failure);
}

int
main(int argc, char **argv)
{
	const char *classes = "fw,fd,fm,fc", *outpath = NULL;
	u_char buf[65536];
	FILE *out = stdout;
	uint64_t nrec = 0, nexists = 0, ngone = 0, npath = 0;
	double sum_lag = 0, max_lag = 0;
	au_mask_t mask;
	int ch, fd, mode, quiet = 0;
	u_int qlen;
	ssize_t n;

	while ((ch = getopt(argc, argv, "qo:c:")) != -1) {
		switch (ch) {
		case 'q': quiet = 1; break;
		case 'o': outpath = optarg; break;
		case 'c': classes = optarg; break;
		default: errx(2, "usage: auditpipe_reader [-q] [-o file] [-c classes]");
		}
	}
	if (outpath != NULL && (out = fopen(outpath, "w")) == NULL)
		err(1, "%s", outpath);
	fd = open("/dev/auditpipe", O_RDONLY);
	if (fd < 0)
		err(1, "open /dev/auditpipe");
	mode = AUDITPIPE_PRESELECT_MODE_LOCAL;
	if (ioctl(fd, AUDITPIPE_SET_PRESELECT_MODE, &mode) != 0)
		err(1, "SET_PRESELECT_MODE");
	mask.am_success = mask.am_failure = classes_mask(classes);
	if (ioctl(fd, AUDITPIPE_SET_PRESELECT_FLAGS, &mask) != 0)
		err(1, "SET_PRESELECT_FLAGS");
	if (ioctl(fd, AUDITPIPE_SET_PRESELECT_NAFLAGS, &mask) != 0)
		err(1, "SET_PRESELECT_NAFLAGS");
	if (ioctl(fd, AUDITPIPE_GET_QLIMIT_MAX, &qlen) == 0)
		(void)ioctl(fd, AUDITPIPE_SET_QLIMIT, &qlen);
	signal(SIGINT, onint);
	signal(SIGTERM, onint);
	fprintf(stderr, "auditpipe_reader: classes %s\n", classes);

	while (!stop) {
		struct timespec now;
		tokenstr_t tok;
		int off, reclen;

		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			err(1, "read");
		}
		clock_gettime(CLOCK_REALTIME, &now);
		for (off = 0; off < n; off += reclen) {
			char path[1024] = "", ev[64] = "?";
			double t_rec = 0, lag;
			int toff, ex = -1;
			struct stat st;

			reclen = 0;
			for (toff = off; toff < n; toff += tok.len) {
				if (au_fetch_tok(&tok, buf + toff, n - toff) != 0)
					break;
				switch (tok.id) {
				case AUT_HEADER32:
				case AUT_HEADER32_EX: {
					struct au_event_ent *e;
					uint32_t s = tok.tt.hdr32.s, ms = tok.tt.hdr32.ms;
					if (tok.id == AUT_HEADER32_EX) {
						s = tok.tt.hdr32_ex.s;
						ms = tok.tt.hdr32_ex.ms;
					}
					reclen = tok.id == AUT_HEADER32 ?
					    (int)tok.tt.hdr32.size :
					    (int)tok.tt.hdr32_ex.size;
					e = getauevnum(tok.id == AUT_HEADER32 ?
					    tok.tt.hdr32.e_type :
					    tok.tt.hdr32_ex.e_type);
					if (e != NULL)
						strlcpy(ev, e->ae_name, sizeof(ev));
					t_rec = s + ms / 1000.0;
					break;
				}
				case AUT_PATH:
					if (path[0] == '\0')
						snprintf(path, sizeof(path), "%.*s",
						    (int)tok.tt.path.len,
						    tok.tt.path.path);
					break;
				}
				if (tok.id == AUT_TRAILER)
					break;
			}
			if (reclen <= 0)
				break;
			nrec++;
			lag = (now.tv_sec + now.tv_nsec / 1e9) - t_rec;
			sum_lag += lag;
			if (lag > max_lag)
				max_lag = lag;
			if (path[0] != '\0') {
				npath++;
				ex = lstat(path, &st) == 0;
				if (ex)
					nexists++;
				else
					ngone++;
			}
			if (!quiet)
				fprintf(out, "%s lag=%.3fms exists=%s size=%jd %s\n",
				    ev, lag * 1e3, ex < 0 ? "-" :
				    ex ? "yes" : "no", ex == 1 ?
				    (intmax_t)st.st_size : (intmax_t)-1, path);
		}
		if (!quiet)
			fflush(out);
	}
	{
		u_int64_t drops = 0;
		(void)ioctl(fd, AUDITPIPE_GET_DROPS, &drops);
		fprintf(out, "summary: records=%ju with_path=%ju path_exists=%ju "
		    "path_gone=%ju lag_avg=%.3fms lag_max=%.3fms drops=%ju\n",
		    (uintmax_t)nrec, (uintmax_t)npath, (uintmax_t)nexists,
		    (uintmax_t)ngone, nrec ? sum_lag / nrec * 1e3 : 0,
		    max_lag * 1e3, (uintmax_t)drops);
	}
	if (out != stdout)
		fclose(out);
	return (0);
}
