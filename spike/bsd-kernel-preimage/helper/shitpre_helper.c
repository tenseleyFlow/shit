/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Userspace consumer for mac_shitpre (design spike).
 *
 *   shitpre_helper [-m mode] [-s stagedir] [-q] -- command [args...]
 *
 * Opens /dev/shitpre, forks the command held behind a pipe, points
 * security.mac.shitpre.root_pid at it, sets the mode, releases it, and
 * drains events until it exits. In mode 1, pinned vnodes are claimed and
 * copied, and in-kernel copies are fetched, into stagedir/<id>. In mode
 * 2, each event starts a userspace copier thread on the path while the
 * syscall is parked in the hook, and the helper ACKs after the copier
 * finishes or after half of wait_ms.
 *
 * Prints one line per event unless -q, then a summary.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../mac_shitpre/shitpre.h"

static const char *opname[] = {
	"?", "unlink", "rename_from", "rename_to", "open_w", "write",
	"mmap_w", "setmode", "setowner", "setflags", "setutimes",
};

static uint64_t
now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_UPTIME, &ts);
	return ((uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}

static int
copy_fd_to(int in, const char *dst, uint64_t *bytes)
{
	char buf[65536];
	ssize_t n;
	int out;

	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (out < 0)
		return (-1);
	*bytes = 0;
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, n) != n) {
			close(out);
			return (-1);
		}
		*bytes += n;
	}
	close(out);
	return (n < 0 ? -1 : 0);
}

static int
fh_present(const fhandle_t *fh)
{
	return (fh->fh_fid.fid_len != 0);
}

/*
 * Turn the event's file handles into a path, in helper context with no
 * kernel locks held: fhopen(2) the parent directory (or the file) and ask
 * F_KINFO for its path. An unlinked file has no path of its own, which is
 * why unlink/rename events carry the parent handle plus the name.
 */
static void
resolve_path(const struct shitpre_event *ev, char *out, size_t outlen)
{
	struct kinfo_file kif;
	int fd;

	snprintf(out, outlen, "?");
	if (fh_present(&ev->dfh)) {
		fd = fhopen(&ev->dfh, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (fd < 0)
			return;
		kif.kf_structsize = sizeof(kif);
		if (fcntl(fd, F_KINFO, &kif) == 0)
			snprintf(out, outlen, "%s/%s",
			    strcmp(kif.kf_path, "/") == 0 ? "" : kif.kf_path,
			    ev->name);
		close(fd);
	} else if (fh_present(&ev->fh)) {
		fd = fhopen(&ev->fh, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			return;
		kif.kf_structsize = sizeof(kif);
		if (fcntl(fd, F_KINFO, &kif) == 0)
			strlcpy(out, kif.kf_path, outlen);
		close(fd);
	}
}

/* Mode 2 copier. */
struct copier {
	pthread_t	th;
	struct shitpre_event ev;
	char		path[SHITPRE_PATHLEN];
	char		dst[1100];
	uint64_t	t_start, t_open, t_done;
	uint64_t	bytes;
	int		open_errno;
	int		done;
	pthread_mutex_t	mu;
	pthread_cond_t	cv;
};

static void *
copier_main(void *arg)
{
	struct copier *c = arg;
	int fd, rc;

	c->t_start = now_ns();
	/* Resolving the handle can itself block on the parked vnode. */
	resolve_path(&c->ev, c->path, sizeof(c->path));
	fd = open(c->path, O_RDONLY);
	c->t_open = now_ns();
	if (fd < 0)
		c->open_errno = errno;
	else {
		rc = copy_fd_to(fd, c->dst, &c->bytes);
		if (rc != 0)
			c->open_errno = errno;
		close(fd);
	}
	c->t_done = now_ns();
	pthread_mutex_lock(&c->mu);
	c->done = 1;
	pthread_cond_signal(&c->cv);
	pthread_mutex_unlock(&c->mu);
	return (NULL);
}

static int
sysctl_set_int(const char *name, int v)
{
	return (sysctlbyname(name, NULL, NULL, &v, sizeof(v)));
}

static int
sysctl_get_int(const char *name)
{
	size_t len;
	int v;

	len = sizeof(v);
	if (sysctlbyname(name, &v, &len, NULL, 0) != 0)
		return (-1);
	return (v);
}

static void
usage(void)
{
	fprintf(stderr, "usage: shitpre_helper [-m 0|1|2] [-s stagedir] [-q] "
	    "-- command [args...]\n");
	exit(2);
}

int
main(int argc, char **argv)
{
	struct shitpre_event ev;
	struct shitpre_claim cl;
	struct shitpre_fetch fe;
	struct pollfd pfd;
	const char *stage = NULL;
	char dst[1100], path[SHITPRE_PATHLEN];
	uint64_t per_op[16] = { 0 }, captured = 0, captured_bytes = 0;
	uint64_t max_hook_ns = 0, sum_hook_ns = 0, max_lag_ns = 0, sum_lag_ns = 0;
	uint64_t waited = 0, copier_blocked = 0, copier_ok = 0, bytes;
	uint64_t t0, t1, nev = 0;
	int ch, dev, mode = 0, quiet = 0, gate[2], status, child_done = 0;
	pid_t child;
	ssize_t n;
	void *buf;

	while ((ch = getopt(argc, argv, "m:s:q")) != -1) {
		switch (ch) {
		case 'm': mode = atoi(optarg); break;
		case 's': stage = optarg; break;
		case 'q': quiet = 1; break;
		default: usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();
	if (stage != NULL && mkdir(stage, 0700) != 0 && errno != EEXIST)
		err(1, "mkdir %s", stage);

	dev = open("/dev/" SHITPRE_DEV, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (dev < 0)
		err(1, "open /dev/%s", SHITPRE_DEV);
	if (sysctl_set_int("security.mac.shitpre.mode", mode) != 0)
		err(1, "sysctl mode");

	if (pipe(gate) != 0)
		err(1, "pipe");
	child = fork();
	if (child == 0) {
		char c;
		close(gate[1]);
		close(dev);
		if (read(gate[0], &c, 1) != 1)
			_exit(127);
		close(gate[0]);
		execvp(argv[0], argv);
		_exit(127);
	}
	close(gate[0]);
	if (sysctl_set_int("security.mac.shitpre.root_pid", child) != 0)
		err(1, "sysctl root_pid");
	t0 = now_ns();
	if (write(gate[1], "g", 1) != 1)
		err(1, "gate");
	close(gate[1]);

	buf = malloc(64 * 1024 * 1024);
	pfd.fd = dev;
	pfd.events = POLLIN;
	for (;;) {
		if (!child_done && waitpid(child, &status, WNOHANG) == child) {
			child_done = 1;
			t1 = now_ns();
		}
		if (poll(&pfd, 1, child_done ? 0 : 5) <= 0) {
			if (child_done)
				break;
			continue;
		}
		while ((n = read(dev, &ev, sizeof(ev))) == sizeof(ev)) {
			uint64_t recv = now_ns();
			nev++;
			if (ev.op < 16)
				per_op[ev.op]++;
			sum_hook_ns += ev.t_done_ns - ev.t_hook_ns;
			if (ev.t_done_ns - ev.t_hook_ns > max_hook_ns)
				max_hook_ns = ev.t_done_ns - ev.t_hook_ns;
			sum_lag_ns += recv - ev.t_done_ns;
			if (recv - ev.t_done_ns > max_lag_ns)
				max_lag_ns = recv - ev.t_done_ns;
			bytes = 0;
			path[0] = '\0';
			if ((ev.flags & SHITPRE_F_WAITED) == 0)
				resolve_path(&ev, path, sizeof(path));
			if ((ev.flags & SHITPRE_F_PINNED) != 0) {
				cl.id = ev.id;
				if (stage == NULL)
					(void)ioctl(dev, SHITPRE_RELEASE, &ev.id);
				else if (ioctl(dev, SHITPRE_CLAIM, &cl) == 0) {
					snprintf(dst, sizeof(dst), "%s/%ju",
					    stage, (uintmax_t)ev.id);
					if (copy_fd_to(cl.fd, dst, &bytes) == 0) {
						captured++;
						captured_bytes += bytes;
					}
					close(cl.fd);
				} else
					warn("claim %ju", (uintmax_t)ev.id);
			} else if ((ev.flags & SHITPRE_F_DATA) != 0) {
				fe.id = ev.id;
				fe.buf = buf;
				fe.len = 64 * 1024 * 1024;
				if (stage == NULL)
					(void)ioctl(dev, SHITPRE_RELEASE, &ev.id);
				else if (ioctl(dev, SHITPRE_FETCH, &fe) == 0) {
					int fd;
					snprintf(dst, sizeof(dst), "%s/%ju",
					    stage, (uintmax_t)ev.id);
					fd = open(dst, O_WRONLY | O_CREAT |
					    O_TRUNC, 0600);
					if (fd >= 0 && write(fd, buf, fe.len) ==
					    (ssize_t)fe.len) {
						captured++;
						captured_bytes += fe.len;
						bytes = fe.len;
					}
					if (fd >= 0)
						close(fd);
				} else
					warn("fetch %ju", (uintmax_t)ev.id);
			} else if ((ev.flags & SHITPRE_F_WAITED) != 0) {
				struct copier *c = calloc(1, sizeof(*c));
				struct timespec dl;
				int wms = sysctl_get_int(
				    "security.mac.shitpre.wait_ms");

				waited++;
				c->ev = ev;
				snprintf(c->dst, sizeof(c->dst), "%s/%ju",
				    stage ? stage : "/tmp", (uintmax_t)ev.id);
				pthread_mutex_init(&c->mu, NULL);
				pthread_cond_init(&c->cv, NULL);
				pthread_create(&c->th, NULL, copier_main, c);
				clock_gettime(CLOCK_REALTIME, &dl);
				dl.tv_nsec += (long)(wms / 2) * 1000000L;
				dl.tv_sec += dl.tv_nsec / 1000000000L;
				dl.tv_nsec %= 1000000000L;
				pthread_mutex_lock(&c->mu);
				while (!c->done && pthread_cond_timedwait(
				    &c->cv, &c->mu, &dl) == 0)
					;
				int done_before_ack = c->done;
				pthread_mutex_unlock(&c->mu);
				uint64_t t_ack = now_ns();
				(void)ioctl(dev, SHITPRE_ACK, &ev.id);
				pthread_join(c->th, NULL);
				if (!done_before_ack)
					copier_blocked++;
				else if (c->open_errno == 0)
					copier_ok++;
				printf("  wait %ju %s %s: copier %s before ack "
				    "(open took %.1f ms, finished %.1f ms "
				    "after ack), result %s, %ju bytes\n",
				    (uintmax_t)ev.id, opname[ev.op], c->path,
				    done_before_ack ? "finished" : "BLOCKED",
				    (c->t_open - c->t_start) / 1e6,
				    c->t_done > t_ack ?
				    (c->t_done - t_ack) / 1e6 : 0.0,
				    c->open_errno ? strerror(c->open_errno) :
				    "ok", (uintmax_t)c->bytes);
				free(c);
			}
			if (!quiet)
				printf("%ju %-11s pid=%d jid=%d comm=%s "
				    "size=%ju mode=%o nlink=%u flags=0x%x "
				    "hook=%.1fus lag=%.1fus bytes=%ju %s\n",
				    (uintmax_t)ev.id, opname[ev.op < 11 ?
				    ev.op : 0], ev.pid, ev.jid, ev.comm,
				    (uintmax_t)ev.size, ev.mode, ev.nlink,
				    ev.flags, (ev.t_done_ns - ev.t_hook_ns) /
				    1e3, (recv - ev.t_done_ns) / 1e3,
				    (uintmax_t)bytes, path);
		}
		if (n < 0 && errno != EAGAIN)
			err(1, "read");
	}
	(void)sysctl_set_int("security.mac.shitpre.root_pid", 0);
	printf("summary: wall=%.3fs events=%ju captured=%ju bytes=%ju "
	    "hook_avg=%.1fus hook_max=%.1fus lag_avg=%.1fus lag_max=%.1fus\n",
	    (t1 - t0) / 1e9, (uintmax_t)nev, (uintmax_t)captured,
	    (uintmax_t)captured_bytes, nev ? sum_hook_ns / 1e3 / nev : 0,
	    max_hook_ns / 1e3, nev ? sum_lag_ns / 1e3 / nev : 0,
	    max_lag_ns / 1e3);
	printf("per-op:");
	for (int i = 1; i < 11; i++)
		if (per_op[i])
			printf(" %s=%ju", opname[i], (uintmax_t)per_op[i]);
	printf("\n");
	if (waited)
		printf("mode2: waited=%ju copier_blocked_until_ack=%ju "
		    "copier_ok_before_ack=%ju\n", (uintmax_t)waited,
		    (uintmax_t)copier_blocked, (uintmax_t)copier_ok);
	close(dev);
	return (WIFEXITED(status) ? WEXITSTATUS(status) : 1);
}
