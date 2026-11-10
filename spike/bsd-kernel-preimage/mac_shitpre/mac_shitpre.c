/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * mac_shitpre: design-spike MAC policy that observes vnode mutations by
 * one process subtree and preserves pre-images from inside the hook.
 *
 * Spike quality. It never denies an operation; every hook returns 0.
 *
 * Modes (sysctl security.mac.shitpre.mode):
 *   0  observe   queue one event per hook, no capture
 *   1  capture   unlink/rename-over: vref the victim vnode ("pin") and let
 *                the helper claim a read-only fd on it later.
 *                open-for-write/write/truncate/mmap-shared: copy the file
 *                into kernel memory while the hook holds the vnode lock,
 *                once per (fsid, fileid) per watch, up to copy_cap bytes.
 *   2  wait      queue the event and sleep up to wait_ms for the helper
 *                to SHITPRE_ACK it. Exists to measure whether a userspace
 *                copy can happen while the syscall is parked in the hook.
 *
 * The watched subtree is security.mac.shitpre.root_pid and its
 * descendants (walked through p_pptr). The consumer is /dev/shitpre; one
 * opener at a time.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/jail.h>
#include <sys/ucred.h>
#include <sys/vnode.h>
#include <sys/namei.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/selinfo.h>
#include <sys/poll.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/mount.h>
#include <sys/time.h>

#include <vm/vm.h>

#include <security/mac/mac_policy.h>

#include "shitpre.h"

static MALLOC_DEFINE(M_SHITPRE, "shitpre", "mac_shitpre spike");

/* Tunables. */
static int sp_root_pid = 0;
static int sp_mode = 0;
static u_long sp_copy_cap = 16 * 1024 * 1024;
static int sp_wait_ms = 200;
static int sp_max_pending = 16384;

/* Counters. */
static u_long sp_stat_events;
static u_long sp_stat_dropped;
static u_long sp_stat_pinned;
static u_long sp_stat_copied_bytes;
static u_long sp_stat_copy_ns;
static u_long sp_stat_waits;
static u_long sp_stat_wait_timeouts;
static u_long sp_stat_hook_calls;
static int sp_nseen;

/* Queue state, all under sp_mtx. */
enum { SP_NOWHERE = 0, SP_PENDING, SP_CLAIM };

struct sp_entry {
	TAILQ_ENTRY(sp_entry)	link;
	struct shitpre_event	ev;
	struct vnode		*pin;
	void			*data;
	int			where;
	int			waiter;
	int			acked;
};
TAILQ_HEAD(sp_list, sp_entry);

struct sp_seen {
	LIST_ENTRY(sp_seen)	link;
	uint64_t		fsid;
	uint64_t		fileid;
};
#define SP_SEEN_BUCKETS	1024
LIST_HEAD(sp_seen_head, sp_seen);

static struct mtx sp_mtx;
static struct sp_list sp_pending = TAILQ_HEAD_INITIALIZER(sp_pending);
static struct sp_list sp_claim = TAILQ_HEAD_INITIALIZER(sp_claim);
static int sp_npending;
static uint64_t sp_next_id = 1;
static pid_t sp_consumer_pid;
static struct selinfo sp_sel;
static struct cdev *sp_dev;
static struct sp_seen_head sp_seen_tbl[SP_SEEN_BUCKETS];

static void	sp_seen_clear_locked(struct sp_seen_head *out);

/* ---- sysctl ---------------------------------------------------------- */

static int
sp_sysctl_root_pid(SYSCTL_HANDLER_ARGS)
{
	struct sp_seen_head drop;
	struct sp_seen *s;
	int error, val;

	val = sp_root_pid;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);
	LIST_INIT(&drop);
	mtx_lock(&sp_mtx);
	sp_root_pid = val;
	sp_seen_clear_locked(&drop);
	mtx_unlock(&sp_mtx);
	while ((s = LIST_FIRST(&drop)) != NULL) {
		LIST_REMOVE(s, link);
		free(s, M_SHITPRE);
	}
	return (0);
}

static SYSCTL_NODE(_security_mac, OID_AUTO, shitpre,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0, "shit pre-image spike policy");
SYSCTL_PROC(_security_mac_shitpre, OID_AUTO, root_pid,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    sp_sysctl_root_pid, "I", "Watched subtree root pid (0 = off)");
SYSCTL_INT(_security_mac_shitpre, OID_AUTO, mode, CTLFLAG_RW,
    &sp_mode, 0, "0 observe, 1 capture in kernel, 2 wait for helper ack");
SYSCTL_ULONG(_security_mac_shitpre, OID_AUTO, copy_cap, CTLFLAG_RW,
    &sp_copy_cap, 0, "Largest file copied in kernel (bytes)");
SYSCTL_INT(_security_mac_shitpre, OID_AUTO, wait_ms, CTLFLAG_RW,
    &sp_wait_ms, 0, "Mode 2 ack timeout (ms)");
SYSCTL_INT(_security_mac_shitpre, OID_AUTO, max_pending, CTLFLAG_RW,
    &sp_max_pending, 0, "Pending event bound");
SYSCTL_ULONG(_security_mac_shitpre, OID_AUTO, events, CTLFLAG_RD,
    &sp_stat_events, 0, "");
SYSCTL_ULONG(_security_mac_shitpre, OID_AUTO, dropped, CTLFLAG_RD,
    &sp_stat_dropped, 0, "");
SYSCTL_ULONG(_security_mac_shitpre, OID_AUTO, pinned, CTLFLAG_RD,
    &sp_stat_pinned, 0, "");
SYSCTL_ULONG(_security_mac_shitpre, OID_AUTO, copied_bytes, CTLFLAG_RD,
    &sp_stat_copied_bytes, 0, "");
SYSCTL_ULONG(_security_mac_shitpre, OID_AUTO, copy_ns, CTLFLAG_RD,
    &sp_stat_copy_ns, 0, "Total ns spent copying inside hooks");
SYSCTL_ULONG(_security_mac_shitpre, OID_AUTO, waits, CTLFLAG_RD,
    &sp_stat_waits, 0, "");
SYSCTL_ULONG(_security_mac_shitpre, OID_AUTO, wait_timeouts, CTLFLAG_RD,
    &sp_stat_wait_timeouts, 0, "");
SYSCTL_ULONG(_security_mac_shitpre, OID_AUTO, hook_calls, CTLFLAG_RD,
    &sp_stat_hook_calls, 0, "Hook entries, watched or not");
SYSCTL_INT(_security_mac_shitpre, OID_AUTO, seen, CTLFLAG_RD,
    &sp_nseen, 0, "Files whose content was copied this watch");

/* ---- helpers --------------------------------------------------------- */

static uint64_t
sp_now_ns(void)
{
	struct timespec ts;

	nanouptime(&ts);
	return ((uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}

static bool
sp_watched(struct thread *td)
{
	struct proc *p;
	pid_t root;
	bool found;

	atomic_add_long(&sp_stat_hook_calls, 1);
	root = atomic_load_int(&sp_root_pid);
	if (root <= 0 || atomic_load_int(&sp_consumer_pid) == 0)
		return (false);
	p = td->td_proc;
	if (p->p_pid == sp_consumer_pid)
		return (false);
	if (p->p_pid == root)
		return (true);
	found = false;
	sx_slock(&proctree_lock);
	for (; p != NULL && p->p_pid > 1; p = p->p_pptr) {
		if (p->p_pid == root) {
			found = true;
			break;
		}
	}
	sx_sunlock(&proctree_lock);
	return (found);
}

static void
sp_seen_clear_locked(struct sp_seen_head *out)
{
	struct sp_seen *s;
	int i;

	mtx_assert(&sp_mtx, MA_OWNED);
	for (i = 0; i < SP_SEEN_BUCKETS; i++) {
		while ((s = LIST_FIRST(&sp_seen_tbl[i])) != NULL) {
			LIST_REMOVE(s, link);
			LIST_INSERT_HEAD(out, s, link);
		}
	}
	sp_nseen = 0;
}

/* Returns true if (fsid, fileid) was already seen; marks it otherwise. */
static bool
sp_seen_test_and_set(uint64_t fsid, uint64_t fileid)
{
	struct sp_seen *s, *n;
	u_int b;

	n = malloc(sizeof(*n), M_SHITPRE, M_WAITOK);
	n->fsid = fsid;
	n->fileid = fileid;
	b = (u_int)((fileid ^ (fsid * 31)) % SP_SEEN_BUCKETS);
	mtx_lock(&sp_mtx);
	LIST_FOREACH(s, &sp_seen_tbl[b], link) {
		if (s->fsid == fsid && s->fileid == fileid) {
			mtx_unlock(&sp_mtx);
			free(n, M_SHITPRE);
			return (true);
		}
	}
	LIST_INSERT_HEAD(&sp_seen_tbl[b], n, link);
	sp_nseen++;
	mtx_unlock(&sp_mtx);
	return (false);
}

static bool
sp_seen_test(uint64_t fsid, uint64_t fileid)
{
	struct sp_seen *s;
	u_int b;
	bool hit;

	hit = false;
	b = (u_int)((fileid ^ (fsid * 31)) % SP_SEEN_BUCKETS);
	mtx_lock(&sp_mtx);
	LIST_FOREACH(s, &sp_seen_tbl[b], link) {
		if (s->fsid == fsid && s->fileid == fileid) {
			hit = true;
			break;
		}
	}
	mtx_unlock(&sp_mtx);
	return (hit);
}

/*
 * Identify the object without resolving a path. An earlier version called
 * vn_fullpath() here. On a name-cache miss that falls into vn_vptocnp(),
 * which takes a shared lock on the vnode this thread already holds
 * exclusively; lockmgr returns EDEADLK and _vn_lock_fallback() retries
 * forever (observed: unkillable bsdtar spinning at 100% CPU, and the
 * policy could no longer be unloaded). The hook therefore records file
 * handles only. VOP_VPTOFH needs no extra locks; the helper turns the
 * handles into paths later with fhopen(2) + F_KINFO, holding no locks.
 */
static void
sp_fh(struct vnode *vp, fhandle_t *fh)
{
	bzero(fh, sizeof(*fh));
	if (vp == NULL || vp->v_mount == NULL)
		return;
	fh->fh_fsid = vp->v_mount->mnt_stat.f_fsid;
	if (VOP_VPTOFH(vp, &fh->fh_fid) != 0)
		bzero(fh, sizeof(*fh));
}

static void
sp_ident(struct vnode *dvp, struct vnode *vp, struct componentname *cnp,
    struct shitpre_event *ev)
{
	sp_fh(vp, &ev->fh);
	sp_fh(dvp, &ev->dfh);
	if (cnp != NULL)
		snprintf(ev->name, sizeof(ev->name), "%.*s",
		    (int)cnp->cn_namelen, cnp->cn_nameptr);
	if (ev->fh.fh_fid.fid_len == 0 && ev->dfh.fh_fid.fid_len == 0)
		ev->flags |= SHITPRE_F_NOPATH;
}

/* vp must be locked. */
static int
sp_getattr(struct vnode *vp, struct ucred *cred, struct shitpre_event *ev)
{
	struct vattr va;
	int error;

	error = VOP_GETATTR(vp, &va, cred);
	if (error != 0) {
		ev->flags |= SHITPRE_F_NOATTR;
		return (error);
	}
	ev->fsid = va.va_fsid;
	ev->fileid = va.va_fileid;
	ev->size = va.va_size;
	ev->mode = va.va_mode;
	ev->uid = va.va_uid;
	ev->gid = va.va_gid;
	ev->nlink = va.va_nlink;
	ev->fflags = va.va_flags;
	return (0);
}

/*
 * Copy the whole file into kernel memory. vp is locked by the caller
 * (the syscall in progress). IO_RANGELOCKED: the writer may already hold
 * a write rangelock on this vnode, so taking a read rangelock here would
 * self-deadlock.
 */
static void
sp_copy(struct vnode *vp, struct ucred *cred, struct sp_entry *e)
{
	ssize_t resid;
	uint64_t t0, sz;
	void *buf;
	int error;

	sz = e->ev.size;
	/*
	 * Mark first, whatever the size. An empty file has no pre-image,
	 * and a file created by the watched command must not be copied
	 * again on its second write (that would capture its post-image).
	 */
	if (sp_seen_test_and_set(e->ev.fsid, e->ev.fileid)) {
		e->ev.flags |= SHITPRE_F_DUP;
		return;
	}
	if (sz == 0)
		return;
	if (sz > sp_copy_cap) {
		e->ev.flags |= SHITPRE_F_TOOBIG;
		return;
	}
	t0 = sp_now_ns();
	buf = malloc(sz, M_SHITPRE, M_WAITOK);
	error = vn_rdwr(UIO_READ, vp, buf, (int)sz, 0, UIO_SYSSPACE,
	    IO_NODELOCKED | IO_NOMACCHECK | IO_RANGELOCKED, cred, NOCRED,
	    &resid, curthread);
	if (error != 0) {
		free(buf, M_SHITPRE);
		return;
	}
	e->data = buf;
	e->ev.data_len = sz - resid;
	e->ev.flags |= SHITPRE_F_DATA;
	atomic_add_long(&sp_stat_copied_bytes, e->ev.data_len);
	atomic_add_long(&sp_stat_copy_ns, sp_now_ns() - t0);
}

static void
sp_entry_free(struct sp_entry *e)
{
	if (e->pin != NULL)
		vrele(e->pin);
	free(e->data, M_SHITPRE);
	free(e, M_SHITPRE);
}

/* Queue e. In wait mode, sleep until acked or timed out, then free e. */
static void
sp_enqueue(struct sp_entry *e)
{
	int error, waiter;

	waiter = e->waiter;
	mtx_lock(&sp_mtx);
	if (sp_consumer_pid == 0 || sp_npending >= sp_max_pending) {
		sp_stat_dropped++;
		mtx_unlock(&sp_mtx);
		sp_entry_free(e);
		return;
	}
	e->ev.id = sp_next_id++;
	e->where = SP_PENDING;
	TAILQ_INSERT_TAIL(&sp_pending, e, link);
	sp_npending++;
	sp_stat_events++;
	wakeup(&sp_pending);
	if (!waiter) {
		mtx_unlock(&sp_mtx);
		selwakeup(&sp_sel);
		return;
	}
	mtx_unlock(&sp_mtx);
	selwakeup(&sp_sel);

	mtx_lock(&sp_mtx);
	sp_stat_waits++;
	error = 0;
	while (!e->acked && e->where != SP_NOWHERE && error == 0)
		error = msleep(e, &sp_mtx, 0, "shitpw",
		    imax(1, sp_wait_ms * hz / 1000));
	if (!e->acked)
		sp_stat_wait_timeouts++;
	if (e->where == SP_PENDING) {
		TAILQ_REMOVE(&sp_pending, e, link);
		sp_npending--;
	} else if (e->where == SP_CLAIM)
		TAILQ_REMOVE(&sp_claim, e, link);
	e->where = SP_NOWHERE;
	mtx_unlock(&sp_mtx);
	sp_entry_free(e);
}

#define	SP_ATTR	0x1
#define	SP_PIN	0x2
#define	SP_COPY	0x4

static int
sp_event(int op, struct ucred *cred, struct vnode *dvp, struct vnode *vp,
    struct componentname *cnp, uint64_t arg, int want)
{
	struct thread *td;
	struct sp_entry *e;
	int mode;

	td = curthread;
	if (!sp_watched(td))
		return (0);
	mode = atomic_load_int(&sp_mode);
	e = malloc(sizeof(*e), M_SHITPRE, M_WAITOK | M_ZERO);
	e->ev.t_hook_ns = sp_now_ns();
	e->ev.op = op;
	e->ev.pid = td->td_proc->p_pid;
	e->ev.jid = cred->cr_prison->pr_id;
	e->ev.arg = arg;
	strlcpy(e->ev.comm, td->td_proc->p_comm, sizeof(e->ev.comm));
	if (vp != NULL && (want & SP_ATTR) != 0)
		(void)sp_getattr(vp, cred, &e->ev);
	else
		e->ev.flags |= SHITPRE_F_NOATTR;

	/* Per-write events are only interesting the first time per file. */
	if (op == SHITPRE_OP_WRITE && (e->ev.flags & SHITPRE_F_NOATTR) == 0 &&
	    sp_seen_test(e->ev.fsid, e->ev.fileid)) {
		free(e, M_SHITPRE);
		return (0);
	}
	sp_ident(dvp, vp, cnp, &e->ev);

	if (mode == 1 && vp != NULL && vp->v_type == VREG &&
	    (e->ev.flags & SHITPRE_F_NOATTR) == 0) {
		if ((want & SP_PIN) != 0) {
			vref(vp);
			e->pin = vp;
			e->ev.flags |= SHITPRE_F_PINNED;
			atomic_add_long(&sp_stat_pinned, 1);
		}
		if ((want & SP_COPY) != 0)
			sp_copy(vp, cred, e);
	} else if (mode == 0 && op == SHITPRE_OP_WRITE &&
	    (e->ev.flags & SHITPRE_F_NOATTR) == 0)
		(void)sp_seen_test_and_set(e->ev.fsid, e->ev.fileid);
	if (mode == 2) {
		e->waiter = 1;
		e->ev.flags |= SHITPRE_F_WAITED;
	}
	e->ev.t_done_ns = sp_now_ns();
	sp_enqueue(e);
	return (0);
}

/* ---- MAC hooks ------------------------------------------------------- */

static int
sp_check_unlink(struct ucred *cred, struct vnode *dvp, struct label *dl,
    struct vnode *vp, struct label *vl, struct componentname *cnp)
{
	return (sp_event(SHITPRE_OP_UNLINK, cred, dvp, vp, cnp, 0,
	    SP_ATTR | SP_PIN));
}

static int
sp_check_rename_from(struct ucred *cred, struct vnode *dvp, struct label *dl,
    struct vnode *vp, struct label *vl, struct componentname *cnp)
{
	/* vp is referenced but not locked here: path only. */
	return (sp_event(SHITPRE_OP_RENAME_FROM, cred, dvp, NULL, cnp, 0, 0));
}

static int
sp_check_rename_to(struct ucred *cred, struct vnode *dvp, struct label *dl,
    struct vnode *vp, struct label *vl, int samedir,
    struct componentname *cnp)
{
	return (sp_event(SHITPRE_OP_RENAME_TO, cred, dvp, vp, cnp, samedir,
	    SP_ATTR | SP_PIN));
}

static int
sp_check_open(struct ucred *cred, struct vnode *vp, struct label *vl,
    accmode_t accmode)
{
	if ((accmode & (VWRITE | VAPPEND)) == 0)
		return (0);
	return (sp_event(SHITPRE_OP_OPEN_W, cred, NULL, vp, NULL, accmode,
	    SP_ATTR | SP_COPY));
}

static int
sp_check_write(struct ucred *active_cred, struct ucred *file_cred,
    struct vnode *vp, struct label *vl)
{
	return (sp_event(SHITPRE_OP_WRITE, active_cred, NULL, vp, NULL, 0,
	    SP_ATTR | SP_COPY));
}

static int
sp_check_mmap(struct ucred *cred, struct vnode *vp, struct label *vl,
    int prot, int flags)
{
	if ((prot & VM_PROT_WRITE) == 0 || (flags & MAP_SHARED) == 0)
		return (0);
	return (sp_event(SHITPRE_OP_MMAP_W, cred, NULL, vp, NULL, prot,
	    SP_ATTR | SP_COPY));
}

static int
sp_check_setmode(struct ucred *cred, struct vnode *vp, struct label *vl,
    mode_t mode)
{
	return (sp_event(SHITPRE_OP_SETMODE, cred, NULL, vp, NULL, mode,
	    SP_ATTR));
}

static int
sp_check_setowner(struct ucred *cred, struct vnode *vp, struct label *vl,
    uid_t uid, gid_t gid)
{
	return (sp_event(SHITPRE_OP_SETOWNER, cred, NULL, vp, NULL,
	    ((uint64_t)uid << 32) | (uint32_t)gid, SP_ATTR));
}

static int
sp_check_setflags(struct ucred *cred, struct vnode *vp, struct label *vl,
    u_long flags)
{
	return (sp_event(SHITPRE_OP_SETFLAGS, cred, NULL, vp, NULL, flags,
	    SP_ATTR));
}

static int
sp_check_setutimes(struct ucred *cred, struct vnode *vp, struct label *vl,
    struct timespec atime, struct timespec mtime)
{
	return (sp_event(SHITPRE_OP_SETUTIMES, cred, NULL, vp, NULL,
	    (uint64_t)mtime.tv_sec, SP_ATTR));
}

/* ---- /dev/shitpre ---------------------------------------------------- */

static void
sp_drain_all(void)
{
	struct sp_list freeq;
	struct sp_seen_head drop;
	struct sp_entry *e;
	struct sp_seen *s;

	TAILQ_INIT(&freeq);
	LIST_INIT(&drop);
	mtx_lock(&sp_mtx);
	while ((e = TAILQ_FIRST(&sp_pending)) != NULL) {
		TAILQ_REMOVE(&sp_pending, e, link);
		sp_npending--;
		e->where = SP_NOWHERE;
		if (e->waiter)
			wakeup(e);
		else
			TAILQ_INSERT_TAIL(&freeq, e, link);
	}
	while ((e = TAILQ_FIRST(&sp_claim)) != NULL) {
		TAILQ_REMOVE(&sp_claim, e, link);
		e->where = SP_NOWHERE;
		if (e->waiter)
			wakeup(e);
		else
			TAILQ_INSERT_TAIL(&freeq, e, link);
	}
	sp_seen_clear_locked(&drop);
	mtx_unlock(&sp_mtx);
	while ((e = TAILQ_FIRST(&freeq)) != NULL) {
		TAILQ_REMOVE(&freeq, e, link);
		sp_entry_free(e);
	}
	while ((s = LIST_FIRST(&drop)) != NULL) {
		LIST_REMOVE(s, link);
		free(s, M_SHITPRE);
	}
}

static int
sp_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	int error;

	error = 0;
	mtx_lock(&sp_mtx);
	if (sp_consumer_pid != 0)
		error = EBUSY;
	else
		sp_consumer_pid = td->td_proc->p_pid;
	mtx_unlock(&sp_mtx);
	return (error);
}

static int
sp_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	mtx_lock(&sp_mtx);
	sp_consumer_pid = 0;
	mtx_unlock(&sp_mtx);
	sp_drain_all();
	return (0);
}

static int
sp_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	struct shitpre_event ev;
	struct sp_entry *e, *tofree;
	int error;

	error = 0;
	mtx_lock(&sp_mtx);
	while (TAILQ_EMPTY(&sp_pending)) {
		if ((ioflag & O_NONBLOCK) != 0) {
			mtx_unlock(&sp_mtx);
			return (EWOULDBLOCK);
		}
		error = msleep(&sp_pending, &sp_mtx, PCATCH, "shitprd", 0);
		if (error != 0) {
			mtx_unlock(&sp_mtx);
			return (error);
		}
	}
	while (uio->uio_resid >= (ssize_t)sizeof(ev) &&
	    (e = TAILQ_FIRST(&sp_pending)) != NULL) {
		TAILQ_REMOVE(&sp_pending, e, link);
		sp_npending--;
		ev = e->ev;
		tofree = NULL;
		if (e->waiter || e->pin != NULL || e->data != NULL) {
			e->where = SP_CLAIM;
			TAILQ_INSERT_TAIL(&sp_claim, e, link);
		} else {
			e->where = SP_NOWHERE;
			tofree = e;
		}
		mtx_unlock(&sp_mtx);
		if (tofree != NULL)
			sp_entry_free(tofree);
		error = uiomove(&ev, sizeof(ev), uio);
		mtx_lock(&sp_mtx);
		if (error != 0)
			break;
	}
	mtx_unlock(&sp_mtx);
	return (error);
}

static int
sp_poll(struct cdev *dev, int events, struct thread *td)
{
	int revents;

	revents = 0;
	mtx_lock(&sp_mtx);
	if ((events & (POLLIN | POLLRDNORM)) != 0) {
		if (!TAILQ_EMPTY(&sp_pending))
			revents |= events & (POLLIN | POLLRDNORM);
		else
			selrecord(td, &sp_sel);
	}
	mtx_unlock(&sp_mtx);
	return (revents);
}

/* Remove a claimable non-waiter entry by id. */
static struct sp_entry *
sp_claim_take(uint64_t id)
{
	struct sp_entry *e;

	mtx_lock(&sp_mtx);
	TAILQ_FOREACH(e, &sp_claim, link) {
		if (e->ev.id == id && !e->waiter) {
			TAILQ_REMOVE(&sp_claim, e, link);
			e->where = SP_NOWHERE;
			break;
		}
	}
	mtx_unlock(&sp_mtx);
	return (e);
}

static int
sp_do_claim(struct thread *td, struct shitpre_claim *c)
{
	struct sp_entry *e;
	struct vnode *vp;
	struct file *fp;
	int error, fd;

	e = sp_claim_take(c->id);
	if (e == NULL)
		return (ENOENT);
	vp = e->pin;
	if (vp == NULL) {
		sp_entry_free(e);
		return (EINVAL);
	}
	e->pin = NULL;
	sp_entry_free(e);

	/* Same sequence as kern_fhopen(), for a vnode we already hold. */
	error = falloc_noinstall(td, &fp);
	if (error != 0) {
		vrele(vp);
		return (error);
	}
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = vn_open_vnode(vp, FREAD, td->td_ucred, td, fp);
	if (error != 0) {
		vput(vp);
		fdrop(fp, td);
		return (error);
	}
	fp->f_vnode = vp;
	finit_vnode(fp, FREAD, NULL, &vnops);
	VOP_UNLOCK(vp);
	error = finstall(td, fp, &fd, O_CLOEXEC, NULL);
	fdrop(fp, td);
	if (error == 0)
		c->fd = fd;
	return (error);
}

static int
sp_do_fetch(struct shitpre_fetch *f)
{
	struct sp_entry *e;
	uint64_t n;
	int error;

	e = sp_claim_take(f->id);
	if (e == NULL)
		return (ENOENT);
	if (e->data == NULL) {
		sp_entry_free(e);
		return (EINVAL);
	}
	n = MIN(f->len, e->ev.data_len);
	error = copyout(e->data, f->buf, n);
	f->len = n;
	sp_entry_free(e);
	return (error);
}

static int
sp_do_ack(uint64_t id)
{
	struct sp_entry *e;

	mtx_lock(&sp_mtx);
	TAILQ_FOREACH(e, &sp_claim, link) {
		if (e->ev.id == id && e->waiter) {
			TAILQ_REMOVE(&sp_claim, e, link);
			e->where = SP_NOWHERE;
			e->acked = 1;
			wakeup(e);
			break;
		}
	}
	mtx_unlock(&sp_mtx);
	return (e == NULL ? ENOENT : 0);
}

static int
sp_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct sp_entry *e;

	switch (cmd) {
	case SHITPRE_CLAIM:
		return (sp_do_claim(td, (struct shitpre_claim *)data));
	case SHITPRE_FETCH:
		return (sp_do_fetch((struct shitpre_fetch *)data));
	case SHITPRE_ACK:
		return (sp_do_ack(*(uint64_t *)data));
	case SHITPRE_RELEASE:
		e = sp_claim_take(*(uint64_t *)data);
		if (e == NULL)
			return (ENOENT);
		sp_entry_free(e);
		return (0);
	default:
		return (ENOTTY);
	}
}

static struct cdevsw sp_cdevsw = {
	.d_version =	D_VERSION,
	.d_name =	SHITPRE_DEV,
	.d_open =	sp_open,
	.d_close =	sp_close,
	.d_read =	sp_read,
	.d_poll =	sp_poll,
	.d_ioctl =	sp_ioctl,
};

/* ---- lifecycle ------------------------------------------------------- */

/*
 * The device is created and destroyed by SYSINIT/SYSUNINIT. kldunload
 * runs the MAC module's MOD_UNLOAD (which unregisters the policy after
 * in-flight hooks drain) before any SYSUNINIT, so no hook can run while
 * the device goes away.
 */
static void
sp_dev_init(void *arg __unused)
{
	int i;

	mtx_init(&sp_mtx, "shitpre", NULL, MTX_DEF);
	for (i = 0; i < SP_SEEN_BUCKETS; i++)
		LIST_INIT(&sp_seen_tbl[i]);
	knlist_init_mtx(&sp_sel.si_note, &sp_mtx);
	sp_dev = make_dev(&sp_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600,
	    SHITPRE_DEV);
}
SYSINIT(shitpre_dev, SI_SUB_MAC_POLICY, SI_ORDER_FIRST, sp_dev_init, NULL);

static void
sp_dev_uninit(void *arg __unused)
{
	if (sp_dev != NULL)
		destroy_dev(sp_dev);
	sp_drain_all();
	seldrain(&sp_sel);
	knlist_destroy(&sp_sel.si_note);
	mtx_destroy(&sp_mtx);
}
SYSUNINIT(shitpre_dev, SI_SUB_MAC_POLICY, SI_ORDER_FIRST, sp_dev_uninit, NULL);

static struct mac_policy_ops sp_ops = {
	.mpo_vnode_check_unlink =	sp_check_unlink,
	.mpo_vnode_check_rename_from =	sp_check_rename_from,
	.mpo_vnode_check_rename_to =	sp_check_rename_to,
	.mpo_vnode_check_open =		sp_check_open,
	.mpo_vnode_check_write =	sp_check_write,
	.mpo_vnode_check_mmap =		sp_check_mmap,
	.mpo_vnode_check_setmode =	sp_check_setmode,
	.mpo_vnode_check_setowner =	sp_check_setowner,
	.mpo_vnode_check_setflags =	sp_check_setflags,
	.mpo_vnode_check_setutimes =	sp_check_setutimes,
};

MAC_POLICY_SET(&sp_ops, mac_shitpre, "shit pre-image spike",
    MPC_LOADTIME_FLAG_UNLOADOK, NULL);
