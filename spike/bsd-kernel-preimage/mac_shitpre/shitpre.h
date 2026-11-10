/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Userspace/kernel ABI for the mac_shitpre spike module. Design spike
 * only: no stability promise, no versioning beyond SHITPRE_ABI.
 */
#ifndef SHITPRE_H
#define SHITPRE_H

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/mount.h>

#define SHITPRE_ABI		2
#define SHITPRE_DEV		"shitpre"
#define SHITPRE_PATHLEN		1024	/* helper-side resolved path */
#define SHITPRE_NAMELEN		256

/* Operations, named after the MAC hook that saw them. */
#define SHITPRE_OP_UNLINK	1	/* unlink(2), rmdir(2) */
#define SHITPRE_OP_RENAME_FROM	2	/* source of rename(2) */
#define SHITPRE_OP_RENAME_TO	3	/* target of rename(2) when it exists */
#define SHITPRE_OP_OPEN_W	4	/* open(2) with write or O_TRUNC intent */
#define SHITPRE_OP_WRITE	5	/* write(2), ftruncate(2), truncate(2) */
#define SHITPRE_OP_MMAP_W	6	/* mmap(2) PROT_WRITE|MAP_SHARED */
#define SHITPRE_OP_SETMODE	7
#define SHITPRE_OP_SETOWNER	8
#define SHITPRE_OP_SETFLAGS	9
#define SHITPRE_OP_SETUTIMES	10

/* Event flags. */
#define SHITPRE_F_PINNED	0x01	/* vnode ref held; claim with SHITPRE_CLAIM */
#define SHITPRE_F_DATA		0x02	/* bytes copied in kernel; fetch with SHITPRE_FETCH */
#define SHITPRE_F_TOOBIG	0x04	/* file exceeded copy_cap; no data */
#define SHITPRE_F_DUP		0x08	/* content already copied this watch */
#define SHITPRE_F_NOPATH	0x10	/* no file handle for vp or dvp */
#define SHITPRE_F_WAITED	0x20	/* mode 2: thread slept for an ack */
#define SHITPRE_F_WAIT_TIMEOUT	0x40	/* mode 2: ack never came */
#define SHITPRE_F_NOATTR	0x80	/* VOP_GETATTR failed or no vnode */

struct shitpre_event {
	uint64_t	id;
	uint32_t	op;
	uint32_t	flags;
	int32_t		pid;
	int32_t		jid;		/* cr_prison->pr_id, 0 = host */
	uint64_t	t_hook_ns;	/* nanouptime() at hook entry */
	uint64_t	t_done_ns;	/* nanouptime() when the hook returned */
	uint64_t	fsid;
	uint64_t	fileid;
	uint64_t	size;		/* pre-change size */
	uint32_t	mode;		/* pre-change mode */
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	nlink;
	uint64_t	fflags;		/* pre-change chflags(2) flags */
	uint64_t	arg;		/* new mode/flags/owner, accmode, prot */
	uint64_t	data_len;
	char		comm[20];
	fhandle_t	fh;		/* vp, if any; zero when absent */
	fhandle_t	dfh;		/* parent dir for unlink/rename */
	char		name[SHITPRE_NAMELEN];	/* component name for unlink/rename */
};

struct shitpre_fetch {
	uint64_t	id;
	void		*buf;
	uint64_t	len;	/* in: buffer size; out: bytes copied */
};

struct shitpre_claim {
	uint64_t	id;
	int32_t		fd;	/* out: O_RDONLY descriptor on the pinned vnode */
	int32_t		pad;
};

#define SHITPRE_CLAIM	_IOWR('S', 1, struct shitpre_claim)
#define SHITPRE_FETCH	_IOWR('S', 2, struct shitpre_fetch)
#define SHITPRE_ACK	_IOW('S', 3, uint64_t)
#define SHITPRE_RELEASE	_IOW('S', 4, uint64_t)

#endif
