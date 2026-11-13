/* SPDX-License-Identifier: AGPL-3.0-or-later */
/*
 * Static mutator for the spike. Built with -static so LD_PRELOAD (the
 * shit preload shim) never loads. Uses raw libc calls only.
 *
 *   mut unlink PATH
 *   mut trunc PATH          open(O_WRONLY|O_TRUNC), write "new\n"
 *   mut inplace PATH        open(O_RDWR), pwrite "XX" at offset 0
 *   mut renameover SRC DST  rename(SRC, DST) replacing DST
 *   mut chmod PATH MODE     chmod (octal)
 *   mut mmapw PATH          MAP_SHARED write of "MM" at offset 0
 */
#include <sys/mman.h>
#include <sys/stat.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int fd;

	if (argc < 3)
		errx(2, "usage");
	if (strcmp(argv[1], "unlink") == 0) {
		if (unlink(argv[2]) != 0)
			err(1, "unlink");
	} else if (strcmp(argv[1], "trunc") == 0) {
		fd = open(argv[2], O_WRONLY | O_TRUNC);
		if (fd < 0 || write(fd, "new\n", 4) != 4)
			err(1, "trunc");
		close(fd);
	} else if (strcmp(argv[1], "inplace") == 0) {
		fd = open(argv[2], O_RDWR);
		if (fd < 0 || pwrite(fd, "XX", 2, 0) != 2)
			err(1, "inplace");
		close(fd);
	} else if (strcmp(argv[1], "renameover") == 0 && argc > 3) {
		if (rename(argv[2], argv[3]) != 0)
			err(1, "rename");
	} else if (strcmp(argv[1], "chmod") == 0 && argc > 3) {
		if (chmod(argv[2], (mode_t)strtol(argv[3], NULL, 8)) != 0)
			err(1, "chmod");
	} else if (strcmp(argv[1], "mmapw") == 0) {
		char *p;
		fd = open(argv[2], O_RDWR);
		if (fd < 0)
			err(1, "open");
		p = mmap(NULL, 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (p == MAP_FAILED)
			err(1, "mmap");
		memcpy(p, "MM", 2);
		msync(p, 2, MS_SYNC);
		munmap(p, 2);
		close(fd);
	} else
		errx(2, "unknown op %s", argv[1]);
	return (0);
}
