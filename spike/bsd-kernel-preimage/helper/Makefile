CFLAGS?=	-O2 -Wall -Wextra -Wno-unused-parameter

all: shitpre_helper mut

shitpre_helper: shitpre_helper.c ../mac_shitpre/shitpre.h
	${CC} ${CFLAGS} -o shitpre_helper shitpre_helper.c -lpthread

mut: mut.c
	${CC} ${CFLAGS} -static -o mut mut.c

clean:
	rm -f shitpre_helper mut
