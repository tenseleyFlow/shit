CFLAGS?=	-O2 -Wall -Wextra

auditpipe_reader: auditpipe_reader.c
	${CC} ${CFLAGS} -o auditpipe_reader auditpipe_reader.c -lbsm

clean:
	rm -f auditpipe_reader
