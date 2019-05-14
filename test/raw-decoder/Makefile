# make file for osdp-dump

PROGS=osdp-dump
CGI_PROGS=osdp-decode osdp-packet-decode
CC=clang
OSDPLIB=../../opt/osdp-conformance/lib
OSDPINCLUDE=../../include
CFLAGS=-c -g -I${OSDPINCLUDE} -Wall -Werror
LINK=clang
LDFLAGS=-g /opt/osdp-conformance/lib/aes.o -L ${OSDPLIB} -l osdp -ljansson

all:	${PROGS} ${CGI_PROGS}

clean:
	rm -rf ${PROGS} *.o core

build:	all
	mkdir -p ../../opt/osdp-conformance/cgi-bin
	cp ${CGI_PROGS} ../../opt/osdp-conformance/cgi-bin

osdp-decode:	osdp-decode.o Makefile 
	${LINK} -o osdp-decode osdp-decode.c ${LDFLAGS}

osdp-decode.o:	osdp-decode.c
	${CC} ${CFLAGS} osdp-decode.c

osdp-dump:	osdp-dump.o Makefile ${OSDPLIB}/libosdp.a
	${LINK} -o osdp-dump osdp-dump.o ${LDFLAGS}

osdp-dump.o:	osdp-dump.c ${OSDPINCLUDE}/open-osdp.h
	${CC} ${CFLAGS} osdp-dump.c

osdp-packet-decode:	osdp-packet-decode.o Makefile
	${LINK} -o osdp-packet-decode -g osdp-packet-decode.o ${LDFLAGS}

osdp-packet-decode.o:	osdp-packet-decode.c
	${CC} ${CFLAGS} osdp-packet-decode.c

