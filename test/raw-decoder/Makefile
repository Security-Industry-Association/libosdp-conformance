# make file for osdp-dump

PROGS=osdp-dump
CC=clang
OSDPLIB=../../opt/osdp-conformance/lib
OSDPINCLUDE=../../include
CFLAGS=-c -g -I${OSDPINCLUDE} -Wall -Werror
LINK=clang
LDFLAGS=-g /opt/osdp-conformance/lib/aes.o -L ${OSDPLIB} -l osdp -ljansson

all:	${PROGS}

clean:
	rm -rf ${PROGS} *.o core

osdp-dump:	osdp-dump.o Makefile ${OSDPLIB}/libosdp.a
	${LINK} -o osdp-dump osdp-dump.o ${LDFLAGS}

osdp-dump.o:	osdp-dump.c ${OSDPINCLUDE}/open-osdp.h
	${CC} ${CFLAGS} osdp-dump.c

