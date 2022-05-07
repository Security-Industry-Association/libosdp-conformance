# make file for osdp-dump

PROGS=osdp-dump osdp-sc-calc
CGI_PROGS=osdp-decode osdp-packet-decode
ACTIONS=\
  osdp_ACK osdp_ACURXSIZE osdp_BIOMATCH osdp_BIOMATCHR osdp_BIOREAD osdp_BIOREADR osdp_BUSY osdp_BUZ osdp_CAP osdp_CCRYPT osdp_CHLNG osdp_COM osdp_COMSET osdp_CRAUTH osdp_CRAUTHR \
  osdp_DATA osdp_DIAG osdp_FILETRANSFER osdp_FTSTAT osdp_GENAUTH osdp_GENAUTHR osdp_ID osdp_ISTAT osdp_ISTATR osdp_KEEPACTIVE osdp_KEYPAD osdp_KEYSET \
  osdp_LED osdp_LSTAT osdp_LSTATR osdp_MFG osdp_MFGERRR osdp_MFGREP osdp_NAK osdp_OSTAT osdp_OSTATR osdp_OUT \
  osdp_PDCAP osdp_PDID osdp_PIVDATA osdp_PIVDATAR osdp_POLL osdp_RAW osdp_RMAC_I osdp_RSTAT osdp_RSTATR osdp_SCRYPT osdp_TEXT \
  osdp_XRD osdp_XWR
OSDPINCLUDE=../include
OSDPBUILD=../opt/osdp-conformance
OSDPLIB=${OSDPBUILD}/lib
CC=gcc
CFLAGS=-c -g -I${OSDPINCLUDE} -I/opt/osdp-conformance/include -Wall -Werror
LINK=${CC}
LDFLAGS=-g /opt/osdp-conformance/lib/aes.o -L ${OSDPLIB} -l osdp-conformance -ljansson

all:	${PROGS} ${CGI_PROGS}

clean:
	rm -rf ${PROGS} ${CGI_PROGS} *.o core

build:	all
	mkdir -p ${OSDPBUILD}/bin
	cp ${PROGS} ${OSDPBUILD}/bin
	mkdir -p ${OSDPBUILD}/cgi-bin
	cp ${CGI_PROGS} ${OSDPBUILD}/cgi-bin
	mkdir -p ${OSDPBUILD}/run/ACU-actions
	(cd actions; cp ${ACTIONS} ../${OSDPBUILD}/run/ACU-actions)

osdp-decode:	osdp-decode.o Makefile 
	${LINK} -o osdp-decode osdp-decode.c ${LDFLAGS}

osdp-decode.o:	osdp-decode.c
	${CC} ${CFLAGS} osdp-decode.c

osdp-dump:	osdp-dump.o Makefile ${OSDPLIB}/libosdp.a
	${LINK} -o osdp-dump osdp-dump.o ${LDFLAGS}

osdp-dump.o:	osdp-dump.c ${OSDPINCLUDE}/open-osdp.h
	${CC} ${CFLAGS} osdp-dump.c

osdp-dump-util.o:	osdp-dump-util.c
	${CC} ${CFLAGS} osdp-dump-util.c

osdp-packet-decode:	osdp-packet-decode.o Makefile
	${LINK} -o osdp-packet-decode -g osdp-packet-decode.o ${LDFLAGS}

osdp-packet-decode.o:	osdp-packet-decode.c
	${CC} ${CFLAGS} osdp-packet-decode.c

osdp-sc-calc:	osdp-sc-calc.o osdp-dump-util.o Makefile
	${LINK} -o osdp-sc-calc -g osdp-sc-calc.o osdp-dump-util.o ${LDFLAGS}

osdp-sc-calc.o:	osdp-sc-calc.c
	${CC} ${CFLAGS} osdp-sc-calc.c

${OSDPLIB}/libosdp.a:
	(cd ../src-lib; make build; cd ../src-tools)

