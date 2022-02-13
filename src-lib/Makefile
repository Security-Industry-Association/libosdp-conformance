# Make file for libosdp-conformance

#  (C)Copyright 2017-2022 Smithee Solutions LLC

#  Support provided by the Security Industry Association
#  http://www.securityindustry.org

#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
 
#    http://www.apache.org/licenses/LICENSE-2.0
 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


OUTLIB=libosdp-conformance.a

# built with gcc.  note it also builds with clang.
CC=gcc
#CC=clang
CFLAGS=-c -DOSDP_CONFORMANCE -g -I../include -I/opt/osdp-conformance/include \
  -Wall -Werror

all:	${OUTLIB}

build:	all
	mkdir -p ../opt/osdp-conformance/lib
	cp ${OUTLIB} ../opt/osdp-conformance/lib

clean:
	rm -f core *.o ${OUTLIB}

${OUTLIB}:	\
	oo-actions.o oo-api.o \
	oo-bio.o oo-callout.o oo-capabilities.o oo-conformance.o oo-crc.o \
	  oo-cmdbreech.o oo-io-actions.o oo-initialize.o \
	oo-logprims.o oo-mfg-actions.o oo-mgmt-actions.o oo-parse.o \
	  oo-printmsg.o oo-process.o \
	  oo-util.o oo-util2.o oo-util3.o \
	  oo-xpm-actions.o oo-xwrite.o \
	  oo-files.o oo-logmsg.o oo-prims.o \
	  oo-secure.o oo-secure-actions.o oo-settings.o oo-ui.o oo-73.o
	ar r ${OUTLIB} \
	  oo-actions.o oo-api.o oo-bio.o oo-capabilities.o oo-callout.o \
	  oo-cmdbreech.o oo-initialize.o oo-io-actions.o oo-logprims.o oo-mfg-actions.o oo-mgmt-actions.o \
	  oo-parse.o oo-printmsg.o oo-process.o oo-util.o oo-util2.o \
	  oo-util3.o oo-xpm-actions.o oo-xwrite.o \
	  oo-conformance.o oo-crc.o oo-files.o \
	  oo-logmsg.o oo-prims.o oo-secure.o \
	  oo-secure-actions.o oo-settings.o oo-ui.o oo-73.o

oo-actions.o:	oo-actions.c ../include/open-osdp.h ../include/iec-nak.h
	${CC} ${CFLAGS} oo-actions.c

oo-api.o:	oo-api.c ../include/osdp-tls.h ../include/open-osdp.h
	${CC} ${CFLAGS} oo-api.c

oo-bio.o:	oo-bio.c ../include/osdp-tls.h ../include/open-osdp.h
	${CC} ${CFLAGS} oo-bio.c

oo-callout.o:	oo-callout.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-callout.c

oo-cmdbreech.o:	oo-cmdbreech.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-cmdbreech.c

oo-initialize.o:	oo-initialize.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-initialize.c

oo-io-actions.o:	oo-io-actions.c ../include/osdp-tls.h ../include/open-osdp.h
	${CC} ${CFLAGS} oo-io-actions.c

oo-mfg-actions.o:	oo-mfg-actions.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-mfg-actions.c

oo-mgmt-actions.o:	oo-mgmt-actions.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-mgmt-actions.c

oo-parse.o:	oo-parse.c ../include/open-osdp.h ../include/iec-nak.h
	${CC} ${CFLAGS} oo-parse.c

oo-process.o:	oo-process.c ../include/open-osdp.h ../include/iec-nak.h
	${CC} ${CFLAGS} oo-process.c

oo-util.o:	oo-util.c ../include/open-osdp.h ../include/iec-nak.h
	${CC} ${CFLAGS} oo-util.c

oo-util2.o:	oo-util2.c ../include/open-osdp.h ../include/iec-nak.h
	${CC} ${CFLAGS} oo-util2.c

oo-util3.o:	oo-util3.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-util3.c

oo-logprims.o:	oo-logprims.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-logprims.c

oo-printmsg.o:	oo-printmsg.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-printmsg.c

oo-xpm-actions.o:	oo-xpm-actions.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-xpm-actions.c

oo-xwrite.o:	oo-xwrite.c ../include/open-osdp.h ../include/iec-xwrite.h
	${CC} ${CFLAGS} oo-xwrite.c

oo-conformance.o:	oo-conformance.c
	${CC} ${CFLAGS} oo-conformance.c

oo-capabilities.o:	oo-capabilities.c
	${CC} ${CFLAGS} oo-capabilities.c

oo-crc.o:	oo-crc.c
	${CC} ${CFLAGS} oo-crc.c

oo-files.o:	oo-files.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-files.c

oo-logmsg.o:	oo-logmsg.c ../include/open-osdp.h ../include/iec-nak.h
	${CC} ${CFLAGS} oo-logmsg.c

oo-prims.o:	oo-prims.c /opt/osdp-conformance/include/open-osdp.h
	${CC} ${CFLAGS} oo-prims.c

oo-secure.o:	oo-secure.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-secure.c

oo-settings.o:	oo-settings.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-settings.c

oo-secure-actions.o:	oo-secure-actions.c ../include/open-osdp.h ../include/iec-nak.h
	${CC} ${CFLAGS} oo-secure-actions.c

oo-ui.o:	oo-ui.c ../include/open-osdp.h ../include/iec-xwrite.h ../include/iec-nak.h
	${CC} ${CFLAGS} oo-ui.c

oo-73.o:	oo-73.c
	${CC} ${CFLAGS} oo-73.c

/opt/osdp-conformance/include/open-osdp.h:	../include/open-osdp.h
	mkdir -p /opt/osdp-conformance/include
	cp ../include/open-osdp.h /opt/osdp-conformance/include
	echo really should be a makefile in the include directory
	cp ../include/oo-api.h /opt/osdp-conformance/include

