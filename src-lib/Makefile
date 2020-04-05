# Make file for libosdp

#  (C)Copyright 2017-2019 Smithee Solutions LLC
#  (C)Copyright 2015-2017 Smithee,Spelvin,Agnew & Plinge, Inc.

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


OUTLIB=libosdp.a

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

libosdp.a:	oo-actions.o oo-initialize.o oo_process.o oo-util.o oo-util2.o oo-util3.o \
	  oo-cmdbreech.o \
	  oo-logprims.o oo-printmsg.o oo-xpm-actions.o oo-xwrite.o \
	  oosdp_crc.o oosdp_conformance.o \
	  oosdp_files.o oosdp_logmsg.o oo-prims.o \
	  oo-secure.o oosdp_secure_actions.o oosdp_ui.o osdp-api.o
	ar r libosdp.a \
	  oo-actions.o \
	  oo-cmdbreech.o oo-initialize.o oo_process.o oo-util.o oo-util2.o \
	  oo-util3.o oo-logprims.o oo-printmsg.o oo-xpm-actions.o oo-xwrite.o \
	  oosdp_conformance.o oosdp_crc.o oosdp_files.o \
	  oosdp_logmsg.o oo-prims.o oo-secure.o \
	  oosdp_secure_actions.o oosdp_ui.o \
	  osdp-api.o

oo-actions.o:	oo-actions.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-actions.c

oo-cmdbreech.o:	oo-cmdbreech.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-cmdbreech.c

oo-initialize.o:	oo-initialize.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-initialize.c

oo_process.o:	oo_process.c
	${CC} ${CFLAGS} oo_process.c

oo-util.o:	oo-util.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-util.c

oo-util2.o:	oo-util2.c ../include/open-osdp.h
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

# different as it uses source here by inclusion
oosdp_conformance.o:	oosdp_conformance.c osdp-SKIP.c
	${CC} ${CFLAGS} -I. oosdp_conformance.c

oosdp_crc.o:	oosdp_crc.c
	${CC} ${CFLAGS} oosdp_crc.c

oosdp_files.o:	oosdp_files.c ../include/open-osdp.h
	${CC} ${CFLAGS} oosdp_files.c

oosdp_logmsg.o:	oosdp_logmsg.c ../include/open-osdp.h
	${CC} ${CFLAGS} oosdp_logmsg.c

oo-prims.o:	oo-prims.c /opt/osdp-conformance/include/open-osdp.h
	${CC} ${CFLAGS} oo-prims.c

oo-secure.o:	oo-secure.c ../include/open-osdp.h
	${CC} ${CFLAGS} oo-secure.c

oosdp_secure_actions.o:	oosdp_secure_actions.c ../include/open-osdp.h
	${CC} ${CFLAGS} oosdp_secure_actions.c

oosdp_ui.o:	oosdp_ui.c ../include/open-osdp.h ../include/iec-xwrite.h
	${CC} ${CFLAGS} oosdp_ui.c

osdp-api.o:	osdp-api.c ../include/osdp-tls.h ../include/open-osdp.h
	${CC} ${CFLAGS} osdp-api.c

/opt/osdp-conformance/include/open-osdp.h:	../include/open-osdp.h
	cp ../include/open-osdp.h /opt/osdp-conformance/include

