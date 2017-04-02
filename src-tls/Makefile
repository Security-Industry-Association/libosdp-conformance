# Make file for osdp-tls

#  (C)Copyright 2014-2017 Smithee,Spelvin,Agnew & Plinge, Inc.

#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
 
#    http://www.apache.org/licenses/LICENSE-2.0
 
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

#  Support provided by the Security Industry Association
#  http://www.securityindustry.org


# built with gcc.  note it also builds with clang.

CC=gcc
#CC=clang
CFLAGS=-I /tester/current/include
LDFLAGS=-L /tester/current/lib


PROGS = osdp-net-client osdp-net-server initiator \
  osdp-tcp-client osdp-tcp-server

all:	${PROGS}

clean:
	rm -f core *.o ${PROGS}

build:	all
	mkdir -p ../opt/osdp-conformance/bin
	cp ${PROGS} ../opt/osdp-conformance/bin

initiator:	initiator.o Makefile
	${CC} ${LDFLAGS} -o initiator -g initiator.o 

osdp-net-client:	osdp-net-client.o \
	  ../src-lib/libosdp.a Makefile
	${CC} ${LDFLAGS} -o osdp-net-client -g osdp-net-client.o \
	  -L ../src-lib -losdp \
	  -lgnutls -ljansson -lrt

osdp-net-server:	osdp-net-server.o \
	  ../src-lib/libosdp.a Makefile
	${CC} ${LDFLAGS} -o osdp-net-server -g osdp-net-server.o \
	  -L ../src-lib -losdp \
	  -lgnutls -ljansson -lrt

initiator.o:	initiator.c
	${CC} ${CFLAGS} -c -g -Wall -Werror \
	  initiator.c

osdp-net-client.o:	osdp-net-client.c \
	  ../include/osdp_conformance.h ../include/osdp-tls.h \
	  ../include/open-osdp.h
	${CC} ${CFLAGS} -c -g -I. -I../include -Wall -Werror \
	  osdp-net-client.c

osdp-net-server.o:	osdp-net-server.c \
	  ../include/osdp_conformance.h ../include/osdp-tls.h \
	  ../include/open-osdp.h
	${CC} ${CFLAGS} -c -g -I. -I../include -Wall -Werror \
	  osdp-net-server.c

osdp-tcp-client:	osdp-tcp-client.o \
	  ../src-lib/libosdp.a Makefile
	${CC} ${LDFLAGS} -o osdp-tcp-client -g osdp-tcp-client.o \
	  -L ../src-lib -losdp \
	  -ljansson -lrt

osdp-tcp-client.o:	osdp-tcp-client.c \
	  ../include/osdp_conformance.h ../include/osdp-tls.h \
	  ../include/open-osdp.h
	${CC} ${CFLAGS} -c -g -I. -I../include -Wall -Werror \
	  osdp-tcp-client.c

osdp-tcp-server:	osdp-tcp-server.o \
	  ../src-lib/libosdp.a Makefile
	${CC} ${LDFLAGS} -o osdp-tcp-server -g osdp-tcp-server.o \
	  -L ../src-lib -losdp \
	  -ljansson -lrt

osdp-tcp-server.o:	osdp-tcp-server.c \
	  ../include/osdp_conformance.h ../include/osdp-tls.h \
	  ../include/open-osdp.h
	${CC} ${CFLAGS} -c -g -I. -I../include -Wall -Werror \
	  osdp-tcp-server.c

../src-lib/libosdp.a:
	(cd ../src-lib; make build)

