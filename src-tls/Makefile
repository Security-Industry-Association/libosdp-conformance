# Make file for osdp-tls

#  (C)Copyright 2014-2015 Smithee,Spelvin,Agnew & Plinge, Inc.

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


CC=clang

PROGS = osdp-net-client osdp-net-server

all:	${PROGS}

clean:
	rm -f core *.o ${PROGS}

osdp-net-client:	osdp-net-client.o \
	  osdp-api.o \
	  Makefile
	${CC} -o osdp-net-client -g osdp-net-client.o \
	  osdp-api.o \
	  -L ../src-lib -losdp \
	  -L /tester/current/lib -lgnutls -lexpat -ljansson

osdp-net-server:	osdp-net-server.o \
	  osdp-api.o \
	  ../src-lib/libosdp.a Makefile
	${CC} -o osdp-net-server -g osdp-net-server.o \
	  osdp-api.o \
	  -L ../src-lib -losdp \
	  -L /tester/current/lib -lgnutls -lexpat -ljansson

oo_util.o:	oo_util.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oo_util.c

osdp-api.o:	osdp-api.c ../include/osdp-tls.h ../include/open-osdp.h
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  osdp-api.c

osdp-net-client.o:	osdp-net-client.c \
	  ../include/osdp_conformance.h ../include/osdp-tls.h \
	  ../include/open-osdp.h
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  osdp-net-client.c

osdp-net-server.o:	osdp-net-server.c \
	  ../include/osdp_conformance.h ../include/osdp-tls.h \
	  ../include/open-osdp.h
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  osdp-net-server.c

../src-lib/libosdp.a:
	(cd ../src-lib; make build)

