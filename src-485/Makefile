# Make file for osdp-485

#  (C)Copyright 2017-2022 Smithee Solutions LLC

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
CFLAGS=-DOSDP_CONFORMANCE -I /tester/current/include
LDFLAGS=/opt/osdp-conformance/lib/aes.o -L /tester/current/lib

PROGS = open-osdp
OSDPLIB = osdp-conformance

all:	${PROGS}

clean:
	rm -f core *.o ${PROGS}

build:	all
	mkdir -p ../opt/osdp-conformance/log
	mkdir -p ../opt/osdp-conformance/bin
	cp ${PROGS} ../opt/osdp-conformance/bin

open-osdp:	open-osdp.o Makefile ../src-lib/libosdp.a
	${CC} ${LDFLAGS} -o open-osdp -g open-osdp.o \
	  -L ../src-lib -l${OSDPLIB} \
	  -ljansson -lrt

open-osdp.o:	open-osdp.c
	${CC} ${CFLAGS} -c -g -I. -I../include -Wall -Werror \
	  open-osdp.c

../src-lib/libosdp.a:
	(cd ../src-lib; make build)

