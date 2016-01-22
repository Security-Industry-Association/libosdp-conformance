# Make file for osdp-485

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
CFLAGS=-I /tester/current/include
LDFLAGS=-L /tester/current/lib

PROGS = open-osdp

all:	${PROGS}

clean:
	rm -f core *.o ${PROGS}

build:	all
	mkdir -p ../opt/open-osdp/bin
	cp ${PROGS} ../opt/open-osdp/bin

open-osdp:	open-osdp.o Makefile ../src-lib/libosdp.a
	${CC} ${LDFLAGS} -o open-osdp -g open-osdp.o \
	  -L ../src-lib -losdp \
	  -ljansson -lrt

open-osdp.o:	open-osdp.c
	${CC} ${CFLAGS} -c -g -I. -I../include -Wall -Werror \
	  open-osdp.c

../src-lib/libosdp.a:
	(cd ../src-lib; make build)

