# Make file for libosdp

#  (C)Copyright 2015 Smithee,Spelvin,Agnew & Plinge, Inc.

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


all:	libosdp.a

build:	all

clean:
	rm -f core *.o libosdp.a

libosdp.a:	oo_initialize.o oo_process.o oo_util.o oo_util2.o \
	  oo_cmdbreech.o oosdp_actions.o oosdp_crc.o oosdp_logmsg.o \
	  oosdp_secure.o oosdp_ui.o
	ar r libosdp.a \
	  oo_cmdbreech.o oo_initialize.o oo_process.o oo_util.o oo_util2.o \
	  oosdp_actions.o oosdp_crc.o oosdp_logmsg.o oosdp_secure.o oosdp_ui.o

oo_cmdbreech.o:	oo_cmdbreech.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oo_cmdbreech.c

oo_initialize.o:	oo_initialize.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oo_initialize.c

oo_process.o:	oo_process.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oo_process.c

oo_util.o:	oo_util.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oo_util.c

oo_util2.o:	oo_util2.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oo_util2.c

oosdp_actions.o:	oosdp_actions.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oosdp_actions.c

oosdp_crc.o:	oosdp_crc.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oosdp_crc.c

oosdp_logmsg.o:	oosdp_logmsg.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oosdp_logmsg.c

oosdp_secure.o:	oosdp_secure.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oosdp_secure.c

oosdp_ui.o:	oosdp_ui.c
	${CC} -c -g -I../include -I /tester/current/include -Wall -Werror \
	  oosdp_ui.c

