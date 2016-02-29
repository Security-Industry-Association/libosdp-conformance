# Make file for osdp-ui

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

CGIPROGS = open-osdp-CP-status open-osdp-PD-status send-osdp-command \
  start-CP-tcp-client
PROGS = open-osdp-kick
PAGES = open-osdp-control.html open-osdp-CP.html open-osdp-PD.html
SCRIPTS = exec-CPtcpclient HUP-CP HUP-PD \
  STOP-CP STOP-PD \
  set-pid \
  write-osdp-CP-command write-osdp-PD-command

all:	${CGIPROGS} ${PAGES} ${SCRIPTS} ${PROGS}

clean:
	rm -f core *.o ${CGIPROGS} ${PROGS}
	rm -rf ../opt/open-osdp

build:	all
	mkdir -p ../opt/open-osdp/bin
	mkdir -p ../opt/open-osdp/cgi-bin
	mkdir -p ../opt/open-osdp/www
	mkdir -p ../opt/open-osdp/run/CP
	mkdir -p ../opt/open-osdp/run/PD
	cp ${PAGES} ../opt/open-osdp/www
	cp ${CGIPROGS} ../opt/open-osdp/cgi-bin
	cp ${SCRIPTS} ../opt/open-osdp/bin
	cp ${PROGS} ../opt/open-osdp/bin

open-osdp-CP-status:	open-osdp-CP-status.o Makefile
	${CC} -o open-osdp-CP-status -g open-osdp-CP-status.o -lrt

open-osdp-PD-status:	open-osdp-PD-status.o Makefile
	${CC} -o open-osdp-PD-status -g open-osdp-PD-status.o -lrt

send-osdp-command:	send-osdp-command.o Makefile
	${CC} -o send-osdp-command -g send-osdp-command.o

start-CP-tcp-client:	start-CP-tcp-client.sh
	cp start-CP-tcp-client.sh start-CP-tcp-client

open-osdp-kick:	open-osdp-kick.o Makefile
	${CC} -o open-osdp-kick -g open-osdp-kick.o

open-osdp-kick.o:	open-osdp-kick.c
	${CC} -c -g -I../include -I/tester/current/include -Wall -Werror \
	  open-osdp-kick.c

open-osdp-CP-status.o:	open-osdp-CP-status.c
	${CC} -c -g -I../include -I/tester/current/include -Wall -Werror \
	  open-osdp-CP-status.c

open-osdp-PD-status.o:	open-osdp-PD-status.c
	${CC} -c -g -I../include -I/tester/current/include -Wall -Werror \
	  open-osdp-PD-status.c

send-osdp-command.o:	send-osdp-command.c
	${CC} -c -g -I../include -I/tester/current/include -Wall -Werror \
	  send-osdp-command.c

