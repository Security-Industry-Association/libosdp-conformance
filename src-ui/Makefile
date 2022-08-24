# Make file for osdp-ui

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

# built with gcc.  note it also builds with clang.

CFLAGS=-c -DOSDP_CONFORMANCE -g -I../include -Wall -Werror
CC=gcc
LINK=${CC}
LDFLAGS=-g -L /opt/tester/lib -ljansson

CGIPROGS = \
  ACU-status open-osdp-ACU-status open-osdp-PD-status send-osdp-command \
  start-CP-485 start-PD-485 start-MON-485 \
  tail-CP-log tail-CP-stderr tail-MON-log tail-PD-log \
  shutdown-osdp vm-status
CGISCRIPTS = conformance-report \
  do-acurxsize do-biomatch do-bioread do-buzz do-comset do-confirm do-keep-active\
  do-get-piv-cak-cert do-init-secure do-keypad do-led do-send-explicit do-text \
  do-transfer do-verb-cp do-verb-pd
TLS_CGIPROGS = start-CP-net-client start-CP-tcp-client \
  start-PD-net-server start-PD-tcp-server
EXTRA = osdp.conf service/osdp.service service/install-osdp-service www-data

PROGS = open-osdp-kick osdp-config-print
TLS_PROGS = 

PAGES = open-osdp-control.html open-osdp-CP.html open-osdp-PD.html \
  open-osdp-MON.html osdp-conformance-CP.html osdp-conformance-PD.html \
  index-conformance.html \
  Test-ACU.html Test-ACU-Status.html Test-PD.html
CSS = picnic.min.css
TLS_PAGES = 

SCRIPTS = clean-run do-ACU-command do-CP-command do-PD-command \
  do-send-explicit exec-CP485 exec-PD485 \
  HUP-ACU HUP-CP HUP-MON HUP-PD \
  STOP-CP STOP-MON STOP-PD \
  set-pid \
  write-osdp-ACU-command write-osdp-PD-command \
  3-identify run-address-scan write-params
TLS_SCRIPTS = exec-CPnetclient exec-CPtcpclient exec-PDnetserver exec-PDtcpserver

all:	${CGIPROGS} ${PAGES} ${CSS} ${SCRIPTS} ${PROGS} ${EXTRA}

clean:
	rm -f core *.o ${CGIPROGS} ${PROGS}
	rm -f core *.o ${TLS_CGIPROGS} ${TLS_PROGS}
	rm -rf ../opt/osdp-conformance

build:	all
	mkdir -p ../opt/osdp-conformance/bin
	mkdir -p ../opt/osdp-conformance/cgi-bin
	mkdir -p ../opt/osdp-conformance/etc
	mkdir -p ../opt/osdp-conformance/www
	mkdir -p ../opt/osdp-conformance/www/css
	mkdir -p ../opt/osdp-conformance/run/ACU
	mkdir -p ../opt/osdp-conformance/run/MON
	mkdir -p ../opt/osdp-conformance/run/PD
	cp ${PAGES} ../opt/osdp-conformance/www
	cp ${CSS} ../opt/osdp-conformance/www/css
	cp ${CGIPROGS} ../opt/osdp-conformance/cgi-bin
	cp ${CGISCRIPTS} ../opt/osdp-conformance/cgi-bin
	(cd ../opt/osdp-conformance/bin; rm -f write-osdp-CP-command; ln -s write-osdp-ACU-command write-osdp-CP-command )
	cp ${SCRIPTS} ../opt/osdp-conformance/bin
	cp ${PROGS} ../opt/osdp-conformance/bin
	cp osdp.conf www-data ../opt/osdp-conformance/etc
	cp service/osdp.service ../opt/osdp-conformance/etc
	cp service/install-osdp-service ../opt/osdp-conformance/bin

build-tls:	${TLS_CGIPROGS} ${TLS_PAGES} ${TLS_SCRIPTS} ${TLS_PROGS} build
	# (no TLS pages) cp ${TLS_PAGES} ../opt/osdp-conformance/www
	cp ${TLS_CGIPROGS} ../opt/osdp-conformance/cgi-bin
	cp ${TLS_SCRIPTS} ../opt/osdp-conformance/bin
	# (no TLS programs) cp ${TLS_PROGS} ../opt/osdp-conformance/bin

build-test:	build
	(cd ../test; make build-test)

osdp-config-print:	osdp-config-print.o Makefile
	${LINK} -o osdp-config-print osdp-config-print.o ${LDFLAGS}

osdp-config-print.o:	osdp-config-print.c ${INCLUDES}
	${CC} ${CFLAGS} osdp-config-print.c

ACU-status:	open-osdp-CP-status.o Makefile
	${LINK} -o ACU-status -g open-osdp-CP-status.o -lrt

open-osdp-ACU-status:	open-osdp-ACU-status.o Makefile
	${LINK} ${LDFLAGS} -o open-osdp-ACU-status open-osdp-ACU-status.o \
	  -ljansson -lrt

open-osdp-PD-status:	open-osdp-PD-status.o Makefile
	${LINK} ${LDFLAGS} -o open-osdp-PD-status open-osdp-PD-status.o \
	  -ljansson -lrt

send-osdp-command:	send-osdp-command.o Makefile
	${LINK} -o send-osdp-command -g send-osdp-command.o

start-CP-tcp-client:	start-CP-tcp-client.sh
	cp start-CP-tcp-client.sh start-CP-tcp-client

start-PD-net-server:	start-PD-net-server.sh
	cp start-PD-net-server.sh start-PD-net-server

start-PD-tcp-server:	start-PD-tcp-server.sh
	cp start-PD-tcp-server.sh start-PD-tcp-server

start-CP-485:	start-CP-485.sh
	cp start-CP-485.sh start-CP-485

start-PD-485:	start-PD-485.sh
	cp start-PD-485.sh start-PD-485

open-osdp-kick:	open-osdp-kick.o Makefile
	${LINK} -o open-osdp-kick open-osdp-kick.o ${LDFLAGS}

open-osdp-kick.o:	open-osdp-kick.c
	${CC} ${CFLAGS}  -c -g -I../include -I/tester/current/include -Wall -Werror \
	  open-osdp-kick.c

open-osdp-CP-status.o:	open-osdp-CP-status.c
	${CC} -c -g -I../include -I/tester/current/include -Wall -Werror \
	  open-osdp-CP-status.c

open-osdp-ACU-status.o:	open-osdp-ACU-status.c
	${CC} -c -g -I../include -I/tester/current/include -Wall -Werror \
	  open-osdp-ACU-status.c

open-osdp-PD-status.o:	open-osdp-PD-status.c
	${CC} -c -g -I../include -I/tester/current/include -Wall -Werror \
	  open-osdp-PD-status.c

send-osdp-command.o:	send-osdp-command.c ../include/oo-api.h
	${CC} ${CFLAGS} -c -g -I../include -I/tester/current/include -Wall -Werror \
	  send-osdp-command.c

tail-CP-log:	tail-CP-log.sh
	cp tail-CP-log.sh tail-CP-log

tail-CP-stderr:	tail-CP-stderr.sh
	cp tail-CP-stderr.sh tail-CP-stderr

start-MON-485:	start-MON-485.sh
	cp start-MON-485.sh start-MON-485

tail-MON-log:	tail-MON-log.sh
	cp tail-MON-log.sh tail-MON-log

tail-PD-log:	tail-PD-log.sh
	cp tail-PD-log.sh tail-PD-log

shutdown-osdp:	shutdown-osdp.sh
	cp shutdown-osdp.sh shutdown-osdp

vm-status:	vm-status.sh
	cp vm-status.sh vm-status

