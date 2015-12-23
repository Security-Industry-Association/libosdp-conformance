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

CGIPROGS = send-osdp-command
PAGES = open-osdp-CP.html
SCRIPTS = HUP-CP STOP-CP set-cp-pid write_osdp_command

all:	${CGIPROGS} ${PAGES} ${SCRIPTS}

clean:
	rm -f core *.o ${CGIPROGS}
	rm -rf ../opt/open-osdp

build:	all
	mkdir -p ../opt/open-osdp/bin
	mkdir -p ../opt/open-osdp/cgi-bin
	mkdir -p ../opt/open-osdp/www
	cp ${PAGES} ../opt/open-osdp/www
	cp ${CGIPROGS} ../opt/open-osdp/cgi-bin
	cp ${SCRIPTS} ../opt/open-osdp/bin

send-osdp-command:	send-osdp-command.o Makefile
	${CC} -o send-osdp-command -g send-osdp-command.o

send-osdp-command.o:	send-osdp-command.c
	${CC} -c -g -I../include -I/tester/current/include -Wall -Werror \
	  send-osdp-command.c

