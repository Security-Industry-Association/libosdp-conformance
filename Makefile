# libosdp-conformance top level make file

# This makes the RS-485 version.  To make the TLS version,
# you need to explicitly do "make osdp-tls"

#  (C)Copyright 2015-2017 Smithee,Spelvin,Agnew & Plinge, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Support provided by the Security Industry Association
#  http://www.securityindustry.org

all:
	(cd src-lib; make all; cd ..)
	(cd src-485; make all; cd ..)
	(cd src-ui; make all; cd ..)

osdp-tls:	release
	(cd src-tls; make all; cd ..)
	(cd src-tls; make build; cd ..)
	(cd src-ui; make build-tls; cd ..)
	rm -f release-osdp-conformance.tgz
	tar czvf release-osdp-conformance.tgz opt/*

clean:
	(cd src-lib; make clean; cd ..)
	(cd src-485; make clean; cd ..)
	(cd src-tls; make clean; cd ..)
	(cd src-ui; make clean; cd ..)
	rm -f release-osdp-conformance.tgz
	rm -rf opt

build:	all
	mkdir -p opt/osdp-conformance/run/CP
	mkdir -p opt/osdp-conformance/run/MON
	mkdir -p opt/osdp-conformance/run/PD
	mkdir -p opt/osdp-conformance/tmp
	chmod 777 opt/osdp-conformance/tmp
	(cd src-lib; make build; cd ..)
	(cd src-485; make build; cd ..)
	(cd src-ui; make build; cd ..)
	cp doc/config-samples/open-osdp-params-CP.json \
	  opt/osdp-conformance/run/CP/
	cp doc/config-samples/open-osdp-params-MON.json \
	  opt/osdp-conformance/run/MON/
	cp doc/config-samples/open-osdp-params-PD.json \
	  opt/osdp-conformance/run/PD/
	(cd test; make build-test; cd ..)

release:	build
	tar czvf release-osdp-conformance.tgz opt/*

