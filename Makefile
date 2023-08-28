# libosdp-conformance package make

# This makes the RS-485 version.  To make the TLS version,
# you need to explicitly do "make osdp-tls"

#  (C)Copyright 2017-2022 Smithee Solutions LLC
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

all:	lib
	(cd include; make all; cd ..)
	(cd src-lib; make all; cd ..)
	(cd src-485; make all; cd ..)
	(cd src-ui; make all; cd ..)
	(cd src-tools; make all; cd ..)

lib:
	(cd src-lib; make all; cd ..)

osdp-tls:	build
	(cd src-tls; make all; cd ..)
	(cd src-tls; make build; cd ..)
	(cd src-ui; make build-tls; cd ..)

package:	osdp-tls
	(cd package; make package)
	echo ---
	echo *** to make the documentation do "make documentation" ***
	echo ---

documentation:
	(cd doc; make; cp *pdf ../opt/osdp-conformance/etc)

service:	osdp-tls
	(cd package; make service)

clean:
	(cd include; make clean; cd ..)
	(cd src-lib; make clean; cd ..)
	(cd src-485; make clean; cd ..)
	(cd src-tls; make clean; cd ..)
	(cd src-ui; make clean; cd ..)
	(cd src-tools; make clean; cd ..)
	(cd test; make clean; cd ..)
	(cd package; make clean)
	rm -f release-osdp-conformance.tgz *.deb
	rm -rf opt

build:	all
	mkdir -p opt/osdp-conformance/run/ACU
	(cd opt/osdp-conformance/run; rm -f CP; ln -s ACU CP)
	mkdir -p opt/osdp-conformance/run/MON
	mkdir -p opt/osdp-conformance/run/PD
	mkdir -p opt/osdp-conformance/tmp
	chmod 777 opt/osdp-conformance/tmp
	(cd include; make build; cd ..)
	(cd src-lib; make build; cd ..)
	(cd src-485; make build; cd ..)
	(cd src-ui; make build; cd ..)
	(cd src-tools; make build; cd ..)
	cp doc/config-examples/open-osdp-params-ACU.json \
	  opt/osdp-conformance/run/ACU/
	cp doc/config-examples/open-osdp-params-MON.json \
	  opt/osdp-conformance/run/MON/
	cp doc/config-examples/open-osdp-params-PD.json \
	  opt/osdp-conformance/run/PD/
	(cd test; make build-test; cd ..)
	(cd package; make)
	echo "/opt/osdp-conformance" >opt/osdp-conformance/run/ACU/my-root
	echo "/opt/osdp-conformance" >opt/osdp-conformance/run/PD/my-root
	echo "/opt/osdp-conformance" >opt/osdp-conformance/run/MON/my-root

