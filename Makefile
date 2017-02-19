# libosdp-conformance top level make file

# This makes the RS-485 version.  To make the TLS version,
# you need to explicitly do "make osdp-tls"

# Makefile for libosdp

all:
	(cd src-lib; make all; cd ..)
	(cd src-485; make all; cd ..)
	(cd src-ui; make all; cd ..)

osdp-tls:	all
	(cd src-tls; make all; cd ..)
	(cd src-tls; make build; cd ..)
	(cd src-ui; make build-tls; cd ..)

clean:
	(cd src-lib; make clean; cd ..)
	(cd src-485; make clean; cd ..)
	(cd src-tls; make clean; cd ..)
	(cd src-ui; make clean; cd ..)
	rm -f release-libosdp.tgz
	rm -rf opt

build:	all
	(cd src-lib; make build; cd ..)
	(cd src-485; make build; cd ..)
	(cd src-ui; make build; cd ..)
	cp doc/config-samples/open-osdp-params-MON.json \
	  opt/open-osdp/run/MON/open-osdp-params.json
	(cd test; make build-test; cd ..)

release:	build
	tar czvf release-libosdp.tgz opt/*

