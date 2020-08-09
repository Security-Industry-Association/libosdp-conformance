# Makefile for libosdp-conformance - include directory

FILES=open-osdp.h oo-api.h iec-nak.h

all:
	echo using ${FILES}

clean:
	rm -f ../opt/osdp-conformance/include

build:	${FILES}
	mkdir -p ../opt/osdp-conformance/include
	cp ${FILES} ../opt/osdp-conformance/include

