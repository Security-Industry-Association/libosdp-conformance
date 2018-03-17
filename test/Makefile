# Make file for test directory of libosdp-conformance

SHELL_SCRIPTS=conformance/100-cp-test conformance/150-cp-comset \
  conformance/200-pd-test

build-test:	${SHELL_SCRIPTS}
	mkdir -p ../opt/osdp-conformance/bin
	cp ${SHELL_SCRIPTS} ../opt/osdp-conformance/bin

