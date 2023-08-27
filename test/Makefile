# Make file for test directory of libosdp-conformance

OSDP_HOME=opt/osdp-conformance
SHELL_SCRIPTS=conformance/100-cp-test conformance/150-cp-comset \
  conformance/200-pd-test

build-test:	${SHELL_SCRIPTS}
	mkdir -p ../${OSDP_HOME}/bin
	cp ${SHELL_SCRIPTS} ../${OSDP_HOME}/bin
	mkdir -p ../../${OSDP_HOME}/etc
	(cd osdpcap-tests; tar czvf osdpcap-samples.tgz *.osdpcap *.md; cp *tgz ../../${OSDP_HOME}/etc )

clean:
	rm -f osdpcap-tests/*.tgz

