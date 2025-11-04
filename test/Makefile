# Make file for test directory of libosdp-conformance

OSDP_HOME=opt/osdp-conformance
SAMPLE_FILES=filexfer/four filexfer/twothousand 

build-test:
	mkdir -p ../${OSDP_HOME}/bin
	mkdir -p ../${OSDP_HOME}/etc/sample-files
	cp ${SAMPLE_FILES} ../${OSDP_HOME}/etc/sample-files
	(cd osdpcap-tests; tar czvf osdpcap-samples.tgz *.osdpcap *.md; cp *tgz ../${OSDP_HOME}/etc )

clean:
	rm -f osdpcap-tests/*.tgz

