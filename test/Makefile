# Make file for test directory of libosdp

CP_SHELL_SCRIPTS=cp-tests/102-led

build-test:	${CP_SHELL_SCRIPTS}
	mkdir -p ../opt/osdp-conformance/bin
	cp ${CP_SHELL_SCRIPTS} ../opt/osdp-conformance/bin

cp-tests/102-led:
	(cd cp-tests; make build-test)

