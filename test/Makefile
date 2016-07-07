# Make file for test directory of libosdp

CP_SHELL_SCRIPTS=cp-tests/102-led

build-test:	${CP_SHELL_SCRIPTS}
	mkdir -p ../opt/open-osdp/bin
	cp ${CP_SHELL_SCRIPTS} ../opt/open-osdp/bin

cp-tests/102-led:
	(cd cp-tests; make build-test)

