PACKAGE_NAME=libosdp-conformance

all:
	@echo make arm64 x86_64

arm64:	${PACKAGE_NAME}-arm64.deb

${PACKAGE_NAME}-arm64.deb: makefile-package
	mkdir -p ${PACKAGE_NAME}/DEBIAN
	cp package-control/control-arm64 ${PACKAGE_NAME}/DEBIAN/control
	make -f makefile-package
	mkdir -p ${PACKAGE_NAME}-dist
	dpkg-deb --build ${PACKAGE_NAME} ${PACKAGE_NAME}-dist
	cp ${PACKAGE_NAME}-dist/*.deb .

clean:
	make -f makefile-package clean
	rm -rf ${PACKAGE_NAME} ${PACKAGE_NAME}-build ${PACKAGE_NAME}-dist ${PACKAGE_NAME}*.deb opt  

