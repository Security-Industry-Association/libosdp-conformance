PACKAGE_NAME=libosdp-conformance

all:	makefile-package
	@echo make amd64 arm64 armhf
	echo `dpkg-architecture | grep DEB_TARGET_ARCH=` printenv DEB_TARGET_ARCH >get-arch
	chmod +x get-arch
	echo architecture is `./get-arch`
	mkdir -p ${PACKAGE_NAME}/DEBIAN
	cp package-control/control-`./get-arch` ${PACKAGE_NAME}/DEBIAN/control
	make -f makefile-package
	mkdir -p ${PACKAGE_NAME}-dist
	dpkg-deb --build ${PACKAGE_NAME} ${PACKAGE_NAME}-dist
	cp ${PACKAGE_NAME}-dist/*.deb .

build:	all

clean:
	make -f makefile-package clean
	rm -rf ${PACKAGE_NAME} ${PACKAGE_NAME}-build ${PACKAGE_NAME}-dist ${PACKAGE_NAME}*.deb opt  get-arch

package:	build
	mv *.deb ..

amd64:	${PACKAGE_NAME}-amd64.deb

arm64:	${PACKAGE_NAME}-arm64.deb

armhf:	${PACKAGE_NAME}-armhf.deb

${PACKAGE_NAME}-amd64.deb: makefile-package
	mkdir -p ${PACKAGE_NAME}/DEBIAN
	cp package-control/control-amd64 ${PACKAGE_NAME}/DEBIAN/control
	make -f makefile-package
	mkdir -p ${PACKAGE_NAME}-dist
	dpkg-deb --build ${PACKAGE_NAME} ${PACKAGE_NAME}-dist
	cp ${PACKAGE_NAME}-dist/*.deb .

${PACKAGE_NAME}-arm64.deb: makefile-package
	mkdir -p ${PACKAGE_NAME}/DEBIAN
	cp package-control/control-arm64 ${PACKAGE_NAME}/DEBIAN/control
	make -f makefile-package
	mkdir -p ${PACKAGE_NAME}-dist
	dpkg-deb --build ${PACKAGE_NAME} ${PACKAGE_NAME}-dist
	cp ${PACKAGE_NAME}-dist/*.deb .

${PACKAGE_NAME}-armhf.deb: makefile-package
	mkdir -p ${PACKAGE_NAME}/DEBIAN
	cp package-control/control-armhf ${PACKAGE_NAME}/DEBIAN/control
	make -f makefile-package
	mkdir -p ${PACKAGE_NAME}-dist
	dpkg-deb --build ${PACKAGE_NAME} ${PACKAGE_NAME}-dist
	cp ${PACKAGE_NAME}-dist/*.deb .

