PACKAGE_NAME=libosdp-conformance

all:	makefile-package
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
	make -f service-package clean
	rm -rf ${PACKAGE_NAME} ${PACKAGE_NAME}-build ${PACKAGE_NAME}-dist ${PACKAGE_NAME}*.deb opt  get-arch
	rm -rf osdp-service osdp-service-dist osdp-service*.deb opt  get-arch

package:	build
	cp *.deb ..

service:	package
	mkdir -p osdp-service/DEBIAN
	cp service-pkgctl/control-`./get-arch` osdp-service/DEBIAN/control
	make -f service-package
	mkdir -p osdp-service-dist
	dpkg-deb --build osdp-service osdp-service-dist
	cp osdp-service-dist/*.deb .
	cp *.deb ..

#amd64:	${PACKAGE_NAME}-amd64.deb

zz${PACKAGE_NAME}-armhf.deb: makefile-package
	mkdir -p ${PACKAGE_NAME}/DEBIAN
	cp package-control/control-armhf ${PACKAGE_NAME}/DEBIAN/control
	make -f makefile-package
	mkdir -p ${PACKAGE_NAME}-dist
	dpkg-deb --build ${PACKAGE_NAME} ${PACKAGE_NAME}-dist
	cp ${PACKAGE_NAME}-dist/*.deb .

