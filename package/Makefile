PACKAGE_NAME=libosdp-conformance

all:	${PACKAGE_NAME}.deb

package:	all

${PACKAGE_NAME}.deb:	${PACKAGE_NAME}
	dpkg-deb --build ${PACKAGE_NAME}

${PACKAGE_NAME}:	/tmp/contents.tgz my_version.txt ../opt/osdp-conformance/bin/open-osdp
	( cd ..; tar czvf /tmp/contents.tgz opt; )
	mkdir -p ${PACKAGE_NAME}/DEBIAN
	echo make sure control version matches `cat my_version.txt`
	cp package-control/control package-control/preinst package-control/postinst package-control/prerm   package-control/postrm  ${PACKAGE_NAME}/DEBIAN
	( cd ${PACKAGE_NAME}/DEBIAN; tar xvf /tmp/contents.tgz; cd ..)

${PACKAGE_NAME}-build:	package-control/control \
		../opt/osdp-conformance/bin/open-osdp

clean:
	rm -rf ${PACKAGE_NAME} ${PACKAGE_NAME}.deb ${PACKAGE_NAME}-build opt ${PACKAGE_NAME}-dist

