DOCUMENTS=osdpcap-format.pdf libosdp-conformance-settings.pdf

all:	${DOCUMENTS}

clean:
	rm -f ${DOCUMENTS}

build:	all
	mkdir -p ../opt/osdp-conformance/etc
	cp ${DOCUMENTS} ../opt/osdp-conformance/etc

libosdp-conformance-settings.pdf:	doc-src/libosdp-conformance-settings.md
	pandoc --toc -o libosdp-conformance-settings.pdf doc-src/libosdp-conformance-settings.md

osdpcap-format.pdf:	doc-src/osdpcap-format.md
	pandoc --toc -o osdpcap-format.pdf doc-src/osdpcap-format.md

