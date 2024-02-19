DOCUMENTS=osdpcap-format.pdf \
  libosdp-conformance-commands.pdf \
  libosdp-conformance-OSDP-programming.pdf \
  libosdp-conformance-settings.pdf

all:	${DOCUMENTS}

clean:
	rm -f ${DOCUMENTS}

build:	all
	echo RUNNING BUILD RULE
	echo RUNNING BUILD RULE
	echo RUNNING BUILD RULE
	echo RUNNING BUILD RULE
	echo RUNNING BUILD RULE
	echo RUNNING BUILD RULE
	mkdir -p ../opt/osdp-conformance/etc
	cp ${DOCUMENTS} ../opt/osdp-conformance/etc

libosdp-conformance-commands.pdf:	doc-src/libosdp-conformance-commands.md
	pandoc --toc -o libosdp-conformance-commands.pdf doc-src/libosdp-conformance-commands.md

libosdp-conformance-OSDP-programming.pdf:	doc-src/libosdp-conformance-OSDP-programming.md
	pandoc --toc -o libosdp-conformance-OSDP-programming.pdf doc-src/libosdp-conformance-OSDP-programming.md

libosdp-conformance-settings.pdf:	doc-src/libosdp-conformance-settings.md
	pandoc --toc -o libosdp-conformance-settings.pdf doc-src/libosdp-conformance-settings.md

osdpcap-format.pdf:	doc-src/osdpcap-format.md
	pandoc --toc -o osdpcap-format.pdf doc-src/osdpcap-format.md

