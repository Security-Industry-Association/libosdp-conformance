DOCUMENTS=osdpcap-format.pdf

all:	${DOCUMENTS}

clean:
	rm -f ${DOCUMENTS}

osdpcap-format.pdf:	doc-src/osdpcap-format.md
	pandoc --toc -o osdpcap-format.pdf doc-src/osdpcap-format.md

