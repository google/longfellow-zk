MMARK := mmark

all: libzk.md
	$(MMARK) libzk.md  > libzk.xml
	xml2rfc --text --v3 libzk.xml
	xml2rfc --html --v3 libzk.xml

.PHONY: clean
clean:
	rm -f *.txt *.xml *.html *.pdf
