AUTOMAKE_OPTIONS = foreign

if HAVE_PYTHON
hipfwmi_PYTHON = ConfigurationInterface.py ManagementLogic.py Rules.py \
                 FirewallController.py ManagementConsole.py
hipfwmidir = $(pyexecdir)/hipfwmi
endif

EXTRA_DIST = hipmi.fwlist report.bib test report.tex \
             hipmi.conf rulefile.ebnf

#PYTHON=/usr/bin/python2.3
#TRACER=/usr/lib/python2.3/trace.py -C test/cover -c -m -s \
#        --ignore-dir=/usr/lib/python2.3

all:
	true

doc:
	epydoc -o gendoc --html -n "Management Interface" $(MODULES)
	epydoc -o gendoc --pdf --private -n "Management Interface" $(MODULES)
	latex report.tex
	bibtex report
	latex report.tex
	latex report.tex
	dvips -o report.ps report.dvi

clean:
	find . -name "*.pyc" -print0 | xargs -r0 rm
	find . -name "*.cover" -print0 | xargs -r0 rm 
	rm -Rf gendoc/* test/cover/* *.aux *.bbl *.blg *.dvi *.ps *.log *.out *.toc

test:
	$(TRACER) test/test_all.py

