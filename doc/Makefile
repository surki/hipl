###############################################################################
#
# TODO:
# - xx
#
### VARIABLE DECLARATIONS  ####################################################

LATEX    = latex
DVIPS    = dvips
FIG2DEV  = fig2dev
BIBTEX   = bibtex
DVIPDF   = dvipdf
PDFLATEX = pdflatex
XMLTO    = xmlto
PERL     = perl

FIGS = fig/collaboration.fig fig/hooks.fig fig/kernel_model.fig \
       fig/input.fig fig/output.fig fig/base_exchange.fig \
       fig/stack_model.fig fig/mm-update.fig fig/bind_diagram.fig \
       fig/connect_diagram.fig fig/send_diagram.fig fig/recv_diagram.fig

BIBS                   = design_choices.bib
DESIGN_CHOICES_SOURCES = catalogue.tex design_choices_macros.tex hipl.tex
DESIGN_CHOICES         = design_choices
HOWTO                  = HOWTO
HOWTO_HTML_DIR         = howto-html

DOCDIR_PREFIX = /usr/share/doc
DOCDIR = $(DOCDIR_PREFIX)/hipl

### COMPILATION RULESETS ######################################################

%.dvi:	%.tex
	$(LATEX) $*
	$(BIBTEX) $(BIBS:.bib=)
	$(LATEX) $*
	$(LATEX) $*

%.pdf:	%.tex
	$(PDFLATEX) $*
	$(BIBTEX) $(BIBS:.bib=)
	$(PDFLATEX) $*
	$(PDFLATEX) $*

%.eps: %.fig
	$(FIG2DEV) -Leps $< $@

%.pdf: %.fig
	$(FIG2DEV) -L pdf $*.fig $*.pdf

%.ps:   %.dvi
	$(DVIPS) -o $*.ps $*.dvi

%.txt:   %.xml
	$(XMLTO) txt $<

%.html:  %.xml
	$(XMLTO) -o $(HOWTO_HTML_DIR) html $<
	#sed -i s/charset=ISO-8859-1/charset=UTF-8/ $(HOWTO_HTML_DIR)/*.html
	cp docshot-*.png $(HOWTO_HTML_DIR)
	cp base-exchange-*.png $(HOWTO_HTML_DIR)

### TARGETS ##################################################################

all:	$(HOWTO).txt $(HOWTO).html \
#	$(DESIGN_CHOICES).dvi $(DESIGN_CHOICES).ps $(DESIGN_CHOICES).pdf

$(DESIGN_CHOICES).dvi:	$(DESIGN_CHOICES).tex $(DESIGN_CHOICES_SOURCES) \
			$(FIGS:.fig=.eps)

$(DESIGN_CHOICES).pdf:	$(DESIGN_CHOICES).tex $(DESIGN_CHOICES_SOURCES) \
			$(FIGS:.fig=.pdf)

$(DESIGN_CHOICES).ps:	$(DESIGN_CHOICES).dvi

$(HOWTO).txt:	$(HOWTO).xml
$(HOWTO).html:	$(HOWTO).xml

clean:
	rm -f *~ *.aux *.log *.toc *.bbl *.blg *.ps *.dvi *.pdf *.out
	rm -f HOWTO.txt
	rm -f $(patsubst %.fig, %.eps, $(FIGS))
	rm -rf $(HOWTO_HTML_DIR)

install: all
	@echo
	@echo "** Copying documentation files to $(DOCDIR) **"
	@echo
	mkdir -p $(DOCDIR)
	cp $(HOWTO).txt $(DOCDIR)
	cp -a $(HOWTO_HTML_DIR) $(DOCDIR)
	#cp $(DESIGN_CHOICES).ps $(DESIGN_CHOICES).pdf $(DESIGN_CHOICES).dvi $(DOCDIR)

.phony: clean
