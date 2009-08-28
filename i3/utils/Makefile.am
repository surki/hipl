AUTOMAKE_OPTIONS = foreign

CFLAGS= $(hipl_common_cflags) $(HIPL_XMLI)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
AM_INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

noinst_LIBRARIES = libutils.a
noinst_HEADERS =    byteorder.h  \
                    eprintf.h  \
                    gen_utils.h  \
                    inetfns.h  \
                    utils.h \
                    event.h \
		    netwrap.h

libutils_a_SOURCES = byteorder.c  eprintf.c  gen_utils.c  inetfns.c event.c netwrap_posix.c

#EXTRA_DIST = .cvsignore
CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
