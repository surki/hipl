AUTOMAKE_OPTIONS = foreign

CFLAGS= $(hipl_common_cflags) $(HIPL_XMLI)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)
INCLUDES += -I$(HIPL_LIBHIPCORE_INCLUDE)

noinst_LIBRARIES = libaes.a
noinst_HEADERS = aescpp.h  aes.h  aesopt.h

libaes_a_SOURCES = aescrypp.c  aescrypt.c  aeshash.c  aeskey.c \
		     aeskeypp.c  aestab.c
# aesxam.c

CLEANFILES = core *.core *~
MAINTAINERCLEANFILES = Makefile.in
