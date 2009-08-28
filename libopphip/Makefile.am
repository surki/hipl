AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libopphip.la

# Original sources
libopphip_la_SOURCES  = wrap.c wrap_db.c

include_HEADERS=wrap_db.h

# HIP additions to the flags.
INCLUDES = $(hipl_common_include_paths) -I$(top_srcdir)/libinet6/include  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include
CFLAGS = $(hipl_common_cflags) -pthread
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
