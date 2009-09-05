AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libhipcore.la

# Original sources
libhipcore_la_SOURCES  = builder.c
libhipcore_la_SOURCES += hashtree.c
libhipcore_la_SOURCES += hipconf.c
libhipcore_la_SOURCES += certtools.c
libhipcore_la_SOURCES += linkedlist.c
libhipcore_la_SOURCES += debug.c
libhipcore_la_SOURCES += message.c
libhipcore_la_SOURCES += esp_prot_common.c
libhipcore_la_SOURCES += misc.c
libhipcore_la_SOURCES += hashchain.c
libhipcore_la_SOURCES += sqlitedbapi.c
libhipcore_la_SOURCES += hashchain_store.c
libhipcore_la_SOURCES += hip_statistics.c
libhipcore_la_SOURCES += getendpointinfo.c

if HIP_PRIVSEP
libhipcore_la_SOURCES += capability.c
endif

include_HEADERS = builder.h
include_HEADERS += certtools.h
include_HEADERS += common_defines.h
include_HEADERS += debug.h
include_HEADERS += esp_prot_common.h
include_HEADERS += hashchain.h
include_HEADERS += hashchain_store.h
include_HEADERS += hashtable.h
include_HEADERS += hashtree.h
include_HEADERS += hipconf.h
include_HEADERS += hip_statistics.h
include_HEADERS += icomm.h
include_HEADERS += ife.h
include_HEADERS += linkedlist.h
include_HEADERS += message.h
include_HEADERS += misc.h
include_HEADERS += protodefs.h
include_HEADERS += sqlitedbapi.h
include_HEADERS += state.h
include_HEADERS += utils.h
include_HEADERS += kerncompat.h
include_HEADERS += list.h

INCLUDES = $(hipl_common_include_paths) -I$(top_srcdir)/libinet6/include  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include
CFLAGS = $(hipl_common_cflags) -pthread
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
CFLAGS += -DHIPL_DEFAULT_PREFIX=\"$(prefix)\"
