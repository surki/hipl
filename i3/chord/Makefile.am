AUTOMAKE_OPTIONS = foreign

CFLAGS= $(hipl_common_cflags) $(HIPL_XMLI)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)
INCLUDES += -I$(HIPL_LIBHIPCORE_LIB)

# chord compilation
noinst_LIBRARIES = libchord.a
noinst_HEADERS = chord_api.h  chord.h  debug.h  eprintf.h

utils_SOURCES = ../utils/gen_utils.c
libchord_a_SOURCES = api.c  eprintf.c  hosts.c  pack.c  sendpkt.c \
		     chord.c  finger.c  join.c  process.c  stabilize.c \
		     util.c $(utils_SOURCES) 

# gen conf, test --- this should be pushed out to tools/check directory
noinst_PROGRAMS = gen_conf gen_conf_same test chord_getfingers chord_traceroute
APP_LDADD = libchord.a

gen_conf_SOURCES = gen_conf.c
gen_conf_LDADD = $(APP_LDADD)

gen_conf_same_SOURCES = gen_conf_same.c
gen_conf_same_LDADD = $(APP_LDADD)

test_SOURCES = test.c
test_LDADD = $(APP_LDADD)

chord_getfingers_SOURCES = chord_getfingers.c ${libchord_a_SOURCES}
chord_getfingers_LDADD = $(APP_LADD)

chord_traceroute_SOURCES = chord_traceroute.c ${libchord_a_SOURCES}
chord_traceroute_LDADD = $(APP_LADD)

CLEANFILES = core *.core *~
MAINTAINERCLEANFILES = Makefile.in
