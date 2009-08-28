AUTOMAKE_OPTIONS = foreign

CFLAGS= $(hipl_common_cflags) $(HIPL_XMLI) -DHIP_UNITTEST_MODE -L$(HIPL_LIBHIPCORE_LIB) $(OPENWRT)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBHIPCORE_INCLUDE)  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include

include_HEADERS = libhipopendht.h libhipopendhtxml.h
LDFLAGS= @LDFLAGS@ $(OPENWRT) -lcrypto $(HIP_XMLL) 

LDADD  = ../libhipcore/.libs/libhipcore.a
if HIP_FORCE_SHLIB
  LDADD += -lhiptool
else
  LDADD += ../libhiptool/.libs/libhiptool.a
endif

lib_LTLIBRARIES = libhipopendht.la

libhipopendht_la_SOURCES = libhipopendht.c libhipopendhtxml.c

