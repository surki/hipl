AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = $(hipl_common_cflags)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)

GTKLDADD   = `pkg-config gtk+-2.0 --libs`
GTHREADLDADD  = `pkg-config --cflags --libs gthread-2.0`
GOBJECTLDADD  = `pkg-config --cflags --libs gobject-2.0`

#include_HEADERS = agent.h connhipd.h hit_db.h lang_finnish.h str_var.h x.h
#include_HEADERS += agent_tools.h  gui_interface.h  lang_english.h  language.h

include_HEADERS = agent.h     gui_interface.h  lang_english.h  language.h  tools.h \
connhipd.h  hitdb.h          lang_finnish.h  str_var.h   x.h


INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBHIPGUI) -I$(HIPL_LIBINET6_INCLUDE)  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include

if HIP_AGENT

sbin_PROGRAMS = hipagent
hipagent_SOURCES = agent.c tools.c connhipd.c hitdb.c gui_interface.c str_var.c language.c

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
# Somewhy @GTK_LIBS@ must be includec here, not enough that its in libhipgui
# Makefile.am... Fix someday?
#hipagent_LDADD += ../libhiptool/.libs/libhiptool.a @GTK_LIBS@

hipagent_LDADD = ../libhipgui/libhipgui.a ../libinet6/.libs/libinet6.a
if HIP_FORCE_SHLIB
  hipagent_LDADD += -lhiptool
else
  hipagent_LDADD += ../libhiptool/.libs/libhiptool.a
endif

hipagent_LDADD += ../libdht/.libs/libhipopendht.a

hipagent_LDFLAGS = -lcrypto -lpthread $(GTKLDADD) $(GTHREADLDADD) $(GOBJECTLDADD)

CFLAGS += -lsqlite3

endif

# This is needed when getting a fresh checkout and "./autogen.sh && ./configure && make install"
# (i.e. the intermediate "make (all)" is missing. Fixes also rpm compilation. -miika
../libhipgui/libhipgui.a:
	make -C ../libhipgui

tags:
	etags $(hipagent_SOURCES) $(include_HEADERS)

