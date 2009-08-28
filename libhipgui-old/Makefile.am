## Makefile.am for HIP GUI
AUTOMAKE_OPTIONS = foreign

#GTKCFLAGS  = `pkg-config gtk+-2.0 --cflags`
#GTKLDADD   = `pkg-config gtk+-2.0 --libs`
#GTHREADLDADD  = `pkg-config --cflags --libs gthread-2.0`
#GOBJECTLDADD  = `pkg-config --cflags --libs gobject-2.0`

include_HEADERS = create.h  events.h  exec.h  hipstart.h  main.h  manage.h  nh.h  rhit_dnd.h  terminal.h  tools.h  tw.h  widgets.h  x.h

CFLAGS = $(hipl_common_cflags)

if HIP_AGENT

libhipgui_adir = $(pkgdatadir)/libhipgui

noinst_LIBRARIES = libhipgui.a

libhipgui_a_SOURCES = main.c events.c manage.c widgets.c exec.c tools.c terminal.c tw_create.c tw_manage.c main_create.c nh_create.c create.c nh_manage.c terminal_server.c terminal_client.c rhit_dnd.c
#libhipgui_a_DATA = logo.png

libhipgui_a_CFLAGS = $(CFLAGS) -DHIP_GUI_DATADIR=\"$(pkgdatadir)/libhipgui\"
LIBADD = @GTK_LIBS@
#libhipgui_a_CFLAGS = $(CFLAGS) -DHIP_GUI_DATADIR=\"$(pkgdatadir)/libhipgui\"

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE) -I$(HIPL_AGENT) @GTK_CFLAGS@

endif

tags:
	etags $(libhipgui_a_SOURCES) $(include_HEADERS)

