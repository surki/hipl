AUTOMAKE_OPTIONS = foreign

CFLAGS= $(hipl_common_cflags) $(HIPL_XMLI)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE) 

noinst_LIBRARIES = libi3client.a
noinst_HEADERS =  downhill_simplex.h coordinates.h i3_client_api.h \
                    i3_client_api_ctx.h i3_client_api_ext.h i3_client_callback.h \
                    i3_client_context.h i3_client_fd.h i3_client_fun.h i3_client.h \
                    i3_client_id.h i3_client_pkt.h i3_client_timer.h i3_client_trigger.h \
                    i3_client_params.h i3server_list.h ping.h http.h ping_thread.h qsort.h
                    
libi3client_a_SOURCES = downhill_simplex.c coordinates.c i3_client_api.c \
			i3_client_api_ctx.c i3_client_api_ext.c i3_client_callback.c \
                        i3_client_context.c i3_client_fd.c i3_client_id.c i3_client_pkt.c \
                        i3_client_timer.c i3_client_trigger.c i3server_list.c ping.c \
                        ping_thread.c http.c qsort.c 
                        
libi3client_a_LIBADD = ../i3/libi3.a ../utils/libutils.a ../aeshash/libaes.a

CLEANFILES = core *.core *~ *.rpo
MAINTAINERCLEANFILES = Makefile.in
