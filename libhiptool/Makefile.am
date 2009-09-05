# $USAGI: Makefile.in,v 1.34 2003/06/21 04:17:42 yoshfuji Exp $
#
# Makefile.am for USAGI libinet6. Conversion from ".in" to ".am" by
# miika@iki.fi.
#
# Copyright (C) 2000-2001 USAGI/WIDE Project.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libhiptool.la

libhiptool_la_SOURCES = crypto.c pk.c nlink.c

if HIP_PFKEY
else
libhiptool_la_SOURCES += xfrmapi.c
endif

CFLAGS  = $(hipl_common_cflags) -DCONFIG_HIP_LIBHIPTOOL
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)

include_HEADERS =  crypto.h nlink.h pk.h xfrm.h xfrmapi.h

INCLUDES = $(hipl_common_include_paths) -I/usr/include/libipq/ -I$(HIPL_LIBINET6_INCLUDE)  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include

#include_HEADERS =

# INCLUDES += -I../libdht
# LDADD = ../libdht/.libs/libhipopendht.a


INCLUDES += -I../i3/i3_client -I../i3/utils -I../i3/i3

