# $USAGI: Makefile.in,v 1.10 2001/02/11 08:07:35 yoshfuji Exp $

# Copyright (C) 2001 USAGI/WIDE Project.
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

LN_S = @LN_S@
INSTALL = @INSTALL@
INSTALL_PROGRAM = @INSTALL_PROGRAM@
INSTALL_SCRIPT = @INSTALL_SCRIPT@
#INSTALL_DATA = @INSTALL_DATA@
INSTALL_LIBRARY = @INSTALL_LIBRARY@
INSTALL_DIR = @INSTALL_DIR@

oldincludedir=@oldincludedir@

MODE=0644

INCLUDES = ifaddrs.h netdb.h \
	bits/in.h bits/socket.h \
	net/if.h \
	netinet/icmp6.h netinet/in.h netinet/ip6.h

INCLUDES_SUBDIRS = bits net netinet 

.PHONY: all install install-includes clean distclean

all: includes
includes: $(INCLUDES)
install:
install-includes:
	for dir in $(INCLUDES_SUBDIRS); do \
		if [ ! -d $(oldincludedir)/$$dir ]; then \
			$(INSTALL_DIR) $(oldincludedir)/$$dir; \
		fi; \
	done;\
	for file in $(INCLUDES); do \
		$(INSTALL_DATA) $$file $(oldincludedir)/$$file; \
	done
clean:
	-rm -f bits/in.h \
		netinet/icmp6.h netinet/ip6.h
distclean: clean
	-rm -f Makefile

bits/in.h: ../include_glibc/bits/in.h
	$(LN_S) -f ../../include_glibc/bits/in.h bits
netinet/icmp6.h: ../include_glibc/netinet/icmp6.h
	$(LN_S) -f ../../include_glibc/netinet/icmp6.h netinet
netinet/ip6.h: ../include_glibc/netinet/ip6.h
	$(LN_S) -f ../../include_glibc/netinet/ip6.h netinet
