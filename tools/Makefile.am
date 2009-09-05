AUTOMAKE_OPTIONS = foreign

CLEANFILES = hipdnsproxy hipdnskeyparse

EXTRA_DIST = gen-python-starter.sh

if HAVE_PYTHON

# These two scripts are generated in the end to get the python paths correct.
# Currently, I don't know a better way to deal with the python code. -miika
dist_sbin_SCRIPTS = hipdnsproxy hipdnskeyparse nsupdate.pl

dns_PYTHON = DNS/Base.py DNS/Lib.py DNS/Type.py DNS/Class.py
dns_PYTHON += DNS/Opcode.py DNS/win32dns.py DNS/__init__.py
dns_PYTHON += DNS/pyip6.py DNS/lazy.py DNS/Status.py
dns_PYTHON += DNS/Serialization.py
dnsdir = $(pyexecdir)/DNS

hipdnsproxy_PYTHON = dnsproxy.py pyip6.py hosts.py util.py
hipdnsproxydir = $(pyexecdir)/hipdnsproxy

hipdnskeyparse_PYTHON = parse-key-3.py myasn.py
hipdnskeyparsedir = $(pyexecdir)/hipdnskeyparse

endif

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#

CFLAGS = $(hipl_common_cflags) # -L$(HIPL_LIBINET6_LIB)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
CFLAGS += -I$(HIPL_LIBHIPCORE_LIB)
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)

include_HEADERS = hipconftool.h

LDFLAGS = @LDFLAGS@ -lc -lcrypto $(HIP_XMLL) $(OPENWRT)

if HIP_OPENDHT
  INCLUDES += -I../libdht
endif

INCLUDES += -I../i3/i3_client -I../i3/utils -I../i3/i3

LDADD=
#if HIP_OPPORTUNISTIC
#  LDADD += ../libopphip/.libs/libopphip.a
#endif

if HIP_FORCE_SHLIB
  LDFLAGS += -L$(HIPL_LIBINET6_LIB)
  LDADD += -linet6 -lhipcore
else
  LDADD += ../libinet6/.libs/libinet6.a ../libhipcore/.libs/libhipcore.a
endif

if HIP_FORCE_SHLIB
  LDFLAGS += -L$(HIPL_LIBHIPTOOL_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
  LDADD += -lhiptool -lhipcore -lhipcore
if HIP_OPENDHT
    LDFLAGS += -L$(HIPL_OPENDHT_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
    LDADD += -lhipopendht -lhipcore
endif
else
    LDADD += ../libhipcore/.libs/libhipcore.a
    LDADD += ../libinet6/.libs/libinet6.a
    LDADD += ../libhiptool/.libs/libhiptool.a
if HIP_OPENDHT
    LDADD += ../libdht/.libs/libhipopendht.a
endif
endif

if HIP_OPENWRT
    LDADD += $(OPENWRT_LIB_STATIC)
endif


# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below

sbin_PROGRAMS = hipconf
hipconf_SOURCES = hipconftool.c

# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#
$(HIPL_LIBINET6_LIB_STATIC):
	$(MAKE) -C $(HIPL_LIBINET6)

# Automake does not build the shell scripts without this
hipdnsproxy:
	@sh gen-python-starter.sh $(pyexecdir)/hipdnsproxy dnsproxy.py hipdnsproxy

hipdnskeyparse:
	@sh gen-python-starter.sh $(pyexecdir)/hipdnskeyparse parse-key-3.py hipdnskeyparse

# This workaround forces automake to generate the scripts on each run. It is
# necessary because otherwise "make rpm" target has the old $pyexecdir from
# "make dist" and it refuses to build the scripts again.
all-local:
	@rm -f hipdnsproxy
	@rm -f hipdnskeyparse
	@sh gen-python-starter.sh $(pyexecdir)/hipdnsproxy dnsproxy.py hipdnsproxy
	@sh gen-python-starter.sh $(pyexecdir)/hipdnskeyparse parse-key-3.py hipdnskeyparse
