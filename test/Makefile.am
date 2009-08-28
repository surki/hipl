AUTOMAKE_OPTIONS = foreign

# Note: HIPL is included because "libinet6/debug.h" is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
#
CFLAGS = $(hipl_common_cflags) -DHIP_UNITTEST_MODE -L$(HIPL_LIBHIPCORE_LIB)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)

if HIP_AGENT
CFLAGS += -lsqlite3
endif

include_HEADERS = checksum.h first_test.h hipsetup.h start-stop-daemon.h
include_HEADERS += unittest.h conntest.h hipconftool.h misc_install.h unit.h

INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBHIPCORE_INCLUDE)  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include

conntest_client_opp_LDFLAGS = 
conntest_client_opp_LDADD = 

if HIP_OPPORTUNISTIC
  # currently opp. library does not work with conntest-client-hip
if HIP_FORCE_SHLIB
  conntest_client_opp_LDFLAGS += -L$(HIPL_LIBOPPHIP_LIB)
  conntest_client_opp_LDADD += -lopphip
else
  conntest_client_opp_LDADD += ../libopphip/.libs/libopphip.a
endif
endif

if HIP_FORCE_SHLIB
conntest_client_opp_LDFLAGS += -L$(HIPL_LIBHIPCORE_LIB)
conntest_client_opp_LDADD += -linet6
else
conntest_client_opp_LDADD += ../libhipcore/.libs/libhipcore.a
endif

if HIP_FORCE_SHLIB
  conntest_client_opp_LDFLAGS += -L$(HIPL_OPENDHT_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
  conntest_client_opp_LDADD += -lhipopendht -lhiptool
else
  conntest_client_opp_LDADD += ../libdht/.libs/libhipopendht.a ../libhiptool/.libs/libhiptool.a
endif

CFLAGS += $(HIPL_XMLL)

opendhtteststub_LDFLAGS = -lcrypto $(HIP_XMLL) 
opendhtteststub_LDADD = 

if HIP_FORCE_SHLIB
  opendhtteststub_LDFLAGS += -L$(HIPL_OPENDHT_LIB)
  opendhtteststub_LDFLAGS += -L$(HIPL_LIBHIPCORE_LIB) -L$(HIPL_LIBHIPTOOL_LIB)
  opendhtteststub_LDADD += -lhipopendht
  opendhtteststub_LDADD += -linet6 -lhiptool
else
  opendhtteststub_LDADD += ../libdht/.libs/libhipopendht.a
  opendhtteststub_LDADD += ../libhipcore/.libs/libhipcore.a ../libhiptool/.libs/libhiptool.a
endif

# For some weird reason, you cannot use $(HIPL_LIBHIPCORE_LIB_STATIC) below
# Note: libhiptool needs to be the last library in LDADD!!
#
if HIP_OPENWRT
  LDADD = $(OPENWRT_LIB_STATIC)
else
  LDADD = 
endif

if HIP_FORCE_SHLIB
  LDADD += -linet6 -lhiptool
else
  LDADD += ../libhipcore/.libs/libhipcore.a ../libhiptool/.libs/libhiptool.a
endif

LDFLAGS = @LDFLAGS@ -L$(HIPL_LIBHIPCORE_LIB) -L$(HIPL_LIBHIPTOOL_LIB)

if HIP_OPENWRT
LDFLAGS += $(OPENWRT)
endif

# TODO Fix me: libinet6 no longer is available. Need to move it into separate project?
bin_PROGRAMS = conntest-client-opp
bin_PROGRAMS += conntest-server
bin_PROGRAMS += conntest-client-hip
# bin_PROGRAMS += conntest-client-native
# bin_PROGRAMS += conntest-client-native-user-key
# bin_PROGRAMS += conntest-server-native
#bin_PROGRAMS += unittest
bin_PROGRAMS += hipsetup
# bin_PROGRAMS += libinet6test
bin_PROGRAMS += listifaces
bin_PROGRAMS += first_test
#sbin_PROGRAMS = modtest
bin_PROGRAMS += cookietest
bin_PROGRAMS += keygentest
#bin_PROGRAMS += sha1ime_test
#bin_PROGRAMS += ttcp
bin_PROGRAMS += hashtest
#bin_PROGRAMS += hipconf
bin_PROGRAMS += listtest
bin_PROGRAMS += opendhtteststub
bin_PROGRAMS += certteststub
bin_PROGRAMS += sqliteteststub
bin_PROGRAMS += hc_performance
bin_PROGRAMS += auth_performance
bin_PROGRAMS += load

#sbin_SCRIPTS = hipsetup

#ttcp_SOURCES = ttcp.c
conntest_client_opp_SOURCES = conntest-client-opp.c  conntest.c
conntest_client_hip_SOURCES = conntest-client-hip.c conntest.c
conntest_client_native_SOURCES = conntest-client-native.c conntest.c
conntest_client_native_user_key_SOURCES = \
                        conntest-client-native-user-key.c
conntest_server_native_SOURCES = conntest-server-native.c conntest.c
conntest_server_SOURCES = conntest-server.c conntest.c
#unittest_SOURCES = unit.c unittest.c hipconftool.c suite.c
hipsetup_SOURCES = hipsetup.c hipconftool.c misc_install.c conntest.c
first_test_SOURCES = first_test.c hipconftool.c misc_install.c conntest.c
cookietest_SOURCES = cookietest.c
keygentest_SOURCES = keygentest.c
#sha1ime_test_SOURCES = sha1ime_test.c
#second_test_SOURCES = second_test.c hipconftool.c misc_install.c conntest.c
#modtest_SOURCES = modtest.c
hashtest_SOURCES = hashtest.c
#hipconf_SOURCE = hipconftool.c
listtest_SOURCES = listtest.c
opendhtteststub_SOURCES = opendhtteststub.c
certteststub_SOURCES = certteststub.c
sqliteteststub_SOURCES = sqliteteststub.c
hc_performance_SOURCES = hc_performance.c debug.c
auth_performance_SOURCES = auth_performance.c
load_SOURCES = load.c


#EXTRA_DIST = $(sbin_SCRIPTS)

# The sources depend on FILE.c, but it is located elsewhere. Linking is
# the probably the best way to access it because the object must be built
# on this directory and we do't want to make reduntant copies.
#
hipconftool.h:
	$(LN_S) -f $(HIPL_TOOLS)/hipconftool.h .
hipconftool.c: hipconftool.h
	$(LN_S) -f $(HIPL_TOOLS)/hipconftool.c .
debug.h:
	$(LN_S) -f $(HIPL_LIBHIPCORE)/debug.h .
debug.c: debug.h
	$(LN_S) -f $(HIPL_LIBHIPCORE)/debug.c .
$(HIPL_LIBHIPCORE_LIB_STATIC):
	$(MAKE) -C $(HIPL)/libhipcore


