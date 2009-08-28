
AUTOMAKE_OPTIONS = foreign

# Note: .. is included because libinet6/debug.h is included; otherwise this
# won't build because there is also the linux/net/ipv6/hip/debug.h include.
CFLAGS = $(hipl_common_cflags)
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)
CFLAGS += -DHIPL_DEFAULT_PREFIX=\"$(prefix)\"

# Note: libinet6 cannot be included here because it has a bad dependency
# with netlink headers.
include_HEADERS =  hadb.h oppdb.h hipd.h netdev.h user.h hiprelay.h
include_HEADERS += bos.h input.h output.h icookie.h blind.h
include_HEADERS += close.h hi3.h keymat.h hiptimer.h configfilereader.h
include_HEADERS += cookie.h hidb.h nat.h update.h dh.h registration.h
include_HEADERS += escrow.h init.h maintenance.h accessor.h oppipdb.h
include_HEADERS += tcptimeout.h cert.h user_ipsec_sadb_api.h user_ipsec_hipd_msg.h
include_HEADERS += esp_prot_hipd_msg.h esp_prot_anchordb.h hipqueue.h esp_prot_light_update.h
include_HEADERS += nsupdate.h hit_to_ip.h

INCLUDES = $(hipl_common_include_paths)  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include

sbin_PROGRAMS = hipd
hipd_SOURCES = update.c hipd.c keymat.c blind.c hiprelay.c registration.c
hipd_SOURCES += user.c hadb.c oppdb.c close.c configfilereader.c
hipd_SOURCES += input.c output.c hidb.c cookie.c netdev.c bos.c nat.c icookie.c
hipd_SOURCES += escrow.c init.c maintenance.c accessor.c oppipdb.c dh.c
hipd_SOURCES += tcptimeout.c cert.c user_ipsec_sadb_api.c user_ipsec_hipd_msg.c
hipd_SOURCES += esp_prot_hipd_msg.c esp_prot_anchordb.c hipqueue.c esp_prot_light_update.c
hipd_SOURCES += nsupdate.c hit_to_ip.c

hipd_LDFLAGS = -lcrypto $(HIPL_XMLL) -lm -DHIPL_HIPD

# For some weird reason, you cannot use $(HIPL_LIBINET6_LIB_STATIC) below
if HIP_FORCE_SHLIB
hipd_LDFLAGS += -L$(HIPL_LIBHIPCORE_LIB)
hipd_LDADD = $(OPENWRT_LIB_STATIC) -lhipcore
else
hipd_LDADD = $(OPENWRT_LIB_STATIC) ../libhipcore/.libs/libhipcore.a
endif

if HIP_FORCE_SHLIB
  hipd_LDFLAGS += -L$(HIPL_LIBHIPTOOL_LIB)
  hipd_LDADD += -lhiptool
else
  hipd_LDADD += ../libhiptool/.libs/libhiptool.a
endif

# Required for pjsip
hipd_LDADD += -lpthread 
if HIP_UUIDLIB
hipd_LDADD += -luuid
endif
hipd_LDADD += ../pjproject/pjnath/lib/libpjnath-hipl.a
hipd_LDADD += ../pjproject/pjlib/lib/libpj-hipl.a
hipd_LDADD += ../pjproject/pjlib-util/lib/libpjlib-util-hipl.a

../pjproject/pjlib/lib/libpj-hipl.a:
../pjproject/pjlib-util/lib/libpjlib-util-hipl.a:
../pjproject/pjnath/lib/libpjnath-hipl.a:

if HIP_PRIVSEP
if HIP_ALTSEP
  hipd_LDFLAGS += 
else
  hipd_LDFLAGS += -lcap
endif
endif

if HIP_I3
hipd_SOURCES += hi3.c
INCLUDES += -I../i3/i3_client -I../i3/utils -I../i3/i3
hipd_LDADD += ../i3/i3_client/libi3client.a ../i3/i3/libi3.a ../i3/utils/libutils.a ../i3/aeshash/libaes.a -lpthread
endif

if HIP_OPENDHT
if HIP_FORCE_SHLIB
  hipd_LDFLAGS += -L$(HIPL_OPENDHT_LIB)
  hipd_LDADD += -lhipopendht
else
  hipd_LDADD += ../libdht/.libs/libhipopendht.a
endif
endif

if HIP_PFKEY
hipd_LDADD += ../libipsec/.libs/libipsec.a
hipd_SOURCES += pfkeyapi.c
endif

# KeyNotev2
#INCLUDES += -Ikeynote
#hipd_LDADD += keynote/.libs/libkeynote.a
#SUBDIRS += keynote

../libdht/.libs/libdhttracker.a:
	$(MAKE) -C $(HIPL)/libdht

../libdht/.libs/libdhtresolver.a:
	$(MAKE) -C $(HIPL)/libdht



# The sources depend on builder, but it is located elsewhere. Linking is
# the best way to access it because the object must be built on this
# directory and we don't want to make reduntant copies.
#

cookie.c: cookie.h
hidb.c: hidb.h
hadb.c: hadb.h
oppdb.c:oppdb.h
keymat.c: keymat.h
user.c: user.h
bos.c: bos.h
input.c: input.h
output.c: output.h
nat.c : nat.h
netdev.c: netdev.h
update.c: update.h
icookie.c: icookie.h
escrow.c: escrow.h
registration.c: registration.h
blind.c: blind.h
tcptimeout.c: tcptimeout.h
hiprelay.c: hiprelay.h
configfilereader.c: configfilereader.h
registration.c: registration.h
linkedlist.c: linkedlist.h
