# HIP additions.
AUTOMAKE_OPTIONS = foreign
INCLUDES = $(hipl_common_include_paths) -I$(HIPL_LIBINET6_INCLUDE)  -I$(HIPL_PJPROJECT_NATH)/include -I$(HIPL_PJPROJECT_LIB)/include -I$(HIPL_PJPROJECT_LIB_UTIL)/include -I$(HIPL_PJPROJECT_MEDIA)/include
CFLAGS = $(hipl_common_cflags) # -DHAVE_NETINET6_IPSEC
CFLAGS += $(OPTIMIZATIONS_CFLAGS)
CFLAGS += $(GPROF_CFLAGS)

#bin_PROGRAMS = test-policy test-policy-priority
lib_LTLIBRARIES = libhipsec.la

libhipsecdir = $(includedir)/libhipsec
libhipsec_HEADERS = libpfkey.h

#man3_MANS = ipsec_set_policy.3 ipsec_strerror.3

#AM_CFLAGS = @GLIBC_BUGS@
AM_YFLAGS = -d -p __libhipsec
AM_LFLAGS = -P__libhipsec -olex.yy.c

BUILT_SOURCES = policy_parse.h

############################ NOTE ##################################
#
# Note: when you upgrade this library, please do the following:
#
# 1. uncomment policy_parse.y and policy_token.l lines
# 2. "make"
# 3. disable the policy_parse.y and policy_token.l lines again
# 4. commit the code (including lex/yacc generated c files)
#
# I could not make the lex/yacc stuff work with "make dist" which
# is mandatory for building e.g. rpm packages. -mk
####################################################################

libhipsec_la_SOURCES =

if HIP_PFKEY
libhipsec_la_SOURCES += \
  ipsec_dump_policy.c \
  ipsec_get_policylen.c \
  ipsec_strerror.c \
  key_debug.c \
  pfkey.c \
  pfkey_dump.c
#  policy_parse.y \
#  policy_token.l
endif

# version is current:revision:age.
# See: http://www.gnu.org/manual/libtool-1.4.2/html_chapter/libtool_6.html#SEC32
#libipsec_la_LDFLAGS = -version-info 0:1:0
#libipsec_la_LIBADD = $(LEXLIB)

noinst_HEADERS = ipsec_strerror.h policy_parse.h

#test_policy_SOURCES = test-policy.c
#test_policy_LDFLAGS = libhipsec.la

#test_policy_priority_SOURCES = test-policy-priority.c
#test_policy_priority_LDFLAGS = libhipsec.la

#EXTRA_DIST = ${man3_MANS} test-policy.c

DISTCLEANFILES = policy_parse.c policy_token.c policy_token.h
