

BASE_PATH := $(call my-dir)

BASE_C_INCLUDES := $(addprefix $(BASE_PATH)/, . hipd libhipandroid libinet6 libhiptool libdht i3 i3/i3_client pjproject/pjlib/include pjproject/pjlib-util/include pjproject/pjnath/include)


###########################################################
# hipd
###########################################################


LOCAL_PATH:= $(BASE_PATH)/hipd

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  update.c \
                    hipd.c \
                    keymat.c \
                    blind.c \
                    hiprelay.c \
                    registration.c \
                    user.c \
                    hadb.c \
                    oppdb.c \
                    close.c \
                    configfilereader.c \
                    input.c \
                    output.c \
                    hidb.c \
                    cookie.c \
                    netdev.c \
                    bos.c \
                    nat.c \
                    icookie.c \
                    escrow.c \
                    init.c \
                    maintenance.c \
                    accessor.c \
                    oppipdb.c \
                    dh.c \
                    tcptimeout.c \
                    cert.c \
                    user_ipsec_sadb_api.c \
                    user_ipsec_hipd_msg.c \
                    esp_prot_hipd_msg.c \
                    esp_prot_anchordb.c \
                    hipqueue.c \
                    esp_prot_light_update.c \
                    nsupdate.c \
                    hit_to_ip.c


LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -g -O0 \
                -DICMP6_FILTER=1 \
                -DANDROID_CHANGES \
                -DCONFIG_HIP_LIBHIPTOOL \
                -DPJ_LINUX \
                -DHIPL_DEFAULT_PREFIX=\"/system/\" \
                -DHAVE_OPENSSL_DSA_H=1 \
                -DHAVE_LIBSQLITE3=1 \
                -DHAVE_LIBXML2=1 \
                -DHIPL_HIPD \
                -DCONFIG_HIP_FIREWALL \
                -DCONFIG_HIP_RVS \
                -DCONFIG_HIP_HIPPROXY \
                -DCONFIG_HIP_OPPORTUNISTIC \
                -DCONFIG_SAVAH_IP_OPTION \
                -DCONFIG_HIP_DEBUG \
                -DHIP_LOGFMT_LONG
# -DCONFIG_HIP_AGENT \
# -DCONFIG_HIP_OPENDHT \
# -DCONFIG_HIP_I3

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include

LOCAL_SHARED_LIBRARIES := libcrypto

LOCAL_STATIC_LIBRARIES := libinet6 libhiptool libhipandroid libpjnath-hipl libpj-hipl libpjlib-util-hipl

LOCAL_MODULE:= hipd

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)


###########################################################
# hipconf
###########################################################


LOCAL_PATH:= $(BASE_PATH)/tools

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  hipconftool.c

LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DANDROID_CHANGES

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include

LOCAL_SHARED_LIBRARIES := libcrypto

LOCAL_STATIC_LIBRARIES := libinet6 libhiptool libhipandroid libpjnath-hipl libpj-hipl libpjlib-util-hipl

LOCAL_MODULE:= hipconf

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_EXECUTABLE)


##########################################################
# libhipandroid
##########################################################


LOCAL_PATH:= $(BASE_PATH)/libhipandroid

include $(CLEAR_VARS)

# TODO ifaddrs.c or getifaddrs.c?
LOCAL_SRC_FILES :=  libhipandroid.c \
                    regex.c

LOCAL_CFLAGS := -g -O0 \
                -DANDROID_CHANGES

LOCAL_SHARED_LIBRARIES :=

LOCAL_MODULE:= libhipandroid

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)


# ###########################################################
# ## libinet6
# ###########################################################


LOCAL_PATH:= $(BASE_PATH)/libinet6

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  getendpointinfo.c \
                    util.c \
                    debug.c \
                    builder.c \
                    misc.c \
                    hipconf.c \
                    message.c \
                    certtools.c \
                    sqlitedbapi.c \
                    ifaddrs.c \
                    ifnames.c

LOCAL_CFLAGS += -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DANDROID_CHANGES \
                -DICMP6_FILTER=1 \
                -DPJ_LINUX \
                -DHIPL_DEFAULT_PREFIX=\"/system/\" \
                -DCONFIG_HIP_OPPORTUNISTIC \
                -DCONFIG_HIP_DEBUG \
                -DCONFIG_HIP_HIPPROXY \
                -DCONFIG_HIP_I3 \
                -DCONFIG_HIP_LIBHIPTOOL \
                -DCONFIG_HIP_RVS \
                -DHIP_TRANSPARENT_API \
                -g -O0

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    $(BASE_PATH)/libinet6/include_glibc23 \
                    external/openssl/include

# TODO Do we need crypto here
#LOCAL_SHARED_LIBRARIES := libcrypto

LOCAL_STATIC_LIBRARIES := libhiptool libhipandroid

LOCAL_MODULE:= libinet6

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)


# ###########################################################
# ## libhiptool
# ###########################################################


LOCAL_PATH:= $(BASE_PATH)/libhiptool

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  crypto.c \
                    pk.c \
                    nlink.c \
                    esp_prot_common.c \
                    hashchain_store.c \
                    hashchain.c \
                    linkedlist.c \
                    hip_statistics.c \
                    hashtree.c \
                    xfrmapi.c


LOCAL_CFLAGS := -include $(BASE_PATH)/libhipandroid/libhipandroid.h \
                -DCONFIG_HIP_LIBHIPTOOL \
                -DPJ_LINUX \
                -DHIPL_DEFAULT_PREFIX=\"/system/\" \
                -g -O0 \
                -DANDROID_CHANGES

LOCAL_C_INCLUDES := $(BASE_C_INCLUDES) \
                    external/openssl/include

LOCAL_STATIC_LIBRARIES := libinet6

LOCAL_MODULE:= libhiptool

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)


###########################################################
## libpj-hipl
###########################################################


LOCAL_PATH := $(BASE_PATH)/pjproject/pjlib/src/pj

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  activesock.c \
                    array.c \
                    config.c \
                    ctype.c \
                    errno.c \
                    except.c \
                    fifobuf.c \
                    guid.c \
                    hash.c \
                    ip_helper_generic.c \
                    list.c \
                    lock.c \
                    log.c \
                    os_time_common.c \
                    pool.c \
                    pool_buf.c \
                    pool_caching.c \
                    pool_dbg.c \
                    rand.c \
                    rbtree.c \
                    sock_common.c \
                    string.c \
                    symbols.c \
                    timer.c \
                    types.c \
                    ioqueue_select.c \
                    addr_resolv_sock.c \
                    file_access_unistd.c \
                    file_io_ansi.c \
                    guid_simple.c \
                    log_writer_stdout.c \
                    os_core_unix.c \
                    os_error_unix.c \
                    os_time_unix.c \
                    os_timestamp_common.c \
                    os_timestamp_posix.c \
                    pool_policy_malloc.c \
                    sock_bsd.c \
                    sock_select.c

LOCAL_CFLAGS := -DPJ_LINUX \
                -g -O0 \
                -DANDROID_CHANGES

LOCAL_C_INCLUDES := $(BASE_PATH)/pjproject/pjlib/include

LOCAL_MODULE:= libpj-hipl

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)


###########################################################
## libpjnath-hipl
###########################################################


LOCAL_PATH := $(BASE_PATH)/pjproject/pjnath/src/pjnath

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  errno.c \
                    ice_session.c \
                    ice_strans.c \
                    nat_detect.c \
                    stun_auth.c \
                    stun_msg.c \
                    stun_msg_dump.c \
                    stun_session.c \
                    stun_sock.c \
                    stun_transaction.c \
                    turn_session.c \
                    turn_sock.c

LOCAL_CFLAGS := -DPJ_LINUX \
                -DANDROID_CHANGES

LOCAL_C_INCLUDES := $(BASE_PATH)/pjproject/pjlib/include \
                    $(BASE_PATH)/pjproject/pjnath/include \
                    $(BASE_PATH)/pjproject/pjlib-util/include

LOCAL_MODULE:= libpjnath-hipl

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)


###########################################################
## libpjlib-util-hipl
###########################################################


LOCAL_PATH := $(BASE_PATH)/pjproject/pjlib-util/src/pjlib-util

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=  base64.c \
                    crc32.c \
                    errno.c \
                    dns.c \
                    dns_dump.c \
                    dns_server.c \
                    getopt.c \
                    hmac_md5.c \
                    hmac_sha1.c \
                    md5.c \
                    pcap.c \
                    resolver.c \
                    scanner.c \
                    sha1.c \
                    srv_resolver.c \
                    string.c \
                    stun_simple.c \
                    stun_simple_client.c \
                    xml.c

LOCAL_CFLAGS := -DPJ_LINUX \
                -DANDROID_CHANGES

LOCAL_C_INCLUDES := $(BASE_PATH)/pjproject/pjlib/include \
                    $(BASE_PATH)/pjproject/pjnath/include \
                    $(BASE_PATH)/pjproject/pjlib-util/include

LOCAL_MODULE:= libpjlib-util-hipl

LOCAL_MODULE_CLASS := STATIC_LIBRARIES

include $(BUILD_STATIC_LIBRARY)
