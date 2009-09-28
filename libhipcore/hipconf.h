/** @file
 * A header file for hipconf.c
 * 
 * @author  Janne Lundberg <jlu_tcs.hut.fi>
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_cc.hut.fi>
 * @author  Anthony D. Joseph <adj_hiit.fi>
 * @author  Abhinav Pathak <abhinav.pathak_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Anu Markkola
 * @author  Lauri Silvennoinen
 * @author  Tao Wan <twan@cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIPCONF_H
#define HIPCONF_H

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#ifndef ANDROID_CHANGES
#include <netinet/ip6.h>
#include <sysexits.h>
#endif
#include <assert.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "debug.h"
#include "crypto.h"
#include "builder.h"
#include "hipd.h"
#include "util.h"
#include "libhipopendht.h"
#include "registration.h"

/*
 * DO NOT TOUCH THESE, unless you know what you are doing.
 * These values are used for TYPE_xxx macros.
 */

/**
 * @addtogroup exec_app_types
 * @{
 */
 /**
 * Execute application with opportunistic library preloaded.
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_OPP	8

/**
 * Execute application with hip-libraries preloaded.
 * Overides example getaddrinfo().
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_HIP	12

/**
 * Execute application,no preloading of libraries.
 * @see handle_exec_application()
 */
#define EXEC_LOADLIB_NONE	13

/**
 * Maximum length of the string for that stores all libraries.
 * @see handle_exec_application()
 */
#define LIB_LENGTH	200
/** @} addtogroup exec_app_types */

/**
 * hipconf tool actions. These are numerical values for the first commandline
 * argument. For example in "tools/hipconf get hi default" -command "get"
 * is the action. If you want a new action named as 'NEWACT', define a
 * constant variable which has value between 0 and ACTION_MAX.
 * Probably you also need to increase the value of ACTION_MAX.
 * @see hip_conf_get_action()
 */

/* 0 is reserved */
#define ACTION_ADD 1
#define ACTION_DEL 2
#define ACTION_NEW 3
#define ACTION_NAT 4
#define ACTION_HIP 5
#define ACTION_SET 6
#define ACTION_INC 7
#define ACTION_DEC 8
#define ACTION_GET 9
#define ACTION_RUN 10
#define ACTION_LOAD 11
#define ACTION_DHT 12
#define ACTION_HA  13
#define ACTION_RST 14
#define ACTION_BOS 15
#define ACTION_DEBUG 16
#define ACTION_HANDOFF 17
#define ACTION_RESTART 18
#define ACTION_LOCATOR 19
#define ACTION_OPENDHT 20
#define ACTION_OPPTCP  21
#define ACTION_TRANSORDER 22
#define ACTION_TCPTIMEOUT 23 /* add By Tao Wan, on 04.01.2008 */
#define ACTION_HIPPROXY 24
#define ACTION_REINIT 25
#define ACTION_HEARTBEAT 26
#define ACTION_HI3 27
#define ACTION_HIT_TO_LSI 28
#define ACTION_BUDDIES 29
#define ACTION_NSUPDATE 30
#define ACTION_HIT_TO_IP 31
#define ACTION_HIT_TO_IP_SET 32
#define ACTION_NAT_LOCAL_PORT 33
#define ACTION_NAT_PEER_PORT 34
#define ACTION_DATAPACKET 35  /*Support for datapacket--Prabhu */
#define ACTION_SHOTGUN 36
#define ACTION_MAP_ID_TO_ADDR 37
#define ACTION_LSI_TO_HIT 38
#define ACTION_MAX 39 /* exclusive */

/**
 * TYPE_ constant list, as an index for each action_handler function.
 * 
 * @note Important! These values are used as array indexes, so keep these
 *       in order. If you add a constant TYPE_NEWTYPE here, the value of
 *       TYPE_NEWTYPE must be a correct index for looking up its corresponding
 *       handler function in action_handler[]. Add values after the last value
 *       and increment TYPE_MAX.
 */
/* 0 is reserved */
#define TYPE_HI      	   1
#define TYPE_MAP     	   2
#define TYPE_RST           3
#define TYPE_SERVER        4
#define TYPE_BOS     	   5
#define TYPE_PUZZLE  	   6
#define TYPE_NAT           7
#define TYPE_OPP     	   EXEC_LOADLIB_OPP /* Should be 8 */
#define TYPE_BLIND  	   9
#define TYPE_SERVICE 	   10
#define TYPE_CONFIG        11
#define TYPE_RUN     	   EXEC_LOADLIB_HIP /* Should be 12 */
#define TYPE_TTL           13
#define TYPE_GW            14
#define TYPE_GET           15
#define TYPE_HA            16
#define TYPE_MODE          17
#define TYPE_DEBUG         18
#define TYPE_DAEMON        19
#define TYPE_LOCATOR       20
#define TYPE_SET           21 /* DHT set <name> */
#define TYPE_DHT           22
#define TYPE_OPPTCP	   23
#define TYPE_ORDER         24
#define TYPE_TCPTIMEOUT	   25 /* add By Tao Wan, on 04.01.2008*/
#define TYPE_HIPPROXY	   26
#define TYPE_HEARTBEAT     27
#define TYPE_HI3           28
#define TYPE_GET_PEER_LSI  29
#define TYPE_BUDDIES	   30
#define TYPE_SAVAHR        31 /* SAVA router HIT IP pair */
#define TYPE_NSUPDATE      32
#define TYPE_HIT_TO_IP     33
#define TYPE_HIT_TO_IP_SET 34
#define TYPE_HIT_TO_LSI    35
#define TYPE_NAT_LOCAL_PORT 36
#define TYPE_NAT_PEER_PORT 37	
#define TYPE_DATAPACKET    38 /*support for data packet mode-- Prabhu */
#define TYPE_SHOTGUN       39
#define TYPE_ID_TO_ADDR    40
#define TYPE_LSI_TO_HIT    41
#define TYPE_MAX           42 /* exclusive */

/* #define TYPE_RELAY         22 */


/* for handle_hi() only */
#define OPT_HI_TYPE 0
#define OPT_HI_FMT  1
#define OPT_HI_FILE 2
#define OPT_HI_KEYLEN 3

#ifdef ANDROID_CHANGES
#    define HIPD_CONFIG_FILE     "/data/hip/hipd_config"
#else
#    define HIPD_CONFIG_FILE     "/etc/hip/hipd_config"
#endif
#define HIPD_CONFIG_FILE_EX \
"# Format of this file is as with hipconf, but without hipconf prefix\n\
# add hi default    # add all four HITs (see bug id 522)\n\
# add map HIT IP    # preload some HIT-to-IP mappings to hipd\n\
# add service rvs   # the host acts as HIP rendezvous (see also /etc/hip/relay_config)\n\
# add server rvs [RVS-HIT] <RVS-IP-OR-HOSTNAME> <lifetime-secs> # register to rendezvous server\n\
hit-to-ip on # resolve HITs to locators in dynamic DNS zone\n\
# hit-to-ip set hit-to-ip.infrahip.net. # resolve HITs to locators in dynamic DNS zone\n\
nsupdate on # send dynamic DNS updates\n\
# add server rvs hiprvs.infrahip.net 50000 # Register to free RVS at infrahip\n\
opendht on # turn DHT support on (use /etc/hip/dhtservers to define the used server)\n\
# heartbeat 10 # send ICMPv6 messages inside HIP tunnels\n\
shotgun on # use all possible src/dst IP combinations to send I1/UPDATE\n\
# locator on        # host sends all of its locators in base exchange\n\
# datapacket on # experimental draft hiccups extensions\n\
# opp normal|advanced|none\n\
# transform order 213 # crypto preference order (1=AES, 2=3DES, 3=NULL)\n\
\n\
nat plain-udp       # use UDP capsulation (for NATted environments)\n\
debug medium        # debug verbosity: all, medium or none\n"

#ifdef ANDROID_CHANGES
#    define HIPD_HOSTS_FILE     "/data/hip/hosts"
#else
#    define HIPD_HOSTS_FILE     "/etc/hip/hosts"
#endif
#define HOSTS_FILE "/etc/hosts"
#define HIPD_HOSTS_FILE_EX \
"# This file stores the HITs of the hosts, in a similar fashion to /etc/hosts.\n\
# The aliases are optional.  Examples:\n\
#2001:1e:361f:8a55:6730:6f82:ef36:2fff kyle kyle.com # This is a HIT with alias\n\
#2001:17:53ab:9ff1:3cba:15f:86d6:ea2e kenny       # This is a HIT without alias\n"

#ifdef ANDROID_CHANGES
#    define HIPD_NSUPDATE_CONF_FILE     "/data/hip/nsupdate.conf"
#else
#    define HIPD_NSUPDATE_CONF_FILE     "/etc/hip/nsupdate.conf"
#endif
#define HIPD_NSUPDATE_CONF_FILE_EX \
"##########################################################\n"\
"# configuration examples\n"\
"##########################################################\n"\
"# update records for 5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net.\n"\
"# $HIT_TO_IP_ZONE = 'hit-to-ip.infrahip.net.';\n"\
"# or in some other zone\n"\
"# $HIT_TO_IP_ZONE = 'hit-to-ip.example.org.';\n"\
"\n"\
"# update is sent to SOA if server empty\n"\
"# $HIT_TO_IP_SERVER = '';\n"\
"# or you may define it \n"\
"# $HIT_TO_IP_SERVER = 'ns.example.net.';\n"\
"\n"\
"# name of key if you configured it on the server\n"\
"# please also chown this file to nobody and chmod 400\n"\
"# $HIT_TO_IP_KEY_NAME='key.hit-to-ip';\n"\
"# $HIT_TO_IP_KEY_NAME = '';\n"\
"\n"\
"# secret of that key\n"\
"# $HIT_TO_IP_KEY_SECRET='Ousu6700S9sfYSL4UIKtvnxY4FKwYdgXrnEgDAu/rmUAoyBGFwGs0eY38KmYGLT1UbcL/O0igGFpm+NwGftdEQ==';\n"\
"# $HIT_TO_IP_KEY_SECRET = '';\n"\
"\n"\
"# TTL inserted for the records\n"\
"# $HIT_TO_IP_TTL = 1;\n"\
"###########################################################\n"\
"# domain with ORCHID prefix \n"\
"# $REVERSE_ZONE = '1.0.0.1.0.0.2.ip6.arpa.'; \n"\
"# \n"\
"# $REVERSE_SERVER = 'ptr-soa-hit.infrahip.net.'; # since SOA 1.0.0.1.0.0.2.ip6.arpa. is dns1.icann.org. now\n"\
"# $REVERSE_KEY_NAME = '';\n"\
"# $REVERSE_KEY_SECRET = '';\n"\
"# $REVERSE_TTL = 86400;\n"\
"# System hostname is used if empty\n"\
"# $REVERSE_HOSTNAME = 'stargazer-hit.pc.infrahip.net';\n"\
"###########################################################\n"

/**
 * A list of prototypes for handler functions.
 *
 * @note If you added a handler function in libinet6/hipconf.c, you also
 *       need to declare its prototype here.
 *       If you added a SO_HIP_NEWMODE in libinet6/icomm.h, you also need to
 *       add a case block for your SO_HIP_NEWMODE constant in the
 *       switch(msg_type) block in this function.
 */
int hip_handle_exec_application(int fork, int type, int argc, char **argv);
int hip_conf_handle_restart(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_append_pathtolib(char **libs, char *lib_all, int lib_all_length);
int hip_conf_handle_hi(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_map(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_rst(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_debug(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_bos(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_server(hip_common_t *msg, int action, const char *opt[], int optc, int send_only);
int hip_conf_handle_del(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_nat_port(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_nat(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_locator(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_puzzle(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_opp(hip_common_t *msg, int action, const char *opt[], int optc, int send_only);
int hip_conf_handle_blind(hip_common_t *, int type, const char **opt, int optc, int send_only);
int hip_conf_handle_service(hip_common_t *msg, int action, const char *opt[], int optc, int send_only);
int hip_conf_handle_load(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_ttl(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_gw(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_trans_order(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_get(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_set(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_dht_toggle(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_conf_handle_run_normal(hip_common_t *msg, int action,
			       const char *opt[], int optc, int send_only);
int hip_get_action(char *action);
int hip_get_type(char *type);
int hip_conf_handle_ha(hip_common_t *msg, int action,const char *opt[], int optc, int send_only);
int hip_conf_handle_handoff(hip_common_t *msg, int action,const char *opt[], int optc, int send_only);
int hip_conf_handle_opptcp(hip_common_t *, int type, const char *opt[], int optc, int send_only);
int hip_do_hipconf(int argc, char *argv[], int send_only);
int hip_conf_handle_opptcp(struct hip_common *, int type, const char *opt[], int optc, int);
int hip_conf_handle_tcptimeout(struct hip_common *, int type, const char *opt[], int optc, int); /*added by Tao Wan, 04.Jan.2008*/
int hip_conf_handle_hipproxy(struct hip_common *msg, int action, const char *opt[], int optc, int);
int hip_conf_handle_heartbeat(hip_common_t *msg, int action, const char *opt[], int optc, int);
int hip_conf_handle_get_dnsproxy(hip_common_t *, int action, const char *opt[], int optc, int);
int hip_conf_handle_buddies_toggle(hip_common_t *msg, int action, const char *opt[], int optc, int);
int hip_conf_handle_shotgun_toggle(hip_common_t *msg, int action, const char *opt[], int optc, int);
int hip_conf_handle_hi3(hip_common_t *, int type, const char *opt[], int optc, int);
int hip_conf_handle_sava (struct hip_common * msg, int action, 
			  const char * opt[], int optc, int send_only); 
int hip_conf_handle_nsupdate(hip_common_t *msg,
			     int action,
			     const char *opt[],
			     int optc, int send_only);
int hip_conf_handle_hit_to_ip(hip_common_t *msg,
			     int action,
			     const char *opt[],
			     int optc, int send_only);
int hip_conf_handle_hit_to_ip_set(hip_common_t *msg,
			     int action,
			     const char *opt[],
			     int optc, int send_only);
int hip_conf_handle_get_peer_lsi(hip_common_t *msg, int action, const char *opt[], int optc, int send_only);
int hip_conf_handle_map_id_to_addr (struct hip_common *msg, int action,
				const char * opt[], int optc, int send_only);
int hip_conf_handle_lsi_to_hit (struct hip_common *msg, int action,
				const char * opt[], int optc, int send_only);

int hip_conf_handle_datapacket(hip_common_t *msg, int action, const char *opt[], int optc, int send_only);
/**
 * Prints the HIT values in use. Prints either all or the default HIT value to
 * stdout.
 *
 * @param  a pointer to a message to be sent to the HIP daemon.
 * @param  a pointer to a commman line option. Either "default" or "all".
 * @return zero if the HITs were printed successfully, negative otherwise.
 */ 
int hip_get_hits(hip_common_t *msg, char *opt, int optc, int send_only);

#endif /* HIPCONF */
