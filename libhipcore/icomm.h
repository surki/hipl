#ifndef _HIP_ICOMM
#define _HIP_ICOMM

/* Workaround for kernels before 2.6.15.3. */
#ifndef IPV6_2292PKTINFO
#  define IPV6_2292PKTINFO 2
#endif

#ifndef __KERNEL__
/* Do not move this before the definition of struct endpoint, as i3
   headers refer to libinet6 headers which in turn require the
   definition of the struct. */
#include "i3_client_api.h"

#include <netinet/in.h>
#endif
#include "protodefs.h"

/* Use this port to send asynchronous/unidirectional messages
   from hipd to hipfw */
#define HIP_FIREWALL_PORT                      971
/* Use this port to send messages from hipd to agent */
#define HIP_AGENT_PORT                         972
/* Use this port to send synchronous/bidirectional (request-response)
   messages from hipd to firewall*/
#define HIP_DAEMON_LOCAL_PORT                  973
#define HIP_FIREWALL_SYNC_PORT                 974


#define SO_HIP_GLOBAL_OPT 1
#define SO_HIP_SOCKET_OPT 2
#define SO_HIP_GET_HIT_LIST 3

/** @addtogroup hip_so
 * HIP socket options. Define a constant SO_HIP_NEWMODE which has value
 * between 0 and HIP_SO_ROOT_MAX. You may also need to increase the value of
 * HIP_SO_ROOT_MAX.
 *
 * @note Values 1 - 64 overlap the message values and thus cannot be used in
 *       hip_message_type_name().
 * @todo Should socket option values 1 - 64 be renumbered starting from 65?
 * @{
 */
#define HIP_SO_ANY_MIN 				1
#define SO_HIP_ADD_PEER_MAP_HIT_IP              2
#define SO_HIP_DEL_PEER_MAP_HIT_IP              3
#define SO_HIP_GET_MY_EID                       4
#define SO_HIP_SET_MY_EID                       5
#define SO_HIP_GET_PEER_EID                     6
#define SO_HIP_SET_PEER_EID                     7
#define SO_HIP_NULL_OP                          8
#define SO_HIP_QUERY_OPPORTUNISTIC_MODE         9
#define SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY  10
#define SO_HIP_SET_PSEUDO_HIT                   11
#define SO_HIP_QUERY_IP_HIT_MAPPING		12
#define SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY	13
#define SO_HIP_GET_PEER_HIT			14
//#define SO_HIP_SET_PEER_HIT			15
#define SO_HIP_DEFAULT_HIT			16
#define SO_HIP_GET_PEER_LIST                    17
/* One free slot here */
#define SO_HIP_GET_PSEUDO_HIT                   19
#define SO_HIP_GET_LOCAL_HI                     20
#define SO_HIP_GET_HITS                         21
#define SO_HIP_GET_HA_INFO			22
#define SO_HIP_DHT_SERVING_GW                   24
//#define SO_HIP_GET_STATE_HA		        25
#define SO_HIP_GET_LSI_PEER                     26
//#define SO_HIP_GET_LSI			        27
//#define SO_HIP_IS_OUR_LSI                       28
//#define SO_HIP_GET_PEER_HIT_BY_LSIS             29
//#define SO_HIP_GET_PEER_HIT_AT_FIREWALL         30
#define SO_HIP_HEARTBEAT                        31
/* inclusive */
#define SO_HIP_PING                             32
#define SO_HIP_TRIGGER_BEX                      33
#define SO_HIP_MAP_ID_TO_ADDR			34
#define SO_HIP_LSI_TO_HIT			35
#define HIP_SO_ANY_MAX 				63


/** @addtogroup hip_so
 * HIP socket options.
 * @{
 */
#define HIP_SO_ROOT_MIN 			64
#define SO_HIP_ADD_LOCAL_HI                     65
#define SO_HIP_DEL_LOCAL_HI                     66
#define SO_HIP_RUN_UNIT_TEST                    67
#define SO_HIP_RST                              68
#define SO_HIP_UNIT_TEST                        69
#define SO_HIP_BOS                              70
#define SO_HIP_NETLINK_DUMMY                    71
#define SO_HIP_CONF_PUZZLE_NEW                  72
#define SO_HIP_CONF_PUZZLE_GET                  73
#define SO_HIP_CONF_PUZZLE_SET                  74
#define SO_HIP_CONF_PUZZLE_INC                  75
#define SO_HIP_CONF_PUZZLE_DEC                  76
#define SO_HIP_STUN                             77
#define SO_HIP_SET_OPPORTUNISTIC_MODE           78
#define SO_HIP_SET_BLIND_ON                     79
#define SO_HIP_SET_BLIND_OFF                    80
/** Socket option for hipconf to change the used gateway with OpenDHT */
#define SO_HIP_DHT_GW                           81
#define SO_HIP_SET_DEBUG_ALL			82
#define SO_HIP_SET_DEBUG_MEDIUM			83
#define SO_HIP_SET_DEBUG_NONE			84
/** Socket option for hipconf to ask about the used gateway with OpenDHT */
#define SO_HIP_LOCATOR_GET                      85
#define SO_HIP_HANDOFF_ACTIVE			86
#define SO_HIP_HANDOFF_LAZY			87
/** Socket option for hipconf to restart daemon. */
#define SO_HIP_RESTART		      		88
#define SO_HIP_SET_LOCATOR_ON                   89
#define SO_HIP_SET_LOCATOR_OFF                  90
#define SO_HIP_DHT_SET                          91
#define SO_HIP_DHT_ON                           92
#define SO_HIP_DHT_OFF                          93
#define SO_HIP_SET_OPPTCP_ON			94
#define SO_HIP_SET_OPPTCP_OFF			95
#define SO_HIP_SET_HI3_ON			96
#define SO_HIP_SET_HI3_OFF			97
#define SO_HIP_RESET_FIREWALL_DB		98

#define SO_HIP_OPPTCP_SEND_TCP_PACKET		99
#define SO_HIP_TRANSFORM_ORDER                  100

/** Socket option for the server to offer the RVS service. (server side) */
#define SO_HIP_OFFER_RVS			101
/** Socket option for the server to cancel the RVS service. (server side) */
#define SO_HIP_CANCEL_RVS                       102
/** Socket option for the server to reinit the RVS service. (server side) */
#define SO_HIP_REINIT_RVS                       103
/**
 * Socket option to ask for additional services or service cancellation from a
 * server, i.e.\ to send a REG_REQUEST parameter to the server. (client side)
 */
#define SO_HIP_ADD_DEL_SERVER                   104
/** Socket option for the server to offer the HIP relay service. (server
    side) */
#define SO_HIP_OFFER_HIPRELAY                   106
/** Socket option for the server to cancel the HIP relay service. (server
    side) */
#define SO_HIP_CANCEL_HIPRELAY                  107
/** Socket option for hipconf to reinit the HIP relay service. (server side) */
#define SO_HIP_REINIT_RELAY                     108
/** Socket option for the server to offer the escrow service. (server side) */
#define SO_HIP_OFFER_ESCROW			111
/** Socket option for the server to cancel the escrow service. (server side) */
#define SO_HIP_CANCEL_ESCROW                    112
#define SO_HIP_ADD_DB_HI                        115
#define SO_HIP_ADD_ESCROW_DATA                  116
#define SO_HIP_DELETE_ESCROW_DATA               117
#define SO_HIP_SET_ESCROW_ACTIVE                118
#define SO_HIP_SET_ESCROW_INACTIVE              119
#define SO_HIP_FIREWALL_PING                    120
#define SO_HIP_FIREWALL_PING_REPLY              121
#define SO_HIP_FIREWALL_QUIT                    122
#define SO_HIP_AGENT_PING                       123
#define SO_HIP_AGENT_PING_REPLY                 124
#define SO_HIP_AGENT_QUIT                       125
#define SO_HIP_DAEMON_QUIT                      126
#define SO_HIP_I1_REJECT                        127
#define SO_HIP_UPDATE_HIU                       128
#define SO_HIP_SET_NAT_PLAIN_UDP                129
#define SO_HIP_SET_NAT_NONE                     130
#define SO_HIP_SET_NAT_OFF                      SO_HIP_SET_NAT_NONE // XX FIXME: REMOVE
#define SO_HIP_SET_HIPPROXY_ON		      	131
#define SO_HIP_SET_HIPPROXY_OFF			132
#define SO_HIP_GET_PROXY_LOCAL_ADDRESS		133
#define SO_HIP_HIPPROXY_STATUS_REQUEST		134
#define SO_HIP_OPPTCP_UNBLOCK_AND_BLACKLIST     135
#define SO_HIP_IPSEC_ADD_SA             	136
#define SO_HIP_SET_TCPTIMEOUT_ON                137
#define SO_HIP_SET_TCPTIMEOUT_OFF               138
#define SO_HIP_SET_NAT_ICE_UDP                  139
#define HIP_PARAM_INT                           140
#define SO_HIP_CERT_SPKI_SIGN                   141
#define SO_HIP_CERT_SPKI_VERIFY                 142
#define SO_HIP_CERT_X509V3_SIGN                 143
#define SO_HIP_CERT_X509V3_VERIFY               144
#define SO_HIP_USERSPACE_IPSEC			145
#define SO_HIP_ESP_PROT_TFM			146
#define SO_HIP_BEX_STORE_UPDATE			147
// free slot
#define SO_HIP_TRIGGER_UPDATE			149
#define SO_HIP_FW_UPDATE_DB                     152
#define SO_HIP_IPSEC_DELETE_SA                  153
#define SO_HIP_IPSEC_FLUSH_ALL_SA          	154
#define SO_HIP_ANCHOR_CHANGE			155
#define SO_HIP_ADD_PEER_MAP_HIT_IP_LSI          156
#define SO_HIP_FW_BEX_DONE                      157
#define SO_HIP_RESTART_DUMMY_INTERFACE		158
#define SO_HIP_VERIFY_DHT_HDRR_RESP             159
#define SO_HIP_ADD_UADB_INFO			160
#define SO_HIP_BUDDIES_SET			161
#define SO_HIP_BUDDIES_ON                       162
#define SO_HIP_BUDDIES_OFF                      163
#define SO_HIP_TURN_INFO                        164
#define SO_HIP_REGISTER_SAVAHR                  165
#define SO_HIP_GET_SAVAHR_HIT                   166
#define SO_HIP_GET_SAVAHR_IN_KEYS               167
#define SO_HIP_GET_SAVAHR_OUT_KEYS              168
#define SO_HIP_OFFER_SAVAH                      169
#define SO_HIP_CANCEL_SAVAH                     170
#define SO_HIP_FW_I2_DONE                       171
#define SO_HIP_SAVAH_CLIENT_STATUS_REQUEST      172
#define SO_HIP_SAVAH_SERVER_STATUS_REQUEST      173
#define SO_HIP_SET_SAVAH_CLIENT_OFF             174
#define SO_HIP_SET_SAVAH_CLIENT_ON              175
#define SO_HIP_SET_SAVAH_SERVER_OFF             176
#define SO_HIP_SET_SAVAH_SERVER_ON              178
#define SO_HIP_NSUPDATE_OFF                     179
#define SO_HIP_NSUPDATE_ON                      180
#define SO_HIP_HIT_TO_IP_OFF                    181
#define SO_HIP_HIT_TO_IP_ON                     182
#define SO_HIP_HIT_TO_IP_SET                    183
#define SO_HIP_SET_NAT_PORT			184
#define SO_HIP_SET_DATAPACKET_MODE_ON           185
#define SO_HIP_SET_DATAPACKET_MODE_OFF          186    
#define SO_HIP_BUILD_HOST_ID_SIGNATURE_DATAPACKET   187
#define SO_HIP_SHOTGUN_ON                       188
#define SO_HIP_SHOTGUN_OFF                      189
#define SO_HIP_SIGN_BUDDY_X509V3                190
#define SO_HIP_SIGN_BUDDY_SPKI                  191
#define SO_HIP_VERIFY_BUDDY_X509V3              192
#define SO_HIP_VERIFY_BUDDY_SPKI                193


/** @} */
/* inclusive */


#define HIP_SO_ROOT_MAX 			255

#define SO_HIP_SET_NAT_ON                     SO_HIP_SET_NAT_PLAIN_UDP
#define FLUSH_HA_INFO_DB                        1


/****** FIREWALL ******/

// the states of the connections as kept in the firewall
#define FIREWALL_STATE_BEX_DEFAULT 		-1  //default entry
#define FIREWALL_STATE_BEX_NOT_SUPPORTED	 0  //detected lack of HIP support at peer
#define FIREWALL_STATE_BEX_ESTABLISHED		 1  //detected HIP support at peer

//definition of firewall db records
struct firewall_hl{
	struct in6_addr ip_peer;
	hip_lsi_t 	lsi;
	hip_hit_t 	hit_our;
        hip_hit_t 	hit_peer;
        int       	bex_state;
};
typedef struct firewall_hl firewall_hl_t;
typedef struct hip_hadb_user_info_state firewall_cache_hl_t;


/*----Firewall cache----*/
/*Values for the port cache of the firewall*/
#define FIREWALL_PORT_CACHE_IPV6_TRAFFIC	1
#define FIREWALL_PORT_CACHE_LSI_TRAFFIC		2
#define FIREWALL_PORT_CACHE_IPV4_TRAFFIC	3
#define FIREWALL_PORT_CACHE_KEY_LENGTH		20

struct firewall_port_cache_hl
{
	char port_and_protocol[FIREWALL_PORT_CACHE_KEY_LENGTH];	//key
	int  traffic_type;					//value
};
typedef struct firewall_port_cache_hl firewall_port_cache_hl_t;

#endif /* _HIP_ICOMM */

