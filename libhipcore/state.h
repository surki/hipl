/** @file
 * This file defines Host Identity Protocol (HIP) header and parameter related
 * constants and structures.
 *
 * @note Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef _HIP_STATE
#define _HIP_STATE

#ifndef __KERNEL__
#include "hashtable.h"
#include "esp_prot_common.h"
#include "hip_statistics.h"

#endif

#define HIP_HIT_KNOWN 1
#define HIP_HIT_ANON  2

#define HIP_ENDPOINT_FLAG_PUBKEY           0
#define HIP_ENDPOINT_FLAG_HIT              1
#define HIP_ENDPOINT_FLAG_ANON             2
#define HIP_HI_REUSE_UID                   4
#define HIP_HI_REUSE_GID                   8
#define HIP_HI_REUSE_ANY                  16
/* Other flags: keep them to the power of two! */

/** @addtogroup hip_ha_state
 * @{
 */
/* When adding new states update debug.h hip_state_str(). Doxygen comments to
   these states are available at doc/doxygen.h */
#define HIP_STATE_NONE                   0
#define HIP_STATE_UNASSOCIATED           1
#define HIP_STATE_I1_SENT                2
#define HIP_STATE_I2_SENT                3
#define HIP_STATE_R2_SENT                4
#define HIP_STATE_ESTABLISHED            5
#define HIP_STATE_FAILED                 7
#define HIP_STATE_CLOSING                8
#define HIP_STATE_CLOSED                 9
/* @} */

#define HIP_UPDATE_STATE_REKEYING        1 /**< @todo REMOVE */
#define HIP_UPDATE_STATE_DEPRECATING     2

#define PEER_ADDR_STATE_UNVERIFIED       1
#define PEER_ADDR_STATE_ACTIVE           2
#define PEER_ADDR_STATE_DEPRECATED       3

#define ADDR_STATE_ACTIVE                1
#define ADDR_STATE_WAITING_ECHO_REQ      2

#define HIP_LOCATOR_TRAFFIC_TYPE_DUAL    0
#define HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL  1
#define HIP_LOCATOR_TRAFFIC_TYPE_DATA    2

#define HIP_LOCATOR_LOCATOR_TYPE_IPV6    0
#define HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI 1
//NAT branch
#define HIP_LOCATOR_LOCATOR_TYPE_UDP 2

#define HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI_PRIORITY 126
#define HIP_LOCATOR_LOCATOR_TYPE_REFLEXIVE_PRIORITY 120
/** for the triple nat mode*/
#define HIP_NAT_MODE_NONE               0
#define HIP_NAT_MODE_PLAIN_UDP          1
#define HIP_NAT_MODE_ICE_UDP            2
//end NAT branch

#define SEND_UPDATE_ESP_INFO             (1 << 0)
#define SEND_UPDATE_LOCATOR              (1 << 1)
#define SEND_UPDATE_ESP_ANCHOR           (1 << 2)

#define HIP_SPI_DIRECTION_OUT            1
#define HIP_SPI_DIRECTION_IN             2

#define HIP_ESCROW_OPERATION_ADD         1
#define HIP_ESCROW_OPERATION_MODIFY      2
#define HIP_ESCROW_OPERATION_DELETE      3

#define HIP_DEFAULT_AUTH                 HIP_AUTH_SHA /**< AUTH transform in R1 */
/**
 * Default rendezvous association lifetime in seconds. The lifetime should be
 * calculated using formula <code>2^((lifetime - 64)/8)</code> as instructed in
 * draft-ietf-hip-registration-02. But since we are just in the test phase of
 * HIP, we settle for a constant value of 600 seconds. Lauri 23.01.2008.
 */
#define HIP_DEFAULT_RVA_LIFETIME         600

#define HIP_FLAG_CONTROL_TRAFFIC_ONLY 0x1

/**
 * HIP host association state.
 *
 * @todo remove HIP_HASTATE_SPIOK
 */
typedef enum {
	HIP_HASTATE_INVALID = 0,
	HIP_HASTATE_SPIOK = 1,
	HIP_HASTATE_HITOK = 2,
	HIP_HASTATE_VALID = 3
} hip_hastate_t;

/** A typedefinition for a functionpointer to a transmitfunction introduced in
    @c hip_xmit_func_set_t. */
typedef int (*hip_xmit_func_t)(struct in6_addr *, struct in6_addr *, in_port_t,
			       in_port_t, struct hip_common*, hip_ha_t *, int);

/**
 * A data structure for storing the source and destination ports of an incoming
 * packet.
 */
typedef struct hip_stateless_info
{
	in_port_t src_port; /**< The source port of an incoming packet. */
	in_port_t dst_port; /**< The destination port of an incoming packet. */
#ifdef CONFIG_HIP_I3
	int hi3_in_use; /**< A boolean to indicate whether this message was
                             sent through I3 or not .*/
#endif
} hip_portpair_t;

/**
 * A data structure for handling retransmission. Used inside host association
 * database entries.
 */
typedef struct hip_msg_retrans{
	int count;
	time_t last_transmit;
	struct in6_addr saddr;
	struct in6_addr daddr;
	struct hip_common *buf;
} hip_msg_retrans_t;

/**
 * A binder structure for storing an IPv6 address and transport layer port
 * number. This structure is used in hip_build_param_relay_to_old().
 *
 * @note This has to be packed since it is used in building @c RELAY_FROM and
 *       @c RELAY_TO parameters.
 * @note obsolete
 */
struct hip_in6_addr_port
{
	struct in6_addr sin6_addr; /**< IPv6 address. */
	in_port_t       sin6_port; /**< Transport layer port number. */
} __attribute__ ((packed));

struct hip_context
{
	//struct sk_buff *skb_in;         /* received skbuff */
	struct hip_common *input;       /**< Received packet. */
	struct hip_common *output;      /**< Packet to be built and sent. */
	struct hip_crypto_key hip_enc_out;
	struct hip_crypto_key hip_hmac_out;
	struct hip_crypto_key esp_out;
	struct hip_crypto_key auth_out;
	struct hip_crypto_key hip_enc_in;
	struct hip_crypto_key hip_hmac_in;
	struct hip_crypto_key esp_in;
	struct hip_crypto_key auth_in;
	char   *dh_shared_key;
	size_t dh_shared_key_len;
	struct hip_esp_info *esp_info;

	uint16_t current_keymat_index; /**< The byte offset index in draft
					  chapter HIP KEYMAT */
	unsigned char current_keymat_K[HIP_AH_SHA_LEN];
	uint8_t keymat_calc_index; /**< The one byte index number used
				      during the keymat calculation. */
	uint16_t keymat_index; /**< KEYMAT offset. */
	uint16_t esp_keymat_index; /**< A pointer to the esp keymat index. */

	int esp_prot_param;
	
	char hip_nat_key[HIP_MAX_KEY_LEN];
	int use_ice;
};

/*
 * Fixed start of this struct must match to struct hip_locator_info_addr_item
 * for the part of address item. It is used in hip_update_locator_match().
 */
struct hip_peer_addr_list_item
{
//	hip_list_t list;
	uint32_t padding;
	unsigned long    hash_key;
	struct in6_addr  address;

	int              address_state; /* current state of the
					 * address (PEER_ADDR_STATE_xx) */
	int              is_preferred;  /* 1 if this address was set as
					   preferred address in the LOCATOR */
	uint32_t         lifetime;
	struct timeval   modified_time; /* time when this address was
					   added or updated */
	uint32_t         seq_update_id; /* the Update ID in SEQ parameter
					   this address is related to */
	uint8_t          echo_data[4];  /* data put into the ECHO_REQUEST parameter */
//NAT branch
	uint8_t  		transport_protocol; /*value 1 for UDP*/

	uint16_t 		port /*port number for transport protocol*/;

	uint32_t 		priority;
	
	uint8_t			kind;
//end NAT branch
};

/* for HIT-SPI hashtable only */
struct hip_hit_spi {
//	hip_list_t list;
	spinlock_t       lock;
	atomic_t         refcnt;
	hip_hit_t        hit_our;
	hip_hit_t        hit_peer;
	uint32_t         spi; /* this SPI spi belongs to the HIT hit */
};

struct hip_spi_in_item
{
//	hip_list_t list;
	uint32_t         spi;
	uint32_t         new_spi; /* SPI is changed to this when rekeying */
        /* ifindex if the netdev to which this is related to */
	int              ifindex;
	unsigned long    timestamp; /* when SA was created */
	int              updating; /* UPDATE is in progress */
	uint32_t         esp_info_spi_out; /* UPDATE, the stored outbound
					    * SPI related to the inbound
					    * SPI we sent in reply (useless?)*/
	uint16_t         keymat_index; /* advertised keymat index */
	int              update_state_flags; /* 0x1=received ack for
						sent SEQ, 0x2=received
						peer's ESP_INFO,
						both=0x3=can move back
						to established */
        /* the Update ID in SEQ parameter these SPI are related to */
	uint32_t seq_update_id;
        /* the corresponding esp_info of peer */
	struct hip_esp_info stored_received_esp_info;
        /* our addresses this SPI is related to, reuse struct to ease coding */
	struct hip_locator_info_addr_item *addresses;
	int addresses_n; /* number of addresses */
};

#ifndef __KERNEL__
struct hip_spi_out_item
{
//	hip_list_t list;
	uint32_t         spi;
	uint32_t         new_spi;   /* spi is changed to this when rekeying */
	uint32_t         seq_update_id; /* USELESS, IF SEQ ID WILL BE RELATED TO ADDRESS ITEMS,
					 * NOT OUTBOUND SPIS *//* the Update ID in SEQ parameter these SPI are related to */

	HIP_HASHTABLE *peer_addr_list; /* Peer's IPv6 addresses */
	struct in6_addr  preferred_address; /* check */
};
#endif

/* this struct is here instead of hidb.h to avoid some weird compilation
   warnings */
struct hip_host_id_entry {
	/* this needs to be first (list_for_each_entry, list
	   head being of different type) */
	//hip_list_t next;
	struct hip_lhi lhi;
	hip_lsi_t lsi;
	/* struct in6_addr ipv6_addr[MAXIP]; */
	struct hip_host_id *host_id; /* allocated dynamically */
	void *private_key; /* RSA or DSA */
	struct hip_r1entry *r1; /* precreated R1s */
	struct hip_r1entry *blindr1; /* pre-created R1s for blind*/
	/* Handler to call after insert with an argument, return 0 if OK*/
	int (*insert)(struct hip_host_id_entry *, void **arg);
	/* Handler to call before remove with an argument, return 0 if OK*/
	int (*remove)(struct hip_host_id_entry *, void **arg);
	void *arg;
};
#ifndef __KERNEL__
/* If you need to add a new boolean type variable to this structure, consider
   adding a control value to the local_controls and/or peer_controls bitmask
   field(s) instead of adding yet another integer. Lauri 24.01.2008. */
/** A data structure defining host association database state i.e.\ a HIP
    association between two hosts. Each successful base exchange between two
    different hosts leads to a new @c hip_hadb_state with @c state set to
    @c HIP_STATE_ESTABLISHED. */
struct hip_hadb_state
{
        /** Our Host Identity Tag (HIT). */
	hip_hit_t                    hit_our;
	/** Peer's Host Identity Tag (HIT). */
	hip_hit_t                    hit_peer;
	/** Information about the usage of the host association related to
	    locking stuff which is currently unimplemented because the daemon
	    is single threaded. When zero, the host association can be freed.
	    @date 24.01.2008 */
	hip_hastate_t                hastate;
	/** Counter to tear down a HA in CLOSING or CLOSED state */
	int purge_timeout;
	/** The state of this host association. @see hip_ha_state */
	int                          state;
	/** This guarantees that retransmissions work properly also in
	    non-established state.*/
	int                          retrans_state;
	/** A kludge to get the UPDATE retransmission to work.
	    @todo Remove this kludge. */
	int                          update_state;
	/** Our control values related to this host association.
	    @see hip_ha_controls */
	hip_controls_t               local_controls;
	/** Peer control values related to this host association.
	    @see hip_ha_controls */
	hip_controls_t               peer_controls;
	/** If this host association is from a local HIT to a local HIT this
	    is non-zero, otherwise zero. */
	int                          is_loopback;
	/** Security Parameter Indices (SPI) for incoming Security Associations
	    (SA). A SPI is an identification tag added to the packet header
	    while using IPsec for tunneling IP traffic.
	    @see hip_spi_in_item. */
	HIP_HASHTABLE                *spis_in;
	/** Security Parameter Indices (SPI) for outbound Security Associations
	    (SA). A SPI is an identification tag added to the packet header
	    while using IPsec for tunneling IP traffic.
	    @see hip_spi_in_item. */
	HIP_HASHTABLE                *spis_out;
 	/** Default SPI for outbound SAs. */
	uint32_t                     default_spi_out;
	/** Preferred peer IP address to use when sending data to peer. */
	struct in6_addr              peer_addr;
	/** Our IP address. */
	struct in6_addr              our_addr;
        /** Rendezvour server address used to connect to the peer; */
        struct in6_addr              *rendezvous_addr;
	/** Peer's Local Scope Identifier (LSI). A Local Scope Identifier is a
	    32-bit localized representation for a Host Identity.*/
	hip_lsi_t                    lsi_peer;
	/** Our Local Scope Identifier (LSI). A Local Scope Identifier is a
	    32-bit localized representation for a Host Identity.*/
	hip_lsi_t                    lsi_our;
	/** ESP transform type */
	int                          esp_transform;
	/** HIP transform type */
	int                          hip_transform;
	/** ESP extension protection transform */
	uint8_t						 esp_prot_transform;
	/** ESP extension protection local_anchor */
	unsigned char				 esp_local_anchor[MAX_HASH_LENGTH];
	/** another local anchor used for UPDATE messages */
	unsigned char				 esp_local_update_anchor[MAX_HASH_LENGTH];
	/** ESP extension protection peer_anchor */
	unsigned char				 esp_peer_anchor[MAX_HASH_LENGTH];
	/** another peer anchor used for UPDATE messages */
	unsigned char				 esp_peer_update_anchor[MAX_HASH_LENGTH];
	/** needed for offset calculation when using htrees */
	uint32_t					 esp_local_active_length;
	uint32_t					 esp_local_update_length;
	uint32_t					 esp_peer_active_length;
	uint32_t					 esp_peer_update_length;
	/** root needed in case of hierarchical hchain linking */
	uint8_t						 esp_root_length;
	unsigned char				 esp_root[MAX_HASH_LENGTH];
	int							 hash_item_length;
	/** parameters needed for soft-updates of hchains */
	/** Stored outgoing UPDATE ID counter. */
	uint32_t                     light_update_id_out;
	/** Stored incoming UPDATE ID counter. */
	uint32_t                     light_update_id_in;
	/** retranmission */
	uint8_t						 light_update_retrans;
#if 0
	/** the offset of the anchor in the link tree */
	int							 anchor_offset;
	/* length of the secret hashed concatenated with this update_anchor */
	int							 secret_length;
	/** the secret itself */
	unsigned char				 secret[MAX_HASH_LENGTH];
	/** length of the branch for verifying the new anchor */
	int							 branch_length;
	/** the branch itself */
	unsigned char				 branch_nodes[MAX_TREE_DEPTH * MAX_HASH_LENGTH];
#endif
	/** Something to do with the birthday paradox.
	    @todo Please clarify what this field is. */
	uint64_t                     birthday;
	/** A pointer to the Diffie-Hellman shared key. */
	char                         *dh_shared_key;
	/** The length of the Diffie-Hellman shared key. */
	size_t                       dh_shared_key_len;
	/** A boolean value indicating whether there is a NAT between this host
	    and the peer. */
	hip_transform_suite_t	                     nat_mode;
	/* this might seem redundant as dst_port == hip_get_nat_udp_port(), but it makes
	 * port handling easier in other functions */
	in_port_t		     local_udp_port;
	 /** NAT mangled port (source port of I2 packet). */
	in_port_t	             	 peer_udp_port;
	/** Non-zero if the escrow service is in use. */
	int                          escrow_used;
	/** Escrow server HIT. */
	struct in6_addr	             escrow_server_hit;
	/* The Initiator computes the keys when it receives R1. The keys are
	   needed only when R2 is received. We store them here in the mean
	   time. */
	/** For outgoing HIP packets. */
	struct hip_crypto_key        hip_enc_out;
	/** For outgoing HIP packets. */
	struct hip_crypto_key        hip_hmac_out;
	/** For outgoing ESP packets. */
	struct hip_crypto_key        esp_out;
	/** For outgoing ESP packets. */
	struct hip_crypto_key        auth_out;
	/** For incoming HIP packets. */
	struct hip_crypto_key        hip_enc_in;
	/** For incoming HIP packets. */
	struct hip_crypto_key        hip_hmac_in;
	/** For incoming ESP packets. */
	struct hip_crypto_key        esp_in;
	/** For incoming ESP packets. */
	struct hip_crypto_key        auth_in;
	/** The byte offset index in draft chapter HIP KEYMAT. */
	uint16_t                     current_keymat_index;
	/** The one byte index number used during the keymat calculation. */
	uint8_t                      keymat_calc_index;
	/** For @c esp_info. */
	uint16_t                     esp_keymat_index;
	/* Last Kn, where n is @c keymat_calc_index. */
	unsigned char                current_keymat_K[HIP_AH_SHA_LEN];
	/** Stored outgoing UPDATE ID counter. */
	uint32_t                     update_id_out;
	/** Stored incoming UPDATE ID counter. */
	uint32_t                     update_id_in;
	/** Our public host identity. */
	struct hip_host_id           *our_pub;
	/** Our private host identity. */
	struct hip_host_id           *our_priv;
	/** Keys in OpenSSL RSA or DSA format */
	void			     *our_priv_key;
	void			     *peer_pub_key;
        /** A function pointer to a function that signs our host identity. */
	int                          (*sign)(struct hip_host_id *, struct hip_common *);
	/** Peer's public host identity. */
	struct hip_host_id           *peer_pub;
	/** A function pointer to a function that verifies peer's host identity. */
	int                          (*verify)(struct hip_host_id *, struct hip_common *);
	/** For retransmission. */
	uint64_t                     puzzle_solution;
	/** 1, if hadb_state uses BLIND protocol. */
	uint16_t	             blind;
	/** The HIT we use with this host when BLIND is in use. */
	hip_hit_t                    hit_our_blind;
	/** The HIT the peer uses when BLIND is in use. */
	hip_hit_t                    hit_peer_blind;
	/** BLIND nonce. */
	uint16_t                     blind_nonce_i;
	/** LOCATOR parameter. Just tmp save if sent in R1 no @c esp_info so
	    keeping it here 'till the hip_update_locator_parameter can be done.
	    @todo Remove this kludge. */
	struct hip_locator           *locator;
 	/** For retransmission. */
	uint64_t                     puzzle_i;
	/** For base exchange or CLOSE. @b Not for UPDATE. */
	char                         echo_data[4];
	/** Temp storage for peer addresses list until
 	SPIs are formed. After SPIs the list is copied to SPI out's
	Peer address list */
	HIP_HASHTABLE                *peer_addr_list_to_be_added;
	/** For storing retransmission related data. */
	hip_msg_retrans_t            hip_msg_retrans;
	/** Receive function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_rcv_function_set() instead. */
	hip_rcv_func_set_t           *hadb_rcv_func;
	/** Handle function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_handle_function_set() instead. */
	hip_handle_func_set_t        *hadb_handle_func;
	/** Miscellaneous function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_handle_function_set() instead. */
	hip_misc_func_set_t          *hadb_misc_func;
	/** Update function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_handle_function_set() instead. */
	hip_update_func_set_t        *hadb_update_func;
	/** Transmission function set.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_handle_function_set() instead. */
	hip_xmit_func_set_t          *hadb_xmit_func;
        /** IPsec function set.
            @note Do not modify this value directly. Use
            hip_ipsec_set_handle_function_set() instead. */
        hip_ipsec_func_set_t *hadb_ipsec_func;
	/** Input filter function set. Input filter used in the GUI agent.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_input_filter_function_set() instead. */
	hip_input_filter_func_set_t  *hadb_input_filter_func;
	/** Output filter function set. Output filter used in the GUI agent.
	    @note Do not modify this value directly. Use
	    hip_hadb_set_output_filter_function_set() instead. */
	hip_output_filter_func_set_t *hadb_output_filter_func;
	/** peer hostname */
	uint8_t peer_hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
	/** True when agent is prompting user and fall back is disabled. */
	int                          hip_opp_fallback_disable;
#ifdef CONFIG_HIP_I3
	/** If the state for hi3, then this flag is 1, otherwise it is zero. */
	int                          is_hi3_state ;
	/** Non-zero if hi3 mode is on. */
	int                          hip_is_hi3_on;
#endif
	/** Non-zero if opportunistic TCP mode is on. */
	int                          hip_is_opptcp_on;
	/** The local port from where the TCP SYN I1 packet will be sent */
	in_port_t                    tcp_opptcp_src_port;
	/** the port at the peer where the TCP SYN I1 packet will be sent */
	in_port_t                    tcp_opptcp_dst_port;
#ifdef CONFIG_HIP_HIPPROXY
	int hipproxy;
#endif
        /** Counters of heartbeats (ICMPv6s) **/
	int                          heartbeats_sent;
	statistics_data_t			 heartbeats_statistics;
#if 0
	int                          heartbeats_received;
	/* sum of all RTTs to calculate the two following */
	u_int32_t                    heartbeats_total_rtt;
	u_int32_t                    heartbeats_total_rtt2;
	/** Heartbeat current mean RTT **/
        u_int32_t                    heartbeats_mean;
	/** Heartbeat current variance RTT **/
	u_int32_t                    heartbeats_variance;
#endif

	//pointer for ice engine
	void*                        ice_session;
	/** a 16 bits flag for nat connectiviy checking engine control*/
	
	uint32_t                     pacing;
        uint8_t                      ice_control_role;
        struct                       hip_esp_info *nat_esp_info;

	char                         hip_nat_key[HIP_MAX_KEY_LEN];
	/**reflexive address(NAT box out bound) when register to relay or RVS */
	struct in6_addr              local_reflexive_address;
	/**reflexive address port (NAT box out bound) when register to relay or RVS */
	in_port_t local_reflexive_udp_port;

	/** These are used in the ICMPv6 heartbeat code. The hipd sends
	    periodic ICMPv6 keepalives through IPsec tunnel. If the
	    tunnel does not exist, a single threaded hipd will blocked
	    forever */
	int outbound_sa_count;
	int inbound_sa_count;

};
#endif /* __KERNEL__ */

/** A data structure defining host association information that is sent
    to the userspace */
struct hip_hadb_user_info_state
{
	hip_hit_t	hit_our;
	hip_hit_t	hit_peer;
	struct in6_addr	ip_our;
	struct in6_addr	ip_peer;
        hip_lsi_t	lsi_our;
        hip_lsi_t	lsi_peer;
	uint8_t		peer_hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
	int		state;
	int		heartbeats_on;
	int		heartbeats_sent;
	int		heartbeats_received;
	double		heartbeats_mean;
	double		heartbeats_variance;
	in_port_t	nat_udp_port_local;
	in_port_t	nat_udp_port_peer;
	hip_controls_t  peer_controls;
};

struct hip_turn_info
{
	uint32_t spi;
	struct in6_addr peer_address;
	in_port_t peer_port;
};

/** @addtogroup hadb_func
 * @{
 */
struct hip_hadb_rcv_func_set {
	int (*hip_receive_i1)(struct hip_common *,
			      struct in6_addr *,
			      struct in6_addr *,
			      hip_ha_t*,
			      hip_portpair_t *);

	int (*hip_receive_r1)(struct hip_common *,
				 struct in6_addr *,
				 struct in6_addr *,
				 hip_ha_t*,
			      hip_portpair_t *);

	/* as there is possibly no state established when i2
	messages are received, the hip_handle_i2 function pointer
	is not executed during the establishment of a new connection*/
	int (*hip_receive_i2)(struct hip_common *,
				 struct in6_addr *,
				 struct in6_addr *,
				 hip_ha_t*,
			     hip_portpair_t *);

	int (*hip_receive_r2)(struct hip_common *,
				 struct in6_addr *,
				 struct in6_addr *,
				 hip_ha_t*,			     hip_portpair_t *);

	int (*hip_receive_update)(struct hip_common *,
				  struct in6_addr *,
				  struct in6_addr *,
				  hip_ha_t*,
				  hip_portpair_t *);

	int (*hip_receive_notify)(const struct hip_common *,
				  const struct in6_addr *,
				  const struct in6_addr *,
				  hip_ha_t*);

	int (*hip_receive_bos)(struct hip_common *,
			       struct in6_addr *,
			       struct in6_addr *,
			       hip_ha_t*,
			       hip_portpair_t *);

	int (*hip_receive_close)(struct hip_common *,
				 hip_ha_t*);

	int (*hip_receive_close_ack)(struct hip_common *,
				     hip_ha_t*);

};

struct hip_hadb_handle_func_set{
	int (*hip_handle_i1)(struct hip_common *r1,
			     struct in6_addr *r1_saddr,
			     struct in6_addr *r1_daddr,
			     hip_ha_t *entry,
			     hip_portpair_t *);

	int (*hip_handle_r1)(struct hip_common *r1,
			     struct in6_addr *r1_saddr,
			     struct in6_addr *r1_daddr,
			     hip_ha_t *entry,
			     hip_portpair_t *);

	/* as there is possibly no state established when i2
	   messages are received, the hip_handle_i2 function pointer
	   is not executed during the establishment of a new connection*/
	int (*hip_handle_i2)(struct hip_common *i2,
			     struct in6_addr *i2_saddr,
			     struct in6_addr *i2_daddr,
			     hip_ha_t *ha,
			     hip_portpair_t *i2_info);

	int (*hip_handle_r2)(struct hip_common *r2,
			     struct in6_addr *r2_saddr,
			     struct in6_addr *r2_daddr,
			     hip_ha_t *ha,
			     hip_portpair_t *r2_info);
	int (*hip_handle_bos)(struct hip_common *bos,
			      struct in6_addr *r2_saddr,
			      struct in6_addr *r2_daddr,
			      hip_ha_t *ha,
			      hip_portpair_t *);
	int (*hip_handle_close)(struct hip_common *close,
				hip_ha_t *entry);
	int (*hip_handle_close_ack)(struct hip_common *close_ack,
				    hip_ha_t *entry);
};

struct hip_hadb_update_func_set{
	int (*hip_handle_update_plain_locator)(hip_ha_t *entry,
					       struct hip_common *msg,
					       struct in6_addr *src_ip,
					       struct in6_addr *dst_ip,
					       struct hip_esp_info *esp_info,
					       struct hip_seq *seq);

	int (*hip_handle_update_addr_verify)(hip_ha_t *entry,
					     struct hip_common *msg,
					     struct in6_addr *src_ip,
					     struct in6_addr *dst_ip);

	void (*hip_update_handle_ack)(hip_ha_t *entry,
				      struct hip_ack *ack,
				      int have_nes);

	int (*hip_handle_update_established)(hip_ha_t *entry,
					     struct hip_common *msg,
					     struct in6_addr *src_ip,
					     struct in6_addr *dst_ip,
					     hip_portpair_t *);
	int (*hip_handle_update_rekeying)(hip_ha_t *entry,
					  struct hip_common *msg,
					  struct in6_addr *src_ip);

	int (*hip_update_send_addr_verify)(hip_ha_t *entry,
					   struct hip_common *msg,
					   struct in6_addr *src_ip,
					   uint32_t spi);

	int (*hip_update_send_echo)(hip_ha_t *entry,
			            uint32_t spi_out,
				    struct hip_peer_addr_list_item *addr);
};

struct hip_hadb_misc_func_set{
	uint64_t (*hip_solve_puzzle)(void *puzzle,
				  struct hip_common *hdr,
				  int mode);
	int (*hip_produce_keying_material)(struct hip_common *msg,
					   struct hip_context *ctx,
					   uint64_t I,
					   uint64_t J,
					   struct hip_dh_public_value **);
	int (*hip_create_i2)(struct hip_context *ctx, uint64_t solved_puzzle,
			     struct in6_addr *r1_saddr,
			     struct in6_addr *r1_daddr,
			     hip_ha_t *entry,
			     hip_portpair_t *,
			     struct hip_dh_public_value *);
	int (*hip_create_r2)(struct hip_context *ctx,
			     struct in6_addr *i2_saddr,
			     struct in6_addr *i2_daddr,
			     hip_ha_t *entry,
			     hip_portpair_t *,
//add by santtu for the relay address and port
			     struct in6_addr *,
			     const in_port_t
//end add
				);
	void (*hip_build_network_hdr)(struct hip_common *msg, uint8_t type_hdr,
				      uint16_t control,
				      const struct in6_addr *hit_sender,
				      const struct in6_addr *hit_receiver);
};

/** A data structure containing function pointers to functions used for sending
    data on wire. */
struct hip_hadb_xmit_func_set{
	/** A function pointer for sending packet on wire. */
	int (*hip_send_pkt)(struct in6_addr *local_addr,
			    struct in6_addr *peer_addr,
			    in_port_t src_port, in_port_t dst_port,
			    struct hip_common* msg, hip_ha_t *entry,
			    int retransmit);
};

struct hip_ipsec_func_set {
	/** A function pointer for userspace/kernelspace ipsec */
	uint32_t (*hip_add_sa)(struct in6_addr *saddr, struct in6_addr *daddr,
			       struct in6_addr *src_hit, struct in6_addr *dst_hit,
			       uint32_t spi, int ealg,
			       struct hip_crypto_key *enckey,
			       struct hip_crypto_key *authkey,
			       int already_acquired,
			       int direction, int update,
			       hip_ha_t *entry);
	void (*hip_delete_sa)(uint32_t spi, struct in6_addr *not_used,
	                   struct in6_addr *dst_addr,
	                   int direction, hip_ha_t *entry);
	int (*hip_flush_all_sa)();
	int (*hip_setup_hit_sp_pair)(hip_hit_t *src_hit, hip_hit_t *dst_hit,
				     struct in6_addr *src_addr,
				     struct in6_addr *dst_addr, u8 proto,
				     int use_full_prefix, int update);
	void (*hip_delete_hit_sp_pair)(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
				       int use_full_prefix);
	int (*hip_flush_all_policy)();
	uint32_t (*hip_acquire_spi)(hip_hit_t *srchit, hip_hit_t *dsthit);
	void (*hip_delete_default_prefix_sp_pair)();
	int (*hip_setup_default_sp_prefix_pair)();
};


struct hip_hadb_input_filter_func_set {
	int (*hip_input_filter)(struct hip_common *msg);
};

struct hip_hadb_output_filter_func_set {
	int (*hip_output_filter)(struct hip_common *msg);
};

/* @} */

#endif /* _HIP_STATE */

