/** @file
 * A header file for input.c.
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author  Anthony D. Joseph
 * @author  Bing Zhou
 * @author  Tobias Heer
 * @author  Samu Varjonen
 * @author	Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_INPUT_H
#define HIP_INPUT_H

#ifdef CONFIG_HIP_RVS
#  include "hiprelay.h"
#endif
#ifdef CONFIG_HIP_BLIND
#  include "hadb.h"
#endif

#include "oppdb.h"
#include "user.h"
#include "debug.h"
#include "hadb.h"
#include "keymat.h"
#include "crypto.h"
#include "builder.h"
#include "misc.h"
#include "hidb.h"
#include "cookie.h"
#include "output.h"
#include "pk.h"
#include "netdev.h"
#include "util.h"
#include "state.h"
#include "oppdb.h"
#include "registration.h"
#include "esp_prot_hipd_msg.h"

#include "i3_client_api.h"
#include "oppipdb.h"

struct hi3_ipv4_addr {
	u8 sin_family;
	struct in_addr sin_addr;
};

struct hi3_ipv6_addr {
	u8 sin6_family;
	struct in6_addr sin6_addr;
};

struct pseudo_header6
{
        unsigned char src_addr[16];
        unsigned char dst_addr[16];
        u32 packet_length;
        char zero[3];
        u8 next_hdr;
};

struct pseudo_header
{
        unsigned char src_addr[4];
        unsigned char dst_addr[4];
        u8 zero;
        u8 protocol;
        u16 packet_length;
};

void hip_inbound(cl_trigger *t, void *data, void *ctx);

extern int hip_icmp_sock;
extern int hip_encrypt_i2_hi;
extern int hip_icmp_interval;
extern int hip_icmp_sock;

/**
 * Gets name for a message type
 * @param type the msg type
 *
 * @return HIP message type as a string.
 */

static inline const char *hip_msg_type_str(int type)
{
        const char *str = "UNKNOWN";
        static const char *types[] =
		{ "", "I1", "R1", "I2", "R2", "CER", "UPDATE",
		  "NOTIFY", "CLOSE", "CLOSE_ACK", "UNKNOWN", "BOS" };
        if (type >= 1 && type < ARRAY_SIZE(types))
                str = types[type];
        else if (type == HIP_PAYLOAD) {
		str = "PAYLOAD";
	}

	return str;
}

/**
 * Checks for illegal controls in a HIP packet Controls field.
 *
 * <b>Do not confuse these controls with host association control fields.</b> HIP
 * packet Controls field values are dictated in RFCs/I-Ds. Therefore any bit
 * that is not dictated in these documents should not appear in the message and
 * should not be among legal values. Host association controls, on the other
 * hand are implementation specific values, and can be used as we please. Just
 * don't put those bits on wire!
 *
 * @param controls control value to be checked
 * @param legal    legal control values to check @c controls against
 * @return         1 if there are no illegal control values in @c controls,
 *                 otherwise 0.
 * @note           controls are given in host byte order.
 * @todo           If BLIND is in use we should include the BLIND bit
 *                 in legal values, shouldn't we?
 */
static inline int hip_controls_sane(u16 controls, u16 legal)
{
     _HIP_DEBUG("hip_controls_sane() invoked.\n");
     return ((controls & HIP_PACKET_CTRL_ANON) | legal) == legal;
}

int hip_check_hip_ri_opportunistic_mode(struct hip_common *, struct in6_addr *,
					struct in6_addr *, hip_portpair_t *,
					hip_ha_t *);

/**
 * Verifies a HMAC.
 *
 * @param buffer    the packet data used in HMAC calculation.
 * @param hmac      the HMAC to be verified.
 * @param hmac_key  integrity key used with HMAC.
 * @param hmac_type type of the HMAC digest algorithm.
 * @return          0 if calculated HMAC is same as @c hmac, otherwise < 0. On
 *                  error < 0 is returned.
 * @note            Fix the packet len before calling this function!
 */
static int hip_verify_hmac(struct hip_common *buffer, uint16_t blen, u8 *hmac,
			   void *hmac_key, int hmac_type);

/**
 * Verifies packet HMAC
 *
 * @param msg HIP packet
 * @param entry HA
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated. Assumes that the hmac includes only the header
 * and host id.
 */
int hip_verify_packet_hmac2(struct hip_common *msg,
			    struct hip_crypto_key *crypto_key,
			    struct hip_host_id *host_id);

/**
 * Verifies packet HMAC
 *
 * @param msg HIP packet
 * @param entry HA
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int hip_verify_packet_hmac(struct hip_common *, struct hip_crypto_key *);

/**
 * Verifies gerenal HMAC in HIP msg
 *
 * @param msg HIP packet
 * @param entry HA
 * @param parameter_type
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */

int hip_verify_packet_hmac_general(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key, hip_tlv_type_t parameter_type);
/**
 * Verifies packet RVS_HMAC
 * @param msg HIP packet
 * @param entry HA
 *
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int hip_verify_packet_rvs_hmac(struct hip_common *, struct hip_crypto_key *);

/**
 * Decides what action to take for an incoming HIP control packet.
 *
 * @param msg   a pointer to the received HIP control packet common header with
 *              source and destination HITs.
 * @param saddr a pointer to the source address from where the packet was
 *              received.
 * @param daddr a pointer to the destination address where to the packet was
 *              sent to (own address).
 * @param info  a pointer to the source and destination ports.
 * @param filter Whether to filter trough agent or not.
 * @return      zero on success, or negative error value on error.
 */
int hip_receive_control_packet(struct hip_common *, struct in6_addr *,
			       struct in6_addr *, hip_portpair_t *, int);
/**
 * Logic specific to HIP control packets received on UDP.
 *
 * Does the logic specific to HIP control packets received on UDP and calls
 * hip_receive_control_packet() after the UDP specific logic.
 * hip_receive_control_packet() is called with different IP source address
 * depending on whether the current machine is a rendezvous server or not:
 *
 * <ol>
 * <li>If the current machine is @b NOT a rendezvous server the source address
 * of hip_receive_control_packet() is the @c preferred_address of the matching
 * host association.</li>
 * <li>If the current machine @b IS a rendezvous server the source address
 * of hip_receive_control_packet() is the @c saddr of this function.</li>
 * </ol>
 *
 * @param msg   a pointer to the received HIP control packet common header with
 *              source and destination HITs.
 * @param saddr a pointer to the source address from where the packet was
 *              received.
 * @param daddr a pointer to the destination address where to the packet was
 *              sent to (own address).
 * @param info  a pointer to the source and destination ports.
 * @return      zero on success, or negative error value on error.
 */
int hip_receive_udp_control_packet(struct hip_common *, struct in6_addr *,
				   struct in6_addr *, hip_portpair_t *);

/**
 * @addtogroup receive_functions
 * @{
 */
/**
 * Determines the action to be executed for an incoming I1 packet.
 *
 * This function is called when a HIP control packet is received by
 * hip_receive_control_packet()-function and the packet is detected to be
 * an I1 packet. The operation of this function depends on whether the current
 * machine is a rendezvous server or not.
 *
 * <ol>
 * <li>If the current machine is @b NOT a rendezvous server:</li>
 * <ul>
 * <li>hip_handle_i1() is invoked.</li>
 * </ul>
 * <li>If the current machine @b IS a rendezvous server:</li>
 * <ul>
 * <li>if a valid rendezvous association is found from the server's rva table,
 * the I1 packet is relayed by invoking hip_rvs_relay_i1().</li>
 * <li>If no valid valid rendezvous association is found, hip_handle_i1() is
 * invoked.</li>
 * </ul>
 * </ol>
 *
 * @param i1       a pointer to the received I1 HIP packet common header with
 *                 source and destination HITs.
 * @param i1_saddr a pointer to the source address from where the I1 packet was
 *                 received.
 * @param i1_daddr a pointer to the destination address where to the I1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param i1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 */
int hip_receive_i1(struct hip_common *, struct in6_addr *, struct in6_addr *,
		   hip_ha_t *, hip_portpair_t *);

/**
 * Determines the action to be executed for an incoming R1 packet.
 *
 * This function is called when a HIP control packet is received by
 * hip_receive_control_packet()-function and the packet is detected to be
 * a R1 packet. First it is checked, if the corresponding I1 packet has
 * been sent. If yes, then the received R1 packet is handled in
 * hip_handle_r1(). The R1 packet is handled also in @c HIP_STATE_ESTABLISHED.
 * Otherwise the packet is dropped and not handled in any way.
 *
 * @param r1       a pointer to the received I1 HIP packet common header with
 *                 source and destination HITs.
 * @param r1_saddr a pointer to the source address from where the R1 packet
 *                 was received.
 * @param i1_daddr a pointer to the destination address where to the R1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param r1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 */
int hip_receive_r1(hip_common_t *r1, in6_addr_t *r1_saddr, in6_addr_t *r1_daddr,
		   hip_ha_t *entry, hip_portpair_t *r1_info);

/**
 * Receive I2 packet.
 *
 * This is the initial function which is called when an I2 packet is received.
 * If we are in correct state, the packet is handled to hip_handle_i2() for
 * further processing.
 *
 * @param i2       a pointer to...
 * @param i2_saddr a pointer to...
 * @param i2_daddr a pointer to...
 * @param entry    a pointer to...
 * @param i2_info  a pointer to...
 * @return         always zero
 * @todo   Check if it is correct to return always 0
 */
int hip_receive_i2(hip_common_t *i2, in6_addr_t *i2_saddr, in6_addr_t *i2_daddr,
		   hip_ha_t *entry, hip_portpair_t *i2_info);

/**
 * hip_receive_r2 - receive R2 packet
 * @param skb sk_buff where the HIP packet is in
 *
 * This is the initial function which is called when an R1 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_r2() for further processing.
 *
 * @return 0 if R2 was processed succesfully, < 0 otherwise.
 */
int hip_receive_r2(struct hip_common *, struct in6_addr *, struct in6_addr *,
		   hip_ha_t *, hip_portpair_t *);

/**
 * Determines the action to be executed for an incoming NOTIFY packet.
 *
 * This function is called when a HIP control packet is received by
 * hip_receive_control_packet()-function and the packet is detected to be
 * a NOTIFY packet.
 *
 * @param notify       a pointer to the received NOTIFY HIP packet common header
 *                     with source and destination HITs.
 * @param notify_saddr a pointer to the source address from where the NOTIFY
 *                     packet was received.
 * @param notify_daddr a pointer to the destination address where to the NOTIFY
 *                     packet was sent to (own address).
 * @param entry        a pointer to the current host association database state.
 */
int hip_receive_notify(const struct hip_common *, const struct in6_addr *,
		       const struct in6_addr *, hip_ha_t*);

/**
 * Receive BOS packet.
 *
 * This function is called when a BOS packet is received. We add the
 * received HIT and HOST_ID to the database.
 *
 * @param bos       a pointer to...
 * @param bos_saddr a pointer to...
 * @param bos_daddr a pointer to...
 * @param entry     a pointer to...
 * @param bos_info  a pointer to...
 * @return          always zero.
 * @todo Check if it is correct to return always zero.
 */
int hip_receive_bos(struct hip_common *, struct in6_addr *, struct in6_addr *,
		    hip_ha_t*, hip_portpair_t *);
int hip_receive_close(struct hip_common *, hip_ha_t*);
int hip_receive_close_ack(struct hip_common *, hip_ha_t*);
/* @} */

/**
 * @addtogroup handle_functions
 * @{
 */

/**
 * Handles an incoming I1 packet.
 *
 * Handles an incoming I1 packet and parses @c FROM or @c RELAY_FROM parameter
 * from the packet. If a @c FROM or a @c RELAY_FROM parameter is found, there must
 * also be a @c RVS_HMAC parameter present. This hmac is first verified. If the
 * verification fails, a negative error value is returned and hip_xmit_r1() is
 * not invoked. If verification succeeds,
 * <ol>
 * <li>and a @c FROM parameter is found, the IP address obtained from the
 * parameter is passed to hip_xmit_r1() as the destination IP address. The
 * source IP address of the received I1 packet is passed to hip_xmit_r1() as
 * the IP of RVS.</li>
 * <li>and a @c RELAY_FROM parameter is found, the IP address and
 * port number obtained from the parameter is passed to hip_xmit_r1() as the
 * destination IP address and destination port. The source IP address and source
 * port of the received I1 packet is passed to hip_xmit_r1() as the IP and port
 * of RVS.</li>
 * <li>If no @c FROM or @c RELAY_FROM parameters are found, this function does
 * nothing else but calls hip_xmit_r1().</li>
 * </ol>
 *
 * @param i1       a pointer to the received I1 HIP packet common header with
 *                 source and destination HITs.
 * @param i1_saddr a pointer to the source address from where the I1 packet was
 *                 received.
 * @param i1_daddr a pointer to the destination address where to the I1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param i1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @warning        This code only handles a single @c FROM or @c RELAY_FROM
 *                 parameter. If there is a mix of @c FROM and @c RELAY_FROM
 *                 parameters, only the first @c FROM parameter is parsed. Also,
 *                 if there are multiple @c FROM or @c RELAY_FROM parameters
 *                 present in the incoming I1 packet, only the first of a kind
 *                 is parsed.
 */
int hip_handle_i1(struct hip_common *, struct in6_addr *, struct in6_addr *,
		  hip_ha_t *, hip_portpair_t *);

/**
 * Handles an incoming R1 packet.
 *
 * Handles an incoming R1 packet and calls hip_create_i2() if the R1 packet
 * passes all tests.
 *
 * @param r1       a pointer to the received R1 HIP packet common header with
 *                 source and destination HITs.
 * @param r1_saddr a pointer to the source address from where the R1 packet was
 *                 received.
 * @param r1_daddr a pointer to the destination address where to the R1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param r1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @todo           When rendezvous service is used, the I1 packet is relayed
 *                 to the responder via the rendezvous server. Responder then
 *                 replies directly to the initiator with an R1 packet that has
 *                 a @c VIA_RVS parameter. This parameter contains the IP
 *                 addresses of the travesed RVSes (usually just one). The
 *                 initiator should store these addresses to cope with the
 *                 double jump problem.
 */
int hip_handle_r1(hip_common_t *r1, in6_addr_t *r1_saddr, in6_addr_t *r1_daddr,
		  hip_ha_t *entry, hip_portpair_t *r1_info);

/**
 * Handles an incoming I2 packet.
 *
 * This function is the actual point from where the processing of I2 is started
 * and corresponding R2 is created. This function also creates a new host
 * association in the host association database if no previous association
 * matching the search key (source HIT XOR destination HIT) was found.
 *
 * @param i2       a pointer to the I2 HIP packet common header with source and
 *                 destination HITs.
 * @param i2_saddr a pointer to the source address from where the I2 packet was
 *                 received.
 * @param i2_daddr a pointer to the destination address where the I2 packet was
 *                 sent to (own address).
 * @param ha       host association corresponding to the peer.
 * @param i2_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error. Success
 *                 indicates that I2 payloads are checked and R2 is created and
 *                 sent.
 */
int hip_handle_i2(hip_common_t *i2, in6_addr_t *i2_saddr, in6_addr_t *i2_daddr,
		  hip_ha_t *ha, hip_portpair_t *i2_info);

/**
 * hip_handle_r2 - handle incoming R2 packet
 * @param skb sk_buff where the HIP packet is in
 * @param entry HA
 *
 * This function is the actual point from where the processing of R2
 * is started.
 *
 * On success (payloads are created and IPsec is set up) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_r2(hip_common_t *r2, in6_addr_t *r2_saddr, in6_addr_t *r2_daddr,
		  hip_ha_t *entry, hip_portpair_t *r2_info);

/**
 * Handles an incoming NOTIFY packet.
 *
 * Handles an incoming NOTIFY packet and parses @c NOTIFICATION parameters and
 * @c VIA_RVS parameter from the packet.
 *
 * @param notify       a pointer to the received NOTIFY HIP packet common header
 *                     with source and destination HITs.
 * @param notify_saddr a pointer to the source address from where the NOTIFY
 *                     packet was received.
 * @param notify_daddr a pointer to the destination address where to the NOTIFY
 *                     packet was sent to (own address).
 * @param entry        a pointer to a host association
 */
int hip_handle_notify(const struct hip_common *, const struct in6_addr *,
		      const struct in6_addr *, hip_ha_t*);
int hip_handle_close(struct hip_common *, hip_ha_t *);
int hip_handle_close_ack(struct hip_common *, hip_ha_t *);
/* @} */

/**
 * Creates shared secret and produce keying material
 * The initial ESP keys are drawn out of the keying material.
 *
 * @param msg the HIP packet received from the peer
 * @param ctx context
 * @param dhpv pointer to the DH public value choosen
 * @return zero on success, or negative on error.
 */
int hip_produce_keying_material(struct hip_common *, struct hip_context *,
				uint64_t, uint64_t,
				struct hip_dh_public_value **);

/**
 * @brief Creates an I2 packet and sends it.
 *
 * @param ctx           context that includes the incoming R1 packet
 * @param solved_puzzle a value that solves the puzzle
 * @param r1_saddr      a pointer to R1 packet source IP address
 * @param r1_daddr      a pointer to R1 packet destination IP address
 * @param entry         a pointer to a host association
 * @param r1_info       a pointer to R1 packet source and destination ports
 * @param dhpv          a pointer to the DH public value chosen
 *
 * @return zero on success, non-negative on error.
 */
int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle,
		  in6_addr_t *r1_saddr, in6_addr_t *r1_daddr, hip_ha_t *entry,
	          hip_portpair_t *r1_info, struct hip_dh_public_value *dhpv);

/**
 * hip_create_r2 - Creates and transmits R2 packet.
 * @param ctx Context of processed I2 packet.
 * @param entry HA
 *
 * @return 0 on success, < 0 on error.
 */
int hip_create_r2(struct hip_context *, struct in6_addr *,
		  struct in6_addr *, hip_ha_t *, hip_portpair_t *,
		  struct in6_addr *,const in_port_t);

// 2007-02-26 oleg
// prototype
hip_rcv_func_set_t *hip_get_rcv_default_func_set();
// 2006-02-26 oleg
// prototype
hip_handle_func_set_t *hip_get_handle_default_func_set();


/**
 * hip_handle_firewall_i1_request - handle I1 request from FIREWALL.
 * @param       a pointer to the I1 HIP packet common header with source and
 *                 destination
 * @param		Source IP Address for I1
 * @param		Destination IP Address for I1
 * @return 0 on success, < 0 on error.
 */
int hip_handle_firewall_i1_request(struct hip_common *, struct in6_addr *, struct in6_addr *);

#endif /* HIP_INPUT_H */
