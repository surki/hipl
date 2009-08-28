/**
 * Provides ESP BEET mode IPsec services
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef USER_IPSEC_ESP_H_
#define USER_IPSEC_ESP_H_

#include "user_ipsec_sadb.h"
#include "firewall.h"

/* needed for transport layer checksum calculation */
typedef struct _pseudo_header
{
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t packet_length;
} pseudo_header;


/** creates a packet according to BEET mode ESP specification
 *
 * @param	...
 * @return	0, if correct, != 0 else
 */
int hip_beet_mode_output(hip_fw_context_t *ctx, hip_sa_entry_t *entry,
		struct in6_addr *preferred_local_addr, struct in6_addr *preferred_peer_addr,
		unsigned char *esp_packet, uint16_t *esp_packet_len);

/** handles a received packet according to BEET mode ESP specification
 *
 * @param	...
 * @return	0, if correct, != 0 else
 */
int hip_beet_mode_input(hip_fw_context_t *ctx, hip_sa_entry_t *entry,
			unsigned char *decrypted_packet,
			uint16_t *decrypted_packet_len);

/** encrypts the payload of ESP packets and adds authentication
 *
 * @param	in the input-buffer containing the data to be encrypted
 * @param	in_len the length of the input-buffer
 * @param	out the output-buffer
 * @param	out_len the length of the output-buffer
 * @param	entry the SA entry containing information about algorithms
 *          and key to be used
 * @return	0, if correct, != 0 else
 */
int hip_payload_encrypt(unsigned char *in, uint8_t in_type, uint16_t in_len,
		unsigned char *out, uint16_t *out_len, hip_sa_entry_t *entry);

/** decrypts the payload of ESP packets and verifies authentication
 *
 * @param	in the input-buffer containing the data to be encrypted
 * @param	in_len the length of the input-buffer
 * @param	out the output-buffer
 * @param	out_len the length of the output-buffer
 * @param	entry the SA entry containing information about algorithms
 *          and key to be used
 * @return	0, if correct, != 0 else
 */
int hip_payload_decrypt(unsigned char *in, uint16_t in_len, unsigned char *out,
		uint8_t *out_type, uint16_t *out_len, hip_sa_entry_t *entry);

/** adds an IPv4-header to the packet */
void add_ipv4_header(struct ip *ip_hdr, struct in6_addr *src_addr,
		struct in6_addr *dst_addr, uint16_t packet_len, uint8_t next_hdr);

/** adds an IPv6-header to the packet */
void add_ipv6_header(struct ip6_hdr *ip6_hdr, struct in6_addr *src_addr,
		struct in6_addr *dst_addr, uint16_t packet_len, uint8_t next_hdr);

/** adds an UDP-header to the packet */
void add_udp_header(struct udphdr *udp_hdr, uint16_t packet_len, hip_sa_entry_t *entry,
		struct in6_addr *src_addr, struct in6_addr *dst_addr);

/** calculates the IP-checksum
 *
 * @param ...
 * @return the IP checksum
 */
uint16_t checksum_ip(struct ip *ip_hdr, unsigned int ip_hl);

/** calculates the UDP-checksum
 *
 * @param ...
 * @return the UDP checksum
 */
uint16_t checksum_udp(struct udphdr *udp_hdr, struct in6_addr *src_addr,
		struct in6_addr *dst_addr);

#if 0
// might be needed when adding IPv6-encapsulation
typedef struct _pseudo_header6
{
	unsigned char src_addr[16];
	unsigned char dst_addr[16];
	uint32_t packet_length;
	char zero[3];
	uint8_t next_hdr;
} pseudo_header6;
#endif

#endif /* USER_IPSEC_ESP_H_*/
