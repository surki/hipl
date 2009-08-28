/**
 * API used by the hipd to set up and maintain userspace IPsec state
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef USER_IPSEC_SADB_API_H_
#define USER_IPSEC_SADB_API_H_

#include "misc.h"
/* used for mapping HIPL ESP ecnryption INDEX to SADB encryption INDEX */
#include <linux/pfkeyv2.h>  /* ESP transform defines */

/** generic send function used to send the below created messages
 *
 * @param	msg the message to be sent
 * @return	0, if correct, else != 0
 */
int hip_userspace_ipsec_send_to_fw(struct hip_common *msg);

/** adds a new SA entry for the specified direction to the sadb in userspace ipsec
 *
 * @param	...
 * @return	0, if correct, else != 0
 */
uint32_t hip_userspace_ipsec_add_sa(struct in6_addr *saddr, struct in6_addr *daddr,
			      struct in6_addr *src_hit, struct in6_addr *dst_hit,
			      uint32_t spi, int ealg,
			      struct hip_crypto_key *enckey,
			      struct hip_crypto_key *authkey,
			      int already_acquired,
			      int direction, int update,
			      hip_ha_t *entry);

/** deletes the specified SA entry from the sadb in userspace ipsec
 *
 * @param	...
 */
void hip_userspace_ipsec_delete_sa(uint32_t spi, struct in6_addr *not_used,
		struct in6_addr *dst_addr, int direction, hip_ha_t *entry);

/** flushes all SA entries in the sadb in userspace ipsec
 *
 * @return	0, if correct, else != 0
 */
int hip_userspace_ipsec_flush_all_sa();

/* security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets */
int hip_userspace_ipsec_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
				    struct in6_addr *src_addr,
				    struct in6_addr *dst_addr, u8 proto,
				    int use_full_prefix, int update);

/* security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets */
void hip_userspace_ipsec_delete_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
				      int use_full_prefix);

/* security policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all matching packets */
int hip_userspace_ipsec_flush_all_policy();

/* returns a random SPI value */
uint32_t hip_userspace_ipsec_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit);

/* securitiy policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all packets matching HITs.
 *
 * @note we could delete the iptables rules here instead of at firewall exit */
void hip_userspace_ipsec_delete_default_prefix_sp_pair();

/* securitiy policies are not used by userspace ipsec, as we have static
 * rules in iptables capturing all packets matching HITs.
 *
 * @note we could set up the iptables rules here instead of at firewall init */
int hip_userspace_ipsec_setup_default_sp_prefix_pair();

#endif /*USER_IPSEC_SADB_API_H_*/
