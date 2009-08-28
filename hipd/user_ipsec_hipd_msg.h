/**
 * Messaging required for the userspace IPsec implementation of the hipfw
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef USER_IPSEC_HIPD_MSG_H_
#define USER_IPSEC_HIPD_MSG_H_

#include "misc.h"

/** handles a userspace ipsec activation message sent by the fw
 *
 * @param	msg the message sent by the firewall
 * @return	0, if ok, != 0 else
 */
int hip_userspace_ipsec_activate(struct hip_common *msg);

/** creates a user-message to add a SA to userspace IPsec
 *
 * @param	...
 * @return	the msg, NULL if an error occured
 */
struct hip_common * create_add_sa_msg(struct in6_addr *saddr,
							    struct in6_addr *daddr,
							    struct in6_addr *src_hit,
							    struct in6_addr *dst_hit,
							    uint32_t spi, int ealg,
							    struct hip_crypto_key *enckey,
							    struct hip_crypto_key *authkey,
							    int retransmission,
							    int direction, int update,
							    hip_ha_t *entry);

/** creates a user-message to delete a SA from userspace IPsec
 *
 * @param	...
 * @return	the msg, NULL if an error occured
 */
struct hip_common * create_delete_sa_msg(uint32_t spi, struct in6_addr *peer_addr,
		struct in6_addr *dst_addr, int family, int src_port, int dst_port);

/** create a user-message to flush all SAs from userspace IPsec
 *
 * @return	the msg, NULL if an error occured
 */
struct hip_common * create_flush_all_sa_msg(void);

#endif /*USER_IPSEC_HIPD_MSG_H_*/
