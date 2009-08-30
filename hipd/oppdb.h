/*
 * hipd oppdb.h
 *
 * Licence: GNU/GPL
 * Authors: 
 * - Bing Zhou <bingzhou@cc.hut.fi>
 *
 */

#ifndef HIP_OPPDB_H
#define HIP_OPPDB_H

#include <sys/un.h>
#include "debug.h"
#include "misc.h"
#include "hidb.h"
#include "hashtable.h"
#include "builder.h"
#include "util.h"
#include "libinet6/utils.h"
#include "oppipdb.h"

#define HIP_LOCK_OPP_INIT(entry)
#define HIP_UNLOCK_OPP_INIT(entry)
#define HIP_LOCK_OPP(entry)  
#define HIP_UNLOCK_OPP(entry)
#define HIP_OPPDB_SIZE 533

typedef struct hip_opp_blocking_request_entry hip_opp_block_t;
typedef struct hip_opp_info hip_opp_info_t;

void hip_init_opp_db();
//void hip_uninit_opp_db();
hip_opp_block_t *hip_create_opp_block_entry();
int hip_handle_opp_fallback(hip_opp_block_t *entry,
			    void *current_time);
void hip_oppdb_dump();
hip_opp_block_t *hip_oppdb_find_byhits(const hip_hit_t *phit, struct sockaddr_in6 *src);
int hip_oppdb_add_entry(const hip_hit_t *phit_peer,
			const hip_hit_t *hit_our,
			const struct in6_addr *ip_peer,
			const struct in6_addr *ip_our,
			const struct sockaddr_in6 *caller);
hip_ha_t *hip_get_opp_hadb_entry(hip_hit_t *resp_hit,
				 struct in6_addr *resp_addr);
int hip_oppdb_del_entry(const hip_hit_t *phit, const struct sockaddr_in6 *src);
void hip_oppdb_del_entry_by_entry(hip_opp_block_t *entry);
int hip_receive_opp_r1(struct hip_common *msg,
		       struct in6_addr *src_addr,
		       struct in6_addr *dst_addr,
		       hip_ha_t *opp_entry,
		       hip_portpair_t *msg_info);

hip_ha_t *hip_oppdb_get_hadb_entry_i1_r1(struct hip_common *msg,
					 struct in6_addr *src_addr,
					 struct in6_addr *dst_addr,
					 hip_portpair_t *msg_info);
int hip_for_each_opp(int (*func)(hip_opp_block_t *entry, void *opaq),
		     void *opaque);

int hip_handle_opp_reject(hip_opp_block_t *entry, void *ips);
int hip_force_opptcp_fallback(hip_opp_block_t *entry, void *ips);
#endif /* HIP_HADB_H */
