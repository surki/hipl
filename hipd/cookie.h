#ifndef HIP_COOKIE_H
#define HIP_COOKIE_H

#include "debug.h"
#include "builder.h"
#include "output.h"
#include "list.h"
#include "hipd.h"

struct hip_r1entry {
	struct hip_common *r1;
	uint32_t generation;
	uint64_t Ci;
	uint8_t Ck;
	uint8_t Copaque[3];
};

#define HIP_PUZZLE_MAX_LIFETIME 60 /* in seconds */
#define HIP_R1TABLESIZE         3 /* precreate only this many R1s */
#define HIP_DEFAULT_COOKIE_K    10ULL
#define HIP_PUZZLE_MAX_K        28

struct hip_common * hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r, struct in6_addr *src_hit, struct in6_addr *peer_hit);
struct hip_r1entry * hip_init_r1(void);
void hip_uninit_r1(struct hip_r1entry *);		 
int hip_precreate_r1(struct hip_r1entry *r1table, 
		     struct in6_addr *hit, 
		     int (*sign)(struct hip_host_id *p, struct hip_common *m),
		     void *privkey,		     
		     struct hip_host_id *pubkey);
int hip_verify_cookie(in6_addr_t *ip_i, in6_addr_t *ip_r,  hip_common_t *hdr,
		      struct hip_solution *cookie);
int hip_verify_generation(struct in6_addr *ip_i, struct in6_addr *ip_r,
			  uint64_t birthday);

#endif /* HIP_COOKIE_H */
