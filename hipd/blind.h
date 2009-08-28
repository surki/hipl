#ifndef BLIND_H
#define BLIND_H 

#include "debug.h"
#include "crypto.h"
#include "ife.h"
#include "state.h"

extern int hip_blind_status; //blind on/off flag

int hip_check_whether_to_use_blind(hip_common_t *msg, hip_ha_t *entry,
				   int *use_blind);
int hip_set_blind_on(void);
int hip_set_blind_off(void);
int hip_blind_get_status(void);
int hip_blind_get_nonce(struct hip_common *msg, 
			uint16_t *msg_nonce);
int hip_plain_fingerprint(uint16_t *nonce, 
			  struct in6_addr *blind_hit, 
			  struct in6_addr *plain_hit);
int hip_blind_fingerprints(hip_ha_t *entry);
int hip_blind_verify(uint16_t *nonce, 
		     struct in6_addr *plain_hit, 
		     struct in6_addr *blind_hit);
int hip_blind_verify_r2(struct hip_common *r2, 
			     hip_ha_t *entry);
 
struct hip_common *hip_blind_build_i1(hip_ha_t *entry, uint16_t *mask);
int hip_blind_build_r2(struct hip_common *i2, 
			 struct hip_common *r2,
			 hip_ha_t *entry, 
			 uint16_t *mask);

struct hip_common *hip_blind_create_r1(const struct in6_addr *src_hit, 
				       int (*sign)(struct hip_host_id *p, struct hip_common *m),
				       struct hip_host_id *host_id_priv,
				       const struct hip_host_id *host_id_pub,
				       int cookie_k);

int hip_blind_precreate_r1(struct hip_r1entry *r1table, 
			   struct in6_addr *hit, 
			   int (*sign)(struct hip_host_id *p, struct hip_common *m),
			   struct hip_host_id *privkey, 
			   struct hip_host_id *pubkey);

#endif
