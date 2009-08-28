#ifndef HIP_BOS_NEW_H
#define HIP_BOS_NEW_H

#include <sys/types.h>
#include <netdb.h>

#include "nlink.h"
#include "debug.h"
#include "hidb.h"
#include "hadb.h"
#include "list.h"
#include "netdev.h"
#include "state.h"

int hip_send_bos(const struct hip_common *msg);
int hip_create_bos_signature(void *priv, int algo, struct hip_common *bos);
int hip_verify_packet_signature(struct hip_common *bos, struct hip_host_id *peer_host_id);

int hip_handle_bos(struct hip_common *bos,
		   struct in6_addr *bos_saddr,
		   struct in6_addr *bos_daddr,
		   hip_ha_t *entry, hip_portpair_t *);


#endif /* HIP_BOS_NEW_H */
