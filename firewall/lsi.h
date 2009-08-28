#ifndef HIP_LSI_H
#define HIP_LSI_H

#include <libipq.h>
#include "firewalldb.h"
#include "debug.h"
#include "ife.h"

int is_packet_reinjection(struct in_addr *ip_src);

int hip_fw_handle_incoming_hit(ipq_packet_msg_t *m, struct in6_addr *ip_src,
			       struct in6_addr *ip_dst, int, int);

int hip_fw_handle_outgoing_lsi(ipq_packet_msg_t *m, struct in_addr *ip_src,
			       struct in_addr *ip_dst);

int reinject_packet(struct in6_addr *src_hit, struct in6_addr *dst_hit,
		    ipq_packet_msg_t *m, int ipOrigTraffic, int incoming);

#endif
