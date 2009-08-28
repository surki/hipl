#ifndef HIP_PROXY_H
#define HIP_PROXY_H

#include "firewall.h"
#include "proxydb.h"

int hip_proxy_send_pkt(struct in6_addr *local_addr, struct in6_addr *peer_addr,	u8 *msg, u16 len, int protocol);
int hip_proxy_send_inbound_icmp_pkt(struct in6_addr* src_addr, struct in6_addr* dst_addr, u8* buff, u16 len);
int hip_proxy_send_to_client_pkt(struct in6_addr *local_addr, struct in6_addr *peer_addr, u8 *buff, u16 len);

#endif /* HIP_PROXY_H */
