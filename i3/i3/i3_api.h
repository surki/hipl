/***************************************************************************
 * 			i3_addr.h  -  description
 **************************************************************************/

#ifndef I3_API_H
#define I3_API_H
#include "../utils/netwrap.h"

int id_local(char *id);
void send_packet_ipv4(char *pkt, int len, struct in_addr *dst_addr, 
		      uint16_t dst_port, nw_skt_t dst_fd);
#ifndef __CYGWIN__
void send_packet_ipv6(char *p, int len, 
		      struct in6_addr *ip6_addr, uint16_t port, nw_skt_t rfd);
#endif
void send_packet_i3(char *p, int len);

#endif //I3_API_H
