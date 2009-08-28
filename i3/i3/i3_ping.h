#ifndef _I3_PING_H
#define _I3_PING_H

#include "../utils/netwrap.h"
#if !defined(_WIN32)
    #include <inttypes.h>
    #include <netinet/in.h>
#else
    #include "fwint.h"
    #include <Winsock2.h>
#endif

void i3_echo_reply(nw_skt_t fd, char *p, int len, struct sockaddr_in *addr);
void i3_echo_request(nw_skt_t fd, uint32_t addr, uint16_t port, uint16_t seq);   
int recv_i3_echo_reply(nw_skt_t fd, uint32_t *addr, uint16_t *port,
				uint16_t *seq, uint64_t *rtt);
char is_i3_echo_request(char *p);

#endif
