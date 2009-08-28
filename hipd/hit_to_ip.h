/*
 * Check if there are records for 5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net for 2001:1e:574e:2505:264a:b360:d8cc:1d75
 * Oleg Ponomarev, Helsinki Institute for Information Technology
 */

#ifndef HIT_TO_IP_H
#define HIT_TO_IP_H

#include <sys/socket.h>
#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif
//#include <netinet/ip6.h>

#include "list.h"
#include "debug.h"
#include "utils.h"

#define HIT_TO_IP_ZONE_DEFAULT "hit-to-ip.infrahip.net"

int hip_hit_to_ip(hip_hit_t *hit, struct in6_addr *retval);

void hip_set_hit_to_ip_status(const int status);
int hip_get_hit_to_ip_status(void);
void hip_hit_to_ip_set(const char *zone);

#endif /* HIT_TO_IP_H */
