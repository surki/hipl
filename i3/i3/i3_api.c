/** @file
 *
 * @note: HIPU: libinet6 requires LD_PRELOAD which is "dylib" on BSD.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>   /* basic system data types */

#include <errno.h>    
#include "../utils/netwrap.h"

#include "i3.h"
#include "i3_fun.h"
#include "i3_debug.h"

int id_local(char *id)
{
  // to be changed when more than one server
  return TRUE; 
}

void send_packet_ipv4(char *pkt, int len, struct in_addr *dst_addr, 
		      uint16_t dst_port, nw_skt_t dst_fd)
{
  struct sockaddr_in dstaddr;

  memset(&dstaddr, 0, sizeof(dstaddr));
  dstaddr.sin_family = AF_INET;
  dstaddr.sin_addr.s_addr = htonl(dst_addr->s_addr);
  dstaddr.sin_port = htons(dst_port);

  if (sendto(dst_fd, pkt, len, 0, 
	     (struct sockaddr *)&dstaddr, sizeof(dstaddr)) < 0)
    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "send_ipv4: sendto error\n");
}

#ifndef __CYGWIN__
void send_packet_ipv6(char *p, int len, 
		      struct in6_addr *ip6_addr, uint16_t port, nw_skt_t rfd)
{
    I3_PRINT_INFO0(I3_INFO_LEVEL_WARNING, "send_packet_ipv6: not implemented yet!\n");
}
#endif

void send_packet_i3(char *p, int len)
{
    I3_PRINT_INFO0(I3_INFO_LEVEL_WARNING, "send_i3: not implemented yet!\n");
}



