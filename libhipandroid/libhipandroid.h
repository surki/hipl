
#ifndef LIBHIPANDROID_H
#define LIBHIPANDROID_H

typedef unsigned int  in_port_t;

#ifndef if_nameindex
struct if_nameindex
  {
    unsigned int if_index;      /* 1, 2, ... */
    char *if_name;              /* null terminated name: "eth0", ... */
  };
#endif

extern const struct in6_addr in6addr_loopback;   /* ::1 */

#define __THROW

#define INET_ADDRSTRLEN 16

#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }

/* From OpenBSD libc */
/* For lockf implementation */
#define F_ULOCK         0       /* unlock locked section */
#define F_LOCK          1       /* lock a section for exclusive use */
#define F_TLOCK         2       /* test and lock a section for exclusive use */
#define F_TEST          3       /* test a section for locks by other procs */

#include <sys/types.h>
#include <linux/in6.h>

struct ip6_hdr {
  union {
    struct ip6_hdrctl {
      u_int32_t ip6_un1_flow;  /* 20 bits of flow ID */
      u_int16_t ip6_un1_plen;  /* payload length */
      u_int8_t  ip6_un1_nxt;   /* next header */
      u_int8_t  ip6_un1_hlim;  /* hop limit */
    } ip6_un1;
    u_int8_t ip6_un2_vfc;   /* version and class */
  } ip6_ctlun;
  struct in6_addr ip6_src;   /* source address */
  struct in6_addr ip6_dst;   /* destination address */
};

#endif
