
#ifndef LIBHIPANDROID_H
#define LIBHIPANDROID_H

typedef unsigned int  in_port_t;

/* #undef IN6_IS_ADDR_V4MAPPED */
/* #define IN6_IS_ADDR_V4MAPPED(a) \ */
/*   ((((__const uint32_t *) (a))[0] == 0)                                 \ */
/*   && (((__const uint32_t *) (a))[1] == 0)                              \ */
/*    && (((__const uint32_t *) (a))[2] == htonl (0xffff))) */

/* #undef IN6_IS_ADDR_LINKLOCAL */
/* #define IN6_IS_ADDR_LINKLOCAL(a) \ */
/*   ((((__const uint32_t *) (a))[0] & htonl (0xffc00000))      \ */
/*    == htonl (0xfe800000)) */

#define IN6_IS_ADDR_MULTICAST(a) (((__const uint8_t *) (a))[0] == 0xff)
#undef IN6_IS_ADDR_MC_LINKLOCAL
#define IN6_IS_ADDR_MC_LINKLOCAL(a) \
  (IN6_IS_ADDR_MULTICAST(a)      \
   && ((((__const uint8_t *) (a))[1] & 0xf) == 0x2))

extern const struct in6_addr in6addr_loopback;   /* ::1 */

#define __THROW

/* TODO Fix me */
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
