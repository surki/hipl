/*
 * The component provides interface to receive IP address and IF
 * events over netlink from the kernel.
 */
#ifndef NETDEV_H
#define NETDEV_H

#include <sys/socket.h>
#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif
#include <linux/netlink.h>      /* get_my_addresses() support   */
#include <linux/rtnetlink.h>    /* get_my_addresses() support   */
#include <netinet/ip6.h>
#include <openssl/rand.h>

#include "nlink.h"
#include "list.h"
#include "debug.h"
#include "libinet6/utils.h"

#define HIP_RTDS_TAB_LEN 256

extern int suppress_af_family; /* Defined in hipd/hipd.c*/
extern int address_count;
extern HIP_HASHTABLE *addresses;
struct rtnl_handle;

int hip_devaddr2ifindex(struct in6_addr *addr);
int hip_netdev_init_addresses(struct rtnl_handle *nl);
void delete_all_addresses(void);
int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg);
int filter_address(struct sockaddr *addr);
int hip_get_default_hit(struct in6_addr *hit);
int hip_get_default_lsi(struct in_addr *lsi);

void add_address_to_list(struct sockaddr *addr, int ifindex, int flags);

void hip_attach_locator_addresses(struct hip_common * in_msg,
				  struct hip_common *msg);

void hip_get_suitable_locator_address(struct hip_common * in_msg,
				      struct in6_addr *addr);


#endif /* NETDEV_H */
