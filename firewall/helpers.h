#ifndef HELPERS_H
#define HELPERS_H

#include <netinet/in.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <limits.h>
#include <linux/netfilter_ipv6.h>

#include "debug.h"
#include "rule_management.h"
#include "firewall.h"
#include "firewall.h"

char * addr_to_numeric(const struct in6_addr *addrp);
struct in6_addr * numeric_to_addr(const char *num);
#endif //helpers
