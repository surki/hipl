#include "helpers.h"

/**
 * get char* out of in6_addr 
 */
char *
addr_to_numeric(const struct in6_addr *addrp)
{
	static char buf[50+1];
	return (char *)inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
}

/**
 * get in6_addr out of char* 
 */
struct in6_addr *
numeric_to_addr(const char *num)
{
	static struct in6_addr ap;
	int err;
	if ((err=inet_pton(AF_INET6, num, &ap)) == 1)
		return &ap;
	return (struct in6_addr *)NULL;
}


