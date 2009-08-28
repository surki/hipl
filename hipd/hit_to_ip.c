/*
 * Check if there are records for 5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net for 2001:1e:574e:2505:264a:b360:d8cc:1d75
 * Oleg Ponomarev, Helsinki Institute for Information Technology
 */

 
#include "hit_to_ip.h"
#include "maintenance.h"
#include "libhipcore/hipconf.h"
#include <netinet/in.h>
#include <string.h>

int hip_hit_to_ip_status = 0;

char *hip_hit_to_ip_zone = NULL;

void hip_set_hit_to_ip_status(const int status) {
  hip_hit_to_ip_status = status;
}

int hip_get_hit_to_ip_status(void) {
  return hip_hit_to_ip_status;
}

void hip_hit_to_ip_set(const char *zone) {
  char *tmp = hip_hit_to_ip_zone;
  
  hip_hit_to_ip_zone = strdup(zone);

  if (tmp!=NULL)
	free(tmp);
}

static const char hex_digits[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

/*
 * returns "5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net" for 2001:1e:574e:2505:264a:b360:d8cc:1d75
 */ 

int hip_get_hit_to_ip_hostname(const hip_hit_t *hit, const char *hostname, const int hostname_len) {
	if ((hit == NULL)||(hostname == NULL))
		return ERR;

        uint8_t *bytes = (uint8_t *) hit->s6_addr;
        char *cp = (char *) hostname;
	int i; // no C99 :(
        for (i = 15; i >= 0; i--) {
		*cp++ = hex_digits[bytes[i] & 0x0f];
                *cp++ = '.';
                *cp++ = hex_digits[(bytes[i] >> 4) & 0x0f];
                *cp++ = '.';
        }

	if (hip_hit_to_ip_zone==NULL)
	  strncpy(cp, HIT_TO_IP_ZONE_DEFAULT, hostname_len-64);
	else
	  strncpy(cp, hip_hit_to_ip_zone , hostname_len-64);

	return OK;
}

/*
 * checks for ip address for hit
 */
int hip_hit_to_ip(hip_hit_t *hit, struct in6_addr *retval) {
	struct addrinfo *rp = NULL; // no C99 :(
	char hit_to_ip_hostname[64+HIT_TO_IP_ZONE_MAX_LEN+1];
	int found_addr = 0;
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	int res;

	if ((hit == NULL)||(retval == NULL))
		return ERR;

	if (hip_get_hit_to_ip_hostname(hit, hit_to_ip_hostname, sizeof(hit_to_ip_hostname))!=OK)
		return ERR;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket. Right? */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	/* getaddrinfo is too complex for DNS lookup, but let us use it now */
	res = getaddrinfo( hit_to_ip_hostname, NULL, &hints, &result );
	HIP_DEBUG("getaddrinfo(%s) returned %d\n", hit_to_ip_hostname, res);

	if (res!=0) {
		HIP_DEBUG("getaddrinfo error %s\n", gai_strerror(res));
		return ERR;
	}

	/* Look at the list and return only one address, let us prefer AF_INET */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		HIP_DEBUG_SOCKADDR("getaddrinfo result", rp->ai_addr);

		if (rp->ai_family == AF_INET) {
			struct sockaddr_in *tmp_sockaddr_in_ptr = (struct sockaddr_in *) (rp->ai_addr);
			IPV4_TO_IPV6_MAP(&(tmp_sockaddr_in_ptr->sin_addr), retval)
			found_addr = 1;
			break;
		} else if (rp->ai_family == AF_INET6) {
			struct sockaddr_in6 *tmp_sockaddr_in6_ptr = (struct sockaddr_in6 *) (rp->ai_addr);
			ipv6_addr_copy(retval, &(tmp_sockaddr_in6_ptr->sin6_addr));
			found_addr = 1;
		}
	}

	if (result)
		freeaddrinfo(result);

	if (found_addr)
		return OK;
	else
		return ERR;
}
