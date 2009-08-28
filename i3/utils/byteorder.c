#include <sys/types.h>
#ifndef _WIN32
    #include <netinet/in.h>
#else
    #include "fwint.h"
    #include <Winsock2.h>
#endif

#include "byteorder.h"

/* Purpose: To raise num to exponent in u64
 * Caveat: No range checking is done!
 */
static uint64_t pow_u64(uint16_t num, uint8_t exp)
{
    uint64_t ret;
    int count;
    
    if (exp <= 30)
	ret = 1 << exp;
    else
	ret = 1 << 30;
    
    for (count = 0; count < exp - 30; count++)
	ret *= 2;
    
    return ret;
}


void hnputl(void *p, uint32_t v)
{
    uint32_t *a;

    a = p;
    *a = htonl(v);
}

void hnputs(void *p, uint16_t v)
{
    uint16_t *a;

    a = p;
    *a = htons(v);
}

void hnput64(void *p, uint64_t v)
{
    // workaround for "initializer element is not constant"
    static char		first_call = 1;
    static uint64_t	two_32;
    
    uint64_t	u64_hi, u64_lo;
    uint32_t	hi,lo;
    uint32_t	*hi_ptr, *lo_ptr;
    
    if (first_call) {
	two_32 = pow_u64(2, 32);
	first_call = 0;
    }
    
    lo_ptr = (uint32_t *) p;
    hi_ptr = (uint32_t *) ((char *) p + sizeof(uint32_t));
    
    u64_lo = v % two_32;
    u64_hi = v / two_32;
    
    lo = (uint32_t) u64_lo;
    hi = (uint32_t) u64_hi;
    
    *lo_ptr = htonl(lo);
    *hi_ptr = htonl(hi);
}


uint32_t nhgetl(void *p)
{
    uint32_t *a;

    a = p;
    return ntohl(*a);
}

uint16_t nhgets(void *p)
{
    uint16_t *a;

    a = p;
    return ntohs(*a);
}

uint64_t nhget64(void *p)
{
    // workaround for "initializer element is not constant"
    static char         first_call = 1;
    static uint64_t	two_32;
    uint32_t *lo_ptr, *hi_ptr;
    
    if (first_call) {
	two_32 = pow_u64(2, 32);
	first_call = 0;
    }   
    
    lo_ptr = (uint32_t *) p;
    hi_ptr = (uint32_t *) ((char *) p + sizeof(uint32_t));
    
    return ntohl(*lo_ptr) + two_32 * ntohl(*hi_ptr);
}
