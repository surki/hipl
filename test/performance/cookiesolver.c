/* $Id: cookiesolver.c,v 1.3 2003/10/14 15:50:31 krisu Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

/* gcc -Wall -o cookiesolver cookiesolver.c -lssl */

#define hton64(i) ( ((uint64_t)(htonl((i) & 0xffffffff)) << 32) | htonl(((i) >> 32) & 0xffffffff ) )
#define ntoh64 hton64
 

struct hip_birthday_cookie {
        uint16_t     type;
        uint16_t     length;
        
        uint32_t     reserved;

        uint64_t     birthday;
        uint64_t     random_i;
        uint64_t     random_j_k;
        uint64_t     hash_target;
} __attribute__ ((packed));


u_int64_t calculate_digest(unsigned char *data, const u_int64_t j)
{
	unsigned char buf[SHA_DIGEST_LENGTH]; // openssl
	u_int64_t result = 0;

	memcpy(&(data[40]), &j, sizeof(u_int64_t));

	SHA1((unsigned char *)data,48,buf);
	memcpy(&result,buf+(SHA_DIGEST_LENGTH-sizeof(u_int64_t)),sizeof(u_int64_t));
	return (ntoh64(result));
}

/*
 * Solve R1 puzzle. Cookie has I, K and Challenge. Sets calculated
 * values Rand and Challenge-Response back to the cookie. Cookie
 * values are expected to be in host byte order.
 *
 * returns 0 if ok, 1 if invalid values are given, -1 on internal
 * errors
*/
/* Unportable code ? */
int solve_puzzle(struct hip_birthday_cookie *cookie, const struct in6_addr *initiator,
		 const struct in6_addr *responder)
{
    u_int64_t challenge_resp = 0;
    u_int64_t randval = 0; /* j */
    u_int64_t mask = 0;
    u_int64_t maxtries = 0;
    unsigned char cookiebuffer[48];
    
    if (cookie->random_j_k > 64) {
	return(1);
    }
    
    /* results in _last_ bits 1s */
    mask = (cookie->random_j_k == 64ULL ? 0xffffffffffffffffULL: (1ULL << cookie->random_j_k)-1);
    
    if (cookie->random_j_k + 2 >= 64)
	maxtries = 0xffffffffffffffffULL;
    else
	maxtries = (1ULL << (cookie->random_j_k + 2));
    
    /* prepare the cookie digest note: random_i must be in MSB order (network).
     * sizeof(u_int64_t) is not used instead of 8 since we are dependent on getting
     * 8 bytes of data. no less and/or no more.
     */

    memcpy(cookiebuffer, &cookie->random_i, 8);
    memcpy(cookiebuffer+8, initiator->s6_addr, 16);
    memcpy(cookiebuffer+24, responder->s6_addr, 16);
	
    /* cookiedata is now (I|HIT-I|HIT-R|xxx). All but the xxx part will remain the same
       throughout the process (loop).
    */

    /* init j (have to find alternative way to do in kernel). Remember to seed the rand() */
    randval = ((uint64_t)(rand()) << 32 | (uint64_t)(rand())); 

    while(maxtries-- > 0) {
	
	challenge_resp = calculate_digest(cookiebuffer,randval);

	if ((challenge_resp & mask) == 0) {
	    break;
	}
	
	randval++; // is in network byte order!
    }


    /* random value J is now found */
    cookie->random_j_k = randval;
    cookie->hash_target = challenge_resp;
    return(0);
}


int main(int argc, char **argv)
{
    signed int rounds = 0;
    int t;
    uint64_t i;
    int diff = 0;
    struct hip_birthday_cookie hbc;
#ifdef TIME
    struct timeval start,end;
#else
    struct rusage start,end;
    signed int s_usec;
#endif
    struct in6_addr init,resp;
    signed int u_usec;
    unsigned long total_usec = 0;

    if (argc != 3) {
      printf("Usage: %s rounds difficulty\n", argv[0]);
      return 1;
    }

    srand(time(NULL) ^ 0x619ABE28); //is it good idea to xor?
    rounds = atoi(argv[1]);
    diff = atoi(argv[2]);

    if (rounds < 1 || diff < 1 || diff > 64) {
      printf("illegal value for rounds/difficulty\n");
      return 1;
    }

    init.s6_addr32[0] = 0x954AB875;
    init.s6_addr32[1] = 0xBAF2DEAC;
    init.s6_addr32[2] = 0x73FF25A1;
    init.s6_addr32[3] = 0x84BB2250;
    
    resp.s6_addr32[0] = 0xDEADBEEF;
    resp.s6_addr32[1] = 0x43B02450;
    resp.s6_addr32[2] = 0x00010002;
    resp.s6_addr32[3] = 0x8000164A;

    hbc.random_i = 0x7851BA92D176F520ULL;
    printf("Executing %d rounds, with difficulty value %d\n",rounds,diff);
    printf("--------------------------------------------------------------\n");
    i = diff;

	for(t=0;t<rounds;t++) {
	    hbc.random_j_k = i;
#ifdef TIME
	    gettimeofday(&start,NULL);
#else
	    getrusage(RUSAGE_SELF,&start);
#endif
	    solve_puzzle(&hbc,&init,&resp);
#ifdef TIME
	    gettimeofday(&end,NULL);
#else
	    getrusage(RUSAGE_SELF,&end);
#endif

#ifdef TIME
	    u_usec = (end.tv_usec - start.tv_usec);
	    u_usec += ((end.tv_sec - start.tv_sec) * 1000000);
	    printf("Time: %d usec\n",u_usec);
#else
	    u_usec = (end.ru_utime.tv_usec - start.ru_utime.tv_usec);
	    u_usec += ((end.ru_utime.tv_sec - start.ru_utime.tv_sec) * 1000000);

	    s_usec = (end.ru_stime.tv_usec - start.ru_stime.tv_usec);
	    s_usec += ((end.ru_stime.tv_sec - start.ru_stime.tv_sec) * 1000000);
	    printf("User time: %d usec System time: %d usec\n", u_usec, s_usec);
#endif
	    total_usec += u_usec;
	}
	printf("--------------------------------------------------------\n");
	//    }

	printf("Total time: %lu usec Avg: %.2f usec\n", total_usec, (float)total_usec/rounds);
	return 0;
}
