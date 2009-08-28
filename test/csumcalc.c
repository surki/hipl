/* $Id: csumcalc.c,v 1.2 2003/10/14 15:50:30 krisu Exp $ */

#include "/home/mika/op/hipl/linux/include/net/hip.h"
#include <stdio.h>
#include <sys/types.h>
#include <netinet/ip6.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>


/*
 gcc -Wall -o csumcalc csumcalc.c /home/mika/op/hipl/linux/arch/i386/lib/checksum.S
*/
extern unsigned int csum_partial(const unsigned char *buff, int len, unsigned int sum);

static inline unsigned int csum_fold(unsigned int sum)
{
	__asm__(
		"addl %1, %0		;\n"
		"adcl $0xffff, %0	;\n"
		: "=r" (sum)
		: "r" (sum << 16), "0" (sum & 0xffff0000)
	);
	return (~sum) >> 16;
}

static __inline__ unsigned short int csum_ipv6_magic(struct in6_addr *saddr,
						     struct in6_addr *daddr,
						     uint32_t len,
						     unsigned short proto,
						     unsigned int sum)
{
	__asm__(
		"addl 0(%1), %0		;\n"
		"adcl 4(%1), %0		;\n"
		"adcl 8(%1), %0		;\n"
		"adcl 12(%1), %0	;\n"
		"adcl 0(%2), %0		;\n"
		"adcl 4(%2), %0		;\n"
		"adcl 8(%2), %0		;\n"
		"adcl 12(%2), %0	;\n"
		"adcl %3, %0		;\n"
		"adcl %4, %0		;\n"
		"adcl $0, %0		;\n"
		: "=&r" (sum)
		: "r" (saddr), "r" (daddr),
		  "r"(htonl(len)), "r"(htonl(proto)), "0"(sum));

	return csum_fold(sum);
}

static inline void ipv6_addr_set(struct in6_addr *addr, 
				     uint32_t w1, uint32_t w2,
				     uint32_t w3, uint32_t w4) {
	addr->s6_addr32[0] = w1; addr->s6_addr32[1] = w2;
	addr->s6_addr32[2] = w3; addr->s6_addr32[3] = w4;
}

void hip_build_network_hdr(struct hip_common *msg, uint8_t type_hdr,
			  uint16_t control, struct in6_addr *hit_sender,
			  struct in6_addr *hit_receiver) {
	msg->payload_proto = IPPROTO_NONE;
	msg->type_hdr = type_hdr;
	msg->ver_res = HIP_VER_RES;
	msg->control = htons(control);
	msg->checksum = htons(0);
	memcpy(&msg->hits, hit_sender, sizeof(struct in6_addr));
	memcpy(&msg->hitr, hit_receiver, sizeof(struct in6_addr));
}

void hexdump(const void *data, int len)
{
#define BYTESPERLINE 16

	char buf[4+2+2*BYTESPERLINE+((BYTESPERLINE-1)/4)+1], *bufpos;
	const void *datapos;
	int buflen, i;
	unsigned char c;

	if (!data) {
	  return;
	}

	/* every hexdump line contains offset+":"+BYTESPERLINE bytes of data */
	buflen = 4+2+2*BYTESPERLINE+((BYTESPERLINE-1)/4)+1;
	printf("hexdump: len=%d bytes\n", len);
	datapos = data;

	i = 0;
	while (i < len) {
	  int j;
	  bufpos = buf;
	  printf("%4d: ", i);

	  bufpos += 6;
	  for (j = 0; i < len && bufpos < buf+buflen-1; j++, i++, bufpos += 2*sizeof(char)) {
//	  for (j = 0; i < len; j++, i++) {
	    c = (unsigned char)(*(((unsigned char *)data)+i));
	    if (j && !(j%4)) {
	      printf(" ");
	      bufpos += sizeof(char);
	    }
	    printf("%02x", c);
	  }
	  printf("\n");
	}
	return;
}


int main(int argc,char **argv) {

  int len, csum_p, csum;
  struct hip_i1 i1;
  struct in6_addr saddr, daddr;
  struct in6_addr hits, hitd;

 if (argc != 5) {
   printf("Usage: %s src_IPv6 dst_IPv6 src_HIT dst_HIT\n", argv[0]);
   return 1;
 }

 if (inet_pton(AF_INET6, argv[1], &saddr) <= 0) {
   printf("illegal source IPv6 address\n");
   return 1;
 }
 if (inet_pton(AF_INET6, argv[2], &daddr) <= 0) {
   printf("illegal destination IPv6 address\n");
   return 1;
 }
 if (inet_pton(AF_INET6, argv[3], &hits) <= 0) {
   printf("illegal source HIT address\n");
   return 1;
 }
 if (inet_pton(AF_INET6, argv[4], &hitd) <= 0) {
   printf("illegal destination HIT address\n");
   return 1;
 }
  /*! \todo TH: hip_build_network_hdr has to be replaced with an appropriate function pointer */
  hip_build_network_hdr((struct hip_common* ) &i1, HIP_I1,
                        HIP_HA_CTRL_NONE, &hits, &hitd);
  i1.payload_len = len = (sizeof(struct hip_i1) >> 3) - 1;
  if (len > HIP_MAX_PACKET) {
   printf("too long a packet\n");
   return 1;
  }
  printf("I1:\n");
  hexdump(&i1, (len + 1) << 3);
  csum_p = csum_partial((const unsigned char *)&i1, (len + 1) << 3, 0);
  csum = csum_ipv6_magic(&saddr, &daddr, (len + 1) << 3, IPPROTO_HIP, csum_p);
  printf("checksum=0x%x (decimal %u)\n", csum, csum);
 
 return 0;
}
