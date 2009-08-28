#if HAVE_CONFIG_H
#include <config.h>
#endif

struct ip6_ahhdr
{
	uint8_t next_hdr;
	uint8_t hlen;
	uint16_t reserved1;

	uint32_t spi;

	uint32_t seq_num;

	/* Authentication data of variable length! */
};

void ipv6_multiplex(int next_hdr, struct ip6_hdr *ip6hdr, 
		    unsigned char *current, unsigned char *cend, int plen);

unsigned short chksum(void* buff, int len, struct in6_addr* src,
		      struct in6_addr* dst, uint32_t plen, uint16_t upproto);

void write_packet(struct ip6_hdr *ip6hdr);

int ipv6_parse_udp(struct ip6_hdr *ip6_hdr, 
		   unsigned char *current, unsigned char *cend, int plen);

int ipv6_parse_tcp(struct ip6_hdr *ip6_hdr, 
		   unsigned char *current, unsigned char *cend, int plen);

int ipv6_parse_icmp(struct ip6_hdr *ip6_hdr, 
		    unsigned char *current, unsigned char *cend, int plen);

int ipv6_parse_ah(struct ip6_hdr *ip6hdr, 
		  unsigned char *current, unsigned char *cend, int plen);

int ipv6_parse_esp(struct ip6_hdr *ip6hdr, 
		   unsigned char *current, unsigned char *cend, int plen);

int parse_ipv6(unsigned char *packet, int plen);

void ipv6_multiplex(int next_hdr, struct ip6_hdr *ip6hdr, 
		    unsigned char *current, unsigned char *cend, int plen);

int parse_packet(unsigned char* packet, int plen);


