/*
 *
 * $Id: checksum.c,v 1.5 2003/06/26 07:31:13 mkomu Exp $
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>

#include <unistd.h>

#include "checksum.h"

#define IPV6_MIN_MTU  1280

int main(int argc, char** args)
{
	int fd;
	int plen;
	unsigned char packet[IPV6_MIN_MTU];
	
	if (argc != 2) {
		fprintf(stderr,"Usage: checksum file\n");
		exit(1);
	}
	
	fd = open(args[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	
	plen = read(fd, packet, IPV6_MIN_MTU);
	if (plen < 0) {
		perror("read");
		exit(1);
	}

	parse_packet(packet, plen);


	close(fd);
	return 0;
}

unsigned short chksum(void* buff, int len, struct in6_addr* src, struct in6_addr* dst,
		      uint32_t plen, uint16_t upproto)
{
	unsigned short* bptr;
	unsigned long adder = 0;
	int l;
	
	bptr = (unsigned short*) buff;
	l = len;
	
	while(l >= 2) {
		adder += ntohs(*bptr);
		l -= 2;
		bptr++;
	}
	
	if(l == 1)
		adder += ntohs(*bptr) & 0xF0;

	bptr = (unsigned short*) src;
	l = sizeof(struct in6_addr);
	while(l > 0) {
		adder += ntohs(*bptr);
		l -= 2;
		bptr++;
	}
	
	bptr = (unsigned short*) dst;
	l = sizeof(struct in6_addr);
	while(l > 0) {
		adder += ntohs(*bptr);
		l -= 2;
		bptr++;
	}
	
	adder += plen;
	
	adder += upproto;
	
	while (adder>>16)
		adder = (adder & 0xffff) + (adder >> 16);
	
	return ~adder;
}

void write_packet(struct ip6_hdr *ip6hdr) 
{
	int i;
	int length;
	unsigned char *buffer;

	length = ntohs(ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_plen) + 
		sizeof(struct ip6_hdr);

	buffer = (unsigned char*) ip6hdr;

	for(i=0; i<length; i++) 
		printf("%c", buffer[i]);
}


int ipv6_parse_udp(struct ip6_hdr *ip6_hdr, 
		   unsigned char *current, unsigned char *cend, int plen)
{
	struct udphdr *udphdr = (struct udphdr*) current;
	unsigned short csum;
	unsigned short clen;

	fprintf(stderr, "Parsing UDP header.\n");

	clen = ntohs(udphdr->len);
	udphdr->check = htons(0);

	csum = chksum(current, clen, &ip6_hdr->ip6_src, &ip6_hdr->ip6_dst, 
			clen, IPPROTO_UDP);

	udphdr->check = htons(csum);

	write_packet(ip6_hdr);

	return 0;
}


int ipv6_parse_tcp(struct ip6_hdr *ip6_hdr, 
		   unsigned char *current, unsigned char *cend, int plen)
{
	struct tcphdr *tcphdr = (struct tcphdr*) current;
	unsigned short csum;
	unsigned int clen;

	fprintf(stderr, "Parsing TCP header.\n");

	clen = cend - current;

	tcphdr->check = htons(0);
	csum = chksum(current, clen, &ip6_hdr->ip6_src, &ip6_hdr->ip6_dst, clen, IPPROTO_TCP);
	tcphdr->check = htons(csum);

	write_packet(ip6_hdr);

	return 0;
}

int ipv6_parse_icmp(struct ip6_hdr *ip6_hdr, 
		    unsigned char *current, unsigned char *cend, int plen)
{
	struct icmp6_hdr *icmphdr = (struct icmp6_hdr*) current;
	unsigned short csum;
	unsigned int clen;

	clen = cend - current;

	icmphdr->icmp6_cksum = htons(0);
	csum = chksum(current, clen, &ip6_hdr->ip6_src, &ip6_hdr->ip6_dst, clen, IPPROTO_ICMPV6);
	icmphdr->icmp6_cksum = htons(csum);

	write_packet(ip6_hdr);

	return 0;
}


int ipv6_parse_ah(struct ip6_hdr *ip6hdr, 
		  unsigned char *current, unsigned char *cend, int plen)
{
	struct ip6_ahhdr *ahhdr = (struct ip6_ahhdr*) current;
	int len;

	len = (ahhdr->hlen + 2) * 4;

	ipv6_multiplex(ahhdr->next_hdr, ip6hdr, current + len, cend, plen); 
	return 0;
}

int ipv6_parse_esp(struct ip6_hdr *ip6hdr, 
		   unsigned char *current, unsigned char *cend, int plen)
{
	unsigned char next_header;
	unsigned char pad_length;

	fprintf(stderr,"Warning: Parsing ESP header. Assuming ESP_NULL without authentication\n");

	/* fprintf(stderr,"plen is %d\n", plen); */

	cend -= 2;

	next_header = *(cend + 1);
	pad_length =  *(cend + 0);

	/* fprintf(stderr,"next_header:  %d, pad_length: %d\n", next_header, pad_length); */

	cend -= pad_length;

	ipv6_multiplex(next_header, ip6hdr, current + 2*4, cend, plen);

	return 0;
}


/* 
 * A (dangerous) special case here. If we need to parse IPv6-in-IPv6 
 * tunneling packets, this must be rewritten
 */
int parse_ipv6(unsigned char *packet, int plen)
{
	struct ip6_hdr *ip6hdr;

	ip6hdr = (struct ip6_hdr*) packet;
	
	ipv6_multiplex(ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt, ip6hdr, 
		       packet + sizeof(struct ip6_hdr), packet + plen, plen);

	return 0;
}

void ipv6_multiplex(int next_hdr, struct ip6_hdr *ip6hdr, 
		    unsigned char *current, unsigned char *cend, int plen)
{
	switch(next_hdr) {
	case IPPROTO_AH:
		ipv6_parse_ah(ip6hdr, current, cend, plen);
		break;

	case IPPROTO_UDP:
		ipv6_parse_udp(ip6hdr, current, cend, plen);
		break;

	case IPPROTO_ICMPV6:
		ipv6_parse_icmp(ip6hdr, current, cend, plen);
		break;

	case IPPROTO_TCP:
		ipv6_parse_tcp(ip6hdr, current, cend, plen);
		break;

	case IPPROTO_ESP:
		ipv6_parse_esp(ip6hdr, current, cend, plen);
		break;

	case IPPROTO_IPV6:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_DSTOPTS:
	default:
		fprintf(stderr, "Unsupported protocol: %d\n", next_hdr);
		exit(1);
	}

}

int parse_packet(unsigned char* packet, int plen)
{
	int version = packet[0] >> 4;

	switch(version) {

	case 6:
		parse_ipv6(packet, plen);
		break;
	  
	case 4:
	default:
		fprintf(stderr,"Unsupported IP version\n");
		exit(1);
		break;
	}

	return 0;
}

