#ifndef _PING_H
#define _PING_H

#include <stdio.h>
#include <stdlib.h>
#include "../utils/netwrap.h"

#define ICMP_ECHOREQ 8
#define ICMP_ECHOREPLY 0
#define ICMP_UNREACH 3
#define ICMP_TIMXCEED 11

#define MAX_PKT_LEN 4096

/* IP Header -- RFC 791 */
typedef struct IPHdr
{
    uint8_t	vihl;	// Version and IHL
    uint8_t	tos;	// Type Of Service
    uint16_t	tlen;	// Total Length
    uint16_t	id;	// Identification
    uint16_t	flagoff;// Flags and Fragment Offset
    uint8_t	ttl;	// Time To Live
    uint8_t	protocol;	// Protocol
    uint16_t	checksum;	// Checksum
    struct in_addr src;		// Internet Address - Source
    struct in_addr dst;		// Internet Address - Destination
} IPHdr;


/* ICMP Header - RFC 792 */
typedef struct ICMPHdr
{
    uint8_t	type;		// Type
    uint8_t	code;		// Code
    uint16_t	checksum;	// Checksum
    uint16_t	id;		// Identification
    uint16_t	seq;		// Sequence
  //char	data;		// Data
} ICMPHdr;

#define REQ_DATASIZE 64		// Echo Request Data size

/* ICMP Echo Request */
typedef struct EchoRequest
{
    ICMPHdr	icmphdr;
    uint32_t	addr;
    uint64_t	time;
    char	data[REQ_DATASIZE];
} EchoRequest;

/* ICMP Echo Reply */
typedef struct EchoReply
{
    IPHdr 	iphdr;
    ICMPHdr	icmphdr;
    uint32_t	addr;
    uint64_t	time;
    char	data[REQ_DATASIZE];
    char 	filler[256];
} EchoReply;

uint16_t in_ping_cksum(uint16_t *addr, int len);

int init_udp_socket(nw_skt_t *sock);
int init_icmp_socket(nw_skt_t *sock);
int send_echo_request(nw_skt_t sock, uint32_t addr, int seq);
int recv_echo_reply(nw_skt_t sock, uint32_t *addr, uint16_t *seq, uint64_t *rtt);

#endif
