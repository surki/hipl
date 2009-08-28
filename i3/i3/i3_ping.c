#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include "../utils/netwrap.h"

#include "i3_ping.h"
#include "i3.h"
#include "../utils/gen_utils.h"
#include "../utils/byteorder.h"

#define ECHO_PACKET_SIZE 40
#define MAX_PACKET_SIZE 2000

/* packet offsets for seq and time */
#define i3_ping_pkt_seq_offset(p) ((p)+1)
#define i3_ping_pkt_time_offset(p) ((p)+3)


/* True if the packet is a request to the i3 server to echo the pkt */
char is_i3_echo_request(char *p)
{
    return (((*p) & I3_PING_PKT) == 1);
}


/* Echo request to an i3 server with addr and port */
void i3_echo_request(nw_skt_t fd, uint32_t addr, uint16_t port, uint16_t seq)
{
    struct sockaddr_in to_addr;
    int rc;
    char p[ECHO_PACKET_SIZE];
    
    memset((void *) &to_addr, 0, sizeof(struct sockaddr_in));
    to_addr.sin_family = AF_INET;
    to_addr.sin_addr.s_addr = htonl(addr);
    to_addr.sin_port = htons(port);

    p[0] = I3_PING_PKT;					// ping packet
    hnputs(i3_ping_pkt_seq_offset(p), seq);		// seq number
    hnput64(i3_ping_pkt_time_offset(p), wall_time());	// curr time

    // TODO: Possible problem
    rc = sendto(fd, p, ECHO_PACKET_SIZE, 0,
            (struct sockaddr *)&to_addr, sizeof(to_addr));
    if (rc < 0)
        perror("Echo request");

}


/* Echo reply (by i3_server back to monitor) */
void i3_echo_reply(nw_skt_t fd, char *p, int len, struct sockaddr_in *addr)
{
    struct sockaddr_in to_addr;
    int rc;
    
    memset((void *) &to_addr, 0, sizeof(struct sockaddr_in));
    to_addr.sin_family = AF_INET;
    to_addr.sin_addr.s_addr = htonl(addr->sin_addr.s_addr);
    to_addr.sin_port = htons(addr->sin_port);

    rc = sendto(fd, p, len, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
    if (rc < 0)
	perror("Echo reply");
}


/* Receive echo reply */
int recv_i3_echo_reply(nw_skt_t fd, uint32_t *addr, uint16_t *port,
				 uint16_t *seq, uint64_t *rtt)
{
    static char buf[MAX_PACKET_SIZE];
    struct sockaddr_in saddr;
    int len = sizeof(struct sockaddr_in);
    int rc;
    
    rc = recvfrom(fd, buf, MAX_PACKET_SIZE, 0, (struct sockaddr *)&saddr, (socklen_t *) &len);
    if (rc < 0) {
	perror("recvfrom");
	return -1;
    }
    if (I3_PING_PKT != buf[0]) {
	return -1;
    }
    *addr = ntohl(saddr.sin_addr.s_addr);
    *port = ntohs(saddr.sin_port);
    *seq = nhgets(i3_ping_pkt_seq_offset(buf));
    *rtt = wall_time() - nhget64(i3_ping_pkt_time_offset(buf));
    return 1;
}
