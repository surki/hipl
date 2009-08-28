#include "i3_tcp_fns.h"
#include "../utils/byteorder.h"
#include "i3_debug.h"

#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include "../utils/netwrap.h"

/* Purpose: Send i3 data on TCP socket 
 * Note: To avoid copying of packets, the two sends are performed */
int send_tcp(char *p, int len, nw_skt_t fd)
{
    char header[TCP_I3_HEADER_SIZE];

       
    /* Send header */
    header[0] = TCP_I3_HEADER_MAGIC;
    hnputs(header + 1, (uint16_t) len);
    
    if (send(fd, header, TCP_I3_HEADER_SIZE, 0) != TCP_I3_HEADER_SIZE) {
	    perror("TCP header send");
	    return -1;
    }

    /* Send rest of the packet */
    if (send(fd, p, len, 0) < len) {
	    perror("TCP Send");
	    return -1;
    }

    return len;
}

/* Purpose: Recv i3 data on TCP socket */
#define MAX_ATTEMPTS 10
int recv_tcp(char *p, int len, nw_skt_t fd)
{
    int recv_len, pkt_size, total_recv_len = 0, num_attempts = 0;

    if (fd < 0) {
        //TODO XXX Fix this..
        I3_PRINT_DEBUG1 (I3_DEBUG_LEVEL_VERBOSE, "invalid fd = %d\n",fd);
        return -1;
    }

    /* recv header */
    recv_len = recv(fd, p, TCP_I3_HEADER_SIZE, 0);
    if (recv_len < 0) {
	    perror("TCP header recv");
        fprintf (stderr, " on fd %d\n\n", fd);
        nw_close (fd);
	    return recv_len;
    }
    
    /* recv rest of the packet */
    if (recv_len > 0) {
      if( (TCP_I3_HEADER_MAGIC != p[0]) ||	// Invalid packet; Not i3?
	  (recv_len < TCP_I3_HEADER_SIZE) ) {
	I3_PRINT_INFO1 (I3_INFO_LEVEL_WARNING,
		    "Invalid i3 tcp header on fd %d\n", fd);
	return -1;
      }
      pkt_size = nhgets(p + 1);
      if (len < pkt_size) {	// Invalid size
	I3_PRINT_INFO2 (I3_INFO_LEVEL_WARNING,
		    "Invalid i3 tcp packet size %d (on fd %d)\n",
		    pkt_size, fd);
	return -1;
      }      

	    while (pkt_size > 0 && num_attempts++ < MAX_ATTEMPTS) {
	        recv_len = recv(fd, p, pkt_size, 0);
	        total_recv_len += recv_len;
	        pkt_size -= recv_len;
	        p += recv_len;
	    }
    }
    
    /* Hack! */
    if (pkt_size > 0) {
	    I3_PRINT_DEBUG0(I3_DEBUG_LEVEL_MINIMAL, "Still some more bytes to be received, quitting!\n");
	    return -1;
    } else {
	    return total_recv_len;
    }
}
