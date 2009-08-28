/* This file implements chord_traceroute command.
 *
 * Syntax: chord_traceroute <id> <node_IP_addr> <port>
 *
 *  id - target ID
 *  node_IP_addr, port - IP address and the port number of a Chord node
 *        from where we originate the traceroute
 *
 *        This command dispalys the chord route to the node that is 
 *        responsibe for target ID (id) starting from the originator node.
 *        
 *  Note: This command doesn't work behind NATs and firewalls.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "chord.h"
//#include "../../utils/gen_utils.h"

#define SELECT_TIMEOUT 2
#define MAX_RETRIES    3
#define CLIENT_PORT 11355
#define KEY_FILE "key.txt"


typedef struct iditem_ {
  chordID id;
  struct iditem_ *next;
} IDitem;

static int unpack_print_getnext(char *buf, int n, ulong *succ_addr, 
				ushort *succ_port);
static IDitem *add_chordID(IDitem *head, chordID *id);
static int find_chordID(IDitem *head, chordID *id);
static int recv_packet(int in_sock, fd_set fdset, int nfds, 
		       char *buf, int buf_len,
		       ulong chordsrv_addr, ulong chordsrv_port);
static int pack_client_traceroute(uchar *buf, byte ttl, chordID *id, 
				  ulong client_addr, ushort client_port);
static int unpack_client_traceroute_repl(char *buf, int n, int orig_ttl,
					 ulong chordsrv_addr, 
					 ushort chordsrv_port);

int main(int argc, char *argv[]) 
{
  Key    key;
  int    in_sock, out_sock, len, rc;
  ulong  chordsrv_addr, client_addr;
  ushort chordsrv_port, client_port;
  struct sockaddr_in chordsrv;
  struct sockaddr_in sin, sout;
  struct hostent *h;
  uchar  ttl = 1;
  fd_set fdset;
  int    nfds, i;
  int    retries = 0;
  byte buf[BUFSIZE];
  chordID id;

  /* check command line args */
  if (argc != 4) 
    eprintf("usage: %s <id> <node_IP_addr> <port>\n", argv[0]);

  for (i = 0; i < ID_LEN; i++) {
    char tmp[3];
    char  t;

    tmp[0] = argv[1][2*i]; 
    tmp[1] = argv[1][2*i+1]; 
    tmp[2] = 0;
    sscanf(tmp, "%x", &id.x[i]);
  }

  /* chord server address and port number */
  h = gethostbyname(argv[2]);
  if(h==NULL) {
    printf("%s: unknown host '%s' \n", argv[0], argv[2]);
    exit(1);
  }
  assert(h->h_length == sizeof(long));
  memcpy((char *) &chordsrv_addr, h->h_addr_list[0], h->h_length);
  chordsrv_addr = ntohl(chordsrv_addr);
  chordsrv_port = (ushort)atoi(argv[3]);

  /* get client's address */
  client_addr = ntohl(get_addr());
  client_port = CLIENT_PORT;

  /* create socket to receieve packets */
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(client_port);
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  
  in_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (in_sock < 0)
    eprintf("incoming socket failed:");
  if (bind(in_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
    eprintf("bind to incoming socket failed:");
  
  /* create outgoing socket */  struct  in_addr ia;

  memset(&sout, 0, sizeof(sout));
  sout.sin_family = AF_INET;
  sout.sin_port = htons(0);
  sout.sin_addr.s_addr = htonl(INADDR_ANY);
  out_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (out_sock < 0)
    eprintf("outgoing socket failed:");
  if (bind(out_sock, (struct sockaddr *) &sout, sizeof(sout)) < 0)
    eprintf("bind to outgoing socket failed:");

  
  /* create CHORD_FINGERS_GET message */
  rc = read_keys(KEY_FILE, &key, 1); 
  if (rc < 1) {
    close(in_sock);;
    close(out_sock);
    if (rc == -1) 
      eprintf("Error opening file: %s\n", KEY_FILE);
    if (rc == 0) 
      eprintf("No key found in %s\n", KEY_FILE);
  }
  len = pack_fingers_get(buf, client_addr, client_port, &key);

  chordsrv.sin_family = h->h_addrtype;
  chordsrv.sin_addr.s_addr = htonl(chordsrv_addr); 
  chordsrv.sin_port = htons(chordsrv_port);

  FD_ZERO(&fdset);
  FD_SET(in_sock, &fdset);
  nfds = in_sock + 1;

  for (;;) {
    /* send CHORD_FINGERS_GET request */
    len = pack_client_traceroute(buf, ttl, &id, client_addr, client_port);
    rc = sendto(out_sock, buf, len, 0, 
		(struct sockaddr *)&chordsrv, sizeof(chordsrv));
    if(rc < 0) {
      printf("cannot send data, errno: %d \n", errno);
      return -1;
    }
    
    len = recv_packet(in_sock, fdset, nfds, buf, sizeof(buf),
		      chordsrv_addr, chordsrv_port);
    
    if (len == -1 && retries < MAX_RETRIES) {
      retries++;
      continue;
    }
    if (len == -1 || 
	(!unpack_client_traceroute_repl(buf, len, ttl,
					chordsrv_addr, chordsrv_port))) {
      if (len == -1) {
	printf("... giving up...\n");
	printf("\nAlso, check whether file %s exists at the chord node,\n",
	       ACCLIST_FILE); 
	printf("and if does, check whether it contains the key in %s\n",
	       KEY_FILE);
	printf("(see README for details).\n");
      }
      break;
    }
    else {
      retries = 0;
      ttl++;
    }
  }

  close(in_sock);;
  close(out_sock);
  printf("\n");

  return 1;
}


/* this function unpacks the CHORD_FINGERS_REPL message 
 * and prints its content
 *
 * the function returns TRUE if the successor of the Chord node
 * has not been visited so far, and FALSE otherwise.
 * the functions also returns the successor address and port
 * number in succ_addr and succ_port variables
 */
static int unpack_client_traceroute_repl(char *buf, int n, int orig_ttl,
					 ulong chordsrv_addr, 
					 ushort chordsrv_port)
{
  chordID id;
  char    type;
  ulong   addr;
  ushort  port; 
  ulong   rtt_avg, rtt_dev;
  int     len;
  uchar   ttl, hops;
  struct  in_addr ia;

  len = unpack(buf, "cccx", &type, &ttl, &hops, &id);

  assert(type == CHORD_TRACEROUTE_REPL);

  if (orig_ttl == 1) {
    /* print the last link of the traceroute path */
    len += unpack(buf + len, "xls", &id, &addr, &port);
    
    printf("First hop: (");
    print_chordID(&id);
    ia.s_addr = htonl(addr);
    printf("), (%s:%d))\n", inet_ntoa(ia), port);
    return TRUE;
  } 

  if (ttl)
    /* the last hop has been already returned in the previous call */ 
    return FALSE;

  /* print the last link of the traceroute path */
  len += unpack(buf + len, "xlsll", &id, &addr, &port, &rtt_avg, &rtt_dev);
  
  printf("\n(");
  print_chordID(&id);
  ia.s_addr = htonl(addr);
  printf("), (%s:%d)) --> \n", inet_ntoa(ia), port);
  
  len += unpack(buf + len, "xls", &id, &addr, &port);
  printf("   (");
  print_chordID(&id);
  ia.s_addr = htonl(addr);
  printf("), (%s:%d))\n", inet_ntoa(ia), port);
  
  printf("        rtt_avg = %5.2f ms, rtt_stdev = %5.2f ms\n",
	 (float)rtt_avg/1000., (float)rtt_dev/1000.);
  return TRUE;
}

static int recv_packet(int in_sock, fd_set fdset, int nfds, 
		       char *buf, int buf_len,
		       ulong chordsrv_addr, ulong chordsrv_port)
{
  fd_set readset;
  int    nfound, from_len, len;
  struct timeval timeout;
  struct sockaddr_in from;

  for (;;) {
    readset = fdset;
    /* set a timeout in case we cannot contact the Chord node */
    timeout.tv_sec = SELECT_TIMEOUT;
    timeout.tv_usec = 0;
    nfound = select(nfds, &readset, NULL, NULL, &timeout);

    if (nfound < 0 && errno == EINTR) {
      continue;
    }
    if (nfound == 0) {
      /* timeout expired */
      struct  in_addr ia;
      ia.s_addr = htonl(chordsrv_addr);
      printf("\nCouldn't contact node (%s:%d), try again...\n", 
	     inet_ntoa(ia), chordsrv_port);
      return -1;
    }
    if (FD_ISSET(in_sock, &readset)) {
      /* this is the reply from the Chord node */
      from_len = sizeof(from);
      len = recvfrom(in_sock, buf, buf_len, 0,
		       (struct sockaddr *)&from, &from_len);
      if (len < 0) {
	if (errno != EAGAIN) {
	  printf("recvfrom failed; ");  
	  continue;
	}
	weprintf("try again...");
	continue;   
      }
      return len;
    }
  }
}


/**********************************************************************/

/* pack_client_traceroute: pack traceroute packet */
/* 
 * traceroute packet format:
 *    char pkt_type; 
 *    char ttl; time to live, decremented at every hop. 
 *              When ttl reaches 0, a traceroute_repl packet is returned.
 *    char hops; number of hops up to the current node (not including the
 *               client). hops is inceremented at every hop along the 
 *               forward path. hops should be initialized to 0 by the clients. 
 *    ID target_id;   target ID for traceroute.
 *    Node prev_node; previous node (ie., the node which forwarded the packet) 
 *    ulong rtt; rtt...
 *    ulong dev; ... and std dev frm previous node to this node (in usec)  
 *    Node crt_node; this node
 *    (list of addresses/ports of the nodes along the traceroute path 
 *     up to this node)
 *    ulong addr;  address...   
 *    ushort port; ... and port number of the client
 *    ....
 */
static int pack_client_traceroute(uchar *buf, uchar ttl, chordID *id, 
				  ulong client_addr, ushort client_port)
{
  int   n = 0;

  /* pack type, ttl, hops, and target id fields */
  n = pack(buf+n, "cccx", CHORD_TRACEROUTE, ttl, 0, id);

  /* skip prev node and next node fields */
  n += sizeof_fmt("xlsllxls");

  /* add client's address to the list of addresses .. */
  n += pack(buf+n, "ls", client_addr, client_port);
  
  return n;
}
