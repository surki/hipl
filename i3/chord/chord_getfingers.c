/* This file implements chord_getfingers command.
 *
 * Syntax: chord_getfingers [-all] <node_IP_addr> <port>
 *
 *  node_IP_addr, port - IP address and the port number of a Chord node
 *  -all - if this parameter is specified, the command displays
 *         the information about each node in the system. Otherwise, it
 *         displays only the information about the Chord node whose 
 *         address and port number are specified in the command line.
 *
 *         The node-related information includes its finger list. Associated 
 *         to each finger, the command displays the mean value and standard 
 *         deviation of the round-trip-time.
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
#define CLIENT_PORT 11355
#define KEY_FILE "key.txt"
#define MAX_RETRIES    3


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

int main(int argc, char *argv[]) 
{
  Key    key;
  int    in_sock, out_sock, len, rc;
  int    argc_idx = 0, flag_all = FALSE;
  ulong  chordsrv_addr, client_addr;
  ushort chordsrv_port, client_port;
  struct sockaddr_in chordsrv;
  struct sockaddr_in sin, sout;
  struct hostent *h;
  fd_set fdset;
  int    nfds;
  int    retries = 0;
  byte buf[BUFSIZE];
  chordID id;

  /* check command line args */
  if(argc < 3) 
    eprintf("usage: %s [-all] <node_IP_addr> <port>\n", argv[0]);

  if (argc == 4) {
    if (strcmp(argv[1], "-all")) {
      eprintf("usage: %s [-all] <node_IP_addr> <port>\n", argv[0]);
    } else {
      argc_idx++;
      flag_all = TRUE;
    }
  }

  /* i3 server address and port number */
  h = gethostbyname(argv[argc_idx+1]);
  if(h==NULL) {
    printf("%s: unknown host '%s' \n", argv[0], argv[argc_idx+1]);
    exit(1);
  }
  assert(h->h_length == sizeof(long));
  memcpy((char *) &chordsrv_addr, h->h_addr_list[0], h->h_length);
  chordsrv_addr = ntohl(chordsrv_addr);
  chordsrv_port = (ushort)atoi(argv[argc_idx+2]);

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
    len = pack_fingers_get(buf, client_addr, client_port, &key);
    rc = sendto(out_sock, buf, len, 0, 
		(struct sockaddr *)&chordsrv, sizeof(chordsrv));
    if(rc < 0) {
      eprintf("cannot send data, errno: %d \n", errno);
      break;
    }    
    len = recv_packet(in_sock, fdset, nfds, buf, sizeof(buf),
		      chordsrv_addr, chordsrv_port);

    /* len == -1 -> no answer; the chord node is either done, or
     * the message has been lost, or the acclist.txt is missing
     * at the chord node or it doesn't contain the proper key 
     */
    if (len == -1 && retries < MAX_RETRIES) {
      retries++;
      continue;
    }
    if (len == -1) {
      /* no answer has been received from the chord node 
       * after MAX_RETRIES retries 
       */
      printf("... giving up...\n");
      printf("\nAlso, check whether file %s exists at the chord node,\n",
	     ACCLIST_FILE); 
      printf("and if does, check whether it contains the key in %s\n",
	     KEY_FILE);
      printf("(see README for details).\n");
      break;
    }
    if (unpack_print_getnext(buf, len, &chordsrv_addr, &chordsrv_port)) {
      chordsrv.sin_addr.s_addr = htonl(chordsrv_addr); 
      chordsrv.sin_port = htons(chordsrv_port);
      retries = 0;
      if (flag_all == FALSE)
	break;
    } else
      break;
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
static int unpack_print_getnext(char *buf, int n, 
				ulong *succ_addr, ushort *succ_port)
{
  chordID id;
  char    type;
  ulong   addr, rtt_avg, rtt_dev;
  ushort  port, npings;
  int     len, i, ret_code;
  struct  in_addr ia;
  static IDitem *head_list = NULL;

  len = unpack(buf, "cxls", &type, &id, (ulong*)&addr, (ushort*)&port);
  assert(type == CHORD_FINGERS_REPL);

  if (find_chordID(head_list, &id) == TRUE) {
    return FALSE;
  } else {
    head_list = add_chordID(head_list, &id);
  }
  printf("\nID=("); print_chordID(&id);
  ia.s_addr = htonl(addr);
  printf("), addr=(%s:%d)\n", inet_ntoa(ia), port);

  if (len >= n-1) 
    return FALSE;

  i = 0;
  do {
    len += unpack(buf + len, "xlslls", &id, &addr, &port, 
		  &rtt_avg, &rtt_dev, &npings);

    *succ_addr = addr;
    *succ_port = port;

    printf("  F[%d]: ID=(", i++); print_chordID(&id);
    ia.s_addr = htonl(addr);
    printf("), addr=(%s:%d)\n", inet_ntoa(ia), port);
    printf("        rtt_avg = %5.2f ms, rtt_stdev = %5.2f ms\n",
	   (float)rtt_avg/1000., (float)rtt_dev/1000.);

  } while (len + 1 < n);

  if (len+1 > n) 
    return FALSE;
  
  unpack(buf + len, "c", &ret_code);
  return TRUE;
}

static IDitem *add_chordID(IDitem *head, chordID *id)
{
  IDitem *item;

  if ((item = calloc(1, sizeof(IDitem))) == NULL) {
    eprintf("memory allocation error\n");
  } else 
    copy_id(&item->id, id);
    
  item->next = head;
  return item;
}


/* search a chord ID in the list; use linear search 
 * for now--should change it later...
 */
static int find_chordID(IDitem *head, chordID *id)
{
  IDitem *item = head;

  for (; item; item = item->next) {
    if (equals(&item->id, id))
      return TRUE;
  }
  return FALSE;
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
	  printf("recvfrom failed.");  
	  continue;
	}
	weprintf("try again...");
	continue;   
      }
      return len;
    }
  }
}
