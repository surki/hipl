/* Chord server loop */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include "chord.h"
#include "../utils/gen_utils.h"

/* globals */
extern Server *srv_ref;	/* For use in stabilize() */
Server srv;
Node well_known[MAX_WELLKNOWN];
int nknown;
Key KeyArray[MAX_KEY_NUM];
int NumKeys;

void initialize(Server *srv);
void handle_packet(int network);
int read_keys(char *file, Key *keyarray, int max_num_keys);


/**********************************************************************/

void
chord_main(char *conf_file, int parent_sock)
{
    fd_set interesting, readable;
    int nfound, nfds;
    struct in_addr ia;
    char id[4*ID_LEN];
    FILE *fp;
    int64_t stabilize_wait;
    struct timeval timeout;
    
    setprogname("chord");
    srandom(getpid() ^ time(0));
    memset(&srv, 0, sizeof(Server));
    srv.to_fix_finger = NFINGERS-1;

    fp = fopen(conf_file, "r");
    if (fp == NULL)
	eprintf("fopen(%s,\"r\") failed:", conf_file);
    if (fscanf(fp, "%hd", (short*)&srv.node.port) != 1)
        eprintf("Didn't find port in \"%s\"", conf_file);
    if (fscanf(fp, " %s\n", id) != 1)
        eprintf("Didn't find id in \"%s\"", conf_file);
    srv.node.id = atoid(id);

    /* Figure out one's own address somehow */
    srv.node.addr = ntohl(get_addr());

    ia.s_addr = htonl(srv.node.addr);
    fprintf(stderr, "Chord started.\n");
    fprintf(stderr, "id="); print_id(stderr, &srv.node.id); 
    fprintf(stderr, "\n");
    fprintf(stderr, "ip=%s\n", inet_ntoa(ia));
    fprintf(stderr, "port=%d\n", srv.node.port);

    initialize(&srv);
    srv_ref = &srv;
    join(&srv, fp);
    fclose(fp);

    FD_ZERO(&interesting);
    FD_SET(srv.in_sock, &interesting);
    FD_SET(parent_sock, &interesting);
    nfds = MAX(srv.in_sock, parent_sock) + 1;

    NumKeys = read_keys(ACCLIST_FILE, KeyArray, MAX_KEY_NUM);
    if (NumKeys == -1) {
      printf("Error opening file: %s\n", ACCLIST_FILE);
    }
    if (NumKeys == 0) {
      printf("No key found in %s\n", ACCLIST_FILE);
    }

    /* Loop on input */
    for (;;) {
	readable = interesting;
	stabilize_wait = (int64_t)(srv.next_stabilize_us - wall_time());
	stabilize_wait = MAX(stabilize_wait,0);
	timeout.tv_sec = stabilize_wait / 1000000UL;
	timeout.tv_usec = stabilize_wait % 1000000UL;
	nfound = select(nfds, &readable, NULL, NULL, &timeout);
	if (nfound < 0 && errno == EINTR) {
            continue;
	}
	if (nfound == 0) {
	    stabilize_wait = (int64_t)(srv.next_stabilize_us - wall_time());
	    if( stabilize_wait <= 0 ) {
	        stabilize( &srv );
	    }
	    continue;
	}
	if (FD_ISSET(srv.in_sock, &readable)) {
	    handle_packet(srv.in_sock);
	}
	else if (FD_ISSET(parent_sock, &readable)) {
	    handle_packet(parent_sock);
	}
	else {
	    assert(0);
	}
    }
}

/**********************************************************************/

/* initialize: set up sockets and such <yawn> */
void 
initialize(Server *srv)
{
    int flags;
    struct sockaddr_in sin, sout;

    setservent(1);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(srv->node.port);
    sin.sin_addr.s_addr = htonl(INADDR_ANY);

    srv->in_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv->in_sock < 0)
	eprintf("socket failed:");
    
    if (bind(srv->in_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0)
	eprintf("bind failed:");
	
    /* non-blocking i/o */
    flags = fcntl(srv->in_sock, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(srv->in_sock, F_SETFL, flags);

    /* outgoing socket */
    memset(&sout, 0, sizeof(sout));
    sout.sin_family = AF_INET;
    sout.sin_port = htons(0);
    sout.sin_addr.s_addr = htonl(INADDR_ANY);

    srv->out_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv->out_sock < 0)
	eprintf("socket failed:");

    if (bind(srv->out_sock, (struct sockaddr *) &sout, sizeof(sout)) < 0)
	eprintf("bind failed:");
}

/**********************************************************************/

/* handle_packet: snarf packet from network and dispatch */
void
handle_packet(int network)
{
    int packet_len, from_len;
    struct sockaddr_in from;
    byte buf[BUFSIZE];

    from_len = sizeof(from);
    packet_len = recvfrom(network, buf, sizeof(buf), 0,
			  (struct sockaddr *) &from, &from_len);
    if (packet_len < 0) {
       if (errno != EAGAIN) {
	   weprintf("recvfrom failed:");  /* ignore errors for now */
	   return;
       }
       weprintf("handle_packet: EAGAIN");
       return;   /* pick up this packet later */
    }
    dispatch(&srv, packet_len, buf);
}


/**********************************************************************/

int
read_keys(char *file, Key *keyarray, int max_num_keys)
{
  int   i;
  FILE *fp;

  fp = fopen(file, "r");
  if (fp == NULL) 
    return -1;

  for (i = 0; i < max_num_keys; i++) {
    if (fscanf(fp, "%20c\n", &keyarray[i]) != 1) 
      break;
  }
  return i;
  
  fclose(fp);
}


