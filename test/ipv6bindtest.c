#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <unistd.h>
#include <netdb.h>
#include <syslog.h>
#include <errno.h>

/*
 * $Id: ipv6bindtest.c,v 1.6 2003/03/31 20:51:39 mkomu Exp $
 */


/* gcc -Wall -o ipv6bindtest ipv6bindtest.c */

int main(int argc,char *argv[]) {

  int servsock;
  int peer;
  struct sockaddr_in6 addr, peeraddr;
  unsigned int peerlen;
  char readbuf[128];
  char test[INET6_ADDRSTRLEN];
  int recvnum;
  int i;
  uint32_t flowinfo;
  
  if (argc < 2) {
    printf("usage: %s port\n", argv[0]);
    return(-1);
  }

  servsock = socket(PF_INET6, SOCK_STREAM, 0);  
  if (servsock < 0) {
    perror("server: socket");
    return(-1);
  }

  flowinfo = 0;
  bzero(&addr, sizeof(addr));
  addr.sin6_port = htons(atoi(argv[1]));         /* Transport layer port # */
/*  ip6addr.in6_u = IN6ADDR_LOOPBACK_INIT;*/ /* testi */ /* IPv6 address */
  addr.sin6_addr = in6addr_any; /* testi */ /* IPv6 address */
  addr.sin6_flowinfo = flowinfo;                 /* IPv6 flow information */
  //  addr.sin6_scope_id = 0 ; // does not compile in gaijin


  if (bind(servsock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) < 0) {
    perror("server: bind");
    return(-1);
  }

  listen(servsock, 3);


  while (1) {
    peerlen = sizeof (struct sockaddr_in6);
    fprintf(stderr, "server: Waiting for a connection\n");
    peer = accept(servsock, (struct sockaddr *)&peeraddr, &peerlen);
    if (peer < 0) {
      perror("server: accept");
      exit(-1);
    }
    
    fprintf(stderr, "server: connection\n");
    fprintf(stderr, "server: client info\n");

    fprintf(stderr, "server: inet_ntop: %s\n", inet_ntop(AF_INET6, &peeraddr.sin6_addr, test, sizeof(test)));
    fprintf(stderr, "server: client info: hexaddr:");
    for (i=0; i < sizeof(struct in6_addr); i++) {
      fprintf(stderr, "%.2x",peeraddr.sin6_addr.s6_addr[i]);
    }
    fprintf(stderr, "\n");

    /* scopeid does not compile in gaijin
    fprintf(stderr, "server: client info: port=%d flowinfo=%lu scopeid=%lu\n",
	   ntohs(peeraddr.sin6_port),
	   (long unsigned) ntohl(peeraddr.sin6_flowinfo),
	   (long unsigned) ntohl(peeraddr.sin6_scope_id));
    */

    fprintf(stderr, "server: client info: port=%d flowinfo=%lu\n",
	   ntohs(peeraddr.sin6_port),
	    (long unsigned) ntohl(peeraddr.sin6_flowinfo));

    while(1) {
      recvnum = recv(peer, readbuf, sizeof(readbuf)-1, 0);
      if(recvnum <= 0)
	break;

      readbuf[recvnum]='\0';
      fprintf(stderr, "server: got %d bytes: %s", recvnum, readbuf);
    }

    close(peer);
    fprintf(stderr, "\nserver: Closed\n\n");
  }

  close(servsock);
  return(0);
}
