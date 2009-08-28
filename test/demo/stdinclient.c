/*
 * $Id: stdinclient.c,v 1.3 2003/10/03 11:42:05 mika Exp $
 */

#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>

int create_socket(int proto) {
  int fd;

  if (proto == IPPROTO_TCP) {
    fd = socket(AF_INET6, SOCK_STREAM, 0);
  } else if (proto == IPPROTO_UDP)  {
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
  } else {
    perror("unhandled proto");
    exit(1);
  }

  if (fd < 0) {
    perror("socket");
    exit(1);
  }

  return(fd);
}


// usage: ./conntest-client host tcp|udp port
// reads stdin

int main(int argc,char *argv[]) {

  int sock;
  struct sockaddr_in6 peeraddr;
  char mylovemostdata[IP_MAXPACKET];
  char receiveddata[IP_MAXPACKET];
  int sendnum;
  int port = 0;
  int proto;
  int k;

  if (argc != 4) {
    fprintf(stderr, "Usage: %s host tcp|udp port\n", argv[0]);
    exit(1);
  }

  if (strcmp(argv[2], "tcp") == 0) {
    proto = IPPROTO_TCP;
  } else if (strcmp(argv[2], "udp") == 0) {
    proto = IPPROTO_UDP;
  } else {
    fprintf(stderr, "error: proto != tcp|udp\n");
    exit(1);
  }

  port = atoi(argv[3]);
  if (port <= 0 || port >= 65535) {
    fprintf(stderr, "error: port < 0 || port > 65535\n");
    exit(1);
  }

  sock = create_socket(proto);

  /* set server info */
  bzero(&peeraddr, sizeof(struct sockaddr_in6));
  peeraddr.sin6_family = AF_INET6;
  peeraddr.sin6_port = htons(port);
  peeraddr.sin6_flowinfo = 0;
  if(inet_pton(AF_INET6, argv[1], (struct in6_addr *) &peeraddr.sin6_addr) < 0) {
    perror("inet_pton");
    exit(1);
  }

  // data from stdin to buffer
  bzero(receiveddata, sizeof(receiveddata));
  bzero(mylovemostdata, sizeof(mylovemostdata));

  if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
    if (connect(sock, (struct sockaddr *) &peeraddr, sizeof(struct sockaddr_in6)) < 0) {
      perror("connect");
      exit(1);
    }
  }

  while ((sendnum = recv(sock,mylovemostdata,sizeof(mylovemostdata),0)) > 0)
  {

    fwrite(mylovemostdata,1,sendnum,stdout);
    fflush(stdout);
    
  }

  close(sock);
  return(0);
}
