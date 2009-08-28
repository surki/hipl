/*
 * $Id: stdinserver.c,v 1.3 2003/10/03 11:40:19 mika Exp $
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

int create_serversocket(int proto, int port) {
  int fd;
  struct sockaddr_in6 addr;
  
  if (proto == IPPROTO_TCP) {
    fd = socket(AF_INET6, SOCK_STREAM, 0);
  } else {
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
  }
  if (fd < 0) {
    perror("socket");
    exit(1);
  }

  bzero(&addr, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(port);
  addr.sin6_addr = in6addr_any;
  addr.sin6_flowinfo = 0;

  if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) < 0) {
    perror("bind");
    close(fd);
    exit(1);
  }

  if (proto == IPPROTO_TCP) {
    if (listen(fd, 1) < 0) {
      perror("listen");
      close(fd);
      exit(1);
    }
  }

  return(fd);
}


// usage: ./conntest-client host tcp|udp port
// reads stdin

int main(int argc,char *argv[]) {

  int servsock;
  struct sockaddr_in6 peeraddr;
  char mylovemostdata[IP_MAXPACKET];
  char receiveddata[IP_MAXPACKET];
  int sendnum;
  int port = 0;
  int proto;
  int k;
  int peer;
  int peerlen; 
   
  if (argc != 3) {
    fprintf(stderr, "Usage: %s tcp|udp port\n", argv[0]);
    exit(1);
  }

  if (strcmp(argv[1], "tcp") == 0) {
    proto = IPPROTO_TCP;
  } else if (strcmp(argv[1], "udp") == 0) {
    proto = IPPROTO_UDP;
  } else {
    fprintf(stderr, "error: proto != tcp|udp\n");
    exit(1);
  }

  port = atoi(argv[2]);
  if (port <= 0 || port >= 65535) {
    fprintf(stderr, "error: port < 0 || port > 65535\n");
    exit(1);
  }

  servsock = create_serversocket(proto, port);

  /* set server info */
  bzero(&peeraddr, sizeof(struct sockaddr_in6));
  peeraddr.sin6_family = AF_INET6;
  peeraddr.sin6_port = htons(port);
  peeraddr.sin6_flowinfo = 0;

  // data from stdin to buffer
  bzero(receiveddata, sizeof(receiveddata));
  bzero(mylovemostdata, sizeof(mylovemostdata));

    peer = accept(servsock, (struct sockaddr *)&peeraddr, &peerlen);
    if (peer < 0) {
      perror("accept");
      exit(2);
    }

  while ((k = fread(mylovemostdata,1,sizeof(mylovemostdata),stdin)) > 0) 
  {
	sendnum = send(peer, mylovemostdata, k, 0);
	if (sendnum < 0) {
		perror("sendnum");
		break;
	}
  }

  close(peer);
  close(servsock);
  return(0);
}
