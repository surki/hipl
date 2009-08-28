#include <stdio.h> 
#include <stdlib.h> 
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <unistd.h>
#include <netdb.h>

/*
 * $Id: ipv6conntest.c,v 1.3 2003/03/31 20:51:39 mkomu Exp $
 *
 * IPv6 testing program
 *
 */


/* gcc -Wall -o ipv6conntest ipv6conntest.c */

int main(int argc,char **argv) {
    int sockfd;
    struct sockaddr_in6 addr;
    char buf[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G' };
    unsigned int port;

    char test[INET6_ADDRSTRLEN];

    if(argc < 3) { 
	printf("anna hostname ja portti\n");
	exit(1);
    }
    
    if (atoi(argv[2]) < 1) {
	printf("portti > 0\n"); 
	exit(1);
    }

    port=atoi(argv[2]);

/*    memset(&buf, 'A', sizeof(buf));*/

    bzero(&addr, sizeof(struct sockaddr_in6));

    if(inet_pton(AF_INET6, argv[1], (struct in6_addr *) &addr.sin6_addr) < 0) {
      printf("client: inet_pton < 0\n");
      exit(-1);
    }

    printf("client: inet_ntop: %s\n", inet_ntop(AF_INET6, (struct in6_addr *) &addr.sin6_addr, test, sizeof(test)));

/*    memcpy((char *)&addr.sin6_addr, argv[1], sizeof(struct in6_addr));*/
    addr.sin6_family = AF_INET6;
    addr.sin6_flowinfo = 0;
    addr.sin6_port=htons(port);

    if ((sockfd=socket(PF_INET6, SOCK_STREAM, 0)) < 0) {
      perror("client: socket");
      return(-1);
    }

    if (connect(sockfd,(struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) < 0) {
      printf("client: connection failed!\n");
    } else {
      printf("client: ok, port=%d", port);
      printf("client: sent %d bytes\n",write(sockfd,buf,sizeof(buf)));
    }

    close(sockfd);
    return 0;
}
