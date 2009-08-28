#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif


#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>


/*
 *
 * Dumps IPv6 packet
 *
 * $Id: recvrawdatapkt.c,v 1.2 2003/03/31 20:51:39 mkomu Exp $
 * compile: gcc -Wall -o recvrawdatapkt recvrawdatapkt.c
 *
 */



void printdata2(char *mem, int length, int cols) {
  int i,j;
  unsigned char c;
  
  if (cols < 1) cols=1;

  printf("HEXDATA(%d):\n",length);

  for(i=0; i < length ; i+=cols*4) {
      printf("\n%4d: ",i);

      /* asciidump */
      /* if(show_asciidump) */
      for(j=i; (j < (i+cols*4)) && (j < length); j++) {
        c=(char)mem[j];
        if (c>31 && c<127) /* 128 = DEL */
          putchar(c);
        else
          putchar('.');  /* ei-tulostettavat merkit, kontrollimerkit yms. */
      }

      /* if(show_hexdump) */

      /* aseta viimeisen rivin alignmentti */
      if(j==length)
	while((j++%(cols*4)))
	  putchar(' ');

      /* hexdump */
      for(j=i; (j < (i+cols*4)) && (j < length); j++) {
	if (!(j%4)) putchar(' ');
	printf("%.2X",(unsigned char)mem[j]);
      }

  }
  printf("\n");
  return;
}

int main(int argc,char **argv) {

  int s, n;
  struct sockaddr *from;
  int fromlen;

  char packet[100000];

  s=socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
  if(s < 0) {
    perror("got r00t ? Raw socket");
    exit(EACCES);
  }

  printf("start loop\n");

  while(1) {
    bzero((char *)&packet,sizeof(packet));
    fromlen = sizeof(struct sockaddr);

    n = recvfrom(s, (void *)&packet, sizeof(packet), 0, from, (socklen_t *)&fromlen);

    if (n>0) {
      printdata2((char *)&packet, n ,5);
    } else {   
      /*      printf("n<0\n");*/
      /*      exit(errno);*/
    }

    fflush(stdout);
  }

  close(s); 
  return 0;
}
