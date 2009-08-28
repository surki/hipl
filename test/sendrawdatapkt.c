#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif



/*
 * $Id: sendrawdatapkt.c,v 1.6 2003/03/31 20:51:39 mkomu Exp $
 *
 * compile: gcc -Wall -o sendrawdatapkt sendrawdatapkt.c
 *
 */

static char fixedpacket[] = {
  /* ping6 gaijin */
  0x60,0x00,0x00,0x00,0x00,0x40,0x3A,0x40,0x3F,0xFE,0x26,0x20,0x00,0x10,0x00,0x01,0x02,0x60,0x08,0xFF,0xFE,0x09,0xEB,0xA6,0x3F,0xFE,0x26,0x20,0x00,0x10,0x00,0x01,0x02,0xA0,0xC9,0xFF,0xFE,0xDB,0xA7,0xFD,0x80,0x00,0xEA,0x67,0xBD,0x61,0x00,0x00,0xA1,0xE7,0x73,0x3C,0xA0,0xAC,0x02,0x00,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37
};


/* set MAC address from addr (ascii) to dst */
void set_mac(char *addr, unsigned char *dst) {
  int i, j=0, k=8, n=1;
  unsigned val = 0;

  for (i = 0; i < strlen(addr); i++) {
    char c = tolower(*(addr+i));

    if (c == ':') {
      if (j >= (ETH_ALEN-1)) {
	printf("error: too long MAC addr\n");
	exit(1);
      }
      dst[j] = val;
      j++; k=8; val=0, n=1;
      continue;
    } else if (c >= '0' && c <= '9') {
      val <<= 4; /* * 16 */
      val += c-'0';
    } else if (c >= 'a' && c <= 'f') {
      val <<= 4; /* * 16 */
      val += c-'a'+10;
    } else {
      printf("error, char='%c'\n", c);
      exit(1);
    }
    k >>= 4;

    if (n > 2) {
      printf("argv1: error at pos %d\n", i);
      exit(1);
    }
    n++;
  }

  dst[j] = val;

  if (j != (ETH_ALEN-1)) {
    printf("error: too short MAC addr (%d != 6)\n", j+1);
    exit(1);
  }

  /* for (i = 0; i < ETH_ALEN; i++) {printf("DEBUG: loppu x[%d]=%x\n", i, dst[i]);} */
}



/* hexdump of mem..mem+length */
void printdata(char *mem, int length, int cols) {
  int i,j;
  unsigned char c;
  
  if (cols < 1) cols=1;

  printf("HEXDATA(%d):\n",length);

  for(i=0; i < length ; i+=cols*4) {
    printf("\n%4d: ",i);

    /* asciidump */
    for(j=i; (j < (i+cols*4)) && (j < length); j++) {
      c=(char)mem[j];
      if (c>31 && c<127) /* 128 = DEL */
	putchar(c);
      else
	putchar('.');  /* ei-tulostettavat merkit, kontrollimerkit yms. */
    }

    /* aseta viimeisen rivin alignmentti */
    if(j==length)
      while((j++%(cols*4)))
	putchar(' ');

    /* hexdump */
    for(j=i; (j < (i+cols*4)) && (j < length); j++) {
      if (!(j%4)) putchar(' ');
      printf("%.2X",(unsigned char) mem[j]);
    }

  }
  printf("\n");
  return;
}


/* send packet buf (len = packet length) to MAC dst_mac */
/* retval = bytes sent */
int sendpacket(char *dst_mac, const void *buf, int len) {

  int sock;
  struct sockaddr_ll s_ll;
  struct ifreq ifr;
  int tolen;
  int n;

  bzero((void *) &s_ll,sizeof(struct sockaddr_ll));

  s_ll.sll_family = AF_PACKET;
  s_ll.sll_halen = ETH_ALEN;
  s_ll.sll_protocol = htons(ETH_P_IPV6);
  s_ll.sll_hatype = 0;
  s_ll.sll_pkttype = 0;

  set_mac(dst_mac, &s_ll.sll_addr[0]);   /* 00:A0:C9:DB:A7:FD=gaijin */

  sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
  if(sock < 0) {
    perror("got r00t ? Raw socket");
    exit(EACCES);
  }

  /* fixed ethdevice, kludge */
  strncpy((char *) &ifr.ifr_name, "eth0", IFNAMSIZ);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl SIOCGIFINDEX");
    close(sock);
    exit(1);
  }

  s_ll.sll_ifindex = ifr.ifr_ifindex;
  tolen = sizeof(struct sockaddr_ll);

  n = sendto(sock, buf, len, 0, (struct sockaddr *) &s_ll, tolen);

  if (n>0) {
    fprintf(stderr, "sp: sendto: n=%d\n", n);
  } else {   
    fprintf(stderr, "sp: error: n<0\n");
  }

  close(sock);
  return(n);
}


int main(int argc,char **argv) {

  int n;

  int packetlen;
  char packet[ETH_DATA_LEN];  /* eth 1500 */

  if (argc < 2) {
    printf("%s: MAC [file]\n", argv[0]);
    exit(0);
  }

  /* argument ? y: packet=file n: packet=fixed packet*/
  if (argc > 2) {
    int fd;
    int maxreadlen = sizeof(packet);
    int readbytes = 0;
    int n;

    printf("using custom packet from file %s\n", argv[2]);
    fd = open(argv[2], O_RDONLY);
    if (fd < 0) {
      perror("open error");
      exit(errno);
    }

    while (maxreadlen > 0) {
      n = read(fd, packet+readbytes, maxreadlen);
      readbytes += n;
      /* printf("n= %d, readbytes = %d\n", n, readbytes); */
      if (n <= 0)
	break;
      maxreadlen -= readbytes;
      /* printf("maxreadlen = %d\n", maxreadlen); */
    }

    close(fd);
    packetlen = readbytes;
  } else {
    /* printf("using fixed packet\n"); */
    packetlen = sizeof(fixedpacket);
    memcpy(&packet, fixedpacket, packetlen);
  }

  printf("packetlen = %d\nhexdump of packet:\n\n", packetlen);
  printdata((char *)packet, packetlen, 4);
  printf("\n");

  n = sendpacket(argv[1], (const void *)&packet, packetlen);

  if (n>0) {
    printf("sendto: n=%d bytes\n", n);
  } else {
    perror("sendto error (n<=0)");
  }

  return(0);
}
