/*
 * getaddrinfo test program
 *
 * $Id: libinet6test.c,v 1.7 2003/06/26 20:31:12 mkomu Exp $
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>


int main(int argc, char **argv) {

  int a;
  struct addrinfo hints;
  struct addrinfo *res;
  struct addrinfo *ai;

  if (argc != 2) {
    printf("%s hostname\n", argv[0]);
    exit(2);
  }

  hints.ai_flags = AI_CANONNAME | AI_HIP;
  //  hints.ai_family = AF_INET;
  //  hints.ai_family = AF_UNSPEC;
  hints.ai_family = AF_INET6;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;

  a = getaddrinfo(argv[1], NULL, &hints, &res);

  if (a != 0) {
    printf("*** ERROR: %s ***\n", gai_strerror(a));
    return(1);
  }
  printf("*** Test SUCCESS\n");
  for(ai = res; ai != NULL; ai = ai->ai_next) {
    printf("ai_flags=%d ai_family=%d ai_socktype=%d ai_protocol=%d ai_addrlen=%d ai_canonname=%s\n", ai->ai_flags, ai->ai_family, ai->ai_socktype, ai->ai_protocol, ai->ai_addrlen, ai->ai_canonname);

    if (ai->ai_family == AF_INET6) {
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
      int i = 0;

      printf("AF_INET6\tship6_family=%d\n", s->sin6_family);    
      printf("AF_INET6\tship6_port=%d\n", s->sin6_port);
      printf("AF_INET6\tship6_flowinfo=%lu\n", (long unsigned int)s->sin6_flowinfo);
      printf("AF_INET6\tship6_scope_id=%lu\n", (long unsigned int)s->sin6_scope_id);
      printf("AF_INET6\tin6_addr=0x");
      for (i = 0; i < 16; i++)
	printf("%02x ", (unsigned char) (s->sin6_addr.in6_u.u6_addr8[i]));
      printf("\n");
    } else if (ai->ai_family == AF_INET) {
      struct sockaddr_in *s = (struct sockaddr_in *)ai->ai_addr;
      printf("AF_INET\tin_addr=0x%lx (%s)\n", (long unsigned int) ntohl(s->sin_addr.s_addr), inet_ntoa(s->sin_addr));
    }
#if 0
    else if (ai->ai_family == AF_HIP) {
#ifdef HIP_TRANSPARENT_API
      //#error HIP_TRANSPARENT_API Should not happen ?
#else
      int i = 0;
      struct sockaddr_in6 *s = (struct sockaddr_in6 *)ai->ai_addr;
      printf("AF_HIP\tship6_family=%d\n", s->sin6_family);
      printf("AF_HIP\tship6_port=%d\n", s->sin6_port);
      printf("AF_HIP\tship6_flowinfo=%lu\n", (long unsigned int)s->sin6_flowinfo);
      printf("AF_HIP\tship6_scope_id=%lu\n", (long unsigned int)s->sin6_scope_id);

      printf("AF_HIP\tship6_addr=0x");
      for (i = 0; i < 16; i++) printf("%02x ", (unsigned char) (s->sin6_addr.in6_u.u6_addr8[i]));
      printf("\n");
      //      printf("AF_HIP\tship6_hit= 0x");
      //for (i = 0; i < 16; i++) printf("%02x ", (unsigned char) (s->ship6_hit.in6_u.u6_addr8[i]));
      //printf("\n");
#endif /* HIP_TRANSPARENT_API */
    }
#endif

  }

  freeaddrinfo(res);
  return(0);
}
