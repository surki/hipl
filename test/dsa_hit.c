/*
 *  Create HIT based on DSA pubkey.
 *
 * $Id: dsa_hit.c,v 1.2 2003/03/31 20:51:39 mkomu Exp $
 *
 * gcc -g -Wall -o dsa_hit dsa_hit.c -lcrypto
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/dsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "../tools/crypto.h"


int main(int argc,char *argv[]) {

  DSA *dsa;
  int err;

  unsigned char *pk = "qwertyuiop1234567890asdfghkjlzxcvbnm";
  struct in6_addr hit;
  char addrstr[INET6_ADDRSTRLEN];

  ERR_load_crypto_strings();

  dsa = create_dsa_key(512);
  if (!dsa) {
    HIP_ERROR("create_dsa_key\n");
    exit(1);
  }

  HIP_ERROR("\n");
  memset(&hit, 0, sizeof(struct in6_addr));

  err = dsa_to_hit(dsa, pk, strlen(pk), HIP_HIT_TYPE_HASH120, &hit);
  if (err) {
    HIP_ERROR("dsa_to_hit\n");
    exit(1);
  }

  inet_ntop(AF_INET6, &hit, addrstr, sizeof(addrstr));
  HIP_INFO("HIT=%s\n", addrstr);
  
  HIP_INFO("DSA_free\n");
  DSA_free(dsa);

 return 0;
}
