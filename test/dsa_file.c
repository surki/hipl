/*
 * $Id: dsa_file.c,v 1.5 2003/03/31 20:51:39 mkomu Exp $
 *
 * gcc -g -Wall -o dsa_file dsa_file.c -lcrypto
 *
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/dsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "../tools/crypto.h"


int main(int argc,char *argv[]) {
#if 0
  DSA *dsa, *dsa2;
  long len;
  unsigned char *buf, *origbuf;

  ERR_load_crypto_strings();

  //set_random_seed();

  dsa = create_dsa_key(128);
  if (!dsa) {
    HIP_ERROR("create_dsa_key\n");
    exit(1);
  }

  HIP_INFO("\nOriginal:\n");
  HIP_INFO("BN_bn2hex dsa =%s\n", BN_bn2hex(dsa->pub_key));

  len = get_dsa_der_pubkey(dsa, &buf);
  if (len < 0) {
    HIP_ERROR("get_dsa_der_pubkey failed\n");
    ERR_print_errors_fp(stderr);
    DSA_free(dsa);
    exit(1);
  }

  origbuf = buf;
  dsa2 = d2i_DSAPublicKey(NULL, &buf, len);
  HIP_INFO("From DER decoded data:\n");
  HIP_ERROR("BN_bn2hex dsa2=%s\n", BN_bn2hex(dsa2->pub_key));

  OPENSSL_free(origbuf);
  HIP_ERROR("DSA_free\n");
  DSA_free(dsa);
  DSA_free(dsa2);
#endif
  return 0;
}
