/*
 *
 * Hello World OpenSSL DSA
 *
 * $Id: dsa_openssl.c,v 1.11 2003/06/16 12:44:30 mika Exp $
 *
 * gcc -g -Wall -o dsa_openssl dsa_openssl.c -lcrypto
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

  DSA *dsa;
  int err;
  unsigned char digest[] = "hiaasdasdaasdadasdaa";
  struct hip_dsa_sig_contents sig;
  int i = 0;

  fprintf(stderr, "main start\n");

  ERR_load_crypto_strings();

  /* set_random_seed(); */

  dsa = create_dsa_key(512 /* bits */);
  if (!dsa) {
    fprintf(stderr, "create_dsa_key\n");
    exit(1);
  }

  fprintf(stderr, "\nbignum in bits: p=%d q=%d g=%d priv=%d pub=%d\n",
	  BN_num_bits(dsa->p), BN_num_bits(dsa->q), BN_num_bits(dsa->g),
	  BN_num_bits(dsa->priv_key), BN_num_bits(dsa->pub_key));
  fprintf(stderr, "DSA_sign message (len=%d) '%s' .. ", strlen(digest), digest);

  err = sign_dsa(digest, strlen(digest), &sig, dsa);
  if (err) {
    fprintf(stderr, "failed\n");
    ERR_print_errors_fp(stderr);
    DSA_free(dsa);
    exit(1);
  } else {
    fprintf(stderr, "ok\n");
  }

  fprintf(stderr, "signature type=%d\n", sig.type);
  fprintf(stderr, " R=");
  for (i = 0; i < HIP_DSA_SIG_R_SIZE; i++)
    fprintf(stderr, "%.2x", (unsigned char)sig.r[i]);
  fprintf(stderr, "\n");
  fprintf(stderr, " S=");
  for (i = 0; i < HIP_DSA_SIG_S_SIZE; i++)
    fprintf(stderr, "%.2x", (unsigned char)sig.s[i]);
  fprintf(stderr, "\n");

  /* digest[0] ^= 255; */ /* fail test */

  fprintf(stderr, "DSA_verify .. ");
  err = verify_dsa(digest, strlen(digest), &sig, dsa);
  if (err) {
    fprintf(stderr, "failed\n");
    ERR_print_errors_fp(stderr);
    DSA_free(dsa);
    exit(1);
  } else {
    fprintf(stderr, "ok\n");
  }

  fprintf(stderr, "DSA_free\n");
  DSA_free(dsa);

 return 0;
}
