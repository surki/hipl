/*
 *
 * $Id: dh_openssl_test.c,v 1.18 2003/03/31 20:51:39 mkomu Exp $
 *
 * export MALLOC_TRACE=malloctrace-dh_openssl_test
 * rm -f $MALLOC_TRACE
 * gcc -g -Wall -DDEBUG -o dh_openssl_test dh_openssl_test.c ../tools/debug.c ../tools/crypto.c -lcrypto && ./dh_openssl_test
 * mtrace dh_openssl_test malloctrace-dh_openssl_test
 *
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/dh.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#ifdef DEBUG
#include <mcheck.h>
#endif

#include "../tools/crypto.h"


void jutska(int a, int b, void* joku) {
  fprintf(stderr, ".");
}

void error_exit(void *free_this, DH *free_dh) {
    fprintf(stderr, "failed\n");
    ERR_print_errors_fp(stderr);
    if (free_this) free(free_this);
    if (free_dh) DH_free(free_dh);
    ERR_free_strings();
    exit(1);
}

int main(int argc, char **argv) {

  DH *my_dh = NULL;
  DH *bob_dh = NULL;
  void *cb_arg = NULL;
  int check_codes;
  unsigned char *shared_secret = NULL; /* shared secret */
  unsigned char *shared_secret_bob = NULL; /* shared secret bob */
  int shared_secret_len = -1;
  int shared_secret_bob_len = -1;
  BIO *bio_out;
  int i;
  char *pembuf;
  int len;
  DH *pem_dh;
  char *pem_n_buf;

#ifdef DEBUG
  mtrace();
#endif

  ERR_load_crypto_strings();

  bio_out=BIO_new(BIO_s_file());
  if (!bio_out){
    fprintf(stderr, "bio_out on null\n");
    error_exit(NULL, NULL);
  }

  BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
  set_random_seed();

  fprintf(stderr, "DH_generate_parameters ");
  my_dh = DH_generate_parameters(128, DH_GENERATOR_5, jutska, cb_arg);

  if (!my_dh)
    error_exit(NULL, NULL);

  fprintf(stderr, " ok\n");

  fprintf(stderr, "DH_generate_key .. ");
  if (!DH_generate_key(my_dh))
    error_exit(NULL, my_dh);

  fprintf(stderr, "ok\n");

  fprintf(stderr, "DH_check .. ");
  if (!DH_check(my_dh, &check_codes))
    error_exit(NULL, my_dh);

  fprintf(stderr, "ok\n");

  /* fprintf(stderr, "DH_CHECK_P_NOT_SAFE_PRIME = %d\n", check_codes & DH_CHECK_P_NOT_SAFE_PRIME); */
  fprintf(stderr, "DH_CHECK_P_NOT_STRONG_PRIME = %d\n", check_codes & DH_CHECK_P_NOT_STRONG_PRIME);
  fprintf(stderr, "DH_CHECK_P_NOT_PRIME = %d\n", check_codes & DH_CHECK_P_NOT_PRIME);
  fprintf(stderr, "DH_NOT_SUITABLE_GENERATOR = %d\n", check_codes & DH_NOT_SUITABLE_GENERATOR);
  fprintf(stderr, "DH_UNABLE_TO_CHECK_GENERATOR = %d\n", check_codes & DH_UNABLE_TO_CHECK_GENERATOR);
  fprintf(stderr, "\n");

  /* alusta Bobin kamat */
  bob_dh = DH_new();
  if (!bob_dh)
    error_exit(NULL, my_dh);

  /* p ja g ovat shared */
  bob_dh->p = BN_dup(my_dh->p);
  bob_dh->g = BN_dup(my_dh->g);
  if ((bob_dh->p == NULL) || (bob_dh->g == NULL)) {
    fprintf(stderr, "Bobin dh-systeemi pamahti\n");
    DH_free(bob_dh);
    error_exit(NULL, my_dh);
  }

  /* tee Bobin pub ja privkey k‰ytt‰en p:t‰ ja g:t‰, privkey tehd‰‰n
     jos sit‰ ei sijoitettu t‰h‰n menness‰ */
  if (!DH_generate_key(bob_dh)) {
    fprintf(stderr, "Bobin generate_key dh-systeemi pamahti\n");
    DH_free(bob_dh);
    error_exit(NULL, my_dh);
  }

  /*
    fprintf(stderr, "DHparams_print_fp Bob:\n");
    DHparams_print_fp(stderr, bob_dh);
  */

  shared_secret = (unsigned char *) malloc(DH_size(my_dh));
  if (!shared_secret) {
    fprintf(stderr, "malloc failed\n");
    DH_free(bob_dh);
    error_exit(NULL, my_dh);
  }

  fprintf(stderr, "DH_compute_key .. ");

  shared_secret_len = DH_compute_key(shared_secret, bob_dh->pub_key, my_dh);
  if (shared_secret_len < 0) {
    DH_free(bob_dh);
    error_exit(shared_secret, my_dh);
  } else {
    fprintf(stderr, "ok (shared_secret_len = %d)\n", shared_secret_len);
    fprintf(stderr, "shared secret: ");
    i = 0;
    while(i < shared_secret_len) {
      fprintf(stderr, "%02X", shared_secret[i]);
      i++;
    }
    BIO_puts(bio_out, "\n");
  }

  shared_secret_bob = (unsigned char *) malloc(DH_size(bob_dh));
  if (!shared_secret_bob) {
    fprintf(stderr, "malloc failed\n");
    DH_free(bob_dh);
    error_exit(shared_secret, my_dh);
  }

  fprintf(stderr, "DH_compute_key Bob .. ");

  shared_secret_bob_len = DH_compute_key(shared_secret_bob, my_dh->pub_key, bob_dh);
  if (shared_secret_bob_len < 0) {
    DH_free(bob_dh); 
    free(shared_secret_bob);
    error_exit(shared_secret, my_dh);
  } else {
    fprintf(stderr, "ok (shared_secret_bob_len = %d)\n", shared_secret_bob_len);
    fprintf(stderr, "shared secret Bob: ");
    i = 0;
    while(i < shared_secret_bob_len) {
      fprintf(stderr, "%02X", shared_secret_bob[i]);
      i++;
    }
    BIO_puts(bio_out, "\n");
  }

  fprintf(stderr, "\n");
  fprintf(stderr, "DHparams_print_fp:\n");
  DHparams_print_fp(stderr, my_dh);
  fprintf(stderr, "\n");
  fprintf(stderr, "pub_key =%s\n", BN_bn2hex(my_dh->pub_key));
  fprintf(stderr, "priv_key=%s\n", BN_bn2hex(my_dh->priv_key));
  fprintf(stderr, "\n");

  fprintf(stderr, "DHparams_print_fp Bob:\n");
  DHparams_print_fp(stderr, bob_dh);
  fprintf(stderr, "\n");
  fprintf(stderr, "pub_key Bob =%s\n", BN_bn2hex(bob_dh->pub_key));
  fprintf(stderr, "priv_key Bob=%s\n", BN_bn2hex(bob_dh->priv_key));
  fprintf(stderr, "\n");

  if ((shared_secret_len != shared_secret_bob_len) || memcmp(shared_secret, shared_secret, shared_secret_len) != 0) {
    fprintf(stderr, "\n\n*** ERILAISET SHARED SECRETIT ***\n\n");
  }

  fprintf(stderr, "PEM_write_DHparams(stderr, my_dh):\n");
  PEM_write_DHparams(stderr, my_dh);
  fprintf(stderr, "\n");


  /************** test PEM functions **************/

  /* DH params to ASCII */
  if (!dh2pem_a(my_dh, &pembuf, &len)) {
    HIP_INFO("\n*** dh2pem buf dump (len=%d): ***\n", len);
    HIP_HEXDUMP("pembuf:", pembuf, len);
    fprintf(stderr, "pembuf ascii:\n%s\n", pembuf);
  } else {
    HIP_INFO("main:dh2pem_a failed\n");
  }

  if (len > 0) {
    /* ASCII to DH params */
    HIP_INFO("Try to convert back to DH from ASCII:\n");
    if (!pem2dh_a(&pem_dh, pembuf, len)) {
      HIP_INFO("DHparams_print_fp:\n");
      DHparams_print_fp(stderr, pem_dh);
    } else {
      HIP_INFO("main:pem2dh_a failed\n");
    }
  }


  HIP_INFO("main:testing dh2pem_n:\n");
  for (i=-5; i <= 256; i++) {
    int l;

    HIP_INFO("%d ", i);
    pem_n_buf = malloc(i);
    if (!pem_n_buf) {
      HIP_INFO("malloc pem_n_buf failed\n");
    } else {
      l = dh2pem_n(pem_dh, pem_n_buf, i);
      if (l == 0) {
	HIP_INFO("OK: PEM:\n%s", pem_n_buf);
	// HIP_HEXDUMP("hexdump:", pem_n_buf, i);
      } else if (l > 0) {
	HIP_INFO("failed, needs buf of len %d\n", l);
      } else {
	HIP_INFO("failed, internal error\n");
      }
      free(pem_n_buf);
    }
  }

  HIP_INFO("\n");

  /***** clean up everything *****/

  free(pembuf);
  free(shared_secret);
  free(shared_secret_bob);
  fprintf(stderr, "DH_free\n");
  DH_free(my_dh); 
  DH_free(bob_dh);
  DH_free(pem_dh);
  ERR_free_strings();

  /* lis‰‰ n kpl OPENSSL_free ? */

#ifdef DEBUG
  muntrace();
#endif

  fprintf(stderr, "*** EXIT OK ***\n");
  return(0);
}
