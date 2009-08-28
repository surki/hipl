#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <time.h>

#include "debug.h"
#include "misc.h"

int main(int argc, char *argv[]) {
  struct timeval stats_before, stats_after, stats_res;
  int err = 0, bits, use_rsa;
  DSA *dsa = NULL;
  RSA *rsa = NULL;
  int use_dsa;

  if (argc != 3) {
    printf("usage: keygentest <dsa|rsa> <bits>\n");
    exit(-1);
  }

  if (!strcmp(argv[1], "dsa")) {
    use_dsa = 1;
  } else {
    use_dsa = 0;
  }

  bits= atoi(argv[2]);
  HIP_DEBUG("bits=%d\n", bits);

  ERR_load_crypto_strings();

  gettimeofday(&stats_before, NULL);

  if (use_dsa)
    dsa = (DSA *) create_dsa_key(bits);
  else
    rsa = (RSA *) create_rsa_key(bits);

  HIP_IFEL(!(rsa || dsa), -1, "key creation failed\n")

  gettimeofday(&stats_after, NULL);

  hip_timeval_diff(&stats_after, &stats_before, &stats_res);
  HIP_INFO("%s key created in %ld.%06ld secs\n",
	   (use_dsa ? "dsa" : "rsa"), stats_res.tv_sec, stats_res.tv_usec);

 out_err:

  return err;
}
