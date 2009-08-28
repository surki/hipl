/*
 gcc -g -Wall -o sha-1-test sha-1-test.c -lcrypto
*/

#include <openssl/sha.h>
#include <openssl/err.h>

#include <string.h>

int main(int argc, char **argv) {

  const unsigned char *msg = "abc";
  unsigned char md[SHA_DIGEST_LENGTH];
  unsigned char *sha_retval;

  int i = 0;

  bzero(&md, sizeof(md));
  sha_retval = SHA1(msg, 3, md);

  if (!sha_retval) {
    fprintf(stderr, "!sha:retval\n");
    ERR_print_errors_fp(stdout);
    exit(1);
  }

  fprintf(stderr, "sha_retval = %p digest = ", sha_retval);

  while(i < sizeof(md)) {
   printf("%.2x", md[i]);
   i++;
  }

  printf("\n");

 return(0);
}
