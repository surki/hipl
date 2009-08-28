/*
export MALLOC_TRACE=malloctrace-crtest;rm -f $MALLOC_TRACE;gcc -g -O3 -Wall -Wno-unused -o crtest crtest.c ../hipd/crypto.c ../hipd/debug.c -lcrypto && ./crtest;mtrace crtest malloctrace-crtest
*/

#include <string.h>
#include <netinet/in.h>
#include <limits.h>
#include <mcheck.h>
#include "../tools/crypto.h"

/* b = byteswapped a */
/* ***** LISÄÄ #ifdef BIGENDIAN tms. ***** */
void byteswapconv(unsigned char *a, unsigned char *b, int len) {
  int i;
  for (i=0; i < len; i++) {
    /*
      fprintf(stderr, "i=%d i2=%d ", i, len-i-1);
      fprintf(stderr, "a=0x%x ", (unsigned char)(*(a+i)));
      fprintf(stderr, "b=0x%x\n", (unsigned char)(*(b+i)));
    */
    *(b+i) = (unsigned char)(*(a+len-i-1));
  }
}

u_int64_t byte_swap64( u_int64_t value )
{
    int index;
    int length = 8;
    u_int64_t swapped = value;
    unsigned char *q = (unsigned char *)&swapped;

    for( index = 0; ( index < (length/2) ); index++ ) {
        unsigned char temp = q[index];
        q[index] = q[length - index - 1];
        q[length - index - 1] = temp;
    }

    return swapped;
}

int main(int argc,char **argv) {

  //int retval;
  DSA *test_dsa;

  /* Enable malloc debugging. When the mtrace function is called it looks for
     an environment variable named MALLOC_TRACE.  This variable is
     supposed to contain a valid file name. */
  // saattaa hidastaa huomattavasti ajoa
  mtrace();

  test_dsa = create_dsa_key(128);
  if (!test_dsa) {
    fprintf(stderr, "fail: create_dsa_key\n");
    exit(1);
  }

  /* add much more tests than just a dsa struct creation ... */

#if 0
  u_int64_t a = 0x1234567890abcdef;
  u_int64_t b = 0;

  /* test byteswapconv */
  unsigned long aa,bb;
  unsigned long aa2,bb2;

  /*
  for (a=0; a < 10000; a++) {
    b = byte_swap64(a);
    fprintf(stderr, "a=%llu bb2=%llu\n", a, b);
  }
*/

  /* test my own byteswap64 implementation against other implementation */
  for (a=0xfffffffff0ffffff;a < 0xffffffffffffffff; a++) {
    //fprintf(stderr, "a=%llu ", a);
    if (!(a % 0x1000000)) fprintf(stderr, "0x%llx ", a);
    //    fprintf(stderr, "aa=%ld bb=%ld htonl(aa)=%ld .. ", aa, bb, htonl(aa));
     byteswapconv((unsigned char *)&a, (unsigned char *)&b, sizeof(a));
    //    fprintf(stderr, "bbconv=%ld\n", bb);
    /*
    if (b != htonl(a)) {
      fprintf(stderr, "bb %lu != htonl(aa) %lu\n", bb, htonl(aa));
      exit(1);
    }
    */
    if (byte_swap64(a) != b) {
      fprintf(stderr, "byteswap_64=%llu != b=%llu\n", byte_swap64(a), b);
      exit(1);
    }
    //fprintf(stderr, "b=%llu b64=%llu\n", b, byte_swap64(a));
  }
  exit(0);

#endif

#if 0
  fprintf(stderr, "q=%ld (%lx) w=%ld (%lx)\n", aa, aa, htonl(aa), htonl(aa));
  byteswapconv((unsigned char *)&aa, (unsigned char *)&bb, sizeof(aa));
  fprintf(stderr, "bb=%lx\n", bb);
  byteswapconv((unsigned char *)&bb, (unsigned char *)&aa, sizeof(bb));
  fprintf(stderr, "aa=%lx\n", aa);
  exit(0);

  hexdump("pre a", (unsigned char *)&a, sizeof(a));
  hexdump("pre b", (unsigned char *)&b, sizeof(b));
  byteswapconv((unsigned char *)&a, (unsigned char *)&b, sizeof(u_int64_t));
  hexdump("a", (unsigned char *)&a, sizeof(a));
  hexdump("b", (unsigned char *)&b, sizeof(b));
  exit(0);
#endif

  fprintf(stderr, "cryptotest ok\n");

  //lbl_exit:
  muntrace();
  return(0);
}

