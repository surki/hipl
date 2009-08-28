/*
 * Test alignments.
 *
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <inttypes.h>
#include <stddef.h>

int main(int argc, char *argv[]) {

  /* try the structure with and without the attribute packed */
  struct foo {
    uint8_t a;
    uint16_t b;
    uint32_t c;
    uint8_t d;
    uint64_t e;
    uint16_t f;
    uint8_t g;
    uint32_t h;
    //  } test;
  } __attribute__ ((packed)) test;

  test.a = 1;
  test.b = 2;
  test.c = 3;
  test.d = 4;
  test.e = 5;
  test.f = 6;
  test.g = 7;
  test.h = 8;

  //printf("a=%lu, b=%lu, c=%lu, d=%lu, e=%lu, f=%lu, g=%lu, h=%lu\n",
  //	 test.a, test.b, test.c, test.d, test.e, test.f, test.g, test.h);
  printf("a=%d, b=%d, c=%d, d=%d, e=%d, f=%d, g=%d, h=%d\n",
	 offsetof(struct foo, a),
	 offsetof(struct foo, b) - offsetof(struct foo, a),
	 offsetof(struct foo, c) - offsetof(struct foo, b),
	 offsetof(struct foo, d) - offsetof(struct foo, c),
	 offsetof(struct foo, e) - offsetof(struct foo, d),
	 offsetof(struct foo, f) - offsetof(struct foo, e),
	 offsetof(struct foo, g) - offsetof(struct foo, f),
	 offsetof(struct foo, h) - offsetof(struct foo, g)
	 );
}
