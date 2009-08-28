#include "tools/debug.h"
#include "builder.h"

/*
 * unit tester for builder.c
 *
 * $Id: builder_tester.c,v 1.3 2003/03/31 20:51:39 mkomu Exp $
 *
 * TODO:
 * - hipd_msg size % 8 == 0, alignment
 * - 
 */

int main(int argc, char *argv[]) {
#if 0
  struct hipd_msg *msg = malloc(HIPD_MSG_MAX_LEN);
  if (msg == NULL)
    HIP_DIE("malloc\n");
#endif
  return 0;
}
