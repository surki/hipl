#include <sys/wait.h>
#include "chord_api.h"

main(int argc, char **argv)
{
  chord_init(argv[1]);
  wait(0);

  return 0;
}
