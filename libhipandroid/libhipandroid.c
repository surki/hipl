
#include "libhipandroid.h"
#include <netinet/in.h>

const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int
lockf(int filedes, int function, off_t size)
{
  struct flock fl;
  int cmd;

  fl.l_start = 0;
  fl.l_len = size;
  fl.l_whence = SEEK_CUR;

  switch (function) {
  case F_ULOCK:
    cmd = F_SETLK;
    fl.l_type = F_UNLCK;
    break;
  case F_LOCK:
    cmd = F_SETLKW;
    fl.l_type = F_WRLCK;
    break;
  case F_TLOCK:
    cmd = F_SETLK;
    fl.l_type = F_WRLCK;
    break;
  case F_TEST:
    fl.l_type = F_WRLCK;
    if (fcntl(filedes, F_GETLK, &fl) == -1)
      return (-1);
    if (fl.l_type == F_UNLCK || fl.l_pid == getpid())
      return (0);
    errno = EAGAIN;
    return (-1);
    /* NOTREACHED */
  default:
    errno = EINVAL;
    return (-1);
    /* NOTREACHED */
  }

  return (fcntl(filedes, cmd, &fl));
}

