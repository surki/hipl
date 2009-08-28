#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>    

#define MAXLINE     4096


/*static*/ void err_doit(int errnoflag, const char *fmt, va_list ap)
{
  int     errno_save;
  char    buf[MAXLINE];
  
  errno_save = errno;             /* value caller might want printed */
  vsprintf(buf, fmt, ap);
  if (errnoflag)
    sprintf(buf+strlen(buf), ": %s", strerror(errno_save));
  strcat(buf, "\n");
  fflush(stdout);         /* in case stdout and stderr are the same */
  fputs(buf, stderr);
  fflush(NULL);           /* flushes all stdio output streams */
}

void err_sys(const char *fmt, ...)
{
  va_list         ap;
  
  va_start(ap, fmt);
  err_doit(1, fmt, ap);
  va_end(ap);
  exit(1);
}
