/***************************************************************************
                          i3_utils.h  -  description
                             -------------------
    begin                : Sam Jun 21 2003
    copyright            : (C) 2003 by klaus
    email                : wehrle@icsi.berkeley.edu
 ***************************************************************************/

#ifndef I3_UTILS_H
#define I3_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

/*static*/ void err_doit(int errnoflag, const char *fmt, va_list ap);
void err_sys(const char *fmt, ...);


#endif //I3_UTILS_H
