#ifndef _BYTE_ORDER_H
#define _BYTE_ORDER_H

#include <sys/types.h>
/* stg: under cygwin, _WIN32 can be defined if win32api header files get included */
#if defined(_WIN32)
    #include "fwint.h"
#else
    #include <inttypes.h>
#endif

/***************************************************************************
 * Purpose:     Wrapper functions for byte order conversion
 **************************************************************************/

void hnputl(void *p, uint32_t v);
void hnputs(void *p, uint16_t v);
void hnput64(void *p, uint64_t v);
uint32_t nhgetl(void *p);
uint16_t nhgets(void *p);
uint64_t nhget64(void *p);

#endif
