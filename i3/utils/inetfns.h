#ifndef _INET_FNS_H
#define _INET_FNS_H

/* stg: under cygwin, _WIN32 can be defined if win32api header files get included */
#if defined(_WIN32)
    #include "fwint.h"
#else
    #include <inttypes.h>
#endif

/* Get address of local machine */
uint32_t get_local_addr_eth();
uint32_t name_to_addr(const char *);
uint32_t get_local_addr_uname();
uint32_t get_local_addr();

#endif
