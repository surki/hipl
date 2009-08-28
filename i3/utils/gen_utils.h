#ifndef _GEN_UTILS_H
#define _GEN_UTILS_H

/* stg: under cygwin, _WIN32 can be defined if win32api header files get included */
#if defined(_WIN32)
    #include "fwint.h"  // Need uint8_t
    #include <Winsock2.h> // struct timeval
#else
    #include <inttypes.h>
    #include <sys/time.h> // struct timeval
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

void   init_rand(void);
double f_rand(void);
double funif_rand(double a, double b);
int    n_rand(int n);
int    unif_rand(int a, int b);
int    random_sec(void);
uint64_t wall_time(void);
void     sub_wall_time(struct timeval *tv, uint64_t a, uint64_t b);
uint64_t get_cycles(void);

#endif
