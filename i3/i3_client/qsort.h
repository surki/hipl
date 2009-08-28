#ifndef _QSORT_H
#define _QSORT_H

#if !defined(_WIN32)
    #include <inttypes.h>
#else
    #include "../utils/fwint.h"
#endif

void qksort(uint64_t *A, int ilo, int ihi);

#endif
