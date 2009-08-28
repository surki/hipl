/**
 * Basic fixed-width integer types for systems deprived of ANSI compliance (i.e. WIN32).
 *
 * This is not an attempt at implementing a fully ANSI compliant inttypes.h because the i3 code only utilizes the [u]int<n>_t types. Mimicking a standard include file avoids even more platform-dependent #ifdef cruft in source files. inttypes.h was chosen over stdint.h because its availability on MacOS X was unknown.
 */
#ifndef __i3_inttypes_h__
#define __i3_inttypes_h__

/* stg: under cygwin, _WIN32 can be defined if win32api header files get included */
#if defined(_WIN32)

#ifdef _WIN64
#define _INTWIDTH 64
#elif defined(_WIN32)
#define _INTWIDTH 32
#else
#error ERROR: Unable to determine width of int type
#endif


typedef unsigned int uint;

#if _INTWIDTH == 32
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
typedef unsigned long long uint64_t;
typedef char int8_t;
typedef short int16_t;
typedef long int32_t;
typedef long long int64_t;

#ifndef _INTPTR_T_DEFINED
typedef int32_t	intptr_t;
#define _INTPTR_T_DEFINED 1
#endif

#ifndef _UINTPTR_T_DEFINED
typedef uint32_t uintptr_t;
#define _UINTPTR_T_DEFINED 1
#endif


#elif _INTWIDTH == 64


typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long int64_t;

#ifndef _INTPTR_T_DEFINED
typedef int64_t	intptr_t;
#define _INTPTR_T_DEFINED 1
#endif

#ifndef _UINTPTR_T_DEFINED
typedef uint64_t uintptr_t;
#define _UINTPTR_T_DEFINED 1
#endif

#endif

#endif

#endif
