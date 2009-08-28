#ifndef __HIP_KERN_COMPATIBILITY__
#define __HIP_KERN_COMPATIBILITY__

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <asm/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>

typedef struct { } rwlock_t;
typedef uint8_t   u8;
typedef uint16_t  u16;
typedef uint32_t  u32;
typedef struct { volatile int counter; } atomic_t;
typedef struct {
	/** @todo Is empty. */
} spinlock_t;

#define spin_lock_init 

struct list_head {
	struct list_head *next, *prev;
};

#ifndef IPPROTO_HIP
#  define IPPROTO_HIP             139 /* Also in libinet6/include/netinet/in.h */
#endif

#define HIP_MALLOC(size, flags)  malloc(size)
#define HIP_FREE(obj)            free(obj)
#define GFP_ATOMIC               0
#define GFP_KERNEL               0

#if __BYTE_ORDER == __BIG_ENDIAN
  #define hton64(i) (i)
  #define ntoh64(i) (i)
#else
  #define hton64(i) ( ((__u64)(htonl((i) & 0xffffffff)) << 32) | htonl(((i) >> 32) & 0xffffffff ) )
  #define ntoh64 hton64
#endif



#define RW_LOCK_UNLOCKED (rwlock_t) { }

#define jiffies random()

#define atomic_inc(x) \
         (++(*x).counter)

#define atomic_read(x) \
         ((*x).counter)

#define atomic_dec_and_test(x) \
         (--((*x).counter) == 0)

#define atomic_set(x, v) \
         ((*x).counter = v)

/* XX FIX: implement the locking for userspace properly */
#define read_lock_irqsave(a,b) do {} while(0)
#define spin_unlock_irqrestore(a,b) do {} while(0)
#define write_lock_irqsave(a,b) do {} while(0)
#define write_unlock_irqrestore(a,b) do {} while(0)
#define read_unlock_irqrestore(a,b) do {} while(0)

#endif /* __HIP_KERN_COMPATIBILITY__ */
