#ifndef HIP_USER_COMPAT_H
#define  HIP_USER_COMPAT_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <asm/byteorder.h>

#include "debug.h"
#include "misc.h"
#include "builder.h"

#define HIP_MALLOC(a,b) kmalloc(a,b)
#define HIP_FREE(a) kfree(a)

#define PF_HIP 32

#define MAX_HASH_LENGTH 0
#define MAX_TREE_DEPTH 0

#define IN6_IS_ADDR_V4MAPPED(id) 0
#define HIP_INFO_LOCATOR(a,b) {}

/* hipsock won't compile unless this is done in protodefs.h */
/* typedef uint16_t in_port_t; */

extern uint64_t hton64(uint64_t i);
extern uint64_t ntoh64(uint64_t i);
extern int is_big_endian(void);

static inline int hip_send_recv_daemon_info(struct hip_common *msg) {return -1;}
static inline int hip_build_digest(const int type, const void *in, int in_len, void *out) {return -1;}
static inline int hip_write_hmac(int type, void *key, void *in, int in_len, void *out) {return -1;}

#endif /* HIP_USER_COMPAT_H  */
