/** @file
 * oppipdb.h: A header file for oppipdb.c
 *
 * @author  Antti Partanen
 * @author  Alberto Garcia
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */

#ifndef HIP_OPPIPDB_H
#define HIP_OPPIPDB_H

#include "debug.h"
#include "hidb.h"
#include "hashtable.h"

#define HIP_LOCK_OPPIP_INIT(entry)
#define HIP_UNLOCK_OPPIP_INIT(entry)
#define HIP_LOCK_OPPIP(entry)  
#define HIP_UNLOCK_OPPIP(entry)
#define HIP_OPPIPDB_SIZE 200

typedef struct in6_addr hip_oppip_t;

unsigned long hip_oppipdb_hash_ip(const void *ptr);
int hip_oppipdb_match_ip(const void *ptr1, const void *ptr2);
int hip_for_each_oppip(int (*func)(hip_oppip_t *entry, void *opaq), void *opaque);
void hip_oppipdb_del_entry_by_entry(hip_oppip_t *entry);
int hip_oppipdb_uninit_wrap(hip_oppip_t *entry, void *unused);
void hip_oppipdb_uninit(void);
hip_oppip_t *hip_create_oppip_entry(void);
int hip_oppipdb_add_entry(const struct in6_addr *ip_peer);
int hip_init_oppip_db(void);
void hip_oppipdb_dump(void);
hip_oppip_t *hip_oppipdb_find_byip(const struct in6_addr *ip_peer);
void hip_oppipdb_delentry(const struct in6_addr *ip_peer);

#endif /* HIP_OPPIPDB_H */



