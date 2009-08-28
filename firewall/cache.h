#ifndef HIP_CACHE_H
#define HIP_CACHE_H

#include "debug.h"
#include "icomm.h"
#include "misc.h"

extern int hip_fw_sock;

int firewall_cache_db_match(   struct in6_addr *, struct in6_addr *,
				hip_lsi_t       *, hip_lsi_t       *,
				struct in6_addr *, struct in6_addr *, int *);
int firewall_add_new_entry(firewall_cache_hl_t *);

//Initializes the firewall cache database
void firewall_cache_init_hldb(void);

firewall_cache_hl_t *hip_cache_create_hl_entry(void);

int firewall_add_new_entry(firewall_cache_hl_t *ha_entry);

unsigned long hip_firewall_cache_hash_ip_peer(const void *ptr);

int hip_firewall_cache_match_ip_peer(const void *ptr1, const void *ptr2);

void firewall_cache_init_hldb(void);

void hip_firewall_cache_delete_hldb(void);



#endif /* HIP_CACHE_H */











