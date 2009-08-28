#ifndef _HIP_DB
#define _HIP_DB

#include <asm/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include "kerncompat.h"
#include "list.h"
#include "debug.h"
#include "cookie.h"
#include "blind.h"

#if 0
#define HIP_INIT_DB(name,id) \
        struct hip_db_struct name = { LIST_HEAD_INIT(name.db_head), \
        RW_LOCK_UNLOCKED, id, 0}

#define HIP_READ_LOCK_DB(db) do { \
        read_lock_irqsave(&(db)->db_lock,lf); \
	} while(0)

#define HIP_WRITE_LOCK_DB(db) do { \
	write_lock_irqsave(&(db)->db_lock,lf); \
	} while(0)

#define HIP_READ_UNLOCK_DB(db) do { \
	read_unlock_irqrestore(&(db)->db_lock,lf); \
        } while(0)

#define HIP_WRITE_UNLOCK_DB(db) do { \
	write_unlock_irqrestore(&(db)->db_lock,lf); \
        } while(0)
#else
#define HIP_INIT_DB(name,id)
#define HIP_READ_LOCK_DB(db)
#define HIP_WRITE_LOCK_DB(db)
#define HIP_READ_UNLOCK_DB(db)
#define HIP_WRITE_UNLOCK_DB(db)
#endif

typedef  HIP_HASHTABLE hip_db_struct_t;

#define HIP_MAX_HOST_ID_LEN 1600

#define HIP_MAX_COOKIE_INFO 10
/* for debugging with in6_ntop */
#define INET6_ADDRSTRLEN 46

struct hip_entry_list {
	hip_list_t list;
	struct in6_addr peer_hit;
	/* These two _MUST_ be left untouched. Feel free to add more
	 * to the end */
};

struct hip_hadb_multi {
	hip_list_t m_head;
	void *           m_arg;
	int              m_type;
};

static char *lsi_addresses[] = {"1.0.0.1","1.0.0.2","1.0.0.3","1.0.0.4"};
/*
 * Note: lhit->hit and hid are stored in network byte order.
 */
#define HIP_ARG_HIT                 0x000001
#define HIP_ARG_SPI                 0x000002
#define HIP_HADB_ACCESS_ARGS        (HIP_ARG_HIT | HIP_ARG_SPI)

/* Use this to point your target while accessing a database */
#define HIP_DB_LOCAL_HID   (hip_local_hostid_db)

/* ... and not this! */
extern hip_db_struct_t *hip_local_hostid_db;

struct hip_host_id_entry *hip_get_hostid_entry_by_lhi_and_algo(hip_db_struct_t *db,
							       const struct in6_addr *hit,
							       int algo, int anon);
int hip_get_any_localhost_hit(struct in6_addr *target, int algo, int anon);
struct hip_host_id *hip_get_any_localhost_public_key(int algo);
struct hip_host_id *hip_get_any_localhost_dsa_public_key(void);
struct hip_host_id *hip_get_any_localhost_rsa_public_key(void);
struct hip_host_id *hip_get_public_key(struct hip_host_id *hi);
struct hip_host_id *hip_get_host_id(hip_db_struct_t *db, 
				    struct in6_addr *hit, int algo);
int hip_add_host_id(hip_db_struct_t *db,
		    const struct hip_lhi *lhi,
		    hip_lsi_t *lsi,
		    const struct hip_host_id *host_id,
		    int (*insert)(struct hip_host_id_entry *, void **arg),		
		    int (*remove)(struct hip_host_id_entry *, void **arg),
		    void *arg);
int hip_hit_is_our(struct in6_addr *hit);

void hip_uninit_host_id_dbs(void);

int hip_handle_add_local_hi(const struct hip_common *input);

int hip_handle_del_local_hi(const struct hip_common *input);

int hip_for_each_hi(int (*func)(struct hip_host_id_entry *entry, void *opaq), void *opaque);

int hip_blind_find_local_hi(uint16_t *nonce, struct in6_addr *test_hit,
			    struct in6_addr *local_hit);
/*lsi support*/
int hip_hidb_add_lsi(hip_db_struct_t *db, const struct hip_host_id_entry *id_entry);
int hip_hidb_exists_lsi(hip_lsi_t *lsi);
struct hip_host_id_entry *hip_hidb_get_entry_by_lsi(hip_db_struct_t *db, const struct in_addr *lsi);
int hip_hidb_associate_default_hit_lsi(hip_hit_t *default_hit, hip_lsi_t *default_lsi);
int hip_hidb_get_lsi_by_hit(const hip_hit_t *our, hip_lsi_t *our_lsi);

/* existence */
int hip_hidb_hit_is_our(const hip_hit_t *src);

unsigned long hip_hidb_hash(const void *ptr);
int hip_hidb_match(const void *ptr1, const void *ptr2);

int hip_for_all_hi(int (*func)(struct hip_host_id_entry *entry, void *opaq), void *opaque);

#endif /* _HIP_DB */
