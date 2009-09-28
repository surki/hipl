/**
 * Security association database for IPsec connections
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef USER_IPSEC_SADB_H_
#define USER_IPSEC_SADB_H_

#include <openssl/des.h>		/* des_key_schedule */
#include <openssl/aes.h>		/* aes_key */
#ifndef ANDROID_CHANGES
#include <openssl/blowfish.h>	/* bf_key */
#endif
#include <inttypes.h>
#include "hashchain.h"
#include "hashtable.h"
#include "esp_prot_defines.h"
#include "ife.h"

#ifdef ANDROID_CHANGES
#include <pthread.h>
#endif

/* mode: 1-transport, 2-tunnel, 3-beet
 *
 * however right now we only support mode 3, no need for variable yet */
#define BEET_MODE 3
// not implemented yet
#define DEFAULT_LIFETIME 0

/* HIP Security Association entry */
typedef struct hip_sa_entry
{
	pthread_mutex_t rw_lock;				/* keep other threads from modifying */
	int direction;							/* direction of the SA: inbound/outbound */
	uint32_t spi;							/* needed for demultiplexing incoming packets */
	uint32_t mode; 							/* ESP mode :  1-transport, 2-tunnel, 3-beet */
	struct in6_addr *src_addr;				/* source address of outer IP header */
	struct in6_addr *dst_addr;				/* destination address of outer IP header */
	/* inner addresses for BEET SAs (the above addresses
	 * are used as outer addresses) */
	struct in6_addr *inner_src_addr;
	struct in6_addr *inner_dst_addr;
	uint8_t encap_mode;						/* Encapsulation mode: 0 - none, 1 - udp */
	uint16_t src_port;						/* src port for UDP encaps. ESP */
	uint16_t dst_port;						/* dst port for UDP encaps. ESP */
	/****************** crypto parameters *******************/
	int ealg;								/* crypto transform in use */
	struct hip_crypto_key *auth_key;		/* raw crypto keys */
	struct hip_crypto_key *enc_key;
	des_key_schedule ks[3];					/* 3-DES keys */
	AES_KEY aes_key;						/* AES key */
#ifndef ANDROID_CHANGES
	BF_KEY bf_key;							/* BLOWFISH key */
#endif
	/*********************************************************/
	uint64_t lifetime;			/* seconds until expiration */
	uint64_t bytes;				/* bytes transmitted */
	struct timeval usetime;		/* last used timestamp */
	struct timeval usetime_ka;	/* last used timestamp, incl keep-alives */
	uint32_t sequence;			/* sequence number counter */
	uint32_t replay_win;		/* anti-replay window */
	uint32_t replay_map;		/* anti-replay bitmap */
	/*********** esp protection extension params *************/
	/* hash chain parameters for this SA used in secure ESP extension */
	/* for outbound SA */
	// can be a hchain or a htree
	void * active_hash_items[MAX_NUM_PARALLEL_HCHAINS];
	void * next_hash_items[MAX_NUM_PARALLEL_HCHAINS];
	int last_used_chain;
	// packet hash buffer for the cumulative packet authentication
	esp_cumulative_item_t hash_buffer[RINGBUF_SIZE];
	uint32_t next_free;
	int active_item_length;
	int update_item_length;
	uint8_t update_item_acked[MAX_NUM_PARALLEL_HCHAINS];
	/* for both */
	uint8_t esp_prot_transform;
} hip_sa_entry_t;

/* stores short-cuts to an entry, indexed by dst_addr and spi */
typedef struct hip_link_entry
{
	struct in6_addr *dst_addr;				/* destination address of outer IP header */
	uint32_t spi;							/* needed for demultiplexing incoming packets */
	hip_sa_entry_t *linked_sa_entry;		/* direct link to sa entry */
} hip_link_entry_t;

/* declarations for the callback wrappers */
static DECLARE_LHASH_HASH_FN(hip_sa_entry_hash, const hip_sa_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sa_entries_compare, const hip_sa_entry_t *);
static DECLARE_LHASH_HASH_FN(hip_link_entry_hash, const hip_sa_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_link_entries_compare, const hip_sa_entry_t *);

/** initializes the sadb and the linkdb
 *
 * @return 0, if no error occured, else -1
 */
int hip_sadb_init(void);

/** uninits the sadb and linkdb by deleting all entries stored in there
 *
 * @return 0, if no error occured, else -1
 */
int hip_sadb_uninit(void);

/** to be called when a SA entry is to be added or updated
 *
 * @param	...
 * @return	0, if no error occured, else -1
 */
int hip_sadb_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t local_port, uint16_t peer_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
		uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		int retransmission, int update);

/** to be called if a SA entry and all its links should be remove from the sadb
 *
 * @param	dst_addr the destination ip address of the entry
 * @param	spi the spi number of the entry
 * @return	0, if no error occured, else -1
 */
int hip_sadb_delete(struct in6_addr *dst_addr, uint32_t spi);

/** to be called, if the whole sadb should be flushed
 *
 * @return	0, if no error occured, else -1
 */
int hip_sadb_flush(void);

/** searches the linkdb
 *
 * @param	dst_addr destination address of the searched entry
 * @param	spi SPI number of the searched entry
 * @return	the searched entry; NULL if no matching entry found
 */
hip_sa_entry_t * hip_sa_entry_find_inbound(struct in6_addr *dst_addr, uint32_t spi);

/** searches the linkdb for a SA entry
 *
 * @param	src_hit the source HIT of the searched entry
 * @param	dst_hit the destination HIT of the searched entry
 * @return	the searched SA entry; NULL if no matching entry found
 */
hip_sa_entry_t * hip_sa_entry_find_outbound(struct in6_addr *src_hit,
		struct in6_addr *dst_hit);

/** prints the whole contents of the sadb
 */
void hip_sadb_print(void);


/******** hashtable helper functions *********/

/** hash function for the sa hash table */
unsigned long hip_sa_entry_hash(const hip_sa_entry_t *sa_entry);

/** compare function for the sa hash table */
int hip_sa_entries_compare(const hip_sa_entry_t *sa_entry1,
		const hip_sa_entry_t *sa_entry2);

/** hash function for the link hash table */
unsigned long hip_link_entry_hash(const hip_link_entry_t *link_entry);

/** compare function for the link hash table */
int hip_link_entries_compare(const hip_link_entry_t *link_entry1,
		const hip_link_entry_t *link_entry2);

/******** sadb helper functions *********/

/** allocates memory for a new SA entry and adds it to the db
 *
 * @param	...
 * @return	0, if no error occured, else != 0
 */
int hip_sa_entry_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
		uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		int update);

/** updates an already stored entry
 *
 * @param	...
 * @return	0, if no error occured, else != 0
 */
int hip_sa_entry_update(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
		uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		int update);

/** sets all values of a SA entry
 *
 * @param	...
 * @return	0, if no error occured, else != 0
 */
int hip_sa_entry_set(hip_sa_entry_t *entry, int direction, uint32_t spi,
		uint32_t mode, struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
		uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		int update);

/** deletes a SA entry and all its links
 *
 * @param	...
 * @return	0, if no error occured, else != 0
 */
int hip_sa_entry_delete(struct in6_addr *src_addr, struct in6_addr *dst_addr);

/** adds a new entry to the passed entry in the linkdb
 *
 * @param	...
 * @return	0, if no error occured, else != 0
 */
int hip_link_entry_add(struct in6_addr *dst_addr, hip_sa_entry_t *entry);

/** adds new entries to the passed entry in the linkdb for all destination address
 * and spi combination
 *
 * @param	...
 * @return	0, if no error occured, else != 0
 */
int hip_link_entries_add(hip_sa_entry_t *entry);

/** searches the linkdb for a link entry
 *
 * @param	dst_addr destination address of the searched entry
 * @param	spi SPI number of the searched entry
 * @return	the searched link entry; NULL if no matching entry found
 */
hip_link_entry_t *hip_link_entry_find(struct in6_addr *dst_addr, uint32_t spi);

/** deletes a link entry from the linkdb
 *
 * @param	...
 * @return	0, if no error occured, else != 0
 */
int hip_link_entry_delete(struct in6_addr *dst_addr, uint32_t spi);

/** deletes all link entries to the passed entry in the linkdb for all
 * destination address and spi combination
 *
 * @param	...
 * @return	0, if no error occured, else != 0
 */
int hip_link_entries_delete_all(hip_sa_entry_t *entry);

/** prints a link entry */
void hip_link_entry_print(hip_link_entry_t *entry);

/** frees all members of a SA entry */
void hip_sa_entry_free(hip_sa_entry_t * entry);

/** prints a SA entry */
void hip_sa_entry_print(hip_sa_entry_t *entry);

/** prints all entries in the the linkdb */
void hip_linkdb_print(void);

#endif /* USER_IPSEC_SADB_H_ */

