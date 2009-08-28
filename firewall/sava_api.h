#ifndef HIP_SAVA_API
#define HIP_SAVA_API

#include "hashtable.h"
#include "ife.h"

#include "builder.h"
#include "message.h"
#include "firewall.h"

#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/blowfish.h>

#include <netinet/ip.h>

#define SAVA_INBOUND_KEY 0
#define SAVA_OUTBOUND_KEY 1

#define SAVA_IPV6_OPTION_TYPE 193
#define SAVA_IPV4_OPTION_TYPE 159

#define IPPROTO_SAVAH         0 //140

typedef struct sava_tlv_padding {
  char type;
  char length;
} sava_tvl_padding_t;

typedef struct sava_tlv_option {
  char action:2;
  char change:1;
  char type:5;
  char length;
} sava_tlv_option_t;

typedef struct sava_ip_option {
  u_int8_t   type;
  //  unsigned char   type:1;
  //  unsigned char   class:2;
  //  unsigned char   number:5;
  u_int8_t   length;
  char data[16];
  char padding[2];
} sava_ip_option_t;

typedef struct sava_addrinfo {
  struct in6_addr * sava_hit;
  struct in6_addr * sava_ip;
  //  struct sava_addrinfo * next;
} sava_addrinfo_t;

typedef struct hip_sava_peer_info {
  int ealg; 		              /* crypto transform in use */    
  struct hip_crypto_key *ip_enc_key;  /* raw crypto keys         */
} hip_sava_peer_info_t;

typedef struct hip_sava_enc_ip_entry {
  struct in6_addr           * src_enc;
  struct hip_sava_hit_entry * hit_link;
  struct hip_sava_ip_entry  * ip_link;
  struct hip_sava_peer_info * peer_info;
} hip_sava_enc_ip_entry_t;

typedef struct hip_sava_hit_entry {
  struct in6_addr          * src_hit;
  struct hip_sava_ip_entry * link;
  struct hip_sava_enc_ip_entry *enc_link;
} hip_sava_hit_entry_t;

typedef struct hip_sava_ip_entry {
  struct in6_addr           * src_addr;
  struct hip_sava_hit_entry * link;
  struct hip_sava_hit_entry * enc_link;
} hip_sava_ip_entry_t;

typedef struct hip_sava_conn_entry {
  struct in6_addr * src;
  struct in6_addr * dst;
} hip_sava_conn_entry_t;

int hip_sava_init_all();

static DECLARE_LHASH_HASH_FN(hip_sava_ip_entry_hash, const hip_sava_ip_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sava_ip_entries_compare, const hip_sava_ip_entry_t *);

static DECLARE_LHASH_HASH_FN(hip_sava_hit_entry_hash, const hip_sava_ip_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sava_hit_entries_compare, const hip_sava_ip_entry_t *);

static DECLARE_LHASH_HASH_FN(hip_sava_enc_ip_entry_hash, const hip_sava_enc_ip_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sava_enc_ip_entries_compare, const hip_sava_enc_ip_entry_t *);

static DECLARE_LHASH_HASH_FN(hip_sava_conn_entry_hash, const hip_sava_conn_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sava_conn_entries_compare, const hip_sava_conn_entry_t *);


unsigned long hip_sava_conn_entry_hash(const hip_sava_conn_entry_t * entry);

int hip_sava_conn_entries_compare(const hip_sava_conn_entry_t * entry1,
				  const hip_sava_conn_entry_t * entry2);
int hip_sava_conn_db_init();
int hip_sava_conn_db_uninit();

hip_sava_conn_entry_t * hip_sava_conn_entry_find(struct in6_addr * src,
						   struct in6_addr * dst);

int hip_sava_conn_entry_add(struct in6_addr *src,
			    struct in6_addr * dst);

int hip_sava_conn_entry_delete(struct in6_addr * src,
			       struct in6_addr * dst);

unsigned long hip_sava_enc_ip_entry_hash(const hip_sava_enc_ip_entry_t * entry);

int hip_sava_enc_ip_entries_compare(const hip_sava_enc_ip_entry_t * entry1,
				const hip_sava_enc_ip_entry_t * entry2);

int hip_sava_enc_ip_db_init();
int hip_sava_enc_ip_db_uninit();

hip_sava_enc_ip_entry_t * hip_sava_enc_ip_entry_find(struct in6_addr * src_enc);

int hip_sava_enc_ip_entry_add(struct in6_addr *src_enc,
			      hip_sava_ip_entry_t * ip_link,
			      hip_sava_hit_entry_t * hit_link,
			      hip_sava_peer_info_t * info_link);

int hip_sava_enc_ip_entry_delete(struct in6_addr * src_enc);

unsigned long hip_sava_hit_entry_hash(const hip_sava_hit_entry_t * entry);

int hip_sava_hit_entries_compare(const hip_sava_hit_entry_t * entry1,
				const hip_sava_hit_entry_t * entry2);

int hip_sava_hit_db_init();
int hip_sava_hit_db_uninit();

hip_sava_hit_entry_t *hip_sava_hit_entry_find(struct in6_addr * src_hit);

int hip_sava_hit_entry_add(struct in6_addr *src_hit,
			  hip_sava_ip_entry_t * link);

int hip_sava_hit_entry_delete(struct in6_addr * src_addr);

unsigned long hip_sava_ip_entry_hash(const hip_sava_ip_entry_t * entry);

int hip_sava_ip_entries_compare(const hip_sava_ip_entry_t * entry1,
				const hip_sava_ip_entry_t * entry2);

int hip_sava_ip_db_init();
int hip_sava_ip_db_uninit();

hip_sava_ip_entry_t *hip_sava_ip_entry_find(struct in6_addr * src_addr);

int hip_sava_ip_entry_add(struct in6_addr *src_addr,
			  hip_sava_hit_entry_t * link);

int hip_sava_ip_entry_delete(struct in6_addr * src_addr);

struct in6_addr * hip_sava_find_hit_by_enc(struct in6_addr * src_enc);

int hip_sava_verify_ip(struct in6_addr * enc_addr);

struct in6_addr * hip_sava_auth_ip(struct in6_addr * orig_addr,
				      hip_sava_peer_info_t * info_entry);

hip_common_t * hip_sava_make_keys_request(const struct in6_addr * hit,
					  int direction);

hip_sava_peer_info_t * hip_sava_get_key_params(hip_common_t * msg);

int hip_sava_reinject_ip_packet(u8 *msg, u16 len, int protocol);

int hip_sava_handle_output(struct hip_fw_context * ctx);

int hip_sava_init_ip4_raw_socket(int * ip4_raw_socket, int proto);

int hip_sava_init_ip6_raw_socket(int * ip6_raw_socket, int proto);

int hip_sava_reinject_packet(char * buf, int proto);

struct in6_addr * map_enc_ip_addr_to_network_order(struct in6_addr * enc_addr, int ip_version);

struct sava_ip_option * hip_sava_build_enc_addr_ipv4_option(struct in6_addr * enc_addr);

#endif //HIP_SAVA_API
