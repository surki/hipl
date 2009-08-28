#include "sava_api.h"



/* database storing shortcuts to sa entries for incoming packets */
HIP_HASHTABLE *sava_ip_db = NULL;

HIP_HASHTABLE *sava_hit_db = NULL;

HIP_HASHTABLE *sava_enc_ip_db = NULL;

HIP_HASHTABLE *sava_conn_db = NULL;


int ipv6_raw_raw_sock = 0;
int ipv6_raw_tcp_sock = 0;
int ipv6_raw_udp_sock = 0;
int ipv4_raw_tcp_sock = 0;
int ipv4_raw_udp_sock = 0;

/* hash functions used for calculating the entries' hashes */
#define INDEX_HASH_FN		HIP_DIGEST_SHA1
/* the length of the hash value used for indexing */
#define INDEX_HASH_LENGTH	SHA_DIGEST_LENGTH

static IMPLEMENT_LHASH_HASH_FN(hip_sava_ip_entry_hash, 
			       const hip_sava_ip_entry_t *)

static IMPLEMENT_LHASH_COMP_FN(hip_sava_ip_entries_compare, 
			       const hip_sava_ip_entry_t *)

static IMPLEMENT_LHASH_HASH_FN(hip_sava_hit_entry_hash, 
			       const hip_sava_hit_entry_t *)

static IMPLEMENT_LHASH_COMP_FN(hip_sava_hit_entries_compare, 
			       const hip_sava_hit_entry_t *)

static IMPLEMENT_LHASH_HASH_FN(hip_sava_enc_ip_entry_hash, 
			       const hip_sava_enc_ip_entry_t *)

static IMPLEMENT_LHASH_COMP_FN(hip_sava_enc_ip_entries_compare, 
			       const hip_sava_enc_ip_entry_t *)

static IMPLEMENT_LHASH_HASH_FN(hip_sava_conn_entry_hash, 
			       const hip_sava_conn_entry_t *)

static IMPLEMENT_LHASH_COMP_FN(hip_sava_conn_entries_compare, 
			       const hip_sava_conn_entry_t *)

unsigned long hip_sava_conn_entry_hash(const hip_sava_conn_entry_t * entry) {
  unsigned char hash[INDEX_HASH_LENGTH];
  struct in6_addr addrs[2];
  int err = 0;
  
  // values have to be present
  HIP_ASSERT(entry != NULL && entry->src != NULL && entry->dst);

  memcpy(&addrs[0], entry->src, sizeof(struct in6_addr));
  memcpy(&addrs[1], entry->dst, sizeof(struct in6_addr));
  
  memset(hash, 0, INDEX_HASH_LENGTH);

  HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)addrs, 
			    2*sizeof(struct in6_addr), hash),
	   -1, "failed to hash addresses\n");
  
 out_err:
  if (err) {
    *hash = 0;
  }

  return *((unsigned long *)hash);
}

int hip_sava_conn_entries_compare(const hip_sava_conn_entry_t * entry1,
				  const hip_sava_conn_entry_t * entry2) {
  int err = 0;
  unsigned long hash1 = 0;
  unsigned long hash2 = 0;

  // values have to be present
  HIP_ASSERT(entry1 != NULL && entry1->src != NULL && entry1->dst != NULL);
  HIP_ASSERT(entry2 != NULL && entry2->src != NULL && entry2->dst != NULL);

  HIP_IFEL(!(hash1 = hip_sava_conn_entry_hash(entry1)), 
	   -1, "failed to hash sa entry\n");

  HIP_IFEL(!(hash2 = hip_sava_conn_entry_hash(entry2)), 
	   -1, "failed to hash sa entry\n");

  err = (hash1 != hash2);

  out_err:
    return err;
  return 0;
}

int hip_sava_conn_db_init() {
  int err = 0;
  HIP_IFEL(!(sava_conn_db = hip_ht_init(LHASH_HASH_FN(hip_sava_conn_entry_hash),
	     LHASH_COMP_FN(hip_sava_conn_entries_compare))), -1,
	     "failed to initialize sava_ip_db \n");
  HIP_DEBUG("sava ip db initialized\n");
 out_err:
  return err;
}

int hip_sava_conn_db_uninit() {
  return 0;
}

hip_sava_conn_entry_t * hip_sava_conn_entry_find(struct in6_addr * src,
						 struct in6_addr * dst) {
  hip_sava_conn_entry_t *search_link = NULL, *stored_link = NULL;
  int err = 0;

  HIP_IFEL(!(search_link = 
	     (hip_sava_conn_entry_t *) malloc(sizeof(hip_sava_conn_entry_t))),
	     -1, "failed to allocate memory\n");
  memset(search_link, 0, sizeof(hip_sava_conn_entry_t));

  // search the linkdb for the link to the corresponding entry
  search_link->src = src;
  search_link->dst = dst;

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("src", search_link->src);
  HIP_DEBUG_HIT("dst", search_link->dst);

  HIP_IFEL(!(stored_link = hip_ht_find(sava_conn_db, search_link)), -1,
				"failed to retrieve link entry\n");

 out_err:
  if (err)
    stored_link = NULL;
  
  if (search_link)
    free(search_link);

  return stored_link;
}

int hip_sava_conn_entry_add(struct in6_addr *src,
			    struct in6_addr * dst) {
  hip_sava_conn_entry_t *  entry = malloc(sizeof(hip_sava_conn_entry_t));
  
  HIP_DEBUG_HIT("Adding connection entry for src ", src);
  HIP_DEBUG_HIT("Adding connection entry for dst ", dst);

  HIP_ASSERT(src != NULL && dst != NULL);
  
  memset(entry, 0, sizeof(hip_sava_conn_entry_t));
  
  entry->src = 
    (struct in6_addr *) malloc(sizeof(struct in6_addr));
  entry->dst = 
    (struct in6_addr *) malloc(sizeof(struct in6_addr));
  
  memcpy(entry->src, src,
  	 sizeof(struct in6_addr));
  
  memcpy(entry->dst, dst,
  	 sizeof(struct in6_addr));

  hip_ht_add(sava_conn_db, entry);

  return 0;
}

int hip_sava_conn_entry_delete(struct in6_addr * src,
			       struct in6_addr * dst) {
  hip_sava_conn_entry_t *stored_link = NULL;
  int err = 0;
  
  // find link entry and free members
  HIP_IFEL(!(stored_link = hip_sava_conn_entry_find(src, dst)), -1,
	   "failed to retrieve sava enc ip entry\n");

  hip_ht_delete(sava_conn_db, stored_link);
  // we still have to free the link itself
  free(stored_link);

 out_err:
  return err;
  return 0;
}

unsigned long hip_sava_enc_ip_entry_hash(const hip_sava_enc_ip_entry_t * entry) {
  unsigned char hash[INDEX_HASH_LENGTH];
  int err = 0;

  // values have to be present
  HIP_ASSERT(entry != NULL && entry->src_enc != NULL);

  memset(hash, 0, INDEX_HASH_LENGTH);

  HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)entry->src_enc, 
			    sizeof(struct in6_addr), hash),
	   -1, "failed to hash addresses\n");

  out_err:
  if (err) {
    *hash = 0;
  }

  return *((unsigned long *)hash);
}

int hip_sava_enc_ip_entries_compare(const hip_sava_enc_ip_entry_t * entry1,
				    const hip_sava_enc_ip_entry_t * entry2) {
    int err = 0;
  unsigned long hash1 = 0;
  unsigned long hash2 = 0;

  // values have to be present
  HIP_ASSERT(entry1 != NULL && entry1->src_enc != NULL);
  HIP_ASSERT(entry2 != NULL && entry2->src_enc != NULL);

  _HIP_DEBUG_HIT("Entry1 addr ", entry1->src_enc);
  _HIP_DEBUG_HIT("Entry2 addr ", entry2->src_enc);

  HIP_IFEL(!(hash1 = hip_sava_ip_entry_hash(entry1)), 
	   -1, "failed to hash sa entry\n");

  HIP_IFEL(!(hash2 = hip_sava_ip_entry_hash(entry2)), 
	   -1, "failed to hash sa entry\n");

  err = (hash1 != hash2);

  out_err:
  return err;
}

int hip_sava_enc_ip_db_init() {
  int err = 0;
  HIP_IFEL(!(sava_enc_ip_db = hip_ht_init(LHASH_HASH_FN(hip_sava_enc_ip_entry_hash),
	     LHASH_COMP_FN(hip_sava_enc_ip_entries_compare))), -1,
	     "failed to initialize sava_ip_db \n");
  HIP_DEBUG("sava ip db initialized\n");
 out_err:
  return err;
}
int hip_sava_enc_ip_db_uninit() {
  return 0;
}

hip_sava_enc_ip_entry_t *hip_sava_enc_ip_entry_find(struct in6_addr * src_enc) {
  hip_sava_enc_ip_entry_t *search_link = NULL, *stored_link = NULL;
  int err = 0;

  HIP_IFEL(!(search_link = 
	     (hip_sava_enc_ip_entry_t *) malloc(sizeof(hip_sava_enc_ip_entry_t))),
	     -1, "failed to allocate memory\n");
  memset(search_link, 0, sizeof(hip_sava_enc_ip_entry_t));

  // search the linkdb for the link to the corresponding entry
  search_link->src_enc = src_enc;

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("src_enc", search_link->src_enc);

  //hip_linkdb_print();

  HIP_IFEL(!(stored_link = hip_ht_find(sava_enc_ip_db, search_link)), -1,
				"failed to retrieve link entry\n");

 out_err:
  if (err)
    stored_link = NULL;
  
  if (search_link)
    free(search_link);

  return stored_link;
}

int hip_sava_enc_ip_entry_add(struct in6_addr *src_enc,
			      hip_sava_ip_entry_t * ip_link,
			      hip_sava_hit_entry_t * hit_link,
			      hip_sava_peer_info_t * info_link) {

  hip_sava_enc_ip_entry_t  * entry = (hip_sava_enc_ip_entry_t *)
    malloc(sizeof(hip_sava_enc_ip_entry_t));
  
  HIP_ASSERT(src_enc != NULL);
  
  memset(entry, 0, sizeof(hip_sava_enc_ip_entry_t));

  entry->src_enc =  (struct in6_addr *) malloc(sizeof(struct in6_addr));

  memset(entry->src_enc, 0, sizeof(struct in6_addr));

  memcpy(entry->src_enc, src_enc,
	 sizeof(struct in6_addr));

  HIP_DEBUG_HIT("Adding enc IP ", entry->src_enc);

  entry->hit_link = hit_link;

  entry->ip_link = ip_link;

  entry->peer_info = info_link;

  hip_ht_add(sava_enc_ip_db, entry);

  return 0;
}

int hip_sava_enc_ip_entry_delete(struct in6_addr * src_enc) {
  hip_sava_enc_ip_entry_t *stored_link = NULL;
  int err = 0;
  
  // find link entry and free members
  HIP_IFEL(!(stored_link = hip_sava_enc_ip_entry_find(src_enc)), -1,
	   "failed to retrieve sava enc ip entry\n");

  hip_ht_delete(sava_enc_ip_db, stored_link);
  // we still have to free the link itself
  free(stored_link);

  HIP_DEBUG("sava IP entry deleted\n");

 out_err:
  return err;
}


unsigned long hip_sava_hit_entry_hash(const hip_sava_hit_entry_t * entry) {
  unsigned char hash[INDEX_HASH_LENGTH];
  int err = 0;

  // values have to be present
  HIP_ASSERT(entry != NULL && entry->src_hit != NULL);

  memset(hash, 0, INDEX_HASH_LENGTH);

  HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)entry->src_hit, 
			    sizeof(struct in6_addr), hash),
	   -1, "failed to hash addresses\n");

  out_err:
  if (err) {
    *hash = 0;
  }

  
  return *((unsigned long *)hash);
}

unsigned long hip_sava_ip_entry_hash(const hip_sava_ip_entry_t * entry) {
  unsigned char hash[INDEX_HASH_LENGTH];
  int err = 0;

  // values have to be present
  HIP_ASSERT(entry != NULL && entry->src_addr != NULL);

  memset(hash, 0, INDEX_HASH_LENGTH);

  HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)entry->src_addr, 
			    sizeof(struct in6_addr), hash),
	   -1, "failed to hash addresses\n");

  out_err:
  if (err) {
    *hash = 0;
  }
  
  return *((unsigned long *)hash);
}

int hip_sava_ip_entries_compare(const hip_sava_ip_entry_t * entry1,
				const hip_sava_ip_entry_t * entry2) {

  int err = 0;
  unsigned long hash1 = 0;
  unsigned long hash2 = 0;

  // values have to be present
  HIP_ASSERT(entry1 != NULL && entry1->src_addr != NULL);
  HIP_ASSERT(entry2 != NULL && entry2->src_addr != NULL);

  HIP_IFEL(!(hash1 = hip_sava_ip_entry_hash(entry1)), 
	   -1, "failed to hash sa entry\n");

  HIP_IFEL(!(hash2 = hip_sava_ip_entry_hash(entry2)), 
	   -1, "failed to hash sa entry\n");

  err = (hash1 != hash2);

  out_err:
    return err;
  return 0;
}

int hip_sava_hit_entries_compare(const hip_sava_hit_entry_t * entry1,
				const hip_sava_hit_entry_t * entry2) {

  int err = 0;
  unsigned long hash1 = 0;
  unsigned long hash2 = 0;

  // values have to be present
  HIP_ASSERT(entry1 != NULL && entry1->src_hit != NULL);
  HIP_ASSERT(entry2 != NULL && entry2->src_hit != NULL);

  HIP_IFEL(!(hash1 = hip_sava_hit_entry_hash(entry1)), 
	   -1, "failed to hash sa entry\n");

  HIP_IFEL(!(hash2 = hip_sava_hit_entry_hash(entry2)), 
	   -1, "failed to hash sa entry\n");

  err = (hash1 != hash2);

  out_err:
    return err;
  return 0;
}

int hip_sava_hit_db_init() {
  int err = 0;
  HIP_IFEL(!(sava_hit_db = hip_ht_init(LHASH_HASH_FN(hip_sava_hit_entry_hash),
	     LHASH_COMP_FN(hip_sava_hit_entries_compare))), -1,
	     "failed to initialize sava_ip_db \n");
  HIP_DEBUG("sava ip db initialized\n");
 out_err:
  return err;
}

int hip_sava_ip_db_init() {
  int err = 0;
  HIP_IFEL(!(sava_ip_db = hip_ht_init(LHASH_HASH_FN(hip_sava_ip_entry_hash),
	     LHASH_COMP_FN(hip_sava_ip_entries_compare))), -1,
	     "failed to initialize sava_ip_db \n");
  HIP_DEBUG("sava ip db initialized\n");
 out_err:
  return err;
}

int hip_sava_ip_db_uninit() {
  /* TODO: check wether we need to free the db structure */
  return 0;
}

int hip_sava_hit_db_uninit() {

  return 0;
}

hip_sava_ip_entry_t *hip_sava_ip_entry_find(struct in6_addr *src_addr) {

  hip_sava_ip_entry_t *search_link = NULL, *stored_link = NULL;
  int err = 0;

  HIP_IFEL(!(search_link = 
	     (hip_sava_ip_entry_t *) malloc(sizeof(hip_sava_ip_entry_t))),
	     -1, "failed to allocate memory\n");
  memset(search_link, 0, sizeof(hip_sava_ip_entry_t));

  // search the linkdb for the link to the corresponding entry
  search_link->src_addr = src_addr;
  
  /* memcpy(search_link->src_addr, 
	 src_addr, 
	 sizeof(struct in6_addr));*/

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("src_addr", search_link->src_addr);

  HIP_IFEL(!(stored_link = hip_ht_find(sava_ip_db, search_link)), -1,
  "failed to retrieve link entry\n");

 out_err:
  if (err)
    stored_link = NULL;
  
  if (search_link)
    free(search_link);

  return stored_link;
}

hip_sava_hit_entry_t *hip_sava_hit_entry_find(struct in6_addr *src_hit) {

  hip_sava_hit_entry_t *search_link = NULL, *stored_link = NULL;
  int err = 0;

  HIP_IFEL(!(search_link = 
	     (hip_sava_hit_entry_t *) malloc(sizeof(hip_sava_hit_entry_t))),
	     -1, "failed to allocate memory\n");
  memset(search_link, 0, sizeof(hip_sava_hit_entry_t));

  // search the linkdb for the link to the corresponding entry
  search_link->src_hit = src_hit;

  HIP_DEBUG("looking up link entry with following index attributes:\n");
  HIP_DEBUG_HIT("dst_addr", search_link->src_hit);

  HIP_IFEL(!(stored_link = hip_ht_find(sava_hit_db, search_link)), -1,
				"failed to retrieve link entry\n");

 out_err:
  if (err)
    stored_link = NULL;
  
  if (search_link)
    free(search_link);

  return stored_link;
}

int hip_sava_ip_entry_add(struct in6_addr * src_addr, 
			  hip_sava_hit_entry_t * link) {
  hip_sava_ip_entry_t *  entry = malloc(sizeof(hip_sava_ip_entry_t));

  HIP_ASSERT(src_addr != NULL);
  
  memset(entry, 0, sizeof(hip_sava_ip_entry_t));
  
  entry->src_addr = 
    (struct in6_addr *) malloc(sizeof(struct in6_addr));
  
  memcpy(entry->src_addr, src_addr,
  	 sizeof(struct in6_addr));
 
  entry->link = link;
  
  hip_ht_add(sava_ip_db, entry);

  return 0;
}

int hip_sava_hit_entry_add(struct in6_addr * src_hit,    
			  hip_sava_ip_entry_t * link) {
  hip_sava_hit_entry_t * entry = malloc(sizeof(hip_sava_hit_entry_t));

  HIP_ASSERT(src_hit != NULL);
  
  memset(entry, 0, sizeof(hip_sava_hit_entry_t));

  entry->src_hit =  (struct in6_addr *) malloc(sizeof(struct in6_addr));
  
  memcpy(entry->src_hit, src_hit,
	 sizeof(struct in6_addr));

  entry->link = link;

  hip_ht_add(sava_hit_db, entry);

  return 0;
}

int hip_sava_ip_entry_delete(struct in6_addr * src_addr) {
  hip_sava_ip_entry_t *stored_link = NULL;
  int err = 0;
  
  // find link entry and free members
  HIP_IFEL(!(stored_link = hip_sava_ip_entry_find(src_addr)), -1,
	   "failed to retrieve sava ip entry\n");

  hip_ht_delete(sava_ip_db, stored_link);
  // we still have to free the link itself
  free(stored_link);

  HIP_DEBUG("sava IP entry deleted\n");

 out_err:
  return err;
}

int hip_sava_hit_entry_delete(struct in6_addr * src_hit) {
  hip_sava_ip_entry_t *stored_link = NULL;
  int err = 0;
  
  // find link entry and free members
  HIP_IFEL(!(stored_link = hip_sava_hit_entry_find(src_hit)), -1,
	   "failed to retrieve sava ip entry\n");

  hip_ht_delete(sava_hit_db, stored_link);
  // we still have to free the link itself
  free(stored_link);

  HIP_DEBUG("sava IP entry deleted\n");

 out_err:
  return err;
}


int hip_sava_init_all() {
  int err = 0;
  HIP_IFEL(hip_sava_ip_db_init(), -1, "error init ip db \n");
  HIP_IFEL(hip_sava_enc_ip_db_init(), -1, "error init enc ip db \n");
  HIP_IFEL(hip_sava_hit_db_init(), -1, "error init hit db \n"); 
  HIP_IFEL(hip_sava_conn_db_init(), -1, "error init sava conn db \n");
  HIP_IFEL(hip_sava_init_ip6_raw_socket(&ipv6_raw_tcp_sock, IPPROTO_TCP), 
	   -1, "error creating raw IPv6 socket \n");
  HIP_IFEL(hip_sava_init_ip4_raw_socket(&ipv4_raw_tcp_sock, IPPROTO_TCP), 
	   -1, "error creating raw IPv4 socket \n");
  HIP_IFEL(hip_sava_init_ip6_raw_socket(&ipv6_raw_udp_sock, IPPROTO_TCP), 
	   -1, "error creating raw IPv6 socket \n");
  HIP_IFEL(hip_sava_init_ip4_raw_socket(&ipv4_raw_udp_sock, IPPROTO_TCP), 
	   -1, "error creating raw IPv4 socket \n");
 out_err:
  return err;
}

int hip_sava_client_init_all() {
  int err = 0;
  HIP_IFEL(hip_sava_init_ip6_raw_socket(&ipv6_raw_tcp_sock, IPPROTO_TCP), 
	   -1, "error creating raw IPv6 socket \n");
  HIP_IFEL(hip_sava_init_ip4_raw_socket(&ipv4_raw_tcp_sock, IPPROTO_TCP), 
	   -1, "error creating raw IPv4 socket \n");
  HIP_IFEL(hip_sava_init_ip6_raw_socket(&ipv6_raw_udp_sock, IPPROTO_TCP), 
	   -1, "error creating raw IPv6 socket \n");
  HIP_IFEL(hip_sava_init_ip4_raw_socket(&ipv4_raw_udp_sock, IPPROTO_TCP), 
	   -1, "error creating raw IPv4 socket \n");
  HIP_IFEL(hip_sava_init_ip6_raw_socket(&ipv6_raw_raw_sock, IPPROTO_RAW), 
	   -1, "error creating raw IPv6 socket  IPPROTO_RAW \n");
 out_err:
  return err;
}

struct in6_addr * hip_sava_find_hit_by_enc(struct in6_addr * src_enc) {
  hip_sava_enc_ip_entry_t * entry; 
  
  entry = hip_sava_enc_ip_entry_find(src_enc);
  
  if (entry)
    return entry->hit_link->src_hit;

  return NULL;
}

struct in6_addr * hip_sava_find_ip_by_enc(struct in6_addr * src_enc) {
  hip_sava_enc_ip_entry_t * entry; 
  
  entry = hip_sava_enc_ip_entry_find(src_enc);
  
  if (entry)
    return entry->ip_link->src_addr;

  return NULL;
}


hip_common_t * hip_sava_get_keys_build_msg(const struct in6_addr * hit) {



}

hip_common_t * hip_sava_make_keys_request(const struct in6_addr * hit, 
					  int direction) {
  int err = 0;
  hip_common_t * msg = NULL;
  HIP_DEBUG_HIT("SAVAH HIT ", hit);
  HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed.\n");
  memset(msg, 0, HIP_MAX_PACKET);
  
  HIP_IFEL(hip_build_param_contents(msg, (void *) hit, HIP_PARAM_HIT,
				    sizeof(in6_addr_t)), -1,
	   "build param hit failed\n");
  if (direction == SAVA_INBOUND_KEY) {
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_SAVAHR_IN_KEYS,
				0), -1, "Failed to buid user header\n");
  }else {
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_SAVAHR_OUT_KEYS,
				0), -1, "Failed to buid user header\n");
  }

  if (hip_send_recv_daemon_info(msg, 0, hip_fw_sock) == 0)
    return msg;

 out_err:
  return NULL;
}

hip_common_t * hip_sava_make_hit_request() {
  int err = 0;
  hip_common_t * msg = NULL;
  HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed.\n");
  memset(msg, 0, HIP_MAX_PACKET);
  
  HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_SAVAHR_HIT,
			      0), -1, "Failed to buid user header\n");

  if(hip_send_recv_daemon_info(msg, 0, hip_fw_sock) == 0)
    return msg;

 out_err:
  return NULL;
}



hip_sava_peer_info_t * hip_sava_get_key_params(hip_common_t * msg) {
  hip_sava_peer_info_t * peer_info;

  struct hip_tlv_common *param = NULL;

  int ealg = 0, err = 0;

  struct hip_crypto_key *auth_key = NULL;
  
  //peer_info = (hip_sava_peer_info_t *)malloc(sizeof(hip_sava_peer_info_t));
  
  //memset (peer_info, 0, sizeof(hip_sava_peer_info_t));
  
  param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_KEYS);

  if (param == NULL) 
    return NULL;

  auth_key = (struct hip_crypto_key *) hip_get_param_contents_direct(param);

  if (auth_key == NULL)
    return NULL;
  HIP_HEXDUMP("crypto key:", auth_key, sizeof(struct hip_crypto_key));
  
  param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_INT);
  ealg = *((int *) hip_get_param_contents_direct(param));
  HIP_DEBUG("ealg value is %d \n", ealg);

  peer_info->ip_enc_key = auth_key;
  peer_info->ealg = ealg;
    
  return peer_info;
}

struct in6_addr * hip_sava_auth_ip(struct in6_addr * orig_addr, 
				      hip_sava_peer_info_t * info_entry) {

  int err = 0;
  struct in6_addr * enc_addr = (struct in6_addr *)malloc(sizeof(struct in6_addr));
  char out[EVP_MAX_MD_SIZE];
  int out_len;
  char in_len = sizeof(struct in6_addr);

  HIP_DEBUG_HIT("Authenticating address ", orig_addr);

  memset(enc_addr, 0, sizeof(struct in6_addr));
  
  switch(info_entry->ealg) {
  case HIP_ESP_3DES_MD5:
    // same authentication chiper as next transform
  case HIP_ESP_NULL_MD5:
    if (!info_entry->ip_enc_key) {
      HIP_ERROR("authentication keys missing\n");
      err = -1;
      goto out_err;
    }
    HMAC(EVP_md5(), info_entry->ip_enc_key,
	 hip_auth_key_length_esp(info_entry->ealg),
	 (void *)orig_addr, in_len, out, &out_len);
    HIP_DEBUG("alen: %i \n", out_len);
    break;
  case HIP_ESP_3DES_SHA1:
  case HIP_ESP_NULL_SHA1:
  case HIP_ESP_AES_SHA1:
    if (!info_entry->ip_enc_key) {
      HIP_ERROR("authentication keys missing\n");
      
      err = -1;
      goto out_err;
    }
    
    HMAC(EVP_sha1(), info_entry->ip_enc_key,
	 hip_auth_key_length_esp(info_entry->ealg),
	 (void *)orig_addr, in_len, out, &out_len);
    
    HIP_DEBUG("alen: %i \n", out_len);
    
    break;
  default:
    HIP_DEBUG("Unsupported authentication algorithm: %i\n", info_entry->ealg);
    err = -1;
    goto out_err;
  }
  if (out_len > 0) {
    memcpy(enc_addr, out, (out_len < in_len ? out_len : in_len));
    HIP_DEBUG_HIT("Encrypted address ", enc_addr);
    return enc_addr;
  } else {
    goto out_err;
  }
  
 out_err:
  return NULL;
}

int hip_sava_handle_output (struct hip_fw_context *ctx) {
  int verdict = DROP;
  int err = 0, sent = 0;
  struct hip_common * msg = NULL;
  struct in6_addr * sava_hit;
  struct hip_sava_peer_info * info_entry;
  
  struct ip6_hdr * ip6hdr= NULL;	
  struct ip * iphdr= NULL;
  char * buff_ip_opt = NULL;

  struct in6_addr * enc_addr = NULL;

  struct sockaddr_storage dst;

  struct sockaddr_in *dst4 = (struct sockaddr_in *)&dst;

  struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&dst;

  struct tcphdr* tcp = NULL;
  struct udphdr* udp = NULL;

  struct sava_ip_option * opt = NULL;

  struct sava_tlv_padding * sava_ip6_padding = NULL;

  struct sava_ip6_option * sava_hdr = NULL;

  struct sava_tlv_option * sava_ip6_opt = NULL;

  struct ip6_hbh * ip6hbh_hdr = NULL;

  int protocol = 0;

  int ip_raw_sock = 0;

  int on = 1, off = 0;

  char * buff = ctx->ipq_packet->payload;
  int buff_len = ctx->ipq_packet->data_len;

  int dst_len = 0;


  if (ctx->ip_version == 6) { //IPv6
    ip6hdr = (struct ip6_hdr*) buff;
    protocol = ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt; //get next header protocol type
    if (protocol == IPPROTO_SAVAH) {
      HIP_DEBUG("Packet contains IPv6 SAVA option. Allow packet \n");
      verdict = ACCEPT;
      goto out_err;
    } else {
      ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_SAVAH;
    }
  } else {
    iphdr = (struct ip *)buff;
    if (iphdr->ip_hl == 10) {
      opt = (struct sava_ip_option *) (((char *)iphdr) + 20);
      if (opt->type ==  SAVA_IPV4_OPTION_TYPE) {
	HIP_DEBUG("Packet contains IPv4 SAVA option. Allow packet \n");
	verdict = ACCEPT;
	goto out_err;
      }
    }
  }

  memset(&dst, 0, sizeof(struct sockaddr_storage));

  //remove this as it is decreases performance 
  HIP_IFEL((msg = hip_sava_make_hit_request()) == NULL, DROP,
	   "HIT request from daemon failed \n");
  
  HIP_IFEL((sava_hit = hip_get_param_contents(msg,HIP_PARAM_HIT)) == NULL, DROP,
	   "Failed to get SAVA HIT from the daemon \n");
  
  HIP_DEBUG_HIT("SAVAH HIT ", sava_hit);
  
  HIP_IFEL((msg = hip_sava_make_keys_request(sava_hit, SAVA_OUTBOUND_KEY)) == NULL, DROP,
	   "Key request from daemon failed \n");
  
  HIP_DEBUG("Secret key acquired. Lets encrypt the src IP address \n");
  
  HIP_IFEL((info_entry = hip_sava_get_key_params(msg)) == NULL, DROP,
	   "Error parsing user message");

  enc_addr = hip_sava_auth_ip(&ctx->src, info_entry);
  
  if (ctx->ip_version == 6) { //IPv6
    
    dst6->sin6_family = AF_INET6;    
    
    memcpy(&dst6->sin6_addr, &ctx->dst, sizeof(struct in6_addr));
    
    dst_len = sizeof(struct sockaddr_in6);
    
#ifdef CONFIG_SAVAH_IP_OPTION
    if (protocol == 0) { //HOP-BY-HOP Options
#if 0
      int hbh_len = 0;
      
      ip6hbh_hdr = (struct ip6_hbh *)(ip6hdr + 40); // size of IPv6 header 40 after HBH header ext starts 
      
      hbh_len = ip6hbh_hdr->ip6h_len * 8; // hbh_len size in bytes

      ip6hbh_hdr->ip6h_len += 3;          //we add 3 additional 8-octet units to the header extension
      
      buff_ip_opt = (char *) malloc(buff_len + 24); //24 extra bytes(or 3 8-octet units) + 2 bytes ext hdr fields

      sava_ip6_opt = (struct sava_tlv_option *)malloc(sizeof(struct sava_tlv_option)); //standard IPv6 option format

      memset (sava_ip6_opt, 0, sizeof(struct sava_ip6_option)); 

      sava_ip6_opt->type = SAVA_IPV6_OPTION_TYPE;
      sava_ip6_opt->action = 0; //skip the option on the router as it is unknown
      sava_ip6_opt->change = 0; //don't alter the option
      sava_ip6_opt->length = 22; //size of IPv6 address in octets + 6 padding
      sava_ip6_opt->data = (char *)malloc (22);
 
      memcpy(sava_ip6_opt->data, enc_addr, sizeof(struct in6_addr));
      
      memcpy(buff_ip_opt, buff, 42 + hbh_len); //copy IPv6 main header + 2 octets of HBH header + HBH header data
      memcpy(buff_ip_opt + 42 + hbh_len,
	     sava_ip6_opt, sizeof(sava_ip6_opt));  //copy sava option
      memcpy(buff_ip_opt + 42 + hbh_len + sizeof(sava_ip6_opt), //copy rest of the packet data
	     buff + 42 + hbh_len,
	     buff_len - 42 - hbh_len);

      buff_len += 24; //add 24 bytes of sava option
#endif

    } else { //No HBH option found in the packet
      if (protocol == IPPROTO_TCP) {
	HIP_DEBUG("Next protocol header is TCP \n");
	ip_raw_sock = ipv6_raw_tcp_sock;	  
      } else if (protocol == IPPROTO_UDP) {
	HIP_DEBUG("Next protocol header is UDP \n");
	ip_raw_sock = ipv6_raw_udp_sock;
      } else {
	ip_raw_sock = ipv6_raw_raw_sock;
      }
      {
	char hbh_buff[24];

	buff_ip_opt = (char *) malloc(buff_len + 24); //24 extra bytes for our HBH option

	memset(buff_ip_opt, 0, buff_len + 24);
	memset(hbh_buff, 0, sizeof(hbh_buff));
	
	ip6hbh_hdr = hbh_buff;//(struct ip6_hbh *) malloc(sizeof(struct ip6_hbh));
	ip6hbh_hdr->ip6h_nxt = protocol; //we should have the same next header as it was previously
	ip6hbh_hdr->ip6h_len = 2; //96 bits of IPv6 address length + padding 32 bits (not including first 8 octets)
	
	sava_ip6_opt = hbh_buff + 2;//(struct sava_tlv_option *)malloc(sizeof(struct sava_tlv_option));
	sava_ip6_opt->type = SAVA_IPV6_OPTION_TYPE;
	sava_ip6_opt->action = 0;
	sava_ip6_opt->change = 0;
	sava_ip6_opt->length = sizeof(struct in6_addr); //size of IPv6 address in octets (16 bytes)

	memcpy(hbh_buff + 4, enc_addr, sizeof(struct in6_addr));
	
	sava_ip6_padding = hbh_buff + 20; //(struct sava_tlv_padding *)malloc(sizeof(struct sava_tlv_padding));
	memset(sava_ip6_padding, 0, sizeof(sava_tvl_padding_t));
	sava_ip6_padding->type = 1;
	sava_ip6_padding->length = 2;
	
	memcpy(buff_ip_opt, buff, 40); //copy main IPv6 header
	memcpy(buff_ip_opt + 40, hbh_buff, 24);
	memcpy(buff_ip_opt + 64, buff + 40, buff_len - 40);

        /*
	memcpy(buff_ip_opt + 40, ip6hbh_hdr, sizeof(ip6hbh_hdr)); //copy HBH header 
	memcpy(buff_ip_opt + 40 + sizeof(ip6hbh_hdr), 
	     sava_ip6_opt, sizeof(sava_ip6_opt));
	memcpy(buff_ip_opt + 40 + sizeof(ip6hbh_hdr) + sizeof(sava_ip6_opt),
	       enc_addr, sizeof(struct in6_addr));
	memcpy(buff_ip_opt + 40 + sizeof(ip6hbh_hdr) + sizeof(sava_ip6_opt) + sizeof(struct in6_addr),
	       sava_ip6_padding, sizeof(sava_ip6_padding)); //As required in IPv6 RFC
	memcpy(buff_ip_opt + 40 + sizeof(ip6hbh_hdr) + 
	       sizeof(sava_ip6_opt) + sizeof(enc_addr) + 
	       sizeof(sava_ip6_padding) + 2, // 2 bytes are the actual padding we just skip this 2 bytes unchanged as they already 0's
	       buff + 40, buff_len - 40);  //this is the rest of the stuff
	
	free(sava_ip6_opt);
	free(ip6hbh_hdr);
	free(sava_ip6_padding);
	*/
	free(hbh_buff);
      }

      ip6hdr = (struct ip6_hdr*) buff_ip_opt;

      ip6hbh_hdr = (struct ip6_hbh *) buff_ip_opt;

      buff_len += 24; // add 24 bytes of sava option
    }
#else

    memcpy(&ip6hdr->ip6_src, (void *)enc_addr, sizeof(struct in6_addr));

    //what about IPv6 Options
    tcp = (struct tcphdr *) (buff + 40); //sizeof ip6_hdr is 40
    udp = (struct udphdr *) (buff + 40); //sizeof ip6_hdr is 40
    
    HIP_DEBUG_INADDR("ipv6 src: ", &ip6hdr->ip6_src);
    HIP_DEBUG_INADDR("ipv6 dst: ", &ip6hdr->ip6_dst);
    
    if (protocol == IPPROTO_TCP) {
      
      HIP_DEBUG("Checksumming TCP packet \n");
      ip_raw_sock = ipv6_raw_tcp_sock;
      
      tcp->check  = 0;
      tcp->check  = ipv6_checksum(IPPROTO_TCP, &(ip6hdr->ip6_src), &(ip6hdr->ip6_dst), tcp, (buff_len - sizeof(struct ip))); //checksum is ok for ipv4
      HIP_HEXDUMP("tcp dump: ", tcp, (buff_len - sizeof(struct ip6_hdr)));
	  
    } else if (protocol == IPPROTO_UDP) {
      
      HIP_DEBUG("Checksumming UDP packet \n");
      ip_raw_sock = ipv4_raw_udp_sock;
      
      udp->check =  0;
      udp->check = ipv4_checksum(IPPROTO_UDP, &(iphdr->ip_src), &(iphdr->ip_dst), udp, (buff_len - sizeof(struct ip))); //checksum is ok for ipv4
      HIP_HEXDUMP("udp dump: ", udp, (buff_len - sizeof(struct ip6_hdr)));
      
    }
#endif
    if(setsockopt(ip_raw_sock, IPPROTO_IPV6, IP_HDRINCL, &on, sizeof(on)) < 0) { 
      HIP_DEBUG("setsockopt IP_HDRINCL ERROR！ \n");
    } else {
      HIP_DEBUG("setsockopt IP_HDRINCL for ipv4 OK！ \n");
    }
  }else { //IPv4

    iphdr = (struct ip *) buff;

    iphdr->ip_sum = 0;

    protocol = iphdr->ip_p;

    dst_len = sizeof(struct sockaddr_in);
    
    IPV6_TO_IPV4_MAP(&ctx->dst, &dst4->sin_addr);
    
    dst4->sin_family = AF_INET;

#ifdef CONFIG_SAVAH_IP_OPTION
    //FIX ME
    if (protocol == IPPROTO_TCP) {
      HIP_DEBUG("Using tcp raw socket \n");
      ip_raw_sock = ipv4_raw_tcp_sock;
    } else if (protocol == IPPROTO_UDP) {
      HIP_DEBUG("Using udp raw socket \n");
      ip_raw_sock = ipv4_raw_udp_sock;
    }

    opt = hip_sava_build_enc_addr_ipv4_option(enc_addr);

    iphdr->ip_hl += 5;

    HIP_DEBUG_INADDR("Source address ", &iphdr->ip_src);
    HIP_DEBUG_INADDR("Destination address ", &iphdr->ip_dst);
    HIP_DEBUG_INADDR("Sock dst addr ", &dst);
    
    buff_ip_opt = (char *) malloc(buff_len + opt->length);

    memcpy(buff_ip_opt, buff, sizeof(struct ip));
    
    memcpy(buff_ip_opt + sizeof(struct ip), opt, opt->length);

    memcpy(buff_ip_opt + sizeof(struct ip) + opt->length, 
	   buff + sizeof(struct ip), buff_len - sizeof(struct ip));

    buff_len += 20;
#else
    IPV6_TO_IPV4_MAP(enc_addr, &iphdr->ip_src);
    
    tcp = (struct tcphdr *) (buff + 20); //sizeof iphdr is 20
    udp = (struct udphdr *) (buff + 20); //sizeof iphdr is 20
        
    HIP_DEBUG_INADDR("ipv4 src: ", &iphdr->ip_src);
    HIP_DEBUG_INADDR("ipv4 dst: ", &iphdr->ip_dst);
    
    if (protocol == IPPROTO_TCP) {
      
      HIP_DEBUG("Checksumming TCP packet \n");
      ip_raw_sock = ipv4_raw_tcp_sock;
      
      tcp->check  = htons(0);
      tcp->check  = ipv4_checksum(IPPROTO_TCP, &(iphdr->ip_src), &(iphdr->ip_dst), tcp, (buff_len - sizeof(struct ip))); //checksum is ok for ipv4
      HIP_HEXDUMP("tcp dump: ", tcp, (buff_len - sizeof(struct ip)));
      
    } else if (protocol == IPPROTO_UDP) {
      
      HIP_DEBUG("Checksumming UDP packet \n");
      ip_raw_sock = ipv4_raw_udp_sock;
      
      udp->check =  htons(0);
      udp->check = ipv4_checksum(IPPROTO_UDP, &(iphdr->ip_src), &(iphdr->ip_dst), udp, (buff_len - sizeof(struct ip))); //checksum is ok for ipv4
      HIP_HEXDUMP("udp dump: ", udp, (buff_len - sizeof(struct ip)));      
    }
#endif
    if(setsockopt(ip_raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) { 
      HIP_DEBUG("setsockopt IP_HDRINCL ERROR！ \n");
    } else {
      HIP_DEBUG("setsockopt IP_HDRINCL for ipv4 OK！ \n");
    }
  }
#ifdef CONFIG_SAVAH_IP_OPTION
  sent = sendto(ip_raw_sock, buff_ip_opt, buff_len, 0,
		(struct sockaddr *) &dst, dst_len);
  free(buff_ip_opt);
#else
  sent = sendto(ip_raw_sock, buff, buff_len, 0,
		(struct sockaddr *) &dst, dst_len);
#endif
  if (ctx->ip_version == 4) {
    if(setsockopt(ip_raw_sock, IPPROTO_IP, IP_HDRINCL, &off, sizeof(off)) < 0) { 
      HIP_DEBUG("setsockopt IP_HDRINCL ERROR！ \n");
    }
  }	else {
    if(setsockopt(ip_raw_sock, IPPROTO_IPV6, IP_HDRINCL, &off, sizeof(off)) < 0) { 
      HIP_DEBUG("setsockopt IP_HDRINCL ERROR！ \n");
    }	
  }
#ifdef CONFIG_SAVAH_IP_OPTION
  if (sent != buff_len) {
#else
  if (sent != ctx->ipq_packet->data_len) {  
#endif
    HIP_ERROR("Could not send the all requested"			\
	      " data (%d/%d)\n", sent, ctx->ipq_packet->data_len);
    HIP_DEBUG("ERROR NUMBER: %d\n", errno);
  } else {
    HIP_DEBUG("sent=%d/%d \n",
	      sent, ctx->ipq_packet->data_len);
    HIP_DEBUG("Packet sent ok\n");
  }

 out_err:
  return verdict; 
}


int hip_sava_handle_router_forward(struct hip_fw_context *ctx) {
  int err = 0, verdict = 0, auth_len = 0, sent = 0;
  struct in6_addr * enc_addr = NULL;
  struct in6_addr * opt_addr = NULL;
  struct in6_addr * enc_addr_no = NULL;
  hip_sava_ip_entry_t  * ip_entry     = NULL;
  hip_sava_enc_ip_entry_t * enc_entry = NULL;
  struct sockaddr_storage dst;
  struct sockaddr_in *dst4 = (struct sockaddr_in *)&dst;
  struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&dst;
  int dst_len = 0;
  
  struct sava_tlv_option * sava_ip6_opt = NULL;
  struct ip6_hdr * ip6hdr= NULL;       
  struct ip * iphdr= NULL;

  struct ip6_hbh * ip6hbh_hdr = NULL;

  struct tcphdr* tcp = NULL;
  struct udphdr* udp = NULL;

  char * buff = ctx->ipq_packet->payload;
  int buff_len = ctx->ipq_packet->data_len;

  int protocol = 0;

  int ip_raw_sock = 0;

  int on = 1, off = 0;

  int hdr_offset = 0;

  int hdr_len = 0;

  char * tmp_buff = NULL;

  char * buff_no_opt = NULL;

  struct sava_ip_option * opt = NULL;

  memset(&dst, 0, sizeof(struct sockaddr_storage));

  HIP_DEBUG("CHECK IP ON FORWARD\n");

  if (hip_sava_conn_entry_find(&ctx->dst, &ctx->src) != NULL) {
    HIP_DEBUG("BYPASS THE PACKET THIS IS AN INBOUND TRAFFIC FOR AUTHENTICATED OUTBOUND \n");
    verdict = ACCEPT;
    goto out_err;
  }

  _HIP_DEBUG("NOT AN INBOUND TRAFFIC OR NOT AUTHENTICATED TRAFFIC \n");
  HIP_DEBUG_HIT("Authenticating source address ", &ctx->src);
#ifdef CONFIG_SAVAH_IP_OPTION 
  HIP_DEBUG("Checking IP option \n");
  if (ctx->ip_version == 4) {
    /*TODO: Check if this is the roght option */
    HIP_DEBUG("IPv4 \n");
    iphdr = (struct ip *)buff;
    if (iphdr->ip_hl == 5) {
      HIP_DEBUG("The packet does not have any options dropping \n");
      verdict = DROP;
      goto out_err;
    }else if (iphdr->ip_hl == 10) {
      HIP_DEBUG("We have the only IPv4 option \n");
      opt = (struct sava_ip_option *) (buff + 20); //first 20 bytes are original IPv4 header
      opt_addr = (struct in6_addr *) opt->data;
      enc_entry = hip_sava_enc_ip_entry_find(opt_addr);
      hdr_offset = 20;
      hdr_len = 20;
    } else {
      HIP_DEBUG("Some other IPv4 options present \n");
    }
  } else { //IPv6
    ip6hdr = (struct ip6_hdr*) buff;
    //HIP_ASSERT(ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO);
    protocol = ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt; // protocol should be only IPPROTO_SAVAH 140
    HIP_DEBUG("We have next header type %d \n", protocol);
    ip6hbh_hdr = (struct ip6_hbh *)buff + 40; //get the SAVAH encapsulated payload
    protocol = ip6hbh_hdr->ip6h_nxt;
    if (ip6hbh_hdr->ip6h_len == 2) { //we have exactly one SAVAH option that needs to be parsed and removed
      //sava_ip6_opt = (struct sava_tlv_option *)buff + 42;
      opt_addr = (struct in6_addr *)buff + 44; //the ipv6 starts after 44 bytes from the IPv6 header start
      enc_entry = hip_sava_enc_ip_entry_find(opt_addr);
      hdr_offset = 40;
      hdr_len = 24;
    }
  }
#else 
  enc_entry = hip_sava_enc_ip_entry_find(&ctx->src);
#endif

#ifdef CONFIG_SAVAH_IP_OPTION
  auth_len = sizeof(struct in6_addr);
#else 
  auth_len = (ctx->ip_version == 6) ? sizeof(struct in6_addr): sizeof(struct in_addr);
#endif
  if (enc_entry) {

    HIP_DEBUG("ENCRYPTED ENTRY FOUND \n");

    _HIP_DEBUG("Secret key acquired. Lets encrypt the src IP address \n");

    //#ifndef CONFIG_SAVAH_IP_OPTION    
    enc_addr = hip_sava_auth_ip(enc_entry->ip_link->src_addr, enc_entry->peer_info);
    //FIX IP version 
    //enc_addr_no = map_enc_ip_addr_to_network_order(enc_addr, 4);
    //free(enc_addr);
    //enc_addr = enc_addr_no;
    HIP_DEBUG_HIT("Found encrypted address ", enc_addr);
    //#endif

#ifdef CONFIG_SAVAH_IP_OPTION    
    HIP_DEBUG("Compare authentication values \n");
    if (!memcmp(opt_addr, enc_addr, sizeof(struct in6_addr))) {
#else
    if (!memcmp(&ctx->src, enc_addr, sizeof(struct in6_addr))) {  
#endif

      //PLACE ORIGINAL IP, RECALCULATE CHECKSUM AND REINJECT THE PACKET 
      //VERDICT DROP PACKET BECAUSE IT CONTAINS ENCRYPTED IP
      //ONLY NEW PACKET WILL GO OUT
      _HIP_DEBUG("Adding <src, dst> tuple to connection db \n");

      hip_sava_conn_entry_add(enc_entry->ip_link->src_addr, &ctx->dst);
      HIP_DEBUG("Source address is authenticated \n");
      _HIP_DEBUG("Reinject the traffic to network stack \n");
      if (ctx->ip_version == 6) { //IPv6
    	ip6hdr = (struct ip6_hdr*) buff;
	dst_len = sizeof(struct sockaddr_in6);
	dst6->sin6_family = AF_INET6;
	protocol = ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;

	memcpy(&dst6->sin6_addr, &ctx->dst, sizeof(struct in6_addr));
       
	HIP_DEBUG_INADDR("ipv6 src: ", &ip6hdr->ip6_src);
	HIP_DEBUG_INADDR("ipv6 dst: ", &ip6hdr->ip6_dst);
#ifdef CONFIG_SAVAH_IP_OPTION
	buff_no_opt = (char *) malloc(buff_len - hdr_len);
	memcpy(buff_no_opt, buff, hdr_offset);
	memcpy(buff_no_opt, (char *)(ip6hdr + hdr_offset + hdr_len), buff_len - hdr_len - hdr_offset);
	buff_len -= hdr_len;
	if (protocol == IPPROTO_TCP) {
	  ip_raw_sock = ipv6_raw_tcp_sock;
      	} else if (protocol == IPPROTO_UDP) {
	  ip_raw_sock = ipv6_raw_udp_sock;
	}
#else    
	memcpy(&ip6hdr->ip6_src, (void *)enc_entry->ip_link->src_addr, sizeof(struct in6_addr));
	
	tcp = (struct tcphdr *) (buff + 40); //sizeof ip6_hdr is 40
	udp = (struct udphdr *) (buff + 40); //sizeof ip6_hdr is 40


	
	if (protocol == IPPROTO_TCP) {

	  HIP_DEBUG("Checksumming TCP packet \n");
	  ip_raw_sock = ipv6_raw_tcp_sock;
	  
	  tcp->check  = 0;
	  tcp->check  = ipv6_checksum(IPPROTO_TCP, &(ip6hdr->ip6_src), &(ip6hdr->ip6_dst), tcp, (buff_len - sizeof(struct ip))); //checksum is ok for ipv4
	  HIP_HEXDUMP("tcp dump: ", tcp, (buff_len - sizeof(struct ip6_hdr)));

      	} else if (protocol == IPPROTO_UDP) {

	  HIP_DEBUG("Checksumming UDP packet \n");
	  ip_raw_sock = ipv4_raw_udp_sock;
	  		
	  udp->check =  0;
	  udp->check = ipv4_checksum(IPPROTO_UDP, &(iphdr->ip_src), &(iphdr->ip_dst), udp, (buff_len - sizeof(struct ip))); //checksum is ok for ipv4
	  _HIP_HEXDUMP("udp dump: ", udp, (buff_len - sizeof(struct ip6_hdr)));

	}
#endif
	if(setsockopt(ip_raw_sock, IPPROTO_IPV6, IP_HDRINCL, &on, sizeof(on)) < 0) { 
	  HIP_DEBUG("setsockopt IP_HDRINCL ERROR！ \n");
	} else {
	  HIP_DEBUG("setsockopt IP_HDRINCL for ipv4 OK！ \n");
	}
      }else { //IPv4
	dst4->sin_family = AF_INET;
	iphdr->ip_sum = 0;
	protocol = iphdr->ip_p;
	dst_len = sizeof(struct sockaddr_in);
	IPV6_TO_IPV4_MAP(&ctx->dst, &dst4->sin_addr);
	_HIP_DEBUG_INADDR("ipv4 src: ", &iphdr->ip_src);
	_HIP_DEBUG_INADDR("ipv4 dst: ", &iphdr->ip_dst);

#ifdef CONFIG_SAVAH_IP_OPTION
	buff_no_opt = (char *) malloc(buff_len - hdr_len);
	iphdr->ip_len = (buff_len - hdr_len);
	iphdr->ip_hl -= (hdr_len / 4);
	memcpy(buff_no_opt, buff, hdr_offset);
	memcpy((buff_no_opt + hdr_offset), buff + hdr_offset + hdr_len,
	       (buff_len - hdr_offset - hdr_len));
	buff_len -= hdr_len;

	if (protocol == IPPROTO_TCP) {	  
	  ip_raw_sock = ipv4_raw_tcp_sock;
	  HIP_HEXDUMP("tcp dump: ", buff_no_opt, buff_len - hdr_offset - hdr_len);
      	} else if (protocol == IPPROTO_UDP) {
	  ip_raw_sock = ipv4_raw_udp_sock;
	  HIP_HEXDUMP("udp dump: ", buff_no_opt, (buff_len - hdr_offset - hdr_len));
	}
#else
	IPV6_TO_IPV4_MAP(enc_entry->ip_link->src_addr, &iphdr->ip_src);

	tcp = (struct tcphdr *) (buff + 20); //sizeof iphdr is 20
	udp = (struct udphdr *) (buff + 20); //sizeof iphdr is 20
		
	if (protocol == IPPROTO_TCP) {

	  HIP_DEBUG("Checksumming TCP packet \n");
	  ip_raw_sock = ipv4_raw_tcp_sock;
	  
	  tcp->check  = htons(0);
	  tcp->check  = ipv4_checksum(IPPROTO_TCP, &(iphdr->ip_src), &(iphdr->ip_dst), tcp, (buff_len - sizeof(struct ip))); //checksum is ok for ipv4
	  HIP_HEXDUMP("tcp dump: ", tcp, (buff_len - sizeof(struct ip)));

      	} else if (protocol == IPPROTO_UDP) {

	  HIP_DEBUG("Checksumming UDP packet \n");
	  ip_raw_sock = ipv4_raw_udp_sock;
	  		
	  udp->check =  htons(0);
	  udp->check = ipv4_checksum(IPPROTO_UDP, &(iphdr->ip_src), &(iphdr->ip_dst), udp, (buff_len - sizeof(struct ip))); //checksum is ok for ipv4
	  _HIP_HEXDUMP("udp dump: ", udp, (buff_len - sizeof(struct ip)));
	}
#endif
	if(setsockopt(ip_raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) { 
	  HIP_DEBUG("setsockopt IP_HDRINCL ERROR！ \n");
	} else {
	  HIP_DEBUG("setsockopt IP_HDRINCL for ipv4 OK！ \n");
	}
      }
#ifdef CONFIG_SAVAH_IP_OPTION
      sent = sendto(ip_raw_sock, buff_no_opt, buff_len, 0,
		    (struct sockaddr *) &dst, dst_len);
      free(buff_no_opt);
#else
      sent = sendto(ip_raw_sock, buff, buff_len, 0,
		    (struct sockaddr *) &dst, dst_len);
#endif
#ifdef CONFIG_SAVAH_IP_OPTION
      if (sent != buff_len) {
#else
      if (sent != ctx->ipq_packet->data_len) {  
#endif
	HIP_ERROR("Could not send the all requested"			\
		  " data (%d/%d)\n", sent, buff_len);
	HIP_DEBUG("ERROR NUMBER: %d\n", errno);
      } else {
	HIP_DEBUG("sent=%d/%d \n",
		  sent, buff_len);
	HIP_DEBUG("Packet sent ok\n");
      }
      if (ctx->ip_version == 4) {
	if(setsockopt(ip_raw_sock, IPPROTO_IP, IP_HDRINCL, &off, sizeof(off)) < 0) { 
	  HIP_DEBUG("setsockopt IP_HDRINCL ERROR！ \n");
	}
      }	else {
	if(setsockopt(ip_raw_sock, IPPROTO_IPV6, IP_HDRINCL, &off, sizeof(off)) < 0) { 
	  HIP_DEBUG("setsockopt IP_HDRINCL ERROR！ \n");
	}	
      }
    } else {
      HIP_DEBUG("Source address authentication failed. Dropping packet \n");
      verdict = DROP;
      goto out_err;
    }

    
  } else {
    HIP_DEBUG("Source address authentication failed \n");
    verdict = DROP;
    goto out_err;
  }
 out_err:
  return verdict;
}


int hip_sava_init_ip4_raw_socket(int * ip4_raw_socket, int proto) {
  int on = 1, err = 0;
  int off = 0;
  
  *ip4_raw_socket = socket(AF_INET, SOCK_RAW, proto);
  HIP_IFEL(*ip4_raw_socket <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

  /* see bug id 212 why RECV_ERR is off */
  err = setsockopt(*ip4_raw_socket, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
  err = setsockopt(*ip4_raw_socket, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
  err = setsockopt(*ip4_raw_socket, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
  err = setsockopt(*ip4_raw_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");
  
 out_err:
  return err;
}

int hip_sava_init_ip6_raw_socket(int * ip6_raw_socket, int proto) {
  int on = 1, err = 0;
  int off = 0;
  
  *ip6_raw_socket = socket(AF_INET6, SOCK_RAW, proto);
  HIP_IFEL(*ip6_raw_socket <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

  /* see bug id 212 why RECV_ERR is off */
  err = setsockopt(*ip6_raw_socket, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v6 recverr failed\n");
  err = setsockopt(*ip6_raw_socket, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v6 pktinfo failed\n");
  err = setsockopt(*ip6_raw_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");
  
 out_err:
  return err;
}


int hip_sava_reinject_packet(char * buf, int proto) {
  return 0;
}


int hip_sava_handle_bex_completed (struct in6_addr * src, struct in6_addr * hitr) {
  HIP_DEBUG("CHECK IP IN THE HIP_R2 SENT STATE \n");
  struct in6_addr * enc_addr = NULL;
  struct in6_addr * enc_addr_no = NULL;

  hip_common_t * msg;
  
  
  hip_sava_ip_entry_t  * ip_entry = NULL;
  hip_sava_hit_entry_t * hit_entry = NULL;
  hip_sava_peer_info_t * info_entry;
  hip_sava_enc_ip_entry_t * enc_entry = NULL;
  
  int err = 0;

  if (hip_sava_ip_entry_find(src) != NULL) {
    HIP_DEBUG("IP already apprears to present in the data base. Most likely retransmitting the I2 \n");

  } else {
    HIP_DEBUG("IP  apprears to be new. Adding to DB \n");

    //TODO: check if the source IP belongs to 
    //the same network as router's IP address
    // Drop the packet IP was not found in the data base
    HIP_DEBUG("Packet accepted! Adding source IP address to the DB \n");
    hip_sava_ip_entry_add(src, NULL);
    hip_sava_hit_entry_add(hitr, NULL);
    
    HIP_IFEL((ip_entry = hip_sava_ip_entry_find(src)) == NULL, -1,
	     "No entry was found for given IP address \n");
    HIP_IFEL((hit_entry = hip_sava_hit_entry_find(hitr)) == NULL, -1,
	     "No entry was found for given HIT \n");
    
    //Adding cross references
    ip_entry->link = hit_entry;
    hit_entry->link = ip_entry; 

    ip_entry = NULL;
    hit_entry = NULL;
    //End adding cross references
  }

  ip_entry = hip_sava_ip_entry_find(src);
  hit_entry = hip_sava_hit_entry_find(hitr);
  
  
  if (ip_entry && hit_entry) {
    HIP_DEBUG("BOTH ENTRIES ARE FOUND \n");
    
    HIP_IFEL((msg = hip_sava_make_keys_request(hitr, SAVA_INBOUND_KEY)) == NULL, -1,
	     "Key request from daemon failed \n");
    HIP_DEBUG("Secret key acquired. Lets encrypt the src IP address \n");
		  
    info_entry = hip_sava_get_key_params(msg);
    
    enc_addr = hip_sava_auth_ip(src, info_entry);

#ifdef CONFIG_SAVAH_IP_OPTION
    //Since the IP option have space for 128 bits we can store the whole IPv6 address
    //enc_addr_no = map_enc_ip_addr_to_network_order(enc_addr, 6);
#else
    if(IN6_IS_ADDR_V4MAPPED(src))
      enc_addr_no = map_enc_ip_addr_to_network_order(enc_addr, 4);
    else 
      enc_addr_no = map_enc_ip_addr_to_network_order(enc_addr, 6);
#endif
    

#ifndef CONFIG_SAVAH_IP_OPTION
    HIP_IFEL(hip_sava_enc_ip_entry_add(enc_addr_no,
				       ip_entry,
				       hit_entry, info_entry), 
	     -1, "error adding enc ip entry");    

    HIP_IFEL((enc_entry = hip_sava_enc_ip_entry_find(enc_addr_no)) == NULL, 
	     -1, "Could not retrieve enc ip entry \n");
#else
     HIP_IFEL(hip_sava_enc_ip_entry_add(enc_addr,
				       ip_entry,
				       hit_entry, info_entry), 
	     -1, "error adding enc ip entry");    

    HIP_IFEL((enc_entry = hip_sava_enc_ip_entry_find(enc_addr)) == NULL, 
	     -1, "Could not retrieve enc ip entry \n");
#endif
    ip_entry->enc_link = enc_entry;
    hit_entry->enc_link = enc_entry;

    free(enc_addr);
    
  } else {
    HIP_DEBUG("<HIT, IP> NOT FOUND ERROR!! \n");
    return -1;
  }
 out_err:
  return (err);
}

struct in6_addr * map_enc_ip_addr_to_network_order(struct in6_addr * enc_addr, int ip_version) {
  struct in6_addr * no_addr = 
    (struct in6_addr *)malloc(sizeof(struct in6_addr));
  memset(no_addr, 0, sizeof(struct in6_addr));
  
  HIP_DEBUG_HIT("Encrypted address in original ", enc_addr);
  
  if (ip_version == 4) {
    // Produce IPv4 mapped to IPv6 address
    no_addr->s6_addr32[2] = htonl (0xffff);
    no_addr->s6_addr32[3] = htonl(enc_addr->s6_addr32[3]);
  } else {
    no_addr->s6_addr32[0] = htonl(enc_addr->s6_addr32[0]);
    no_addr->s6_addr32[1] = htonl(enc_addr->s6_addr32[1]);
    no_addr->s6_addr32[2] = htonl(enc_addr->s6_addr32[2]);
    no_addr->s6_addr32[3] = htonl(enc_addr->s6_addr32[3]);
  }
  HIP_DEBUG_IN6ADDR("Encrypted address in network byte order ", no_addr);
  return no_addr;
}


struct sava_ip_option * hip_sava_build_enc_addr_ipv4_option(struct in6_addr * enc_addr){

  HIP_ASSERT(enc_addr != NULL);
  
  struct sava_ip_option * opt = (struct sava_ip_option *) malloc(sizeof(struct sava_ip_option));
  memset(opt, 0, 20);
  opt->type = SAVA_IPV4_OPTION_TYPE;
  opt->length = 20;
  
  memcpy(opt->data,
	 enc_addr,
	 sizeof(struct in6_addr));

  return opt;
}
