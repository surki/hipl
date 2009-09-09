/**
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "user_ipsec_sadb.h"
#include "esp_prot_api.h"
#include <openssl/sha.h>
#include "firewall.h"
#include "ife.h"

/* hash functions used for calculating the entries' hashes */
#define INDEX_HASH_FN		HIP_DIGEST_SHA1
/* the length of the hash value used for indexing */
#define INDEX_HASH_LENGTH	SHA_DIGEST_LENGTH

/* database storing the sa entries, indexed by src _and_ dst hits */
HIP_HASHTABLE *sadb = NULL;
/* database storing shortcuts to sa entries for incoming packets */
HIP_HASHTABLE *linkdb = NULL;

/* callback wrappers providing per-variable casts before calling the
 * type-specific callbacks */
static IMPLEMENT_LHASH_HASH_FN(hip_sa_entry_hash, const hip_sa_entry_t *)
static IMPLEMENT_LHASH_COMP_FN(hip_sa_entries_compare, const hip_sa_entry_t *)
static IMPLEMENT_LHASH_HASH_FN(hip_link_entry_hash, const hip_link_entry_t *)
static IMPLEMENT_LHASH_COMP_FN(hip_link_entries_compare, const hip_link_entry_t *)


int hip_sadb_init()
{
	int err = 0;

	HIP_IFEL(!(sadb = hip_ht_init(LHASH_HASH_FN(hip_sa_entry_hash),
			LHASH_COMP_FN(hip_sa_entries_compare))), -1,
			"failed to initialize sadb\n");
	HIP_IFEL(!(linkdb = hip_ht_init(LHASH_HASH_FN(hip_link_entry_hash),
			LHASH_COMP_FN(hip_link_entries_compare))), -1,
			"failed to initialize linkdb\n");

	HIP_DEBUG("sadb initialized\n");

  out_err:
  	return err;
}

int hip_sadb_uninit()
{
	int err = 0;

	if (err = hip_sadb_flush())
		HIP_ERROR("failed to flush sadb\n");

	if (sadb)
		free(sadb);
	if (linkdb)
		free(linkdb);

  out_err:
	return err;
}

int hip_sadb_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t local_port, uint16_t peer_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
		uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		int retransmission, int update)
{
	int err = 0;
	struct in6_addr *check_local_hit = NULL;
	struct in6_addr *default_hit = NULL;
	in_port_t src_port, dst_port;

	/* @todo handle retransmission and update correctly */

	default_hit = hip_fw_get_default_hit();

	/*
	* Switch port numbers depending on direction and make sure that we
	* are testing correct local hit.
	*/
	if (direction == HIP_SPI_DIRECTION_OUT)
	{
		src_port = local_port;
		dst_port = peer_port;
		check_local_hit = inner_src_addr;

	} else
	{
		src_port = peer_port;
		dst_port = local_port;
		check_local_hit = inner_dst_addr;
	}

	HIP_DEBUG_HIT("default hit", default_hit);
	HIP_DEBUG_HIT("check hit", check_local_hit);

	HIP_IFEL(ipv6_addr_cmp(default_hit, check_local_hit), -1,
			"only default HIT supported in userspace ipsec\n");


	if (update)
	{
		HIP_IFEL(hip_sa_entry_update(direction, spi, mode, src_addr, dst_addr,
				inner_src_addr, inner_dst_addr, encap_mode, src_port, dst_port, ealg,
				auth_key, enc_key, lifetime, esp_prot_transform, hash_item_length,
				esp_num_anchors, esp_prot_anchors, update), -1, "failed to update sa entry\n");
	} else
	{
		HIP_IFEL(hip_sa_entry_add(direction, spi, mode, src_addr, dst_addr,
				inner_src_addr, inner_dst_addr, encap_mode, src_port, dst_port, ealg,
				auth_key, enc_key, lifetime, esp_prot_transform, hash_item_length,
				esp_num_anchors, esp_prot_anchors, update), -1, "failed to add sa entry\n");
	}

  out_err:
  	return err;
}

int hip_sadb_delete(struct in6_addr *dst_addr, uint32_t spi)
{
	hip_sa_entry_t *entry = NULL;
	int err = 0;

	HIP_IFEL(!(entry = hip_sa_entry_find_inbound(dst_addr, spi)), -1,
			"failed to retrieve sa entry\n");

	HIP_IFEL(hip_sa_entry_delete(entry->inner_src_addr, entry->inner_dst_addr), -1,
			"failed to delete entry\n");

  out_err:
	return err;
}

int hip_sadb_flush()
{
	int err = 0, i = 0;
	hip_list_t *item = NULL, *tmp = NULL;
	hip_sa_entry_t *entry = NULL;

	// iterating over all elements
	list_for_each_safe(item, tmp, sadb, i)
	{
		HIP_IFEL(!(entry = list_entry(item)), -1, "failed to get list entry\n");
		HIP_IFEL(hip_sa_entry_delete(entry->inner_src_addr, entry->inner_dst_addr), -1,
				"failed to delete sa entry\n");
	}

	HIP_DEBUG("sadb flushed\n");

  out_err:
  	return err;
}

hip_sa_entry_t * hip_sa_entry_find_inbound(struct in6_addr *dst_addr, uint32_t spi)
{
	hip_link_entry_t *stored_link = NULL;
	hip_sa_entry_t *stored_entry = NULL;
	int err = 0;

	HIP_IFEL(!(stored_link = hip_link_entry_find(dst_addr, spi)), -1,
			"failed to find link entry\n");

	stored_entry = stored_link->linked_sa_entry;

  out_err:
  	if (err)
  		stored_entry = NULL;

  	return stored_entry;
}

hip_sa_entry_t * hip_sa_entry_find_outbound(struct in6_addr *src_hit,
		struct in6_addr *dst_hit)
{
	hip_sa_entry_t *search_entry = NULL, *stored_entry = NULL;
	int err = 0;

	HIP_IFEL(!(search_entry = (hip_sa_entry_t *) malloc(sizeof(hip_sa_entry_t))), -1,
			"failed to allocate memory\n");
	memset(search_entry, 0, sizeof(hip_sa_entry_t));

	// fill search entry with information needed by the hash function
	search_entry->inner_src_addr = src_hit;
	search_entry->inner_dst_addr = dst_hit;
	search_entry->mode = BEET_MODE;

	HIP_DEBUG("looking up sa entry with following index attributes:\n");
	HIP_DEBUG_HIT("inner_src_addr", search_entry->inner_src_addr);
	HIP_DEBUG_HIT("inner_dst_addr", search_entry->inner_dst_addr);
	HIP_DEBUG("mode: %i\n", search_entry->mode);

	//hip_sadb_print();

	// find entry in sadb db
	HIP_IFEL(!(stored_entry = (hip_sa_entry_t *)hip_ht_find(sadb, search_entry)), -1,
			"failed to retrieve sa entry\n");

  out_err:
  	if (err)
  		stored_entry = NULL;

  	if (search_entry)
  		free(search_entry);

  	return stored_entry;
}

void hip_sadb_print()
{
	int i = 0;
	hip_list_t *item = NULL, *tmp = NULL;
	hip_sa_entry_t *entry = NULL;

	HIP_DEBUG("printing sadb...\n");

	// iterating over all elements
	list_for_each_safe(item, tmp, sadb, i)
	{
		if (!(entry = list_entry(item)))
		{
			HIP_ERROR("failed to get list entry\n");
			break;
		}
		HIP_DEBUG("sa entry %i:\n", i + 1);
		hip_sa_entry_print(entry);
	}

	if (i == 0)
	{
		HIP_DEBUG("sadb contains no items\n");
	}
}



unsigned long hip_sa_entry_hash(const hip_sa_entry_t *sa_entry)
{
	struct in6_addr addr_pair[2];		/* in BEET-mode these are HITs */
	unsigned char hash[INDEX_HASH_LENGTH];
	int err = 0;

	// values have to be present
	HIP_ASSERT(sa_entry != NULL && sa_entry->inner_src_addr != NULL
			&& sa_entry->inner_dst_addr != NULL);

	if (sa_entry->mode == 3)
	{
		/* use hits to index in beet mode
		 *
		 * NOTE: the index won't change during ongoing connection
		 * NOTE: the HIT fields of an host association struct cannot be assumed to
		 * be alligned consecutively. Therefore, we must copy them to a temporary
		 * array. */
		memcpy(&addr_pair[0], sa_entry->inner_src_addr, sizeof(struct in6_addr));
		memcpy(&addr_pair[1], sa_entry->inner_dst_addr, sizeof(struct in6_addr));

	} else
	{
		HIP_ERROR("indexing for non-BEET-mode not implemented!\n");

		err = -1;
		goto out_err;
	}

	HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)addr_pair,
			2 * sizeof(struct in6_addr), hash), -1, "failed to hash addresses\n");

  out_err:
  	if (err)
  	{
  		*hash = 0;
  	}

  	_HIP_HEXDUMP("sa entry hash: ", hash, INDEX_HASH_LENGTH);
  	_HIP_DEBUG("hash (converted): %lu\n", *((unsigned long *)hash));

	return *((unsigned long *)hash);
}

int hip_sa_entries_compare(const hip_sa_entry_t *sa_entry1,
		const hip_sa_entry_t *sa_entry2)
{
	int err = 0;
	unsigned long hash1 = 0;
	unsigned long hash2 = 0;

	// values have to be present
	HIP_ASSERT(sa_entry1 != NULL && sa_entry1->inner_src_addr != NULL
			&& sa_entry1->inner_dst_addr != NULL);
	HIP_ASSERT(sa_entry2 != NULL && sa_entry2->inner_src_addr != NULL
				&& sa_entry2->inner_dst_addr != NULL);

	_HIP_DEBUG("calculating hash1:\n");
	HIP_IFEL(!(hash1 = hip_sa_entry_hash(sa_entry1)), -1, "failed to hash sa entry\n");
	_HIP_DEBUG("calculating hash2:\n");
	HIP_IFEL(!(hash2 = hip_sa_entry_hash(sa_entry2)), -1, "failed to hash sa entry\n");

	err = (hash1 != hash2);

  out_err:
    return err;
}

unsigned long hip_link_entry_hash(const hip_link_entry_t *link_entry)
{
	int input_length = sizeof(struct in6_addr) + sizeof(uint32_t);
	unsigned char hash_input[input_length];
	unsigned char hash[INDEX_HASH_LENGTH];
	int err = 0;

	// values have to be present
	HIP_ASSERT(link_entry != NULL && link_entry->dst_addr != NULL &&
			link_entry->spi != 0);

	memset(hash, 0, INDEX_HASH_LENGTH);

	/* concatenate dst_addr and spi */
	memcpy(&hash_input[0], link_entry->dst_addr, sizeof(struct in6_addr));
	memcpy(&hash_input[sizeof(struct in6_addr)], &link_entry->spi,
			sizeof(uint32_t));

	HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *)hash_input, input_length, hash),
			-1, "failed to hash addresses\n");

  out_err:
  	if (err)
  	{
  		*hash = 0;
  	}

  	_HIP_HEXDUMP("sa entry hash: ", hash, INDEX_HASH_LENGTH);
  	_HIP_DEBUG("hash (converted): %lu\n", *((unsigned long *)hash));

	return *((unsigned long *)hash);
}

int hip_link_entries_compare(const hip_link_entry_t *link_entry1,
		const hip_link_entry_t *link_entry2)
{
	int err = 0;
	unsigned long hash1 = 0;
	unsigned long hash2 = 0;

	// values have to be present
	HIP_ASSERT(link_entry1 != NULL && link_entry1->dst_addr != NULL
			&& link_entry1->spi != 0);
	HIP_ASSERT(link_entry2 != NULL && link_entry2->dst_addr != NULL
				&& link_entry2->spi != 0);

	_HIP_DEBUG("calculating hash1:\n");
	HIP_IFEL(!(hash1 = hip_link_entry_hash(link_entry1)), -1,
			"failed to hash link entry\n");
	_HIP_DEBUG("calculating hash2:\n");
	HIP_IFEL(!(hash2 = hip_link_entry_hash(link_entry2)), -1,
			"failed to hash link entry\n");

	err = (hash1 != hash2);

  out_err:
    return err;
}

int hip_sa_entry_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
		uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		int update)
{
	hip_sa_entry_t *entry = NULL;
	int err = 0;

	/* initialize members to 0/NULL */
	HIP_IFEL(!(entry = (hip_sa_entry_t *) malloc(sizeof(hip_sa_entry_t))), -1,
			"failed to allocate memory\n");
	memset(entry, 0, sizeof(hip_sa_entry_t));

	HIP_IFEL(!(entry->src_addr = (struct in6_addr *) malloc(sizeof(struct in6_addr))), -1,
			"failed to allocate memory\n");
	memset(entry->src_addr, 0, sizeof(struct in6_addr));
	HIP_IFEL(!(entry->dst_addr = (struct in6_addr *) malloc(sizeof(struct in6_addr))), -1,
			"failed to allocate memory\n");
	memset(entry->dst_addr, 0, sizeof(struct in6_addr));
	HIP_IFEL(!(entry->inner_src_addr = (struct in6_addr *) malloc(sizeof(struct in6_addr))),
			-1, "failed to allocate memory\n");
	memset(entry->inner_src_addr, 0, sizeof(struct in6_addr));
	HIP_IFEL(!(entry->inner_dst_addr = (struct in6_addr *) malloc(sizeof(struct in6_addr))),
			-1, "failed to allocate memory\n");
	memset(entry->inner_dst_addr, 0, sizeof(struct in6_addr));

	HIP_IFEL(!(entry->auth_key = (struct hip_crypto_key *)
			malloc(hip_auth_key_length_esp(ealg))), -1, "failed to allocate memory\n");
	memset(entry->auth_key, 0, hip_auth_key_length_esp(ealg));
	if (hip_enc_key_length(ealg) > 0)
	{
		HIP_IFEL(!(entry->enc_key = (struct hip_crypto_key *)
				malloc(hip_enc_key_length(ealg))), -1, "failed to allocate memory\n");
		memset(entry->enc_key, 0, hip_enc_key_length(ealg));
	}

	HIP_IFEL(hip_sa_entry_set(entry, direction, spi, mode, src_addr, dst_addr,
			inner_src_addr, inner_dst_addr, encap_mode, src_port, dst_port, ealg,
			auth_key, enc_key, lifetime, esp_prot_transform, hash_item_length,
			esp_num_anchors, esp_prot_anchors, update), -1, "failed to set the entry members\n");

	HIP_DEBUG("adding sa entry with following index attributes:\n");
	HIP_DEBUG_HIT("inner_src_addr", entry->inner_src_addr);
	HIP_DEBUG_HIT("inner_dst_addr", entry->inner_dst_addr);
	HIP_DEBUG("mode: %i\n", entry->mode);

	/* returns the replaced item or NULL on normal operation and error.
	 * A new entry should not replace another one! */
	HIP_IFEL(hip_ht_add(sadb, entry), -1, "hash collision detected!\n");

	// add links to this entry for incoming packets
	HIP_IFEL(hip_link_entries_add(entry), -1, "failed to add link entries\n");

	HIP_DEBUG("sa entry added successfully\n");

	//hip_sadb_print();
	//hip_linkdb_print();

  out_err:
  	if (err)
  	{
  		if (entry)
  		{
  			hip_link_entries_delete_all(entry);
  			hip_sa_entry_free(entry);
  			free(entry);
  		}
  		entry = NULL;
  	}

  	return err;
}

int hip_sa_entry_update(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
		uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		int update)
{
	hip_sa_entry_t *stored_entry = NULL;
	int err = 0;

	// we need the sadb entry to go through entries in the linkdb
	HIP_IFEL(!(stored_entry = hip_sa_entry_find_outbound(inner_src_addr,
			inner_dst_addr)), -1, "failed to retrieve sa entry\n");

	pthread_mutex_lock(&stored_entry->rw_lock);
	/* delete all links
	 *
	 * XX TODO more efficient to delete entries in inbound db for all (addr, oldspi)
	 * or just those with (oldaddr, spi) */
	HIP_IFEL(hip_link_entries_delete_all(stored_entry), -1, "failed to remove links\n");

	/* change members of entry in sadb and add new links */
	HIP_IFEL(hip_sa_entry_set(stored_entry, direction, spi, mode, src_addr, dst_addr,
			inner_src_addr, inner_dst_addr, encap_mode, src_port, dst_port, ealg,
			auth_key, enc_key, lifetime, esp_prot_transform, hash_item_length,
			esp_num_anchors, esp_prot_anchors, update), -1, "failed to update the entry members\n");

	HIP_IFEL(hip_link_entries_add(stored_entry), -1, "failed to add links\n");
	pthread_mutex_unlock(&stored_entry->rw_lock);

	HIP_DEBUG("sa entry updated\n");

  out_err:
  	return err;
}

int hip_sa_entry_set(hip_sa_entry_t *entry, int direction, uint32_t spi,
		uint32_t mode, struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
		uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		int update)
{
	int key_len = 0; 							/* for 3-DES */
	unsigned char key1[8], key2[8], key3[8]; 	/* for 3-DES */
	int enc_key_changed = 0;
	int err = 0;

	// XX TODO handle update case, introducing backup of spi and keying material

	/* copy values for non-zero members */
	entry->direction = direction;
	entry->spi = spi;
	entry->mode = mode;
	memcpy(entry->src_addr, src_addr, sizeof(struct in6_addr));
	memcpy(entry->dst_addr, dst_addr, sizeof(struct in6_addr));
	if (entry->mode == 3)
	{
		memcpy(entry->inner_src_addr, inner_src_addr, sizeof(struct in6_addr));
		memcpy(entry->inner_dst_addr, inner_dst_addr, sizeof(struct in6_addr));
	}
	entry->encap_mode = encap_mode;
	entry->src_port = src_port;
	entry->dst_port = dst_port;

	entry->ealg = ealg;

	// copy raw keys, if they changed
	if (memcmp(entry->auth_key, auth_key, hip_auth_key_length_esp(ealg)))
		memcpy(entry->auth_key, auth_key, hip_auth_key_length_esp(ealg));

	if (hip_enc_key_length(ealg) > 0 && memcmp(entry->enc_key, enc_key, hip_enc_key_length(ealg)))
	{
		memcpy(entry->enc_key, enc_key, hip_enc_key_length(ealg));
		enc_key_changed = 1;
	}

	// set up encrpytion keys, if raw keys changed
	if (enc_key_changed)
	{
		// set up keys for the transform in use
		switch (ealg)
		{
			case HIP_ESP_3DES_SHA1:
			case HIP_ESP_3DES_MD5:
				key_len = hip_enc_key_length(ealg)/3;

				memset(key1, 0, key_len);
				memset(key2, 0, key_len);
				memset(key3, 0, key_len);

				memcpy(key1, &enc_key[0], key_len);
				memcpy(key2, &enc_key[8], key_len);
				memcpy(key3, &enc_key[16], key_len);

				des_set_odd_parity((des_cblock*)key1);
				des_set_odd_parity((des_cblock*)key2);
				des_set_odd_parity((des_cblock*)key3);

				err = des_set_key_checked((des_cblock*)key1, entry->ks[0]);
				err += des_set_key_checked((des_cblock*)key2, entry->ks[1]);
				err += des_set_key_checked((des_cblock*)key3, entry->ks[2]);

				HIP_IFEL(err, -1, "3DES key problem\n");

				break;
			case HIP_ESP_AES_SHA1:
				HIP_IFEL(!entry->enc_key, -1, "enc_key required!\n");

				/* AES key differs for encryption/decryption, so we need
				 * to distinguish the directions here */
				if (direction == HIP_SPI_DIRECTION_OUT)
				{
					// needs length of key in bits
					HIP_IFEL(AES_set_encrypt_key(entry->enc_key->key,
							8 * hip_enc_key_length(entry->ealg),
							&entry->aes_key), -1, "AES key problem!\n");
				} else
				{
					HIP_IFEL(AES_set_decrypt_key(entry->enc_key->key,
							8 * hip_enc_key_length(entry->ealg),
							&entry->aes_key), -1, "AES key problem!\n");
				}

				break;
#ifndef ANDROID_CHANGES
			case HIP_ESP_BLOWFISH_SHA1:
				BF_set_key(&entry->bf_key, hip_enc_key_length(ealg), enc_key->key);

				break;
#endif
			case HIP_ESP_NULL_SHA1:
				// same encryption chiper as next transform
			case HIP_ESP_NULL_MD5:
				// nothing needs to be set up
				break;
			default:
				HIP_ERROR("Unsupported encryption transform: %i.\n", ealg);

				err = -1;
				goto out_err;
		}
	}

	// only set the seq no in case there is NO update
	if (!update)
		entry->sequence = 1;
	entry->lifetime = lifetime;

	HIP_IFEL(esp_prot_sa_entry_set(entry, esp_prot_transform, hash_item_length,
			esp_num_anchors, esp_prot_anchors, update), -1, "failed to set esp protection members\n");

  out_err:
  	return err;
}


int hip_sa_entry_delete(struct in6_addr *src_addr, struct in6_addr *dst_addr)
{
	hip_sa_entry_t *stored_entry = NULL;
	int err = 0;

	/* find entry in sadb and delete entries in linkdb for all (addr, spi)-matches */
	HIP_IFEL(!(stored_entry = hip_sa_entry_find_outbound(src_addr, dst_addr)), -1,
			"failed to retrieve sa entry\n");

	/* NOTE: no need to unlock mutex as the entry is already freed and can't be
	 * accessed any more */
	pthread_mutex_lock(&stored_entry->rw_lock);

	HIP_IFEL(hip_link_entries_delete_all(stored_entry), -1, "failed to delete links\n");

	// delete the entry from the sadb
	hip_ht_delete(sadb, stored_entry);
	// free all entry members
	hip_sa_entry_free(stored_entry);
	// we still have to free the entry itself
	free(stored_entry);

	HIP_DEBUG("sa entry deleted\n");

  out_err:
  	return err;
}

int hip_link_entry_add(struct in6_addr *dst_addr, hip_sa_entry_t *entry)
{
	hip_link_entry_t *link = NULL;
	int err = 0;

	HIP_IFEL(!(link = (hip_link_entry_t *) malloc(sizeof(hip_link_entry_t))), -1,
					"failed to allocate memory\n");

	link->dst_addr = dst_addr;
	link->spi = entry->spi;
	link->linked_sa_entry = entry;

	hip_ht_add(linkdb, link);

  out_err:
  	return err;
}

int hip_link_entries_add(hip_sa_entry_t *entry)
{
	int err = 0;

	HIP_DEBUG("adding links to this sadb entry...\n");

	// XX TODO add multihoming support here
	//while (entry has more dst_addr)
	HIP_IFEL(hip_link_entry_add(entry->dst_addr, entry), -1,
				"failed to add link entry\n");

  out_err:
  	return err;
}

hip_link_entry_t *hip_link_entry_find(struct in6_addr *dst_addr, uint32_t spi)
{
	hip_link_entry_t *search_link = NULL, *stored_link = NULL;
	int err = 0;

	HIP_IFEL(!(search_link = (hip_link_entry_t *) malloc(sizeof(hip_link_entry_t))),
			-1, "failed to allocate memory\n");
	memset(search_link, 0, sizeof(hip_link_entry_t));

	// search the linkdb for the link to the corresponding entry
	search_link->dst_addr = dst_addr;
	search_link->spi = spi;

	HIP_DEBUG("looking up link entry with following index attributes:\n");
	HIP_DEBUG_HIT("dst_addr", search_link->dst_addr);
	HIP_DEBUG("spi: 0x%lx\n", search_link->spi);

	//hip_linkdb_print();

	HIP_IFEL(!(stored_link = hip_ht_find(linkdb, search_link)), -1,
				"failed to retrieve link entry\n");

  out_err:
  	if (err)
  		stored_link = NULL;

	if (search_link)
	  	free(search_link);

	return stored_link;
}

int hip_link_entry_delete(struct in6_addr *dst_addr, uint32_t spi)
{
	hip_link_entry_t *stored_link = NULL;
	int err = 0;

	// find link entry and free members
	HIP_IFEL(!(stored_link = hip_link_entry_find(dst_addr, spi)), -1,
				"failed to retrieve link entry\n");

	/* @note do NOT free dst_addr, as this is a pointer to the same memory used by the
	 *       sa entry */

	// delete the link
	hip_ht_delete(linkdb, stored_link);
	// we still have to free the link itself
	free(stored_link);

	HIP_DEBUG("link entry deleted\n");

  out_err:
  	return err;
}

int hip_link_entries_delete_all(hip_sa_entry_t *entry)
{
	int err = 0;

	HIP_DEBUG("delete all links to this sadb entry...\n");

	// XX TODO lock link hashtable and add multihoming support here
	//while (entry has more dst_addr)
	HIP_IFEL(hip_link_entry_delete(entry->dst_addr, entry->spi), -1,
			"failed to add link entry\n");

	HIP_DEBUG("all link entries for this sa entry deleted\n");

  out_err:
  	return err;
}

void hip_link_entry_print(hip_link_entry_t *entry)
{
	if (entry)
	{
		HIP_DEBUG_HIT("dst_addr", entry->dst_addr);
		HIP_DEBUG("spi: 0x%lx\n", entry->spi);
		HIP_DEBUG("> sa entry:\n");

		hip_sa_entry_print(entry->linked_sa_entry);

	} else
	{
		HIP_DEBUG("link entry is NULL\n");
	}
}

void hip_sa_entry_free(hip_sa_entry_t * entry)
{
	if (entry)
	{
		if (entry->src_addr)
			free(entry->src_addr);
		if (entry->dst_addr)
			free(entry->dst_addr);
		if (entry->inner_src_addr)
			free(entry->inner_src_addr);
		if (entry->inner_dst_addr)
			free(entry->inner_dst_addr);
		if (entry->auth_key)
			free(entry->auth_key);
		if (entry->enc_key)
			free(entry->enc_key);

		// also free all hchain related members
		esp_prot_sa_entry_free(entry);
	}
}

void hip_sa_entry_print(hip_sa_entry_t *entry)
{
	if (entry)
	{
		HIP_DEBUG("direction: %i\n", entry->direction);
		HIP_DEBUG("spi: 0x%lx\n", entry->spi);
		HIP_DEBUG("mode: %u\n", entry->mode);
		HIP_DEBUG_HIT("src_addr", entry->src_addr);
		HIP_DEBUG_HIT("dst_addr", entry->dst_addr);
		HIP_DEBUG_HIT("inner_src_addr", entry->inner_src_addr);
		HIP_DEBUG_HIT("inner_dst_addr", entry->inner_dst_addr);
		HIP_DEBUG("encap_mode: %u\n", entry->encap_mode);
		HIP_DEBUG("src_port: %u\n", entry->src_port);
		HIP_DEBUG("dst_port: %u\n", entry->dst_port);
		HIP_DEBUG("... (more members)\n");

// XX TODO print the rest in case this information is needed
#if 0
		/****************** crypto parameters *******************/
		int ealg;								/* crypto transform in use */
		uint32_t a_keylen;						/* length of raw keys */
		uint32_t e_keylen;
		unsigned char *a_key;					/* raw crypto keys */
		unsigned char *e_key;
		des_key_schedule ks[3];					/* 3-DES keys */
		AES_KEY *aes_key;						/* AES key */
		BF_KEY *bf_key;							/* BLOWFISH key */
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
		/* for outgoing SA */
		hash_chain_t *active_hchain;
		hash_chain_t *next_hchain;
		/* for incoming SA */
		int tolerance;
		unsigned char *active_anchor;
		unsigned char *next_anchor;
		/* for both */
		uint8_t active_transform;
		uint8_t next_transform;
#endif
	} else
	{
		HIP_DEBUG("sa entry is NULL\n");
	}
}

void hip_linkdb_print()
{
	int i = 0;
	hip_list_t *item = NULL, *tmp = NULL;
	hip_link_entry_t *entry = NULL;

	HIP_DEBUG("printing linkdb...\n");

	// iterating over all elements
	list_for_each_safe(item, tmp, linkdb, i)
	{
		if (!(entry = list_entry(item)))
		{
			HIP_ERROR("failed to get list entry\n");
			break;
		}
		HIP_DEBUG("link entry %i:\n", i + 1);
		hip_link_entry_print(entry);
	}

	if (i == 0)
	{
		HIP_DEBUG("linkdb contains no items\n");
	}
}
