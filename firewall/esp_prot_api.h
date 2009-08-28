/**
 * API for the TPA functionality
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef ESP_PROT_API_H_
#define ESP_PROT_API_H_

#include "hashchain_store.h"
#include "hip_statistics.h"
#include "user_ipsec_sadb.h"
#include "esp_prot_fw_msg.h"
#include "esp_prot_common.h"
#include "esp_prot_defines.h"


/* maps from the transform_id defined above to the hash-function id
 * and hash length id
 *
 * NOTE: this ensures, we don't use uninitialized
 *       (hash_function, hash_length)-combinations in the array
 */
typedef struct esp_prot_tfm
{
	int is_used; /* indicates if the transform is configured */
	int hash_func_id; /* index of the hash function used by the transform */
	int hash_length_id; /* index of the hash length used by the transform */
} esp_prot_tfm_t;

/* used to cache anchor element updates in conntracking */
struct esp_anchor_item
{
	uint32_t seq; /* current sequence of the IPsec SA */
	uint8_t transform; /* negotiated TPA transform */
	uint32_t hash_item_length; /* length of the update hash structure */
	unsigned char *active_anchor; /* the active hash anchor element */
	unsigned char *next_anchor; /* the update hash anchor element */
	uint8_t root_length; /* length of the eventual root element (HHL) */
	unsigned char *root; /* the root element (HHL) */
};

/** initializes the TPA extension for the hipfw and the hipd
 *
 * @return	0 on success, -1 on error
 */
int esp_prot_init(void);

/** un-initializes the TPA extension for the hipfw and the hipd
 *
 * @return	0 on success, -1 on error
 */
int esp_prot_uninit(void);

/** sets the TPA-specific information of an IPsec SA
 *
 * @param	entry the corresponding IPsec SA
 * @param	esp_prot_transform the TPA transform
 * @param	hash_item_length length of the employed hash structure
 * @param	esp_prot_anchor either active or update anchor element, depends on update
 * @param	update indicates whether we are processing a BEX or an UPDATE
 * @return	0 on success, 1 if TPA transforms not matching, -1 on error
 */
int esp_prot_sa_entry_set(hip_sa_entry_t *entry, uint8_t esp_prot_transform,
		uint32_t hash_item_length, unsigned char *esp_prot_anchor, int update);

/** frees the TPA-specific information of an IPsec SA
 *
 * @param	entry the corresponding IPsec SA
 */
void esp_prot_sa_entry_free(hip_sa_entry_t *entry);

int esp_prot_cache_packet_hash(unsigned char *packet, uint16_t packet_length, int ip_version,
		hip_sa_entry_t *entry);
int esp_prot_add_packet_hashes(unsigned char *out_hash, int *out_length, hip_sa_entry_t *entry);

/** adds a TPA token to a TPA-protected IPsec packet
 *
 * @param	out_hash buffer where to write to
 * @param	out_length length of the output (return value)
 * @param	entry the corresponding outbound IPsec SA
 */
int esp_prot_add_hash(unsigned char *out_hash, int *out_length,
		hip_sa_entry_t *entry);

#if 0
int esp_prot_verify(hip_sa_entry_t *entry, unsigned char *hash_value);
#endif

/** verifies a hash chain-based TPA token
 *
 * @param	hash_function the hash function to be used to derive the hashes
 * @param	hash_length the hash length specified for the used TPA transform
 * @param	active_anchor the active anchor element of the payload channel
 * @param	next_anchor the update anchor element of the payload channel
 * @param	hash_value the hash value to be verified
 * @param	tolerance the maximum number of hash calculations
 * @param	active_root the eventual root element committed to in the active hash chain
 * @param	active_root_length the length of the active root element
 * @param	next_root the eventual root element committed to in the next hash chain
 * @param	next_root_length the length of the next root element
 * @return	0 on success, 1 in case of an implicit anchor element change, -1 on error
 */
int esp_prot_verify_hchain_element(hash_function_t hash_function, int hash_length,
		unsigned char *active_anchor, unsigned char *next_anchor,
		unsigned char *hash_value, int tolerance, unsigned char *active_root,
		int active_root_length, unsigned char *next_root, int next_root_length);

/** verifies a hash tree-based TPA token
 *
 * @param	hash_function the hash function to be used to derive the hashes
 * @param	hash_length the hash length specified for the used TPA transform
 * @param	hash_tree_depth depth of the hash tree in use
 * @param	active_root the active root element of the payload channel
 * @param	next_root the update root element of the payload channel
 * @param	active_uroot the eventual root element committed to in the active hash tree
 * @param	active_uroot_length the length of the active root element
 * @param	next_uroot the eventual root element committed to in the next hash tree
 * @param	next_uroot_length the length of the next root element
 * @param	hash_value contains the data block and verification branch to be verified
 * @return	0 on success, 1 in case of an implicit root element change, -1 on error
 */
int esp_prot_verify_htree_element(hash_function_t hash_function, int hash_length,
		uint32_t hash_tree_depth, unsigned char *active_root, unsigned char *next_root,
		unsigned char *active_uroot, int active_uroot_length, unsigned char *next_uroot,
		int next_uroot_length, unsigned char *hash_value);

/** resolves a TPA transform to the hash function and hash length in use
 *
 * @param	transform the TPA transform
 * @return	resolved transform, NULL for UNUSED transform
 */
esp_prot_tfm_t * esp_prot_resolve_transform(uint8_t transform);

/** resolves a TPA transform to the hash function in use
 *
 * @param	transform the TPA transform
 * @return	resolved hash function, NULL for UNUSED transform
 */
hash_function_t esp_prot_get_hash_function(uint8_t transform);

/** resolves a TPA transform to the hash length in use
 *
 * @param	transform the TPA transform
 * @return	resolved hash length, 0 for UNUSED transform
 */
int esp_prot_get_hash_length(uint8_t transform);

/** helper function - gets hash structure by anchor element from BEX store,
 * refills BEX store and sends update message to hipd
 *
 * @param	item_anchor anchor element of the hash structure to be looked up
 * @param	transform the TPA transform of the corresponding hash structure
 * @return	pointer to the hash structure, NULL if not found
 */
void * esp_prot_get_bex_item_by_anchor(unsigned char *item_anchor,
		uint8_t transform);

/** gets the data offset of the ESP IV and payload
 *
 * @param	entry the corresponding IPsec SA
 * @return	ESP header length if no TPA, else ESP header length + TPA token length
 */
int esp_prot_get_data_offset(hip_sa_entry_t *entry);

/** does maintenance operations - sets update hash structure and triggers update
 * when active one reaches threshold, does the hash structure change when active
 * one is depleted, refills the update store
 *
 * @param	entry the corresponding IPsec SA
 * @return	0 on success, -1 on error
 */
int esp_prot_sadb_maintenance(hip_sa_entry_t *entry);

#endif /*ESP_PROT_API_H_*/
