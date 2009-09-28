/**
 * TPA and HHL-specific inter-process communication with the hipd
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef ESP_PROT_FW_MSG_H_
#define ESP_PROT_FW_MSG_H_

#include <inttypes.h>
#include "builder.h"
#include "hashchain_store.h"
#include "user_ipsec_sadb.h"

extern int hip_fw_sock;

/** sends the preferred transform to hipd implicitely turning on
 * the esp protection extension there
 *
 * @param	active 1 to activate, 0 to deactivate the extension in the hipd
 * @return	0 on success, -1 on error
 */
int send_esp_prot_to_hipd(int active);

/** sends a list of all available anchor elements in the BEX store
 * to the hipd
 *
 * @param	hcstore the BEX store
 * @param	use_hash_trees indicates whether hash chains or hash trees are stored
 * @return	0 on success, -1 on error
 */
int send_bex_store_update_to_hipd(hchain_store_t *hcstore, int use_hash_trees);

/** creates the anchor element message
 *
 * @param	hcstore the BEX store
 * @param	use_hash_trees indicates whether hash chains or hash trees are stored
 * @return	the message on success, NULL on error
 *
 * @note this will only consider the first hchain item in each shelf, as only
 *       this should be set up for the store containing the hchains for the BEX
 * @note the created message contains hash_length and anchors for each transform
 */
hip_common_t *create_bex_store_update_msg(hchain_store_t *hcstore, int use_hash_trees);

/** invokes an UPDATE message containing an anchor element as a hook to
 * next hash structure to be used when the active one depletes
 *
 * @param	entry the sadb entry for the outbound direction
 * @param	soft_update indicates if HHL-based updates should be used
 * @param	anchor_offset the offset of the anchor element in the link tree
 * @param	secret the eventual secret
 * @param	secret_length length of the secret
 * @param	branch_nodes nodes of the verification branch
 * @param	branch length length of the verification branch
 * @param	root the root element of the next link tree
 * @param	root_length length of the root element
 * @return	0 on success, -1 on error
 */
int send_trigger_update_to_hipd(hip_sa_entry_t *entry, unsigned char **anchors,
		int hash_item_length, int soft_update, int *anchor_offset, hash_tree_t **link_trees);

/** notifies the hipd about an anchor change in the hipfw
 *
 * @param	entry the sadb entry for the outbound direction
 * @return	0 on success, -1 on error, 1 for inbound sadb entry
 */
int send_anchor_change_to_hipd(hip_sa_entry_t *entry);

/** handles the TPA specific parts in the setup of new IPsec SAs
 *
 * @param	msg	the HIP message
 * @param	esp_prot_transform the TPA transform (return value)
 * @param	num_anchors number of anchor in the array
 * @param	esp_prot_anchors array storing the anchors
 * @param	hash_item_length length of the employed hash structure at the peer (return value)
 * @return	the anchor element on success, NULL on error
 */
int esp_prot_handle_sa_add_request(struct hip_common *msg, uint8_t *esp_prot_transform,
		uint16_t * num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		uint32_t * hash_item_length);

#endif /* ESP_PROT_FW_MSG_H_ */
