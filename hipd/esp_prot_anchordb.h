/**
 * References to the hash structures stored in the BEX store of the hipfw
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef ESP_PROT_ANCHORDB_H_
#define ESP_PROT_ANCHORDB_H_

#include "esp_prot_common.h"
#include "hashchain_store.h"
#include "builder.h"

/* defines the structure storing the anchors */
typedef struct anchor_db
{
	/* amount of anchors for each transform */
	int num_anchors[MAX_NUM_ESP_PROT_TFMS];
	/* length of the anchors for each transform */
	int anchor_lengths[MAX_NUM_ESP_PROT_TFMS];
	/* length of the corresponding hchain/htree */
	int hash_item_length[MAX_NUM_ESP_PROT_TFMS];
	/* set to support max amount of anchors possible */
	unsigned char *anchors[MAX_NUM_ESP_PROT_TFMS][MAX_HCHAINS_PER_ITEM];
} anchor_db_t;


/** inits the anchorDB */
void anchor_db_init(void);

/** uninits the anchorDB */
void anchor_db_uninit(void);

/** handles a user-message sent by the firewall when the bex-store is updated
 *
 * @param	msg the user-message sent by fw
 * @return	0 if ok, != 0 else
 */
int anchor_db_update(struct hip_common *msg);

/** checks if the anchorDB has more elements for the given transform
 *
 * @param	transform the ESP protection extension transform
 * @return	1 if more elements, 0 else
 */
int anchor_db_has_more_anchors(uint8_t transform);

/* returns an unused anchor element for the given transform
 *
 * @param	transform the ESP protection extension transform
 * @return	anchor, NULL if empty */
unsigned char * anchor_db_get_anchor(uint8_t transform);

/** returns the anchor-length for a given transform
 *
 * @param	transform the ESP protection extension transform
 * @return	anchor-length, 0 for UNUSED transform
 */
int anchor_db_get_anchor_length(uint8_t transform);

/** returns the hash-item-length for a given transform
 *
 * @param	transform the ESP protection extension transform
 * @return	hash-item-length, 0 for UNUSED transform
 */
int anchor_db_get_hash_item_length(uint8_t transform);

#endif /*ESP_PROT_ANCHORDB_H_*/
