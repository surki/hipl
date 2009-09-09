/**
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "esp_prot_anchordb.h"


/* stores all anchors sent by the firewall */
anchor_db_t anchor_db;


void anchor_db_init()
{
	// set to 0 / NULL
	memset(anchor_db.num_anchors, 0, MAX_NUM_ESP_PROT_TFMS * sizeof(int));
	memset(anchor_db.anchor_lengths, 0, MAX_NUM_ESP_PROT_TFMS * sizeof(int));
	memset(anchor_db.anchor_lengths, 0, MAX_NUM_ESP_PROT_TFMS * sizeof(int));
	memset(anchor_db.anchors, 0, MAX_NUM_ESP_PROT_TFMS * MAX_HCHAINS_PER_ITEM);

	HIP_DEBUG("inited hchain anchorDB\n");
}

void anchor_db_uninit()
{
	int i, j;

	// free all hashes
	for (i = 0; i < MAX_NUM_ESP_PROT_TFMS; i++)
	{
		anchor_db.num_anchors[i] = 0;
		anchor_db.anchor_lengths[i] = 0;
		anchor_db.hash_item_length[i] = 0;

		for (j = 0; j < MAX_HCHAINS_PER_ITEM; j++)
		{
			if (anchor_db.anchors[i][j])
				free(anchor_db.anchors[i][j]);

			anchor_db.anchors[i][j] = NULL;
		}
	}

	HIP_DEBUG("uninited hchain anchorDB\n");
}

int anchor_db_update(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	unsigned char *anchor = NULL;
	int err = 0, i, j;
	extern int esp_prot_num_transforms;
	uint8_t esp_transforms[NUM_TRANSFORMS];

	// if this function is called, the extension should be active
	HIP_ASSERT(esp_prot_num_transforms > 1);
	HIP_ASSERT(msg != NULL);

	memset(esp_transforms, 0, NUM_TRANSFORMS * sizeof(uint8_t));

	HIP_DEBUG("updating hchain anchorDB...\n");

	/* XX TODO ineffcient -> only add non-existing elements instead of
	 *         uniniting and adding all elements again */
	anchor_db_uninit();

	/*** set up anchor_db.num_anchors and anchor_db.anchor_lengths ***/
	// get first int value
	HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_UINT)),
			-1, "parameter missing in user-message from fw\n");

	// don't set up anything for UNUSED transform
	for (i = 0; i < esp_prot_num_transforms - 1; i++)
	{
		// needed for redirection to correct slot in anchor_db
		esp_transforms[i] = *(uint8_t *) hip_get_param_contents_direct(param);
		HIP_DEBUG("esp_transform is %u\n", esp_transforms[i]);

		HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_next_param(msg, param)),
				-1, "parameter missing in user-message from fw\n");
		anchor_db.num_anchors[esp_transforms[i]] = *(int *) hip_get_param_contents_direct(param);
		HIP_DEBUG("num_anchors is %i\n", anchor_db.num_anchors[esp_transforms[i]]);

		HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_next_param(msg, param)),
				-1, "parameter missing in user-message from fw\n");
		anchor_db.anchor_lengths[esp_transforms[i]] = *(int *) hip_get_param_contents_direct(param);
		HIP_DEBUG("anchor_length is %i\n", anchor_db.anchor_lengths[esp_transforms[i]]);

		HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_next_param(msg, param)),
				-1, "parameter missing in user-message from fw\n");
	}

	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		HIP_DEBUG("transform %u:\n", esp_transforms[i]);

		for (j = 0; j < anchor_db.num_anchors[esp_transforms[i]]; j++)
		{
			HIP_IFEL(!(anchor_db.anchors[esp_transforms[i]][j] = (unsigned char *)malloc(anchor_db.
					anchor_lengths[esp_transforms[i]])), -1, "failed to allocate memory\n");

			anchor = (unsigned char *) hip_get_param_contents_direct(param);
			memcpy(anchor_db.anchors[esp_transforms[i]][j], anchor,
					anchor_db.anchor_lengths[esp_transforms[i]]);
			HIP_HEXDUMP("adding anchor: ", anchor_db.anchors[esp_transforms[i]][j],
					anchor_db.anchor_lengths[esp_transforms[i]]);

			HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_next_param(
					msg, param)), -1, "parameter missing in user-message from fw\n");
			anchor_db.hash_item_length[esp_transforms[i]] = *(int *)
					hip_get_param_contents_direct(param);
			HIP_DEBUG("adding hash_item_length: %i\n",
					anchor_db.hash_item_length[esp_transforms[i]]);

			// exclude getting the next param for the very last loop
			if (!(i == NUM_TRANSFORMS - 1 && j == anchor_db.num_anchors[esp_transforms[i]] - 1))
			{
				HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_next_param(
						msg, param)), -1, "parameter missing in user-message from fw\n");
			}
		}
	}

	HIP_DEBUG("anchor_db successfully updated\n");

  out_err:
	return err;
}

int anchor_db_get_num_anchors(uint8_t transform)
{
	HIP_ASSERT(transform > 0);

	HIP_DEBUG("anchor_db.num_anchors[%u]: %i\n", transform, anchor_db.num_anchors[transform]);

	return anchor_db.num_anchors[transform];
}

int anchor_db_has_more_anchors(uint8_t transform)
{
	HIP_ASSERT(transform > 0);

	if (anchor_db.num_anchors[transform] > 0)
		return 1;
	else
		return 0;
}

unsigned char * anchor_db_get_anchor(uint8_t transform)
{
	unsigned char *stored_anchor = NULL;
	int transform_id = 0;
	int anchor_offset = 0;
	int err = 0;

	// ensure correct boundaries
	HIP_ASSERT(transform > 0);

	// get index of last unused anchor for this transform
	HIP_IFEL((anchor_offset = anchor_db.num_anchors[transform] - 1) < 0, -1,
			"anchor_db is empty for this transform\n");

	// ensure correct boundaries
	HIP_ASSERT(anchor_offset >= 0 && anchor_offset < MAX_HCHAINS_PER_ITEM);
	HIP_IFEL(!(stored_anchor = anchor_db.anchors[transform][anchor_offset]), -1,
			"anchor_offset points to empty slot\n");

	// remove anchor from db
	anchor_db.anchors[transform][anchor_offset] = NULL;
	anchor_offset = anchor_db.num_anchors[transform]--;

  out_err:
  	if (err)
  	{
  		if (stored_anchor)
  			free(stored_anchor);

  		stored_anchor = NULL;
  	}

  	return stored_anchor;
}

int anchor_db_get_anchor_length(uint8_t transform)
{
	HIP_ASSERT(transform > 0);

	return anchor_db.anchor_lengths[transform];
}

int anchor_db_get_hash_item_length(uint8_t transform)
{
	HIP_ASSERT(transform > 0);

	return anchor_db.hash_item_length[transform];
}
