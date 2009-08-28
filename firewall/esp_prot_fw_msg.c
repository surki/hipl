/**
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "esp_prot_fw_msg.h"
#include "esp_prot_common.h"
#include "esp_prot_api.h"

int send_esp_prot_to_hipd(int activate)
{
	struct hip_common *msg = NULL;
	int num_transforms = 0;
	uint8_t transform = 0;
	int err = 0, i;
	extern const uint8_t preferred_transforms[];

	HIP_ASSERT(activate >= 0);

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ESP_PROT_TFM, 0), -1,
		 "build hdr failed\n");

	if (activate > 0)
	{
		/*** activation case ***/
		HIP_DEBUG("sending preferred esp prot transforms to hipd...\n");

		// all "in use" transforms + UNUSED
		num_transforms = NUM_TRANSFORMS + 1;

		HIP_DEBUG("adding num_transforms: %i\n", num_transforms);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&num_transforms,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");

		for (i = 0; i < num_transforms; i++)
		{
			HIP_DEBUG("adding transform %i: %u\n", i + 1, preferred_transforms[i]);
			HIP_IFEL(hip_build_param_contents(msg, (void *)&preferred_transforms[i],
					HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
					"build param contents failed\n");
		}
	} else
	{
		/*** deactivation case ***/
		HIP_DEBUG("sending esp prot transform ESP_PROT_TFM_UNUSED to hipd...\n");

		// we are only sending ESP_PROT_TFM_UNUSED
		num_transforms = 1;
		transform = ESP_PROT_TFM_UNUSED;

		HIP_DEBUG("adding num_transforms: %i\n", num_transforms);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&num_transforms,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");

		HIP_DEBUG("adding transform ESP_PROT_TFM_UNUSED: %u\n", transform);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&transform,
				HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
				"build param contents failed\n");
	}

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}

int send_bex_store_update_to_hipd(hchain_store_t *hcstore, int use_hash_trees)
{
	struct hip_common *msg = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_ASSERT(hcstore != NULL);

	HIP_DEBUG("sending bex-store update to hipd...\n");

	HIP_IFEL(!(msg = (struct hip_common *)create_bex_store_update_msg(hcstore, use_hash_trees)),
			-1, "failed to create bex store anchors update message\n");

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}

hip_common_t *create_bex_store_update_msg(hchain_store_t *hcstore, int use_hash_trees)
{
	struct hip_common *msg = NULL;
	int hash_length = 0, num_hchains = 0;
	esp_prot_tfm_t *transform = NULL;
	hash_chain_t *hchain = NULL;
	hash_tree_t *htree = NULL;
	unsigned char *anchor = NULL;
	int err = 0, j;
	int hash_item_offset = 0;
	uint8_t i;
	int hash_item_length = 0;
	uint8_t esp_transform = 0;

	HIP_ASSERT(hcstore != NULL);

	if (use_hash_trees)
	{
		hash_item_offset = ESP_PROT_TFM_HTREE_OFFSET;
	}

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_BEX_STORE_UPDATE, 0), -1,
		 "build hdr failed\n");

	// first add hash_length and num_hchain for each transform
	for (i = 1; i <= NUM_TRANSFORMS; i++)
	{
		esp_transform = i + hash_item_offset;

		HIP_DEBUG("transform %i:\n", esp_transform);

		HIP_IFEL(!(transform = esp_prot_resolve_transform(esp_transform)), -1,
				"failed to resolve transform\n");

		HIP_IFEL((hash_length = esp_prot_get_hash_length(esp_transform)) <= 0, -1,
				"hash_length <= 0, expecting something bigger\n");

		HIP_IFEL((num_hchains = hip_ll_get_size(&hcstore->hchain_shelves[transform->hash_func_id]
		        [transform->hash_length_id].
		        hchains[DEFAULT_HCHAIN_LENGTH_ID][NUM_BEX_HIERARCHIES - 1])) <= 0, -1,
				"num_hchains <= 0, expecting something higher\n");

		// tell hipd about transform
		HIP_IFEL(hip_build_param_contents(msg, (void *)&esp_transform,
				HIP_PARAM_UINT, sizeof(uint8_t)), -1,
				"build param contents failed\n");
		HIP_DEBUG("added esp_transform: %u\n", esp_transform);

		// add num_hchains for this transform, needed on receiver side
		HIP_IFEL(hip_build_param_contents(msg, (void *)&num_hchains,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");
		HIP_DEBUG("added num_hchains: %i\n", num_hchains);

		// add the hash_length for this transform, needed on receiver side
		HIP_IFEL(hip_build_param_contents(msg, (void *)&hash_length,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");
		HIP_DEBUG("added hash_length: %i\n", hash_length);
	}

	// now add the hchain anchors
	for (i = 1; i <= NUM_TRANSFORMS; i++)
	{
		esp_transform = i + hash_item_offset;

		HIP_DEBUG("transform %i:\n", esp_transform);

		HIP_IFEL(!(transform = esp_prot_resolve_transform(esp_transform)), -1,
				"failed to resolve transform\n");

		HIP_IFEL((hash_length = esp_prot_get_hash_length(esp_transform)) <= 0, -1,
				"hash_length <= 0, expecting something bigger\n");

		// ensure correct boundaries
		HIP_ASSERT(transform->hash_func_id >= 0
				&& transform->hash_func_id < NUM_HASH_FUNCTIONS);
		HIP_ASSERT(transform->hash_length_id >= 0
				&& transform->hash_length_id < NUM_HASH_LENGTHS);

		// add anchor with this transform
		for (j = 0; j <  hip_ll_get_size(&hcstore->hchain_shelves[transform->hash_func_id]
				[transform->hash_length_id].
				hchains[DEFAULT_HCHAIN_LENGTH_ID][NUM_BEX_HIERARCHIES - 1]); j++)
		{
			if (use_hash_trees)
			{
				HIP_IFEL(!(htree = hip_ll_get(&hcstore->hchain_shelves[transform->hash_func_id]
									[transform->hash_length_id].
									hchains[DEFAULT_HCHAIN_LENGTH_ID][NUM_BEX_HIERARCHIES - 1], j)), -1,
									"failed to retrieve htree\n");

				anchor = htree->root;
				hash_item_length = htree->num_data_blocks;

			} else
			{
				HIP_IFEL(!(hchain = hip_ll_get(&hcstore->hchain_shelves[transform->hash_func_id]
					[transform->hash_length_id].
					hchains[DEFAULT_HCHAIN_LENGTH_ID][NUM_BEX_HIERARCHIES - 1], j)), -1,
					"failed to retrieve hchain\n");

				anchor = hchain->anchor_element->hash;
				hash_item_length = hchain->hchain_length;
			}

			HIP_IFEL(hip_build_param_contents(msg, (void *)anchor,
					HIP_PARAM_HCHAIN_ANCHOR, hash_length),
					-1, "build param contents failed\n");
			HIP_HEXDUMP("added anchor: ", anchor, hash_length);

			// also send the hchain/htree length for each item
			HIP_IFEL(hip_build_param_contents(msg, (void *)&hash_item_length,
					HIP_PARAM_INT, sizeof(int)),
					-1, "build param contents failed\n");
			HIP_DEBUG("added hash_item_length: %i\n", hash_item_length);
		}
	}

  out_err:
  	if (err)
  	{
  		free(msg);
  		msg = NULL;
  	}

  	return msg;
}

int send_trigger_update_to_hipd(hip_sa_entry_t *entry, int soft_update,
		int anchor_offset, unsigned char *secret, int secret_length,
		unsigned char *branch_nodes, int branch_length, unsigned char *root,
		int root_length)
{
	int err = 0;
	struct hip_common *msg = NULL;
	int hash_length = 0;
	unsigned char *anchor = NULL;
	hash_chain_t *hchain = NULL;
	hash_tree_t *htree = NULL;
	int hash_item_length = 0;

	HIP_ASSERT(entry != NULL);

	HIP_IFEL((hash_length = esp_prot_get_hash_length(entry->esp_prot_transform)) <= 0,
			-1, "error or tried to resolve UNUSED transform\n");

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_TRIGGER_UPDATE, 0), -1,
		 "build hdr failed\n");

	HIP_DEBUG_HIT("src_hit", entry->inner_src_addr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)entry->inner_src_addr,
			HIP_PARAM_HIT, sizeof(struct in6_addr)), -1, "build param contents failed\n");

	HIP_DEBUG_HIT("dst_hit", entry->inner_dst_addr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)entry->inner_dst_addr,
			HIP_PARAM_HIT, sizeof(struct in6_addr)), -1, "build param contents failed\n");

	HIP_DEBUG("esp_prot_transform: %u\n", entry->esp_prot_transform);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->esp_prot_transform,
			HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
			"build param contents failed\n");

	if (entry->esp_prot_transform > ESP_PROT_TFM_HTREE_OFFSET)
	{
		htree = (hash_tree_t *)entry->next_hash_item;
		anchor = htree->root;
		hash_item_length = htree->num_data_blocks;

	} else
	{
		hchain = (hash_chain_t *)entry->next_hash_item;
		anchor = hchain->anchor_element->hash;
		hash_item_length = hchain->hchain_length;
	}

	HIP_HEXDUMP("anchor: ", anchor, hash_length);
	HIP_IFEL(hip_build_param_contents(msg, (void *)anchor, HIP_PARAM_HCHAIN_ANCHOR, hash_length), -1,
			"build param contents failed\n");

	// also send the hchain/htree length for each item
	HIP_IFEL(hip_build_param_contents(msg, (void *)&hash_item_length, HIP_PARAM_INT,
			sizeof(int)), -1, "build param contents failed\n");
	HIP_DEBUG("added hash_item_length: %i\n", hash_item_length);

	HIP_DEBUG("root_length: %i\n", root_length);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&root_length, HIP_PARAM_INT,
			sizeof(int)), -1, "build param contents failed\n");

	if (root && root_length > 0)
	{
		HIP_HEXDUMP("root: ", root, root_length);
		HIP_IFEL(hip_build_param_contents(msg, (void *)root,
				HIP_PARAM_ROOT, root_length), -1,
				"build param contents failed\n");
	}

	HIP_DEBUG("soft_update: %i\n", soft_update);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&soft_update, HIP_PARAM_INT,
			sizeof(int)), -1, "build param contents failed\n");

	if (soft_update)
	{
		HIP_DEBUG("anchor_offset: %i\n", anchor_offset);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&anchor_offset, HIP_PARAM_INT,
				sizeof(int)), -1, "build param contents failed\n");

		HIP_DEBUG("secret_length: %i\n", secret_length);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&secret_length, HIP_PARAM_INT,
				sizeof(int)), -1, "build param contents failed\n");

		HIP_DEBUG("branch_length: %i\n", branch_length);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&branch_length, HIP_PARAM_INT,
				sizeof(int)), -1, "build param contents failed\n");

		HIP_HEXDUMP("secret: ", secret, secret_length);
		HIP_IFEL(hip_build_param_contents(msg, (void *)secret,
				HIP_PARAM_SECRET, secret_length), -1,
				"build param contents failed\n");

		HIP_HEXDUMP("branch_nodes: ", branch_nodes, branch_length);
		HIP_IFEL(hip_build_param_contents(msg, (void *)branch_nodes,
				HIP_PARAM_BRANCH_NODES, branch_length), -1,
				"build param contents failed\n");
	}

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}

int send_anchor_change_to_hipd(hip_sa_entry_t *entry)
{
	int err = 0;
	struct hip_common *msg = NULL;
	int hash_length = 0;
	int direction = 0;
	unsigned char *anchor = NULL;
	hash_chain_t *hchain = NULL;
	hash_tree_t *htree = NULL;

	HIP_ASSERT(entry != NULL);

	HIP_IFEL((hash_length = esp_prot_get_hash_length(entry->esp_prot_transform)) <= 0,
			-1, "error or tried to resolve UNUSED transform\n");

	if (entry->esp_prot_transform > ESP_PROT_TFM_HTREE_OFFSET)
	{
		htree = (hash_tree_t *)entry->active_hash_item;
		anchor = htree->root;

	} else
	{
		hchain = (hash_chain_t *)entry->active_hash_item;
		anchor = hchain->anchor_element->hash;
	}

	// only outbound anchor changes are of interest
	if (entry->direction != HIP_SPI_DIRECTION_OUT)
	{
		err = 1;
		goto out_err;
	}

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ANCHOR_CHANGE, 0), -1,
		 "build hdr failed\n");

	HIP_DEBUG_HIT("src_hit", entry->inner_src_addr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)entry->inner_src_addr,
			HIP_PARAM_HIT, sizeof(struct in6_addr)), -1, "build param contents failed\n");

	HIP_DEBUG_HIT("dst_hit", entry->inner_dst_addr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)entry->inner_dst_addr,
			HIP_PARAM_HIT, sizeof(struct in6_addr)), -1, "build param contents failed\n");

	HIP_DEBUG("direction: %i\n", entry->direction);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->direction,
			HIP_PARAM_INT, sizeof(int)), -1, "build param contents failed\n");

	HIP_DEBUG("esp_prot_transform: %u\n", entry->esp_prot_transform);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->esp_prot_transform,
			HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
			"build param contents failed\n");

	// the anchor change has already occurred on fw-side
	HIP_HEXDUMP("anchor: ", anchor, hash_length);
	HIP_IFEL(hip_build_param_contents(msg, (void *)anchor,
			HIP_PARAM_HCHAIN_ANCHOR, hash_length), -1,
			"build param contents failed\n");

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}

unsigned char * esp_prot_handle_sa_add_request(struct hip_common *msg,
		uint8_t *esp_prot_transform, uint32_t * hash_item_length)
{
	struct hip_tlv_common *param = NULL;
	unsigned char *esp_prot_anchor = NULL;
	int hash_length = 0, err = 0;
	*esp_prot_transform = 0;

	HIP_ASSERT(msg != NULL);
	HIP_ASSERT(esp_prot_transform != NULL);

	HIP_IFEL(!(param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM)),
			-1, "esp prot transform missing\n");
	*esp_prot_transform = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("esp protection transform is %u\n", *esp_prot_transform);

	// this parameter is only included, if the esp extension is used
	if (*esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		// retrieve hash length for the received transform
		HIP_IFEL((hash_length = esp_prot_get_hash_length(*esp_prot_transform)) <= 0,
				-1, "error or tried to resolve UNUSED transform\n");

		HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR)),
				-1, "transform suggests anchor, but it is NOT included in msg\n");
		esp_prot_anchor = (unsigned char *) hip_get_param_contents_direct(param);
		HIP_HEXDUMP("esp protection anchor is ", esp_prot_anchor, hash_length);

		HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_ITEM_LENGTH)),
				-1, "transform suggests hash_item_length, but it is NOT included in msg\n");
		*hash_item_length = *((uint32_t *) hip_get_param_contents_direct(param));
		HIP_DEBUG("esp protection item length: %u\n", *hash_item_length);

	} else
	{
		esp_prot_anchor = NULL;
	}

  out_err:
	if (err)
	{
		esp_prot_anchor = NULL;
		*esp_prot_transform = 0;
	}

	return esp_prot_anchor;
}
