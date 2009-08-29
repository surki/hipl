/**
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "esp_prot_hipd_msg.h"
#include "esp_prot_anchordb.h"
#include "esp_prot_light_update.h"
#include "esp_prot_common.h"

int esp_prot_set_preferred_transforms(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	extern int esp_prot_num_transforms;
	extern uint8_t esp_prot_transforms[NUM_TRANSFORMS];
	int err = 0, i;

	// process message and store the preferred transforms
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_INT);
	esp_prot_num_transforms = *((int *)hip_get_param_contents_direct(param));
	HIP_DEBUG("esp protection num_transforms: %i\n", esp_prot_num_transforms);

	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		if (i < esp_prot_num_transforms)
		{
			param = (struct hip_tlv_common *)hip_get_next_param(msg, param);
			esp_prot_transforms[i] = *((uint8_t *)hip_get_param_contents_direct(param));
			HIP_DEBUG("esp protection transform %i: %u\n", i + 1, esp_prot_transforms[i]);

		} else
		{
			esp_prot_transforms[i] = 0;
		}
	}

	// this works as we always have to send at least ESP_PROT_TFM_UNUSED
	if (esp_prot_num_transforms > 1)
		HIP_DEBUG("switched to esp protection extension\n");
	else
		HIP_DEBUG("switched to normal esp mode\n");

	/* we have to make sure that the precalculated R1s include the esp
	 * protection extension transform */
	HIP_DEBUG("recreate all R1s\n");
	HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1, "failed to recreate all R1s\n");

  out_err:
  	return err;
}

int esp_prot_handle_trigger_update_msg(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	hip_hit_t *local_hit = NULL, *peer_hit = NULL;
	uint8_t esp_prot_tfm = 0;
	int hash_length = 0;
	unsigned char *esp_prot_anchor = NULL;
	int soft_update = 0, anchor_offset = 0;
	int anchor_length = 0, secret_length = 0, branch_length = 0, root_length = 0;
	unsigned char *secret = NULL, *branch_nodes = NULL, *root = NULL;
	hip_ha_t *entry = NULL;
	int hash_item_length = 0;
	int err = 0;

	param = hip_get_param(msg, HIP_PARAM_HIT);
	local_hit = (hip_hit_t *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("src_hit", local_hit);

	param = hip_get_next_param(msg, param);
	peer_hit = (hip_hit_t *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("dst_hit", peer_hit);

	param = hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM);
	esp_prot_tfm = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("esp_prot_transform: %u\n", esp_prot_tfm);

	param = hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);
	esp_prot_anchor = (unsigned char *) hip_get_param_contents_direct(param);
	HIP_HEXDUMP("anchor: ", esp_prot_anchor, hash_length);

	param = hip_get_param(msg, HIP_PARAM_INT);
	hash_item_length  = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("hash_item_length: %i\n", hash_item_length);

	param = hip_get_next_param(msg, param);
	root_length  = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("root_length: %i\n", root_length);

	if (root_length > 0)
	{
		param = hip_get_param(msg, HIP_PARAM_ROOT);
		root = (unsigned char *) hip_get_param_contents_direct(param);
		HIP_HEXDUMP("root: ", root, root_length);
	}

	param = hip_get_next_param(msg, param);
	soft_update  = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("soft_update: %i\n", soft_update);

	if (soft_update)
	{
		param = hip_get_next_param(msg, param);
		anchor_offset  = *((int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("anchor_offset: %i\n", anchor_offset);

		param = hip_get_next_param(msg, param);
		secret_length  = *((int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("secret_length: %i\n", secret_length);

		param = hip_get_next_param(msg, param);
		branch_length  = *((int *) hip_get_param_contents_direct(param));
		HIP_DEBUG("branch_length: %i\n", branch_length);

		param = hip_get_param(msg, HIP_PARAM_SECRET);
		secret = (unsigned char *) hip_get_param_contents_direct(param);
		HIP_HEXDUMP("secret: ", secret, secret_length);

		param = hip_get_param(msg, HIP_PARAM_BRANCH_NODES);
		branch_nodes = (unsigned char *) hip_get_param_contents_direct(param);
		HIP_HEXDUMP("branch_nodes: ", branch_nodes, branch_length);
	}


	// get matching entry from hadb for HITs provided above
	HIP_IFEL(!(entry = hip_hadb_find_byhits(local_hit, peer_hit)), -1,
			"failed to retrieve requested HA entry\n");

	// check if transforms are matching and add anchor as new local_anchor
	HIP_IFEL(entry->esp_prot_transform != esp_prot_tfm, -1,
			"esp prot transform changed without new BEX\n");
	HIP_DEBUG("esp prot transforms match\n");

	// we need to know the hash_length for this transform
	hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

	// make sure that the update-anchor is not set yet
	HIP_IFEL(*(entry->esp_local_update_anchor) != 0, -1,
			"next hchain changed in fw, but we still have the last update-anchor set!");

	// set the update anchor
	//memset(entry->esp_local_update_anchor, 0, MAX_HASH_LENGTH);
	memcpy(entry->esp_local_update_anchor, esp_prot_anchor, hash_length);

	if (root)
	{
		// store the root for usage in update msgs
		entry->esp_root_length = root_length;
		memcpy(entry->esp_root, root, root_length);

	} else
	{
		// reset to unused
		entry->esp_root_length = 0;
		memset(entry->esp_root, 0, root_length);
	}

	// set the hash_item_length of the item used for this update
	entry->hash_item_length = hash_item_length;

	if (soft_update)
	{
		HIP_IFEL(esp_prot_send_light_update(entry, anchor_offset, secret, secret_length,
				branch_nodes, branch_length), -1,
				"failed to send anchor update\n");

	} else
	{
		/* this should send an update only containing the mandatory params
		 * HMAC and HIP_SIGNATURE as well as the ESP_PROT_ANCHOR and the
		 * SEQ param (to garanty freshness of the ANCHOR) in the signed part
		 * of the message
		 *
		 * params used for this call:
		 * - hadb entry matching the HITs passed in the trigger msg
		 * - not sending locators -> list = NULL and count = 0
		 * - no interface triggers this event -> -1
		 * - bitwise telling about which params to add to UPDATE -> set 3rd bit to 1
		 * - UPDATE not due to adding of a new addresses
		 * - not setting any address, as none is updated */
		HIP_IFEL(hip_send_update(entry, NULL, 0, -1, SEND_UPDATE_ESP_ANCHOR, 0, NULL),
				-1, "failed to send anchor update\n");
	}

  out_err:
	return err;
}

int esp_prot_handle_anchor_change_msg(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	hip_hit_t *local_hit = NULL, *peer_hit = NULL;
	uint8_t esp_prot_tfm = 0;
	int hash_length = 0;
	unsigned char *esp_prot_anchor = NULL;
	hip_ha_t *entry = NULL;
	int direction = 0;
	int err = 0;

	param = hip_get_param(msg, HIP_PARAM_HIT);
	local_hit = (hip_hit_t *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("src_hit", local_hit);

	param = hip_get_next_param(msg, param);
	peer_hit = (hip_hit_t *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("dst_hit", peer_hit);

	param = hip_get_param(msg, HIP_PARAM_INT);
	direction = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("direction: %i\n", direction);

	param = hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM);
	esp_prot_tfm = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("esp_prot_transform: %u\n", esp_prot_tfm);

	param = hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);
	esp_prot_anchor = (unsigned char *) hip_get_param_contents_direct(param);
	HIP_HEXDUMP("anchor: ", esp_prot_anchor, hash_length);


	// get matching entry from hadb for HITs provided above
	HIP_IFEL(!(entry = hip_hadb_find_byhits(local_hit, peer_hit)), -1,
			"failed to retrieve requested HA entry\n");

	// check if transforms are matching and add anchor as new local_anchor
	HIP_IFEL(entry->esp_prot_transform != esp_prot_tfm, -1,
			"esp prot transform changed without new BEX\n");
	HIP_DEBUG("esp prot transforms match\n");

	// we need to know the hash_length for this transform
	hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

	// only handle outbound direction here
	if (direction == HIP_SPI_DIRECTION_OUT)
	{
		// make sure that the update-anchor is set
		HIP_IFEL(memcmp(entry->esp_local_update_anchor, esp_prot_anchor, hash_length),
				-1, "hchain-anchors used for outbound connections NOT in sync\n");

		// set update anchor as new active local anchor
		//memset(entry->esp_local_anchor, 0, MAX_HASH_LENGTH);
		memcpy(entry->esp_local_anchor, entry->esp_local_update_anchor, hash_length);
		memset(entry->esp_local_update_anchor, 0, MAX_HASH_LENGTH);

		HIP_DEBUG("changed update_anchor to local_anchor\n");

		goto out_err;
	}

// inbound hashes are tracked separately
#if 0
	else
	{
		// make sure that the update-anchor is set
		HIP_IFEL(memcmp(entry->esp_peer_update_anchor, esp_prot_anchor, hash_length),
				-1, "hchain-anchors used for outbound connections NOT in sync\n");

		// set update anchor as new active local anchor
		//memset(entry->esp_peer_anchor, 0, MAX_HASH_LENGTH);
		memcpy(entry->esp_peer_anchor, entry->esp_peer_update_anchor, hash_length);
		memset(entry->esp_peer_update_anchor, 0, MAX_HASH_LENGTH);
	}
#endif

	HIP_ERROR("did NOT change update_anchor to local_anchor\n");
	err = -1;

  out_err:
	return err;
}

int esp_prot_sa_add(hip_ha_t *entry, struct hip_common *msg, int direction,
		int update)
{
	unsigned char *hchain_anchor = NULL;
	int hash_length = 0;
	uint32_t hash_item_length = 0;
	int err = 0;

	HIP_DEBUG("direction: %i\n", direction);

	// we always tell the negotiated transform to the firewall
	HIP_DEBUG("esp protection transform is %u \n", entry->esp_prot_transform);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->esp_prot_transform,
			HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
			"build param contents failed\n");

	// but we only transmit the anchor to the firewall, if the esp extension is used
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

		// choose the anchor depending on the direction and update or add
		if (update)
		{
			if (direction == HIP_SPI_DIRECTION_OUT)
			{
				HIP_IFEL(!(hchain_anchor = entry->esp_local_update_anchor), -1,
						"hchain anchor expected, but not present\n");

				hash_item_length = entry->esp_local_update_length;

			} else
			{
				HIP_IFEL(!(hchain_anchor = entry->esp_peer_update_anchor), -1,
						"hchain anchor expected, but not present\n");

				hash_item_length = entry->esp_peer_update_length;
			}
		} else
		{
			if (direction == HIP_SPI_DIRECTION_OUT)
			{
				HIP_IFEL(!(hchain_anchor = entry->esp_local_anchor), -1,
						"hchain anchor expected, but not present\n");

				hash_item_length = entry->esp_local_active_length;

			} else
			{
				HIP_IFEL(!(hchain_anchor = entry->esp_peer_anchor), -1,
						"hchain anchor expected, but not present\n");

				hash_item_length = entry->esp_peer_active_length;
			}
		}

		HIP_HEXDUMP("esp protection anchor is ", hchain_anchor, hash_length);

		HIP_IFEL(hip_build_param_contents(msg, (void *)hchain_anchor,
				HIP_PARAM_HCHAIN_ANCHOR, hash_length), -1,
				"build param contents failed\n");

		HIP_IFEL(hip_build_param_contents(msg, (void *)&hash_item_length,
				HIP_PARAM_ITEM_LENGTH, sizeof(uint32_t)), -1,
				"build param contents failed\n");

	} else
	{
		HIP_DEBUG("no anchor added, transform UNUSED\n");
	}

  out_err:
	return err;
}

int esp_prot_r1_add_transforms(hip_common_t *msg)
{
	extern int esp_prot_num_transforms;
	extern uint8_t esp_prot_transforms[NUM_TRANSFORMS];
	int err = 0, i;

	/* only supported in usermode and optional there
 	 *
 	 * add the transform only when usermode is active */
 	if (hip_use_userspace_ipsec)
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension might be in use\n");

 		/* send the stored transforms */
		HIP_IFEL(hip_build_param_esp_prot_transform(msg, esp_prot_num_transforms,
				esp_prot_transforms), -1,
				"Building of ESP protection mode failed\n");

		HIP_DEBUG("ESP prot transforms param built\n");

 	} else
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension UNUSED, skip\n");
 	}

 	_HIP_DUMP_MSG(msg);

  out_err:
 	return err;
}

int esp_prot_r1_handle_transforms(hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_preferred_tfms *prot_transforms = NULL;
	int err = 0;

	/* this is only handled if we are using userspace ipsec,
	 * otherwise we just ignore it */
	if (hip_use_userspace_ipsec)
	{
		HIP_DEBUG("userspace IPsec hint: ESP extension might be in use\n");

		param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_TRANSFORMS);

		// check if the transform parameter was sent
		if (param)
		{
			HIP_DEBUG("received preferred transforms from peer\n");

			// store that we received the param for further processing
			ctx->esp_prot_param = 1;

			prot_transforms = (struct esp_prot_preferred_tfms *) param;

			// select transform and store it for this connection
			entry->esp_prot_transform = esp_prot_select_transform(prot_transforms->num_transforms,
					prot_transforms->transforms);

		} else
		{
			HIP_DEBUG("R1 does not contain preferred ESP protection transforms, " \
					"locally setting UNUSED\n");

			// store that we didn't received the param
			ctx->esp_prot_param = 0;

			// if the other end-host does not want to use the extension, we don't either
			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	} else
	{
		HIP_DEBUG("no userspace IPsec hint for ESP extension, locally setting UNUSED\n");

		// make sure we don't add the anchor now and don't add any transform or anchor
		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
	return err;
}

int esp_prot_i2_add_anchor(hip_common_t *i2, hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	unsigned char *anchor = NULL;
	int hash_length = 0;
	int hash_item_length = 0;
	int err = 0;

	/* only add, if extension in use and we agreed on a transform
	 *
	 * @note the transform was selected in handle R1 */
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		if (anchor_db_has_more_anchors(entry->esp_prot_transform))
		{
			hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

			HIP_DEBUG("hash_length: %i\n", hash_length);

			HIP_IFEL(!(anchor = anchor_db_get_anchor(entry->esp_prot_transform)), -1,
					"no anchor elements available, threading?\n");
			hash_item_length = anchor_db_get_hash_item_length(entry->esp_prot_transform);
			HIP_IFEL(hip_build_param_esp_prot_anchor(i2, entry->esp_prot_transform,
					anchor, NULL, hash_length, hash_item_length), -1,
					"Building of ESP protection anchor failed\n");

			// store local_anchor
			memset(entry->esp_local_anchor, 0, MAX_HASH_LENGTH);
			memcpy(entry->esp_local_anchor, anchor, hash_length);
			HIP_HEXDUMP("stored local anchor: ", entry->esp_local_anchor, hash_length);

			entry->esp_local_active_length = anchor_db_get_hash_item_length(
					entry->esp_prot_transform);
			HIP_DEBUG("entry->esp_local_active_length: %u\n",
					entry->esp_local_active_length);

		} else
		{
			// fall back
			HIP_ERROR("agreed on using esp hchain protection, but no elements");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

			// inform our peer
			HIP_IFEL(hip_build_param_esp_prot_anchor(i2, entry->esp_prot_transform,
					NULL, NULL, 0, 0), -1,
					"Building of ESP protection anchor failed\n");
		}
	} else
	{
		// only reply, if transforms param in R1; send UNUSED param
		if (ctx->esp_prot_param)
		{
			HIP_DEBUG("R1 contained transforms, but agreed not to use the extension\n");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

			HIP_IFEL(hip_build_param_esp_prot_anchor(i2, entry->esp_prot_transform,
					NULL, NULL, 0, 0), -1,
					"Building of ESP protection anchor failed\n");
		} else
		{
			HIP_DEBUG("peer didn't send transforms in R1, locally setting UNUSED\n");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	}

  out_err:
	if (anchor)
		free(anchor);

 	return err;
}

int esp_prot_i2_handle_anchor(hip_ha_t *entry, struct hip_context *ctx)
{
	extern int esp_prot_num_transforms;
	extern uint8_t esp_prot_transforms[NUM_TRANSFORMS];
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	int hash_length = 0;
	int err = 0;

	/* only supported in user-mode ipsec and optional there */
 	if (hip_use_userspace_ipsec && esp_prot_num_transforms > 1)
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension might be in use\n");

		if (param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_ANCHOR))
		{
			prot_anchor = (struct esp_prot_anchor *) param;

			// check if the anchor has a supported transform
			if (esp_prot_check_transform(esp_prot_num_transforms, esp_prot_transforms,
					prot_anchor->transform) >= 0)
			{
				// we know this transform
				entry->esp_prot_transform = prot_anchor->transform;

				if (entry->esp_prot_transform == ESP_PROT_TFM_UNUSED)
				{
					HIP_DEBUG("agreed NOT to use esp protection extension\n");

				} else
				{
					hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

					// store peer_anchor
					memset(entry->esp_peer_anchor, 0, MAX_HASH_LENGTH);
					memcpy(entry->esp_peer_anchor, &prot_anchor->anchors[0],
							hash_length);
					HIP_HEXDUMP("received anchor: ", entry->esp_peer_anchor,
												hash_length);

					// ignore a possible update anchor
#if 0
					memset(entry->esp_peer_update_anchor, 0, MAX_HASH_LENGTH);
					memcpy(entry->esp_peer_update_anchor,
							&prot_anchor->anchor[hash_length], hash_length);
#endif

					entry->esp_peer_active_length = ntohl(prot_anchor->hash_item_length);
					HIP_DEBUG("entry->esp_peer_active_length: %u\n",
							entry->esp_peer_active_length);

				}
			} else
			{
				HIP_ERROR("received anchor with unknown transform, falling back\n");

				entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
			}
		} else
		{
			HIP_DEBUG("NO esp anchor sent, locally setting UNUSED\n");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	} else
	{
		HIP_DEBUG("userspace IPsec hint: esp protection extension NOT in use\n");

		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
 	return err;
}

int esp_prot_r2_add_anchor(hip_common_t *r2, hip_ha_t *entry)
{
	unsigned char *anchor = NULL;
	int hash_length = 0;
	int hash_item_length = 0;
	int err = 0;

	// only add, if extension in use, we agreed on a transform and no error until now
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		if (anchor_db_has_more_anchors(entry->esp_prot_transform))
		{
			hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

			HIP_IFEL(!(anchor = anchor_db_get_anchor(entry->esp_prot_transform)),
					-1, "no anchor elements available, threading?\n");

			hash_item_length = anchor_db_get_hash_item_length(entry->esp_prot_transform);

			HIP_IFEL(hip_build_param_esp_prot_anchor(r2, entry->esp_prot_transform,
					anchor, NULL, hash_length, hash_item_length), -1,
					"Building of ESP protection anchor failed\n");

			// store local_anchor
			memset(entry->esp_local_anchor, 0, MAX_HASH_LENGTH);
			memcpy(entry->esp_local_anchor, anchor, hash_length);

			HIP_HEXDUMP("stored local anchor: ", entry->esp_local_anchor, hash_length);

			entry->esp_local_active_length = anchor_db_get_hash_item_length(
								entry->esp_prot_transform);
			HIP_DEBUG("entry->esp_local_active_length: %u\n",
					entry->esp_local_active_length);

		} else
		{
			// fall back
			HIP_ERROR("agreed on using esp hchain protection, but no elements");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

			// inform our peer
			HIP_IFEL(hip_build_param_esp_prot_anchor(r2, entry->esp_prot_transform,
					NULL, NULL, 0, 0), -1,
					"Building of ESP protection anchor failed\n");
		}
	} else
	{
		HIP_DEBUG("esp protection extension NOT in use for this connection\n");

		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
	if (anchor)
		free(anchor);

 	return err;
}

int esp_prot_r2_handle_anchor(hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	unsigned char *anchor = NULL;
	int hash_length = 0;
	int err = 0;

	// only process anchor, if we agreed on using it before
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		if (param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_ANCHOR))
		{
			prot_anchor = (struct esp_prot_anchor *) param;

			// check if the anchor has got the negotiated transform
			if (prot_anchor->transform == entry->esp_prot_transform)
			{
				hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

				memset(entry->esp_peer_anchor, 0, MAX_HASH_LENGTH);
				memcpy(entry->esp_peer_anchor, &prot_anchor->anchors[0], hash_length);
				HIP_HEXDUMP("received anchor: ", entry->esp_peer_anchor, hash_length);

				// ignore a possible update anchor
#if 0
				memset(entry->esp_peer_update_anchor, 0, MAX_HASH_LENGTH);
				memcpy(entry->esp_peer_update_anchor,
						&prot_anchor->anchors[hash_length], hash_length);
#endif

				entry->esp_peer_active_length = ntohl(prot_anchor->hash_item_length);
				HIP_DEBUG("entry->esp_peer_active_length: %u\n",
						entry->esp_peer_active_length);

			} else if (prot_anchor->transform == ESP_PROT_TFM_UNUSED)
			{
				HIP_DEBUG("peer encountered problems and did fallback\n");

				// also fallback
				entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

			} else
			{
				HIP_ERROR("received anchor does NOT use negotiated transform, falling back\n");

				// fallback
				entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
			}
		} else
		{
			HIP_DEBUG("agreed on using esp hchain extension, but no anchor sent or error\n");

			// fall back option
			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	} else
	{
		HIP_DEBUG("NOT using esp protection extension\n");

		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
 	return err;
}

/* only processes pure ANCHOR-UPDATEs */
int esp_prot_handle_update(hip_common_t *recv_update, hip_ha_t *entry,
		in6_addr_t *src_ip, in6_addr_t *dst_ip)
{
	struct hip_seq * seq = NULL;
	struct hip_ack * ack = NULL;
	struct hip_esp_info * esp_info = NULL;
	uint32_t spi = 0;
	int err = 0;

	HIP_ASSERT(entry != NULL);

	seq = (struct hip_seq *) hip_get_param(recv_update, HIP_PARAM_SEQ);
	ack = (struct hip_ack *) hip_get_param(recv_update, HIP_PARAM_ACK);
	esp_info = (struct hip_esp_info *) hip_get_param(recv_update, HIP_PARAM_ESP_INFO);

	if (seq && !ack && !esp_info)
	{
		/* this is the first ANCHOR-UPDATE msg
		 *
		 * @note contains anchors -> update inbound SA
		 * @note response has to contain corresponding ACK and ESP_INFO */
		HIP_IFEL(esp_prot_update_handle_anchor(recv_update, entry,
				src_ip, dst_ip, &spi), -1,
				"failed to handle anchor in UPDATE msg\n");
		HIP_DEBUG("successfully processed anchors in ANCHOR-UPDATE\n");

		// send ANCHOR_UPDATE response, when the anchor was verified above
		HIP_IFEL(esp_prot_send_update_response(recv_update, entry, dst_ip,
				src_ip, spi), -1, "failed to send UPDATE replay");

	} else if (!seq && ack && esp_info)
	{
		/* this is the second ANCHOR-UPDATE msg
		 *
		 * @note contains ACK for previously sent anchors -> update outbound SA */
		HIP_DEBUG("received ACK for previously sent ANCHOR-UPDATE\n");

		// the update was successful, stop retransmission
		entry->update_state = 0;

		// notify sadb about next anchor
		HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(dst_ip, src_ip,
				&entry->hit_our, &entry->hit_peer, entry->default_spi_out,
				entry->esp_transform, &entry->esp_out, &entry->auth_out, 0,
				HIP_SPI_DIRECTION_OUT, 1, entry), -1,
				"failed to notify sadb about next anchor\n");

	} else
	{
		HIP_DEBUG("NOT a pure ANCHOR-UPDATE, unhandled\n");
	}

  out_err:
	return err;
}

int esp_prot_update_add_anchor(hip_common_t *update, hip_ha_t *entry)
{
	struct hip_seq * seq = NULL;
	int hash_length = 0;
	int err = 0;

	// only do further processing when extension is in use
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		/* we only want to send anchors in 1. and 2. UPDATE message
		 *
		 * @note we can distinguish the 1. and 2. UPDATE message by
		 * 		 looking at the presence of SEQ param in the packet
		 * 		 to be sent */
		seq = (struct hip_seq *) hip_get_param(update, HIP_PARAM_SEQ);

		if (seq)
		{
			// we need to know the hash_length for this transform
			hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

			/* @note update-anchor will be set, if there was a anchor UPDATE before
			 *       or if this is an anchor UPDATE; otherwise update-anchor will
			 *       be NULL
			 *
			 * XX TODO we need to choose the correct SA with the anchor we want to
			 *         update, when supporting multihoming and when this is a
			 *         pure anchor-update */
			HIP_IFEL(hip_build_param_esp_prot_anchor(update,
					entry->esp_prot_transform, entry->esp_local_anchor,
					entry->esp_local_update_anchor, hash_length, entry->hash_item_length),
					-1, "building of ESP protection ANCHOR failed\n");

			entry->esp_local_update_length = anchor_db_get_hash_item_length(
					entry->esp_prot_transform);
			HIP_DEBUG("entry->esp_local_update_length: %u\n",
					entry->esp_local_update_length);

			// only add the root if it is specified
			if (entry->esp_root_length > 0)
			{
				HIP_IFEL(hip_build_param_esp_prot_root(update,
						entry->esp_root_length, entry->esp_root), -1,
						"building of ESP ROOT failed\n");
			}
		}
	}

  out_err:
	return err;
}

int esp_prot_update_handle_anchor(hip_common_t *recv_update, hip_ha_t *entry,
		in6_addr_t *src_ip, in6_addr_t *dst_ip, uint32_t *spi)
{
	struct esp_prot_anchor *prot_anchor = NULL;
	int hash_length = 0;
	unsigned char cmp_value[MAX_HASH_LENGTH];
	int err = 0;

	HIP_ASSERT(spi != NULL);

	*spi = 0;
	prot_anchor = (struct esp_prot_anchor *) hip_get_param(recv_update,
			HIP_PARAM_ESP_PROT_ANCHOR);

	if (prot_anchor)
	{
		/* XX TODO find matching SA entry in host association for active_anchor
		 *         and _inbound_ direction */

		// check that we are receiving an anchor matching the negotiated transform
		HIP_IFEL(entry->esp_prot_transform != prot_anchor->transform, -1,
				"esp prot transform changed without new BEX\n");
		HIP_DEBUG("esp prot transforms match\n");

		// we need to know the hash_length for this transform
		hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

		// compare peer_update_anchor to 0
		memset(cmp_value, 0, MAX_HASH_LENGTH);

		// treat the very first hchain update after the BEX differently
		if (!memcmp(entry->esp_peer_update_anchor, cmp_value, MAX_HASH_LENGTH))
		{
			// check that we are receiving an anchor matching the active one
			HIP_IFEL(memcmp(&prot_anchor->anchors[0], entry->esp_peer_anchor,
					hash_length), -1, "esp prot active peer anchors do NOT match\n");
			HIP_DEBUG("esp prot active peer anchors match\n");

			// set the update anchor as the peer's update anchor
			//memset(entry->esp_peer_update_anchor, 0, MAX_HASH_LENGTH);
			memcpy(entry->esp_peer_update_anchor, &prot_anchor->anchors[hash_length],
					hash_length);
			HIP_DEBUG("peer_update_anchor set\n");

			entry->esp_peer_update_length = ntohl(prot_anchor->hash_item_length);
			HIP_DEBUG("entry->esp_peer_update_length: %u\n",
					entry->esp_peer_update_length);

		} else if (!memcmp(&prot_anchor->anchors[0], entry->esp_peer_update_anchor,
					hash_length))
		{
			// checked that we are receiving an anchor matching the one of the last update
			HIP_DEBUG("last received esp prot update peer anchor and sent one match\n");

			// track the anchor updates by moving one anchor forward
			memcpy(entry->esp_peer_anchor, entry->esp_peer_update_anchor, hash_length);

			// set the update anchor as the peer's update anchor
			//memset(entry->esp_peer_update_anchor, 0, MAX_HASH_LENGTH);
			memcpy(entry->esp_peer_update_anchor, &prot_anchor->anchors[hash_length],
					hash_length);
			HIP_DEBUG("peer_update_anchor set\n");

			entry->esp_peer_update_length = ntohl(prot_anchor->hash_item_length);
			HIP_DEBUG("entry->esp_peer_update_length: %u\n",
					entry->esp_peer_update_length);

		} else
		{
			HIP_IFEL(memcmp(&prot_anchor->anchors[0], entry->esp_peer_anchor,
					hash_length), -1, "received unverifiable anchor\n");

			/**** received newer update for active anchor ****/

			// set the update anchor as the peer's update anchor
			//memset(entry->esp_peer_update_anchor, 0, MAX_HASH_LENGTH);
			memcpy(entry->esp_peer_update_anchor, &prot_anchor->anchors[hash_length],
					hash_length);
			HIP_DEBUG("peer_update_anchor set\n");

			entry->esp_peer_update_length = ntohl(prot_anchor->hash_item_length);
			HIP_DEBUG("entry->esp_peer_update_length: %u\n",
					entry->esp_peer_update_length);
		}

		/* @note spi is also needed in ACK packet
		 * @note like this we do NOT support multihoming
		 *
		 * XX TODO instead use the SA of the SPI looked up in TODO above
		 * when merging with UPDATE re-implementation */
		*spi = hip_hadb_get_latest_inbound_spi(entry);

// as we don't verify the hashes in the end-host, we don't have to update the SA
#if 0
		/* notify sadb about next anchor */
		HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(src_ip, dst_ip,
				&entry->hit_peer, &entry->hit_our, *spi, entry->esp_transform,
				&entry->esp_in, &entry->auth_in, 0, HIP_SPI_DIRECTION_IN, 1, entry),
				-1, "failed to notify sadb about next anchor\n");
#endif
	}

  out_err:
	return err;
}

int esp_prot_send_update_response(hip_common_t *recv_update, hip_ha_t *entry,
		in6_addr_t *src_ip, in6_addr_t *dst_ip, uint32_t spi)
{
	hip_common_t *resp_update = NULL;
	struct hip_seq *seq = NULL;
	uint16_t mask = 0;
	int err = 0;

	HIP_IFEL(!(seq = (struct hip_seq *) hip_get_param(recv_update, HIP_PARAM_SEQ)), -1,
			"SEQ not found\n");

	HIP_IFEL(!(resp_update = hip_msg_alloc()), -ENOMEM, "out of memory\n");

	entry->hadb_misc_func->hip_build_network_hdr(resp_update, HIP_UPDATE, mask,
			&recv_update->hitr, &recv_update->hits);

	/* Add ESP_INFO */
	HIP_IFEL(hip_build_param_esp_info(resp_update, entry->current_keymat_index,
			spi, spi), -1, "Building of ESP_INFO param failed\n");

	/* Add ACK */
	HIP_IFEL(hip_build_param_ack(resp_update, ntohl(seq->update_id)), -1,
			"Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(resp_update, &entry->hip_hmac_out), -1,
			"Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv_key, resp_update), -EINVAL,
			"Could not sign UPDATE. Failing\n");

	HIP_IFEL(entry->hadb_xmit_func->hip_send_pkt(src_ip, dst_ip,
			(entry->nat_mode ? hip_get_local_nat_udp_port() : 0), entry->peer_udp_port,
			resp_update, entry, 0), -1, "failed to send ANCHOR-UPDATE\n");

  out_err:
	return err;
}

/* simple transform selection: find first match in both arrays
 *
 * returns transform, UNUSED transform on error
 */
uint8_t esp_prot_select_transform(int num_transforms, uint8_t *transforms)
{
	extern int esp_prot_num_transforms;
	extern uint8_t esp_prot_transforms[NUM_TRANSFORMS];
	uint8_t transform = ESP_PROT_TFM_UNUSED;
	int err = 0, i, j;

	for (i = 0; i < esp_prot_num_transforms; i++)
	{
		for (j = 0; j < num_transforms; j++)
		{
			if (esp_prot_transforms[i] == transforms[j])
			{
				HIP_DEBUG("found matching transform: %u\n", esp_prot_transforms[i]);

				transform = esp_prot_transforms[i];
				goto out_err;
			}
		}
	}

	HIP_ERROR("NO matching transform found\n");
	transform = ESP_PROT_TFM_UNUSED;

  out_err:
	if (err)
	{
		transform = ESP_PROT_TFM_UNUSED;
	}

	return transform;
}