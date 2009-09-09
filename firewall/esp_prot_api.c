/**
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * License: GNU/GPL
 *
 */

#include "esp_prot_api.h"
#include "esp_prot_fw_msg.h"
#include "firewall_defines.h"

// right now only either hchain or htree supported
//#if 0
extern const uint8_t preferred_transforms[NUM_TRANSFORMS + 1] =
		{ESP_PROT_TFM_SHA1_20_TREE, ESP_PROT_TFM_UNUSED};
//#endif

#if 0
extern const uint8_t preferred_transforms[NUM_TRANSFORMS + 1] =
		{ESP_PROT_TFM_SHA1_20, ESP_PROT_TFM_UNUSED};
#endif

// is used for hash chains and trees simultaneously
// used hash functions
const hash_function_t hash_functions[NUM_HASH_FUNCTIONS]
				   = {SHA1};
// used hash lengths
const int hash_lengths[NUM_HASH_FUNCTIONS][NUM_HASH_LENGTHS]
				   = {{20}};

// lengths of the hash structures in the stores
static const int bex_hchain_length = 16;
static const int update_hchain_lengths[NUM_UPDATE_HCHAIN_LENGTHS] = {16};

// changed for measurements
#if 0
/* preference of the supported transforms in decreasing order
 *
 * @note make sure to always include ESP_PROT_TFM_UNUSED
 */
extern const uint8_t preferred_transforms[NUM_TRANSFORMS + 1] =
		{ESP_PROT_TFM_SHA1_20, ESP_PROT_TFM_SHA1_16, ESP_PROT_TFM_MD5_16,
				ESP_PROT_TFM_SHA1_8, ESP_PROT_TFM_MD5_8, ESP_PROT_TFM_UNUSED};

extern const hash_function_t hash_functions[NUM_HASH_FUNCTIONS]
				   = {SHA1, MD5};
extern const int hash_lengths[NUM_HASH_FUNCTIONS][NUM_HASH_LENGTHS]
				   = {{8, 16, 20}, {8, 16, 0}};


static const int bex_hchain_length = 100000;
static const int update_hchain_lengths[NUM_UPDATE_HCHAIN_LENGTHS] = {100000};
#endif


/* stores the mapping transform_id -> (function_id, hash_length_id)
 *
 * @note no mapping for UNUSED transform */
esp_prot_tfm_t esp_prot_transforms[MAX_NUM_ESP_PROT_TFMS];


// this store only contains hchains used when negotiating esp protection in BEX
hchain_store_t bex_store;
// this stores hchains used during UPDATE
hchain_store_t update_store;


int esp_prot_init(void)
{
	int bex_function_id = 0, update_function_id = 0;
	int bex_hash_length_id = 0, update_hash_length_id = 0;
	int transform_id = 0;
	int use_hash_trees = 0;
	int err = 0, i, j, g;
	int activate = 1;

	HIP_DEBUG("Initializing the esp protection extension...\n");

	/* activate the extension in hipd
	 *
	 * @note this has to be set first, otherwise hipd won't understand the
	 *       anchor message */
	HIP_DEBUG("activating esp prot in hipd...\n");
	HIP_IFEL(send_esp_prot_to_hipd(activate), -1,
			"failed to activate the esp protection in hipd\n");

	/* init the hash-chain stores */
	HIP_IFEL(hcstore_init(&bex_store), -1, "failed to initialize the bex-store\n");
	HIP_IFEL(hcstore_init(&update_store), -1, "failed to initialize the update-store\n");

	HIP_DEBUG("setting up esp_prot_transforms...\n");

	// init all possible transforms
	memset(esp_prot_transforms, 0, MAX_NUM_ESP_PROT_TFMS * sizeof(esp_prot_tfm_t));
	// set available transforms to used
	for (i = 0; i < NUM_TRANSFORMS + 1; i++)
	{
		if (preferred_transforms[i] > 0)
		{
			esp_prot_transforms[preferred_transforms[i] - 1].is_used = 1;
		}
	}

	HIP_DEBUG("setting up hchain stores...\n");

	/* set up meta-info for each store and init the esp protection transforms
	 *
	 * NOTE: this only covers the hash chains!
	 */
	for (i = 0; i < NUM_HASH_FUNCTIONS; i++)
	{
		// first we have to register the function
		HIP_IFEL((bex_function_id = hcstore_register_function(&bex_store,
				hash_functions[i])) < 0, -1,
				"failed to register hash-function in bex-store\n");
		HIP_IFEL((update_function_id = hcstore_register_function(&update_store,
				hash_functions[i])) < 0, -1,
				"failed to register hash-function in update-store\n");

		// ensure the 2 stores are in sync
		HIP_ASSERT(bex_function_id == update_function_id);

		for (j = 0; j < NUM_HASH_LENGTHS; j++)
		{
			if (hash_lengths[i][j] > 0)
			{
				// ensure correct boundaries
				HIP_ASSERT(transform_id < NUM_TRANSFORMS);

				// now we can register the hash lengths for this function
				HIP_IFEL((bex_hash_length_id = hcstore_register_hash_length(&bex_store,
						bex_function_id, hash_lengths[i][j])) < 0, -1,
						"failed to register hash-length in bex-store\n");
				HIP_IFEL((update_hash_length_id = hcstore_register_hash_length(
						&update_store, update_function_id, hash_lengths[i][j])) < 0, -1,
						"failed to register hash-length in update-store\n");

				// ensure the 2 stores are in sync
				HIP_ASSERT(bex_hash_length_id == update_hash_length_id);

				// store these IDs in the transforms array
				HIP_DEBUG("adding transform: %i\n", transform_id + 1);

				if (esp_prot_transforms[transform_id].is_used)
				{
					esp_prot_transforms[transform_id].hash_func_id = bex_function_id;
					esp_prot_transforms[transform_id].hash_length_id = bex_hash_length_id;
				}
				// register the same hash function and hash length for the htree
				if (esp_prot_transforms[transform_id + ESP_PROT_TFM_HTREE_OFFSET].is_used)
				{
					use_hash_trees = 1;

					esp_prot_transforms[transform_id + ESP_PROT_TFM_HTREE_OFFSET]
					                    .hash_func_id = bex_function_id;
					esp_prot_transforms[transform_id + ESP_PROT_TFM_HTREE_OFFSET]
					                    .hash_length_id = bex_hash_length_id;
				}

				transform_id++;

				/* also register the the hchain lengths for this function and this
				 * hash length */
				HIP_IFEL(hcstore_register_hchain_length(&bex_store, bex_function_id,
						bex_hash_length_id, bex_hchain_length) < 0, -1,
						"failed to register hchain-length in bex-store\n");
				/* register number of hierarchies in BEX-store */
				HIP_IFEL(hcstore_register_hchain_hierarchy(&bex_store, bex_function_id,
						bex_hash_length_id, bex_hchain_length, NUM_BEX_HIERARCHIES) < 0,
						-1, "failed to register hchain-hierarchy in bex-store\n");

				for (g = 0; g < NUM_UPDATE_HCHAIN_LENGTHS; g++)
				{
					HIP_IFEL(hcstore_register_hchain_length(&update_store,
							update_function_id, update_hash_length_id,
							update_hchain_lengths[g]) < 0, -1,
							"failed to register hchain-length in update-store\n");
					HIP_IFEL(hcstore_register_hchain_hierarchy(&update_store,
							update_function_id, update_hash_length_id,
							update_hchain_lengths[g], NUM_UPDATE_HIERARCHIES) < 0,
							-1, "failed to register hchain-hierarchy in update-store\n");
				}
			} else
			{
				// for this hash-function we have already processed all hash-lengths
				break;
			}
		}
	}

	/* finally we can fill the stores */
	HIP_DEBUG("filling BEX store...\n");
	HIP_IFEL(hcstore_refill(&bex_store, use_hash_trees) < 0, -1,
			"failed to fill the bex-store\n");
	HIP_DEBUG("filling update store...\n");
	HIP_IFEL(hcstore_refill(&update_store, use_hash_trees) < 0, -1,
			"failed to fill the update-store\n");

	/* ...and send the bex-store anchors to hipd */
	HIP_IFEL(send_bex_store_update_to_hipd(&bex_store, use_hash_trees), -1,
		"failed to send bex-store update to hipd\n");

  out_err:
  	return err;
}

int esp_prot_uninit()
{
	int err = 0, i;
	int activate = 0;
	int use_hash_trees = 0;

	for (i = 0; i < NUM_TRANSFORMS + 1; i++)
	{
		if (preferred_transforms[i] > ESP_PROT_TFM_HTREE_OFFSET)
		{
			use_hash_trees = 1;
			break;
		}
	}

	// uninit hcstores
	hcstore_uninit(&bex_store, use_hash_trees);
	hcstore_uninit(&update_store, use_hash_trees);
	// ...and set transforms to 0/NULL
	memset(esp_prot_transforms, 0, sizeof(uint8_t) * sizeof(esp_prot_tfm_t));

	// also deactivate the extension in hipd
	HIP_IFEL(send_esp_prot_to_hipd(activate), -1,
			"failed to activate the esp protection in hipd\n");

  out_err:
	return err;
}

int esp_prot_sa_entry_set(hip_sa_entry_t *entry, uint8_t esp_prot_transform,
		uint32_t hash_item_length, uint16_t esp_num_anchors,
		unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH], int update)
{
	int hash_length = 0, err = 0;
	int use_hash_trees = 0;
	hash_chain_t *hchain = NULL;
	hash_tree_t *htree = NULL;
	uint16_t i;

	HIP_ASSERT(entry != 0);
	HIP_ASSERT(entry->direction == 1 || entry->direction == 2);

	// only set up the anchor or hchain, if esp extension is used
	if (esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		// if the extension is used, an anchor should be provided by the peer
		HIP_ASSERT(esp_prot_anchors != NULL);

		// check if we should use hash trees
		if (esp_prot_transform > ESP_PROT_TFM_HTREE_OFFSET)
			use_hash_trees = 1;

		// distinguish the creation of a new entry and the update of an old one
		if (update)
		{
			HIP_DEBUG("updating ESP prot parameters...\n");

			// check if current and next transform are matching
			HIP_IFEL(entry->esp_prot_transform != esp_prot_transform, 1,
					"transform for active esp prot and next do NOT match\n");
			HIP_DEBUG("found matching esp prot transforms\n");

			// we have to get the hash_length
			hash_length = esp_prot_get_hash_length(esp_prot_transform);

			entry->update_item_length = hash_item_length;

			/* only set up hash chains or anchors for outbound direction */
			if (entry->direction == HIP_SPI_DIRECTION_OUT)
			{
				// update hchains for outbound SA
				for (i = 0; i < esp_num_anchors; i++)
				{
					{
						/* esp_prot_sadb_maintenance should have already set up the next_hchain,
						 * check that the anchor belongs to the one that is set */
						if (use_hash_trees)
						{
							htree = (hash_tree_t *)entry->next_hash_items[i];

							HIP_IFEL(memcmp(&esp_prot_anchors[i][0], htree->root, hash_length), -1,
									"received a non-matching root from hipd for next_hchain\n");
						} else
						{
							hchain = (hash_chain_t *)entry->next_hash_items[i];

							HIP_IFEL(memcmp(&esp_prot_anchors[i][0], hchain_get_anchor(hchain),
									hash_length), -1,
									"received a non-matching anchor from hipd for next_hchain\n");
						}

						entry->update_item_acked[i] = 1;
					}
				}

				HIP_DEBUG("next_hchain-anchors and received anchors from hipd match\n");
			}

		} else
		{
			HIP_DEBUG("setting up ESP prot parameters for new entry...\n");

			// set the esp protection transform
			entry->esp_prot_transform = esp_prot_transform;
			HIP_DEBUG("entry->esp_prot_transform: %u\n", entry->esp_prot_transform);

			entry->active_item_length = hash_item_length;

			/* only set up hash chains or anchors for outbound direction */
			if (entry->direction == HIP_SPI_DIRECTION_OUT)
			{
				// set hchains for outbound SA
				for (i = 0; i < NUM_PARALLEL_CHAINS; i++)
				{
					if (i < esp_num_anchors)
					{
						HIP_IFEL(!(entry->active_hash_items[i] =
							esp_prot_get_bex_item_by_anchor(&esp_prot_anchors[i][0], esp_prot_transform)),
							-1, "corresponding hchain not found\n");

					} else
					{
						entry->active_hash_items[i] = NULL;
					}

					// pre-set acks of hchain updates
					entry->update_item_acked[i] = 0;
				}

				// parallel chains are used in round-robin fashion, set index to first chain now
				entry->last_used_chain = 0;

				// init ring buffer
				memset(&entry->hash_buffer, 0, RINGBUF_SIZE * ((MAX_HASH_LENGTH * sizeof(unsigned char)) + sizeof(uint32_t)));
				entry->next_free = 0;
			}
		}
	} else
	{
		HIP_DEBUG("no esp prot related params set, as UNUSED\n");

		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
  	return err;
}


void esp_prot_sa_entry_free(hip_sa_entry_t *entry)
{
	int i;

#if 0
	if (entry->active_hash_element)
		free(entry->active_hash_element);
	if (entry->next_hash_element)
		free(entry->next_hash_element);
#endif
	if (entry->esp_prot_transform > ESP_PROT_TFM_HTREE_OFFSET)
	{
		for (i = 0; i < NUM_PARALLEL_CHAINS; i++)
		{
			if (entry->active_hash_items[i])
				htree_free((hash_tree_t *)entry->active_hash_items[i]);
			if (entry->next_hash_items[i])
				htree_free((hash_tree_t *)entry->next_hash_items[i]);
		}
	} else
	{
		for (i = 0; i < NUM_PARALLEL_CHAINS; i++)
		{
			if (entry->active_hash_items[i])
				hchain_free((hash_chain_t *)entry->active_hash_items[i]);
			if (entry->next_hash_items[i])
				hchain_free((hash_chain_t *)entry->next_hash_items[i]);
		}
	}
}

int esp_prot_cache_packet_hash(unsigned char *esp_packet, uint16_t esp_length, hip_sa_entry_t *entry)
{
	int err = 0;
	hash_function_t hash_function = NULL;
	int hash_length = 0;
	int esp_offset = 0;

	// check whether cumulative authentication is active
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED && !(entry->esp_prot_transform > ESP_PROT_TFM_HTREE_OFFSET)
			&& CUMULATIVE_AUTH)
	{
		hash_length = esp_prot_get_hash_length(entry->esp_prot_transform);
		hash_function = esp_prot_get_hash_function(entry->esp_prot_transform);

		HIP_DEBUG("adding IPsec packet with SEQ %u to ring buffer at position %u...\n", entry->sequence - 1, entry->next_free);

		// hash packet and store it
		hash_function(esp_packet, esp_length, entry->hash_buffer[entry->next_free].packet_hash);
		entry->hash_buffer[entry->next_free].seq = entry->sequence - 1;

		HIP_HEXDUMP("added packet hash: ", entry->hash_buffer[entry->next_free].packet_hash, hash_length);

		entry->next_free = (entry->next_free + 1) % RINGBUF_SIZE;
	}

  out_err:
	return err;
}

int esp_prot_add_packet_hashes(unsigned char *out_hash, int *out_length, hip_sa_entry_t *entry)
{
	int err = 0, i, j;
	int repeat = 1;
	int hash_length = 0;
	uint32_t chosen_el[NUM_LINEAR_ELEMENTS + NUM_RANDOM_ELEMENTS];
	uint32_t rand_el = 0;
	int item_length = 0;

	HIP_ASSERT(RINGBUF_SIZE >= NUM_LINEAR_ELEMENTS + NUM_RANDOM_ELEMENTS);

	// check whether cumulative authentication is active
	if (CUMULATIVE_AUTH)
	{
		hash_length = esp_prot_get_hash_length(entry->esp_prot_transform);
		item_length = hash_length + sizeof(uint32_t);

		// first add linearly
		for (i = 1; i <= NUM_LINEAR_ELEMENTS; i++)
		{
			memcpy(&out_hash[*out_length], &entry->hash_buffer[(entry->next_free - i) % RINGBUF_SIZE], item_length);

			HIP_HEXDUMP("added packet SEQ and hash: ", &out_hash[*out_length], hash_length + sizeof(uint32_t));

			*out_length += item_length;

			// mark element as used for this packet transmission
			chosen_el[i - 1] = entry->next_free - i;
		}

		// then add randomly
		for (i = 0; i < NUM_RANDOM_ELEMENTS; i++)
		{
			while (repeat)
			{
				repeat = 0;

				// draw random element
				RAND_bytes((unsigned char *) &rand_el, sizeof(uint32_t));
				rand_el = rand_el % RINGBUF_SIZE;

				for (j = 0; j < NUM_LINEAR_ELEMENTS + i; j++)
				{
					if (rand_el == chosen_el[j])
					{
						repeat = 1;
						break;
					}
				}
			}

			memcpy(&out_hash[*out_length], &entry->hash_buffer[rand_el], hash_length + item_length);
			*out_length += item_length;

			HIP_HEXDUMP("added packet SEQ and hash: ", &entry->hash_buffer[entry->next_free], item_length);

			// mark element as used for this packet transmission
			chosen_el[NUM_LINEAR_ELEMENTS + i] = rand_el;
		}
	}

  out_err:
	return err;
}

int esp_prot_add_hash(unsigned char *out_hash, int *out_length, hip_sa_entry_t *entry)
{
	unsigned char *tmp_hash = NULL;
	int err = 0;
	int use_hash_trees = 0;
	uint32_t htree_index = 0;
	uint32_t htree_index_net = 0;
	hash_chain_t *hchain = NULL;
	hash_tree_t *htree = NULL;
	int branch_length = 0;
	int root_length = 0;

	HIP_ASSERT(out_hash != NULL);
	HIP_ASSERT(*out_length == 0);
	HIP_ASSERT(entry != NULL);

	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		HIP_DEBUG("adding hash chain element to outgoing packet...\n");

		// determine whether to use htrees or hchains
		if (entry->esp_prot_transform > ESP_PROT_TFM_HTREE_OFFSET)
		{
			// there should be no parallel hash trees -> index 0
			htree = (hash_tree_t *)entry->active_hash_items[0];

			// only add elements if not depleted yet
			if (htree_has_more_data(htree))
			{
				// get the index of the next hash token and add it
				htree_index = htree_get_next_data_offset(htree);
				htree_index_net = htonl(htree_index);
				memcpy(out_hash, &htree_index_net, sizeof(uint32_t));

				// get hash token and add it - only returns a reference into the array
				tmp_hash = htree_get_data(htree, htree_index, out_length);
				memcpy(out_hash + sizeof(uint32_t), tmp_hash, *out_length);

				*out_length += sizeof(uint32_t);

				// add the verification branch - directly memcpy elements into packet
				HIP_IFEL(!htree_get_branch(htree, htree_index, out_hash + *out_length,
						&branch_length), -1, "failed to get verification branch\n");

				*out_length += branch_length;

				HIP_DEBUG("htree_index: %u\n", htree_index);
				HIP_DEBUG("htree_index (packet): %u\n", *(uint32_t *)out_hash);

			} else
			{
				HIP_DEBUG("htree depleted, dropping packet\n");

				err = 1;
			}

		} else
		{
			if (PARALLEL_CHAINS)
			{
				hchain = (hash_chain_t *)entry->active_hash_items[entry->last_used_chain];

				HIP_DEBUG("entry->last_used_chain: %i\n", entry->last_used_chain);

				entry->last_used_chain = (entry->last_used_chain + 1) % NUM_PARALLEL_CHAINS;

			} else
			{
				hchain = (hash_chain_t *)entry->active_hash_items[0];
			}

			// first determine hash length
			*out_length = esp_prot_get_hash_length(entry->esp_prot_transform);

			// only add elements if not depleted yet
			if (hchain_get_num_remaining(hchain))
			{
				HIP_IFEL(!(tmp_hash = hchain_pop(hchain)), -1,
						"unable to retrieve hash element from hash-chain\n");

				/* don't send anchor as it could be known to third party
				 * -> other end-host will not accept it */
				if (!memcmp(tmp_hash, hchain_get_anchor(hchain),
						*out_length))
				{
					HIP_DEBUG("this is the hchain anchor -> get next element\n");

					// get next element
					HIP_IFEL(!(tmp_hash = hchain_pop(hchain)), -1,
							"unable to retrieve hash element from hash-chain\n");
				}

				memcpy(out_hash, tmp_hash, *out_length);

				// adding hashes for cumulative authentication
				HIP_IFEL(esp_prot_add_packet_hashes(out_hash, out_length, entry), -1,
						"failed to add tokens for cumulative authentication\n");

			} else
			{
				HIP_DEBUG("hchain depleted, dropping packet\n");

				err = 1;
			}
		}

		HIP_DEBUG("hash length is %i\n", *out_length);
		HIP_HEXDUMP("added esp protection hash: ", out_hash, *out_length);

	} else
	{
		HIP_DEBUG("esp prot extension UNUSED, not adding hash\n");
	}

  out_err:
    return err;
}

/* verifies received hchain-elements - should only be called with ESP
 * extension in use
 *
 * returns 0 - ok or UNUSED, < 0 err, > 0 anchor change */
int esp_prot_verify_hchain_element(hash_function_t hash_function, int hash_length,
		unsigned char *active_anchor, unsigned char *next_anchor,
		unsigned char *hash_value, int tolerance, unsigned char *active_root,
		int active_root_length, unsigned char *next_root, int next_root_length)
{
	uint32_t tmp_distance = 0;
	int err = 0;

	HIP_ASSERT(hash_function != NULL);
	HIP_ASSERT(hash_length > 0);
	HIP_ASSERT(active_anchor != NULL);
	// next_anchor may be NULL
	HIP_ASSERT(hash_value != NULL);
	HIP_ASSERT(tolerance >= 0);

	HIP_DEBUG("hash length is %i\n", hash_length);
	HIP_HEXDUMP("active_anchor: ", active_anchor, hash_length);
	HIP_DEBUG("hchain element of incoming packet to be verified:\n");
	HIP_HEXDUMP("-> ", hash_value, hash_length);

	HIP_DEBUG("checking active_anchor...\n");

	if (active_root)
		HIP_HEXDUMP("active_root: ", active_root, active_root_length);

	if (tmp_distance = hchain_verify(hash_value, active_anchor, hash_function,
			hash_length, tolerance, active_root, active_root_length))
	{
		// this will allow only increasing elements to be accepted
		memcpy(active_anchor, hash_value, hash_length);

		HIP_DEBUG("hash matches element in active hash-chain\n");

	} else
	{
		if (next_anchor != NULL)
		{
			/* there might still be a chance that we have to switch to the
			 * next hchain implicitly */
			HIP_DEBUG("checking next_anchor...\n");
			HIP_HEXDUMP("next_anchor: ", next_anchor, hash_length);

			if (next_root)
			{
				HIP_HEXDUMP("next_root: ", next_root, next_root_length);
			}

			if (tmp_distance = hchain_verify(hash_value, next_anchor, hash_function,
					hash_length, tolerance, next_root, next_root_length))
			{
				HIP_DEBUG("hash matches element in next hash-chain\n");

				// we have to notify about the change
				err = 1;

			} else
			{
				HIP_DEBUG("neither active nor update hchain could verify hash element\n");

				// handle incorrect elements -> drop packet
				err = -1;
				goto out_err;
			}

		} else
		{
			HIP_DEBUG("active hchain could not verify hash element, update hchain not set\n");

			// handle incorrect elements -> drop packet
			err = -1;
			goto out_err;
		}
	}

  out_err:
	if (err == -1)
	{
		HIP_DEBUG("INVALID hash-chain element!\n");
	}

    return err;
}

int esp_prot_verify_htree_element(hash_function_t hash_function, int hash_length,
		uint32_t hash_tree_depth, unsigned char *active_root, unsigned char *next_root,
		unsigned char *active_uroot, int active_uroot_length, unsigned char *next_uroot,
		int next_uroot_length, unsigned char *hash_value)
{
	int err = 0;
	uint32_t data_index = 0;
	uint32_t test1 = 0;
	uint32_t test2 = 0;

	HIP_ASSERT(hash_function != NULL);
	HIP_ASSERT(hash_length > 0);
	HIP_ASSERT(hash_tree_depth > 0);
	HIP_ASSERT(active_root != NULL);
	// next_root may be NULL
	HIP_ASSERT(hash_value != NULL);

	HIP_DEBUG("checking active_root...\n");

#ifdef CONFIG_HIP_OPENWRT
	data_index = *((uint32_t *)hash_value);
#else
	data_index = ntohl(*((uint32_t *)hash_value));
#endif

	if (err = htree_verify_branch(active_root, hash_length,
				hash_value + (sizeof(uint32_t) + hash_length),
				hash_tree_depth * hash_length, hash_value + sizeof(uint32_t),
				hash_length, data_index, active_uroot,
				active_uroot_length, htree_leaf_generator, htree_node_generator,
				NULL))
	{
		// err > 0 denotes invalid branch -> try next_root
		HIP_IFEL(err < 0, -1, "failure during tree verification\n");

		HIP_DEBUG("active htree could not verify hash element\n");

		if (next_root)
		{
			HIP_IFEL((err = htree_verify_branch(next_root, hash_length,
					hash_value + (sizeof(uint32_t) + hash_length),
					hash_tree_depth * hash_length, hash_value + sizeof(uint32_t),
					hash_length, *((uint32_t *)hash_value), next_uroot,
					next_uroot_length, htree_leaf_generator, htree_node_generator,
					NULL)) < 0, -1, "failure during tree verification\n");

			if (err)
			{
				HIP_DEBUG("neither active nor update htree could verify hash element\n");

				err = -1;
				goto out_err;

			} else
			{
				HIP_DEBUG("branch successfully verified with next_htree\n");

				// notify about change
				err = 1;
				goto out_err;
			}
		} else
		{
			HIP_DEBUG("active htree could not verify hash element, update htree not set\n");

			err = -1;
			goto out_err;
		}

	} else
	{
		HIP_DEBUG("branch successfully verified with active_htree\n");
	}

  out_err:
	return err;
}

esp_prot_tfm_t * esp_prot_resolve_transform(uint8_t transform)
{
	HIP_DEBUG("resolving transform: %u\n", transform);

	if (transform > ESP_PROT_TFM_UNUSED && esp_prot_transforms[transform - 1].is_used)
		return &esp_prot_transforms[transform - 1];
	else
		return NULL;
}

hash_function_t esp_prot_get_hash_function(uint8_t transform)
{
	esp_prot_tfm_t *prot_transform = NULL;
	hash_function_t hash_function = NULL;
	int err = 0;

	HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(transform)), 1,
			"tried to resolve UNUSED or UNKNOWN transform\n");

	// as both stores' meta-data are in sync, we can use any
	hash_function = hcstore_get_hash_function(&bex_store, prot_transform->hash_func_id);

  out_err:
	if (err)
		hash_function = NULL;

	return hash_function;
}

int esp_prot_get_hash_length(uint8_t transform)
{
	esp_prot_tfm_t *prot_transform = NULL;
	int err = 0;

	// return length 0 for UNUSED transform
	HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(transform)), 0,
			"tried to resolve UNUSED transform\n");

	// as both stores' meta-data are in sync, we can use any
	err = hcstore_get_hash_length(&bex_store, prot_transform->hash_func_id,
			prot_transform->hash_length_id);

  out_err:
	return err;
}

void * esp_prot_get_bex_item_by_anchor(unsigned char *item_anchor,
		uint8_t transform)
{
	esp_prot_tfm_t *prot_transform = NULL;
	void *return_item = NULL;
	int use_hash_trees = 0;
	int err = 0;

	HIP_ASSERT(item_anchor != NULL);

	HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(transform)), 1,
			"tried to resolve UNUSED or UNKNOWN transform\n");

	if (transform > ESP_PROT_TFM_HTREE_OFFSET)
		use_hash_trees = 1;

	HIP_IFEL(!(return_item = hcstore_get_item_by_anchor(&bex_store,
			prot_transform->hash_func_id, prot_transform->hash_length_id,
			NUM_BEX_HIERARCHIES - 1, item_anchor, use_hash_trees)),
			-1, "unable to retrieve hchain from bex store\n");

	// refill bex-store if necessary
	HIP_IFEL((err = hcstore_refill(&bex_store, use_hash_trees)) < 0, -1,
			"failed to refill the bex-store\n");

	// some elements have been added, tell hipd about them
	if (err > 0)
	{
		HIP_IFEL(send_bex_store_update_to_hipd(&bex_store, use_hash_trees), -1,
				"unable to send bex-store update to hipd\n");

		// this is not an error condition
		err = 0;
	}

  out_err:
	if (err)
		return_item = NULL;

  	return return_item;
}

int esp_prot_get_data_offset(hip_sa_entry_t *entry)
{
	int offset = sizeof(struct hip_esp);

	HIP_ASSERT(entry != NULL);

	if (entry->esp_prot_transform > ESP_PROT_TFM_HTREE_OFFSET)
	{
		HIP_DEBUG("entry->active_item_length: %u\n", entry->active_item_length);

		offset += sizeof(uint32_t) +
				((ceil(log_x(2, entry->active_item_length)) + 1) * esp_prot_get_hash_length(entry->esp_prot_transform));
	} else
	{
		offset += esp_prot_get_hash_length(entry->esp_prot_transform);

		if (CUMULATIVE_AUTH)
		{
			offset += ((esp_prot_get_hash_length(entry->esp_prot_transform) + sizeof(uint32_t))
					* (NUM_LINEAR_ELEMENTS + NUM_RANDOM_ELEMENTS));
		}
	}

	HIP_DEBUG("offset: %i\n", offset);

	return offset;
}

int esp_prot_sadb_maintenance(hip_sa_entry_t *entry)
{
	esp_prot_tfm_t *prot_transform = NULL;
	int soft_update = 0, err = 0;
	int anchor_length = 0;
	int anchor_offset[NUM_PARALLEL_CHAINS];
	unsigned char *anchors[NUM_PARALLEL_CHAINS];
	hash_tree_t *htree = NULL;
	hash_chain_t *hchain = NULL;
	hash_tree_t *link_trees[NUM_PARALLEL_CHAINS];
	int hash_item_length = 0;
	int remaining = 0, i;
	int threshold = 0;
	int use_hash_trees = 0;
	int hierarchy_level = 0;
	int num_parallel_hchains = 0;

	HIP_ASSERT(entry != NULL);

	// first check the extension is used for this connection
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		// distinguish different number of conveyed anchors by authentication mode
		if (PARALLEL_CHAINS)
			num_parallel_hchains = NUM_PARALLEL_CHAINS;
		else
			num_parallel_hchains = 1;

		/* now check whether first hchains has got sufficient elements
		 * -> assume same for all parallel hchains (as round-robin) */
		if (entry->esp_prot_transform > ESP_PROT_TFM_HTREE_OFFSET)
		{
			use_hash_trees = 1;
			htree = (hash_tree_t *)entry->active_hash_items[0];
			hash_item_length = htree->num_data_blocks;

			remaining = htree->num_data_blocks - htree->data_position;
			threshold = htree->num_data_blocks * REMAIN_HASHES_TRESHOLD;

		} else
		{
			hchain = (hash_chain_t *)entry->active_hash_items[0];
			hash_item_length = hchain->hchain_length;

			remaining = hchain_get_num_remaining(hchain);
			threshold = hchain->hchain_length * REMAIN_HASHES_TRESHOLD;
		}

		/* ensure that the next hash-items are set up before the active ones
		 * deplete */
		if (!entry->next_hash_items[0] && remaining <= threshold)
		{

			// TODO ensure we stay in the same update mode!!!

			/* we need to update all parallel hash chains before the active
			 * chains deplete */
			for (i = 0; i < num_parallel_hchains; i++)
			{
				if (use_hash_trees)
				{
					htree = (hash_tree_t *)entry->active_hash_items[i];

					link_trees[i] = htree->link_tree;
					hierarchy_level = htree->hierarchy_level;

				} else
				{
					hchain = (hash_chain_t *)entry->active_hash_items[i];

					link_trees[i] = hchain->link_tree;
					hierarchy_level = hchain->hchain_hierarchy;
				}

				HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(entry->esp_prot_transform)),
						1, "tried to resolve UNUSED transform\n");

				/* soft-update vs. PK-update
				 * -> do a soft-update */
				if (link_trees[i])
				{
					HIP_DEBUG("found link_tree, looking for soft-update anchor...\n");

					/* several hash-trees are linking to the same anchors, so it
					 * might happen that an anchor is already used */
					while (htree_has_more_data(link_trees[i]))
					{
						// get the next hchain from the link_tree
						anchor_offset[i] = htree_get_next_data_offset(link_trees[i]);
						anchors[i] = htree_get_data(link_trees[i], anchor_offset[i], &anchor_length);

						// set next_hash_item, if linked one is available
						if (entry->next_hash_items[i] = hcstore_get_item_by_anchor(
								&update_store, prot_transform->hash_func_id, prot_transform->hash_length_id,
								hierarchy_level - 1, anchors[i], use_hash_trees))
						{
							HIP_DEBUG("linked hchain found in store, soft-update\n");

							soft_update = 1;
							break;
						}
					}
				}

				// no link_tree or empty link_tree, therefore get random hchain
				if (!soft_update)
				{
					HIP_DEBUG("no link_tree or empty link_tree, picking random hchain\n");

					/* set next hchain with DEFAULT_HCHAIN_LENGTH_ID of highest hierarchy
					 * level
					 *
					 * @note this needs to be extended when implementing usage of different
					 *       hchain lengths
					 */
					HIP_IFEL(!(entry->next_hash_items[i] = hcstore_get_hash_item(&update_store,
							prot_transform->hash_func_id, prot_transform->hash_length_id,
							update_hchain_lengths[DEFAULT_HCHAIN_LENGTH_ID])),
							-1, "unable to retrieve hchain from store\n");

					if (use_hash_trees)
					{
						htree = (hash_tree_t *)entry->next_hash_items[i];
						anchors[i] = htree->root;

					} else
					{
						hchain = (hash_chain_t *)entry->next_hash_items[i];
						anchors[i] = hchain_get_anchor(hchain);
					}
				}

				// anchor needs to be acknowledged
				entry->update_item_acked[i] = 0;
			}

			// finally issue UPDATE message to be sent for combined hchain update
			HIP_IFEL(send_trigger_update_to_hipd(entry, anchors, hash_item_length, soft_update,
					anchor_offset, link_trees), -1, "unable to trigger update at hipd\n");

			// refill update-store
			HIP_IFEL((err = hcstore_refill(&update_store, use_hash_trees)) < 0, -1,
					"failed to refill the update-store\n");
		}

		/* activate next hchains if current ones are depleted and update has been acked
		 * -> assume first hchain represents all parallel ones */
		if (entry->next_hash_items[0] && entry->update_item_acked[0] && remaining == 0)
		{
			for (i = 0; i < num_parallel_hchains; i++)
			{
				// this will free all linked elements in the hchain
				if (use_hash_trees)
				{
					htree_free((hash_tree_t *)entry->active_hash_items[i]);
				} else
				{
					hchain_free((hash_chain_t *)entry->active_hash_items[i]);
				}

				HIP_DEBUG("changing to next_hchain\n");
				entry->active_hash_items[i] = entry->next_hash_items[i];
				entry->next_hash_items[i] = NULL;
			}

			/* notify hipd about the switch to the next hash-chain for
			 * consistency reasons */
			HIP_IFEL(send_anchor_change_to_hipd(entry), -1,
					"unable to notify hipd about hchain change\n");
		}
	}

  out_err:
    return err;
}
