/*
 * Authors:
 *   - Tobias Heer <heer@tobobox.de> 2006 (original hash-chain store)
 * 	- Rene Hummen <rene.hummen@rwth-aachen.de> 2008 (re-implemtation and extension)
 *
 * Licence: GNU/GPL
 */

#include "hashchain_store.h"

// sets all hash-chain store members and their dependencies to 0 / NULL
int hcstore_init(hchain_store_t *hcstore)
{
	int err = 0, i, j, g, h;

	HIP_ASSERT(hcstore != NULL);

	hcstore->num_functions = 0;

	for (i = 0; i < MAX_FUNCTIONS; i++)
	{
		hcstore->hash_functions[i] = NULL;
		hcstore->num_hash_lengths[i] = 0;

		for (j = 0; j < MAX_NUM_HASH_LENGTH; j++)
		{
			hcstore->hash_lengths[i][j] = 0;
			hcstore->hchain_shelves[i][j].num_hchain_lengths = 0;

			for (g = 0; g < MAX_NUM_HCHAIN_LENGTH; g++)
			{
				hcstore->hchain_shelves[i][j].hchain_lengths[g] = 0;
				hcstore->hchain_shelves[i][j].num_hierarchies[g] = 0;

				for (h = 0; h < MAX_NUM_HIERARCHIES; h++)
				{
					hip_ll_init(&hcstore->hchain_shelves[i][j].hchains[g][h]);
				}
			}
		}
	}

	HIP_DEBUG("hash-chain store initialized\n");

  out_err:
	return err;
}

// this does the same as init but additionally destructs the hchains
void hcstore_uninit(hchain_store_t *hcstore, int use_hash_trees)
{
	int err = 0, i, j, g, h;

	HIP_ASSERT(hcstore != NULL);

	hcstore->num_functions = 0;

	for (i = 0; i < MAX_FUNCTIONS; i++)
	{
		hcstore->hash_functions[i] = NULL;
		hcstore->num_hash_lengths[i] = 0;

		for (j = 0; j < MAX_NUM_HASH_LENGTH; j++)
		{
			hcstore->hash_lengths[i][j] = 0;
			hcstore->hchain_shelves[i][j].num_hchain_lengths = 0;

			for (g = 0; g < MAX_NUM_HCHAIN_LENGTH; g++)
			{
				hcstore->hchain_shelves[i][j].hchain_lengths[g] = 0;
				hcstore->hchain_shelves[i][j].num_hierarchies[g] = 0;

				for (h = 0; h < MAX_NUM_HIERARCHIES; h++)
				{
					if (use_hash_trees)
					{
						hip_ll_uninit(&hcstore->hchain_shelves[i][j].hchains[g][h],
														hcstore_free_htree);
					} else
					{
						hip_ll_uninit(&hcstore->hchain_shelves[i][j].hchains[g][h],
								hcstore_free_hchain);
					}
				}
			}
		}
	}

	HIP_DEBUG("hash-chain store uninitialized\n");
}

void hcstore_free_hchain(void *hchain)
{
	hchain_free((hash_chain_t *) hchain);
}

void hcstore_free_htree(void *htree)
{
	htree_free((hash_tree_t *) htree);
}

int hcstore_register_function(hchain_store_t *hcstore, hash_function_t hash_function)
{
	int err = 0, i;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(hash_function != NULL);

	// first check that there's still some space left
	HIP_IFEL(hcstore->num_functions == MAX_FUNCTIONS, -1,
			"space for function-storage is full\n");

	// also check if the function is already stored
	for (i = 0; i < hcstore->num_functions; i++)
	{
		if (hcstore->hash_functions[i] == hash_function)
		{
			HIP_DEBUG("hchain store already contains this function\n");

			err = i;
			goto out_err;
		}
	}

	// store the hash-function
	err = hcstore->num_functions;
	hcstore->hash_functions[hcstore->num_functions] = hash_function;
	hcstore->num_functions++;

	HIP_DEBUG("hash function successfully registered\n");

  out_err:
	return err;
}

int hcstore_register_hash_length(hchain_store_t *hcstore, int function_id,
		int hash_length)
{
	int err = 0, i;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length > 0);

	// first check that there's still some space left
	HIP_IFEL(hcstore->num_hash_lengths[function_id] == MAX_NUM_HASH_LENGTH, -1,
			"space for hash_length-storage is full\n");

	// also check if the hash length is already stored for this function
	for (i = 0; i < hcstore->num_hash_lengths[function_id]; i++)
	{
		if (hcstore->hash_lengths[function_id][i] == hash_length)
		{
			HIP_DEBUG("hchain store already contains this hash length\n");

			err = i;
			goto out_err;
		}
	}

	// store the hash length
	err = hcstore->num_hash_lengths[function_id];
	hcstore->hash_lengths[function_id][hcstore->num_hash_lengths[function_id]] =
				hash_length;
	hcstore->num_hash_lengths[function_id]++;

	HIP_DEBUG("hash length successfully registered\n");

  out_err:
	return err;
}

int hcstore_register_hchain_length(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length)
{
	int err = 0, i;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_lengths[function_id]);
	HIP_ASSERT(hchain_length > 0);

	// first check that there's still some space left
	HIP_IFEL(hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_lengths
			== MAX_NUM_HCHAIN_LENGTH, -1, "space for hchain_length-storage is full\n");

	// also check if the hash length is already stored for this function
	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
			num_hchain_lengths; i++)
	{
		if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_lengths[i]
			  == hchain_length)
		{
			HIP_DEBUG("hchain store already contains this hchain length\n");

			err = i;
			goto out_err;
		}
	}

	// store the hchain length
	err = hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_lengths;
	hcstore->hchain_shelves[function_id][hash_length_id].
			hchain_lengths[hcstore->hchain_shelves[function_id][hash_length_id].
			        num_hchain_lengths] = hchain_length;
	hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_lengths++;

	HIP_DEBUG("hchain length successfully registered\n");

  out_err:
	return err;
}

int hcstore_register_hchain_hierarchy(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length, int addtional_hierarchies)
{
	int item_offset = -1;
	int err = 0, i;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_lengths[function_id]);
	HIP_ASSERT(hchain_length > 0);
	HIP_ASSERT(addtional_hierarchies > 0);

	// first find the correct hchain item
	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
			num_hchain_lengths; i++)
	{
		if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_lengths[i]
				== hchain_length)
		{
			// set item_offset
			item_offset = i;

			break;
		}
	}

	// handle unregistered hchain length
	HIP_IFEL(item_offset < 0, -1, "hchain with unregistered hchain length requested\n");

	// first check that there's still enough space left
	HIP_IFEL(hcstore->hchain_shelves[function_id][hash_length_id].
			num_hierarchies[item_offset] + addtional_hierarchies >
			MAX_NUM_HIERARCHIES, -1,
			"insufficient space in hchain_hierarchies-storage\n");

	// add hierarchies
	hcstore->hchain_shelves[function_id][hash_length_id].
			num_hierarchies[item_offset] += addtional_hierarchies;
	err = hcstore->hchain_shelves[function_id][hash_length_id].
			num_hierarchies[item_offset];

	HIP_DEBUG("additional hchain hierarchies successfully registered\n");

  out_err:
	return err;
}

int hcstore_fill_item(hchain_store_t *hcstore, int hash_func_id, int hash_length_id,
		int hchain_length_id, int hierarchy_level, int update_higher_level,
		int use_hash_trees)
{
	hash_chain_t *hchain = NULL;
	hash_tree_t *htree = NULL;
	hash_tree_t *link_tree = NULL;
	hash_function_t hash_function = NULL;
	int hash_length = 0, hchain_length = 0;
	int create_hchains = 0;
	hash_chain_t *tmp_hchain = NULL;
	hash_tree_t *tmp_htree = NULL;
	unsigned char *root = NULL;
	int root_length = 0;
	int err = 0, i, j;

	// set necessary parameters
	hash_function = hcstore->hash_functions[hash_func_id];
	hash_length = hcstore->hash_lengths[hash_func_id][hash_length_id];
	hchain_length = hcstore->hchain_shelves[hash_func_id][hash_length_id].
						hchain_lengths[hchain_length_id];

	// how many hchains are missing to fill up the item again
	create_hchains = MAX_HCHAINS_PER_ITEM
		- hip_ll_get_size(&hcstore->hchain_shelves[hash_func_id][hash_length_id].
				hchains[hchain_length_id][hierarchy_level]);

	// only update if we reached the threshold or higher level update
	if ((create_hchains >= ITEM_THRESHOLD * MAX_HCHAINS_PER_ITEM) ||
			update_higher_level)
	{
		if (hierarchy_level > 0)
		{
			/* if we refill a higher level, first make sure the lower levels
			 * are full */
			HIP_IFEL((err = hcstore_fill_item(hcstore, hash_func_id, hash_length_id,
					hchain_length_id, hierarchy_level - 1, 1, use_hash_trees)) < 0, -1,
					"failed to fill item\n");
		}

		// create one hchain at a time
		for (i = 0; i < create_hchains; i++)
		{
			// hierarchy level 0 does not use any link trees
			link_tree = NULL;
			root = NULL;
			root_length = 0;

			if (hierarchy_level > 0)
			{
				// right now the trees only support hashes of 20 bytes
				HIP_ASSERT(hash_length == 20);

				// create a link tree for each hchain on level > 0
				link_tree = htree_init(MAX_HCHAINS_PER_ITEM, hash_length,
						hash_length, hash_length, NULL, 0);
				htree_add_random_secrets(link_tree);

				// lower items should be full by now
				HIP_ASSERT(hip_ll_get_size(
						&hcstore->hchain_shelves[hash_func_id][hash_length_id].
						hchains[hchain_length_id][hierarchy_level - 1]) ==
						MAX_HCHAINS_PER_ITEM);

				// add the anchors of the next lower level as data
				for (j = 0; j < MAX_HCHAINS_PER_ITEM; j++)
				{
					if (use_hash_trees)
					{
						tmp_htree = (hash_tree_t *) hip_ll_get(
								&hcstore->hchain_shelves[hash_func_id][hash_length_id].
								hchains[hchain_length_id][hierarchy_level - 1], j);

						htree_add_data(link_tree, tmp_htree->root,
								hash_length);
					} else
					{
						tmp_hchain = (hash_chain_t *) hip_ll_get(
								&hcstore->hchain_shelves[hash_func_id][hash_length_id].
								hchains[hchain_length_id][hierarchy_level - 1], j);

						htree_add_data(link_tree, tmp_hchain->anchor_element->hash,
								hash_length);
					}
				}

				// calculate the tree
				htree_calc_nodes(link_tree, htree_leaf_generator,
						htree_node_generator, NULL);
			}

			if (use_hash_trees)
			{
				// create a new htree
				HIP_IFEL(!(htree = htree_init(hchain_length, hash_length,
						hash_length, 0, link_tree, hierarchy_level)), -1,
						"failed to alloc memory or to init htree\n");
				HIP_IFEL(htree_add_random_data(htree, hchain_length), -1,
						"failed to add random secrets\n");

				// calculate the tree
				HIP_IFEL(htree_calc_nodes(htree, htree_leaf_generator,
						htree_node_generator, NULL), -1,
						"failed to calculate tree nodes\n");

				// add it as last element to have some circulation
				HIP_IFEL(hip_ll_add_last(
						&hcstore->hchain_shelves[hash_func_id][hash_length_id].
						hchains[hchain_length_id][hierarchy_level], htree), -1,
						"failed to store new htree\n");
			}
			else {
				// create a new hchain
				HIP_IFEL(!(hchain = hchain_create(hash_function, hash_length,
						hchain_length, hierarchy_level, link_tree)), -1,
						"failed to create new hchain\n");

				// add it as last element to have some circulation
				HIP_IFEL(hip_ll_add_last(
						&hcstore->hchain_shelves[hash_func_id][hash_length_id].
						hchains[hchain_length_id][hierarchy_level], hchain), -1,
						"failed to store new hchain\n");
			}

// useful for testing
#if 0
			if (hchain->link_tree)
			{
				/* if the next_hchain has got a link_tree, we need its root for
				 * the verification of the next_hchain's elements */
				root = htree_get_root(hchain->link_tree, &root_length);
			}

			if (!hchain_verify(hchain->source_element->hash,
					hchain->anchor_element->hash, hash_function,
					hash_length, hchain->hchain_length,
					root, root_length))
			{
				HIP_DEBUG("failed to verify next_hchain\n");
			}
#endif

		}

		err += create_hchains;
	}

	HIP_DEBUG("created %i hchains on hierarchy level %i\n", err, hierarchy_level);

  out_err:
	return err;
}

int hcstore_refill(hchain_store_t *hcstore, int use_hash_trees)
{
	int err = 0, i, j, g, h;

	HIP_ASSERT(hcstore != NULL);

	/* go through the store setting up information necessary for creating a new
	 * hchain in the respective item */
	for (i = 0; i < hcstore->num_functions; i++)
	{
		for (j = 0; j < hcstore->num_hash_lengths[i]; j++)
		{
			for (g = 0; g < hcstore->hchain_shelves[i][j].num_hchain_lengths; g++)
			{
				for (h = 0; h < hcstore->hchain_shelves[i][j].num_hierarchies[g]; h++)
				{
					HIP_IFEL((err = hcstore_fill_item(hcstore, i, j, g, h, 0, use_hash_trees)) < 0,
							-1, "failed to refill hchain_store\n");
				}
			}
		}
	}

	HIP_DEBUG("total amount of created hash-chains: %i\n", err);

  out_err:
	return err;
}

void * hcstore_get_hash_item(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length)
{
	// inited to invalid values
	int item_offset = -1;
	void *stored_item = NULL;
	int hierarchy_level = 0;
	int err = 0, i;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_lengths[function_id]);
	HIP_ASSERT(hchain_length > 0);

	// first find the correct hchain item
	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
			num_hchain_lengths; i++)
	{
		if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_lengths[i]
				== hchain_length)
		{
			// set item_offset
			item_offset = i;

			break;
		}
	}

	// handle unregistered hchain length or hierarchy
	HIP_IFEL(item_offset < 0, -1,
			"hchain with unregistered hchain length or hierarchy level requested\n");

	// this exclusively returns a hchain from the highest hierarchy level
	hierarchy_level = hcstore->hchain_shelves[function_id][hash_length_id].
			num_hierarchies[item_offset] - 1;

	HIP_DEBUG("hierarchy_level: %i\n", hierarchy_level);

	HIP_IFEL(!(stored_item = hip_ll_del_first(&hcstore->hchain_shelves[function_id]
	        [hash_length_id].hchains[item_offset][hierarchy_level], NULL)), -1,
			"no hchain available\n");

  out_err:
	if (err)
	{
		// TODO modify this to support htrees
		//if (stored_hchain)
		//	hchain_free(stored_hchain);

		stored_item = NULL;
	}

	return stored_item;
}

void * hcstore_get_item_by_anchor(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hierarchy_level, unsigned char *anchor, int use_hash_trees)
{
	int hash_length = 0;
	hash_chain_t *hchain = NULL;
	hash_tree_t *htree = NULL;
	void *stored_item = NULL;
	int err = 0, i, j;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_lengths[function_id]);
	HIP_ASSERT(hierarchy_level >= 0);
	HIP_ASSERT(anchor != NULL);

	hash_length = hcstore_get_hash_length(hcstore, function_id, hash_length_id);

	HIP_ASSERT(hash_length > 0);

	HIP_HEXDUMP("searching item with anchor: ", anchor, hash_length);

	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
			num_hchain_lengths; i++)
	{
		// look for the anchor at each hchain_length with the respective hierarchy level
		HIP_ASSERT(hierarchy_level < hcstore->hchain_shelves[function_id][hash_length_id].
				num_hierarchies[i]);

		for (j = 0; j < hip_ll_get_size(&hcstore->hchain_shelves[function_id]
		        [hash_length_id].hchains[i][hierarchy_level]); j++)
		{
			stored_item = hip_ll_get(&hcstore->
					hchain_shelves[function_id][hash_length_id].
					hchains[i][hierarchy_level], j);

			if (use_hash_trees)
			{
				htree = (hash_tree_t *)stored_item;

				if (!memcmp(anchor, htree->root, hash_length))
				{
					stored_item = hip_ll_del(&hcstore->
							hchain_shelves[function_id][hash_length_id].
							hchains[i][hierarchy_level], j, NULL);

					HIP_DEBUG("hash-tree matching the anchor found\n");
					//hchain_print(stored_hchain);

					goto out_err;
				}
			} else
			{
				hchain = (hash_chain_t *)stored_item;

				if (!memcmp(anchor, hchain->anchor_element->hash, hash_length))
				{
					stored_item = hip_ll_del(&hcstore->
							hchain_shelves[function_id][hash_length_id].
							hchains[i][hierarchy_level], j, NULL);

					HIP_DEBUG("hash-chain matching the anchor found\n");
					//hchain_print(stored_hchain);

					goto out_err;
				}
			}
		}
	}

	HIP_ERROR("hash-chain matching the anchor NOT found\n");
	stored_item = NULL;
	err = -1;

  out_err:
	if (err)
	{
		// TODO modify this to support htrees
		//if (stored_item)
		//	hchain_free(stored_hchain);

		stored_item = NULL;
	}

	return stored_item;
}

hash_function_t hcstore_get_hash_function(hchain_store_t *hcstore, int function_id)
{
	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);

	return hcstore->hash_functions[function_id];
}

int hcstore_get_hash_length(hchain_store_t *hcstore, int function_id, int hash_length_id)
{
	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_lengths[function_id]);

	return hcstore->hash_lengths[function_id][hash_length_id];
}
