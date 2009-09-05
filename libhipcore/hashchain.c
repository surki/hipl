/*
 * Authors:
 *   - Tobias Heer <heer@tobibox.de> 2006
 *	 - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "hashchain.h"
#include "debug.h"
#include "ife.h"

/* these are not needed and therefore not implemented
   right now but they should be used where necessary */
#define HCHAIN_LOCK(lock_id)
#define HCHAIN_UNLOCK(lock_id)

void hchain_print(const hash_chain_t * hash_chain)
{
	hash_chain_element_t *current_element = NULL;
	int i;

	if(hash_chain)
	{
		HIP_DEBUG("Hash chain: %d\n", (int) hash_chain);

		if(hash_chain->current_element)
		{
			HIP_HEXDUMP("currrent element: ", hash_chain->current_element->hash,
					hash_chain->hash_length);
		} else
		{
			HIP_DEBUG(" -- hash chain not in use -- \n");
		}

		HIP_DEBUG("Remaining elements: %d\n", hchain_get_num_remaining(hash_chain));
		HIP_DEBUG(" - Contents:\n");

		for(current_element = hash_chain->anchor_element, i=0;
				current_element != NULL;
				current_element = current_element->next, i++)
		{
			if(hash_chain->hchain_length - hash_chain->remaining < i+1)
			{
				HIP_DEBUG("(+) element %i:\n", i + 1);
			} else
			{
				HIP_DEBUG("(-) element %i:\n", i + 1);
			}

			HIP_HEXDUMP("\t", current_element->hash, hash_chain->hash_length);
		}
	} else
	{
		HIP_DEBUG("Given hash chain was NULL!\n");
	}
}

int hchain_verify(const unsigned char * current_hash, const unsigned char * last_hash,
		hash_function_t hash_function, int hash_length, int tolerance,
		unsigned char *secret, int secret_length)
{
	/* stores intermediate hash results and allow to concat
	 * with a secret at each step */
	unsigned char buffer[MAX_HASH_LENGTH + secret_length];
	int err = 0, i;

	HIP_ASSERT(current_hash != NULL && last_hash != NULL);
	HIP_ASSERT(hash_function != NULL);
	HIP_ASSERT(hash_length > 0 && tolerance >= 0);

	// init buffer with the hash we want to verify
	memcpy(buffer, current_hash, hash_length);

	if (secret && secret_length > 0)
	{
		HIP_HEXDUMP("secret: ", secret, secret_length);
	}

	_HIP_HEXDUMP("comparing given hash: ", buffer, hash_length);
	_HIP_DEBUG("\t<->\n");
	_HIP_HEXDUMP("last known hash: ", last_hash, hash_length);

	for(i = 1; i <= tolerance; i++)
	{
		_HIP_DEBUG("Calculating round %i:\n", i);

		// add the secret
		if (secret != NULL && secret_length > 0)
			memcpy(&buffer[hash_length], secret, secret_length);

		hash_function(buffer, hash_length + secret_length, buffer);

		_HIP_HEXDUMP("comparing buffer: ", buffer, hash_length);
		_HIP_DEBUG("\t<->\n");
		_HIP_HEXDUMP("last known hash: ", last_hash, hash_length);

		// compare the elements
		if(!(memcmp(buffer, last_hash, hash_length)))
		{
			HIP_DEBUG("hash verfied\n");

			err = i;
			goto out_err;
		}
	}

	HIP_DEBUG("no matches found within tolerance: %i!\n", tolerance);

  out_err:
  	return err;
}

hash_chain_t * hchain_create(hash_function_t hash_function, int hash_length,
		int hchain_length, int hchain_hierarchy, hash_tree_t *link_tree)
{
	hash_chain_t *return_hchain = NULL;
	hash_chain_element_t *last_element = NULL, *current_element = NULL;
	/* the hash function output might be longer than needed
	 * allocate enough memory for the hash function output
	 *
	 * @note we also allow a concatenation with the link tree root here */
	unsigned char hash_value[2 * MAX_HASH_LENGTH];
	int hash_data_length = 0;
	int i, err = 0;

	HIP_ASSERT(hash_function != NULL);
	// make sure that the hash we want to use is smaller than the max output
	HIP_ASSERT(hash_length > 0 && hash_length <= MAX_HASH_LENGTH);
	HIP_ASSERT(hchain_length > 0);
	HIP_ASSERT(!(hchain_hierarchy == 0 && link_tree));

	// allocate memory for a new hash chain and set members to 0/NULL
	HIP_IFEL(!(return_hchain = (hash_chain_t *)malloc(sizeof(hash_chain_t))), -1,
			"failed to allocate memory\n");
	memset(return_hchain, 0, sizeof(hash_chain_t));

	// set the link tree if we are using different hierarchies
	if (link_tree)
	{
		return_hchain->link_tree = link_tree;
		hash_data_length = 2 * hash_length;

	} else
	{
		return_hchain->link_tree = NULL;
		hash_data_length = hash_length;
	}

	for(i = 0; i < hchain_length; i++)
	{
		// reuse memory for hash-value buffer
		//memset(hash_value, 0, MAX_HASH_LENGTH);

		// allocate memory for a new element
		HIP_IFEL(!(current_element = (hash_chain_element_t *)
				malloc(sizeof(hash_chain_element_t))), -1, "failed to allocate memory\n");
		HIP_IFEL(!(current_element->hash = (unsigned char *)malloc(hash_length)), -1,
				"failed to allocate memory\n");

		if (last_element != NULL)
		{
			// (input, input_length, output) -> output_length == 20
			HIP_IFEL(!(hash_function(hash_value, hash_data_length, hash_value)), -1,
					"failed to calculate hash\n");
			// only consider DEFAULT_HASH_LENGTH highest bytes
			memcpy(current_element->hash, hash_value, hash_length);
		} else
		{
			// random bytes as seed
			HIP_IFEL(RAND_bytes(hash_value, hash_length) <= 0, -1,
					"failed to get random bytes for source element\n");

			memcpy(current_element->hash, hash_value, hash_length);

			return_hchain->source_element = current_element;
		}

		/* overwrite parts of the calculated hash with the root in case hash is longer
		 * than what we need */
		if (link_tree)
		{
			memcpy(&hash_value[hash_length], link_tree->root, link_tree->node_length);
		}

		_HIP_HEXDUMP("element created: ", current_element->hash, hash_length);

		// list with backwards links
		current_element->next = last_element;
		last_element = current_element;
	}

	return_hchain->hash_function = hash_function;
	return_hchain->hash_length = hash_length;
	return_hchain->hchain_length = hchain_length;
	return_hchain->remaining = hchain_length;
	return_hchain->hchain_hierarchy = hchain_hierarchy;
	// hash_chain->source_element set above
	return_hchain->anchor_element  = current_element;
	return_hchain->current_element = NULL;

	HIP_DEBUG("Hash-chain with %i elements of length %i created!\n", hchain_length,
			hash_length);
	//hchain_print(return_hchain, hash_length);
	//HIP_IFEL(!(hchain_verify(return_hchain->source_element->hash, return_hchain->anchor_element->hash,
	//		hash_function, hash_length, hchain_length)), -1, "failed to verify the hchain\n");
	//HIP_DEBUG("hchain successfully verfied\n");

  out_err:
    if (err)
    {
    	// try to free all that's there
    	if (return_hchain->anchor_element)
    	{
    		// hchain was fully created
    		hchain_free(return_hchain);
    	} else
    	{
    		while (current_element)
    		{
    			last_element = current_element;
    			current_element = current_element->next;
    			free(last_element);
    		}
    		if (return_hchain->source_element)
    			free(return_hchain->source_element);
    	}

    	if (return_hchain);
    		free(return_hchain);
    	return_hchain = NULL;
    }

	return return_hchain;
}

unsigned char * hchain_pop(hash_chain_t * hash_chain)
{
	int err = 0;
	hash_chain_element_t *tmp_element = NULL;
	unsigned char *popped_hash = NULL;

	HIP_ASSERT(hash_chain != NULL);

	HCHAIN_LOCK(&hash_chain);
	if(hash_chain->current_element != NULL){
		// hash chain already in use
		if(hash_chain->current_element->next == NULL){
			HIP_ERROR("hchain_next: Hash chain depleted!\n");
			exit(1);
		} else
		{
			tmp_element = hash_chain->current_element->next;
		}
	} else
	{
		// hash_chain unused yet
		tmp_element = hash_chain->anchor_element;
	}

	popped_hash = tmp_element->hash;

	HIP_HEXDUMP("Popping hash chain element: ", popped_hash, hash_chain->hash_length);

	// hchain update
	hash_chain->current_element = tmp_element;
	hash_chain->remaining--;

  out_err:
  	HCHAIN_UNLOCK(&hash_chain);

  	if (err)
  		popped_hash = NULL;

	return popped_hash;
}

unsigned char * hchain_next(const hash_chain_t *hash_chain)
{
	unsigned char *next_hash = NULL;
	int err = 0;

	HIP_ASSERT(hash_chain != NULL);

	if(hash_chain->current_element != NULL)
	{
		// hash chain already in use
		if( hash_chain->current_element->next == NULL ){
			// hash chain depleted. return NULL
			HIP_ERROR("hchain_next: Hash chain depleted!\n");
			exit(1);
		} else
		{
			// hash chain in use: return next.
			next_hash = hash_chain->current_element->next->hash;
		}
	} else
	{
		// hash_chain is unused. return the anchor element
		next_hash = hash_chain->anchor_element->hash;
	}

	HIP_HEXDUMP("Next hash chain element: ", next_hash, hash_chain->hash_length);

  out_err:
	if (err)
		next_hash = NULL;

  	return next_hash;
}

unsigned char * hchain_current(const hash_chain_t *hash_chain)
{
	unsigned char *current_hash = NULL;
	int err = 0;

	HIP_ASSERT(hash_chain != NULL);
	HIP_ASSERT(hash_chain->current_element != NULL);

	current_hash = hash_chain->current_element->hash;

	HIP_HEXDUMP("Current hash chain element: ", current_hash, hash_chain->hash_length);

  out_err:
	if (err)
		current_hash = NULL;

	return current_hash;
}


int hchain_free(hash_chain_t *hash_chain)
{
	hash_chain_element_t *current_element = NULL;
	int err = 0;

	if( hash_chain != NULL )
	{
		for (current_element = hash_chain->anchor_element;
		    current_element != NULL;
		    current_element = current_element->next)
		{
			free(current_element->hash);
			free(current_element);
		}

		htree_free(hash_chain->link_tree);

		free(hash_chain);
	}

	HIP_DEBUG("all hash-chain elements freed\n");

  out_err:
	return err;
}

int hchain_get_num_remaining(const hash_chain_t * hash_chain)
{
	return hash_chain->remaining;
}

// previously used by lightweight hip, but not maintained
#if 0
/*************** Helper functions ********************/

/**
 * concat_n_hash_SHA - concatenate various strings and hash them
 * @hash: return value. Needs to be an empty buffer with HIP_HASH_SHA_LEN bytes memory
 * @parts: array with byte strings
 * @part_length: length of each byte string
 * @num_parts: number of parts
 * @return: zero on success, non-zero otherwise
 **/
int concat_n_hash_SHA(unsigned char* hash, unsigned char** parts, int* part_length,
		int num_parts)
{
	int total_len = 0, position = 0, i;
	unsigned char* buffer = NULL;

	/* add up the part lengths */
	for(i = 0; i < num_parts; i++){
		total_len += part_length[i];
		HIP_DEBUG("Part %d [%d]:\n",i, part_length[i]);
		HIP_HEXDUMP("", parts[i], part_length[i]);
	}
	HIP_DEBUG("%d parts, %d bytes\n", num_parts, total_len);
	/* allocate buffer space */
	buffer = malloc(total_len);
	if(buffer == NULL)
		return -1;
	/* copy the parts to the buffer */
	for(i = 0; i < num_parts; i++){
		memcpy(buffer + position, parts[i], part_length[i]);
		position += part_length[i];
	}
	HIP_HEXDUMP("Buffer: ", buffer, total_len);
	/* hash the buffer */
	HIP_SHA(buffer, total_len, hash);
	HIP_HEXDUMP("Buffer: ", buffer, total_len);

	/* free buffer memory*/
	if(buffer)
		free(buffer);
	return 0;
}
#endif
