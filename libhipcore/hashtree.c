/**
 * Authors:
 *   - Tobias Heer <heer@tobobox.de> 2008
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "hashtree.h"
#include <math.h>
#include "ife.h"
#include "debug.h"

hash_tree_t* htree_init(int num_data_blocks, int max_data_length, int node_length,
		int secret_length, hash_tree_t *link_tree, int hierarchy_level)
{
    hash_tree_t *tree = NULL;
    int i;
    int err = 0;
    double log = 0.0;

    HIP_ASSERT(num_data_blocks > 0);
    HIP_ASSERT(max_data_length > 0);
    HIP_ASSERT(node_length > 0);


    // allocate the memory for the tree
    HIP_IFEL(!(tree = (hash_tree_t *) malloc(sizeof(hash_tree_t))), -1, "failed to allocate memory\n");
    bzero(tree, sizeof(hash_tree_t));

    // check here whether leaf_set_size is a power of 2 and compute correct value if it is not
    log = log_x(2, num_data_blocks);
    if (num_data_blocks == 1)
	{
		tree->leaf_set_size = 2;

	} else if (floor(log) != ceil(log))
    {
    	tree->leaf_set_size = pow(2, ceil(log));

    } else
    {
    	tree->leaf_set_size = num_data_blocks;
    }
    HIP_DEBUG("num_data_blocks: %i\n", num_data_blocks);
    HIP_DEBUG("tree->leaf_set_size: %i\n", tree->leaf_set_size);

    HIP_IFEL(!(tree->data = (unsigned char *) malloc(max_data_length * tree->leaf_set_size)), -1,
    		"failed to allocate memory\n");
    // a binary tree with n leafs has got 2n-1 total nodes
    HIP_IFEL(!(tree->nodes = (unsigned char *) malloc(node_length * tree->leaf_set_size * 2)), -1,
    		"failed to allocate memory\n");

    // if link_tree is set, overwrite secret_length
	if (link_tree)
	{
		HIP_DEBUG("link_tree set\n");

		secret_length = link_tree->node_length;
	}

    // init array elements to 0
    bzero(tree->data, max_data_length * tree->leaf_set_size);
    bzero(tree->nodes, node_length * tree->leaf_set_size * 2);

    tree->is_open = 1;
    tree->data_position = 0;
    tree->num_data_blocks = num_data_blocks;
    tree->max_data_length = max_data_length;
    tree->node_length = node_length;
    tree->secret_length = secret_length;
    tree->depth = ceil(log_x(2, tree->leaf_set_size));
    // set the link tree
	tree->link_tree = link_tree;
	tree->hierarchy_level = hierarchy_level;

    HIP_DEBUG("tree->depth: %i\n", tree->depth);

    tree->root = NULL;

    // now we can init the secret array
    if (secret_length > 0)
	{
		HIP_IFEL(!(tree->secrets = (unsigned char *) malloc(secret_length * tree->leaf_set_size)), -1,
				"failed to allocate memory\n");

		if (link_tree)
		{
			// add the root as secret for each leaf
			for (i = 0; i < num_data_blocks; i++)
			{
				HIP_IFEL(htree_add_secret(tree, link_tree->root, secret_length, i), -1,
						"failed to add linking root as secrets\n");
			}

			bzero(&tree->secrets[num_data_blocks * secret_length], secret_length * (tree->leaf_set_size - num_data_blocks));

		} else
		{
			bzero(tree->secrets, secret_length * tree->leaf_set_size);
		}
	}

  out_err:
	if (err)
	{
		htree_free(tree);
	}

    return tree;
}

void htree_free(hash_tree_t *tree)
{
	if (tree)
	{
		htree_free(tree->link_tree);

		if (tree->nodes)
			free(tree->nodes);
		if (tree->data)
			free(tree->data);
		if (tree->secrets)
			free(tree->secrets);

		free(tree);
	}

	tree = NULL;
}

int htree_add_data(hash_tree_t *tree, char *data, int data_length)
{
	int err = 0;

	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(data != NULL);
	HIP_ASSERT(data_length > 0 && data_length <= tree->max_data_length);
    HIP_ASSERT(tree->is_open > 0);
    HIP_ASSERT(tree->data_position >= 0 && tree->data_position < tree->num_data_blocks);

    /* add the leaf the leaf-array
     *
     * @note data_length < tree->max_data_length will result in 0 bits padding
     */
    memcpy(&tree->data[tree->data_position * tree->max_data_length], data, data_length);
    // move to next free position
    tree->data_position++;
    HIP_DEBUG("added data block\n");

    // close the tree, if it is full
    if(tree->data_position == tree->num_data_blocks)
    {
    	HIP_DEBUG("tree is full! closing...\n");

    	// fill up unused leaf nodes
    	if (tree->num_data_blocks < tree->leaf_set_size)
    	{
    		HIP_IFEL(htree_add_random_data(tree, tree->leaf_set_size - tree->num_data_blocks), 1,
    				"failed to fill unused leaf nodes\n");
    	}

        tree->is_open = 0;
        tree->data_position = 0;
    }

  out_err:
    return err;
}

int htree_add_random_data(hash_tree_t *tree, int num_random_blocks)
{
	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(num_random_blocks > 0);
    HIP_ASSERT(tree->is_open > 0);
    HIP_ASSERT(tree->data_position + num_random_blocks <= tree->leaf_set_size);

    // add num_random_blocks random data to the data-array
    RAND_bytes(&tree->data[tree->data_position * tree->max_data_length],
    		num_random_blocks * tree->max_data_length);
    // move to next free position
    tree->data_position += num_random_blocks;
    HIP_DEBUG("added %i random data block(s)\n", num_random_blocks);

    // close the tree, if it is full
    if(tree->data_position >= tree->num_data_blocks)
    {
        HIP_DEBUG("tree is full! closing...\n");

    	// fill up unused leaf nodes
    	if (tree->num_data_blocks < tree->leaf_set_size)
    	{
    		RAND_bytes(&tree->data[tree->data_position * tree->max_data_length],
    				(tree->leaf_set_size - tree->data_position) * tree->max_data_length);

    		HIP_DEBUG("added %i leaf slots as padding\n", tree->leaf_set_size - tree->data_position);
    	}

        tree->is_open = 0;
        tree->data_position = 0;
    }

    return 0;
}

int htree_add_secret(hash_tree_t *tree, char *secret, int secret_length, int secret_index)
{
	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(secret != NULL);
	HIP_ASSERT(secret_length == tree->secret_length);
	HIP_ASSERT(secret_index >= 0 && secret_index < tree->num_data_blocks);
    HIP_ASSERT(tree->is_open > 0);

    memcpy(&tree->secrets[secret_index * secret_length], secret, secret_length);
    _HIP_DEBUG("added secret block\n");

    return 0;
}

int htree_add_random_secrets(hash_tree_t *tree)
{
	int err = 0;

	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(tree->secrets != NULL);
	HIP_ASSERT(tree->secret_length > 0);

	// add num_random_blocks random data to the data-array
	RAND_bytes(&tree->secrets[0],
			tree->num_data_blocks * tree->secret_length);

	HIP_DEBUG("random secrets added\n");

  out_err:
    return err;
}

int htree_calc_nodes(hash_tree_t *tree, htree_leaf_gen_t leaf_gen,
		htree_node_gen_t node_gen, htree_gen_args_t *gen_args)
{
	int level_width = 0, i, err = 0;
	// first leaf to be used when calculating next tree level in bytes
    int source_index = 0;
    int target_index = 0;
    unsigned char *secret = NULL;

	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(tree->is_open == 0);
	HIP_ASSERT(tree->data_position == 0);

    /* traverse all data blocks and create the leafs */
    HIP_DEBUG("computing leaf nodes: %i\n", tree->leaf_set_size);

    for(i = 0; i < tree->leaf_set_size; i++)
    {
    	_HIP_DEBUG("calling leaf generator function...\n");

    	// only use secrets if they are defined
		if (tree->secret_length > 0)
			secret = &tree->secrets[i * tree->secret_length];

    	// input: i-th data block -> output as i-th node-array element
    	HIP_IFEL(leaf_gen(&tree->data[i * tree->max_data_length], tree->max_data_length,
				secret, tree->secret_length,
    			&tree->nodes[i * tree->node_length], gen_args),
    			-1, "failed to calculate leaf hashes\n");
    }

    /* compute hashes on all other levels */
    HIP_DEBUG("computing intermediate nodes and root...\n");

    // the leaf level has got full width
    level_width = tree->leaf_set_size;

    // based on the current level, we are calculating the nodes for the next level
    while(level_width > 1)
    {
    	HIP_DEBUG("calculating nodes: %i\n", level_width / 2);

        /* set the target for the this level directly behind the
         * already calculated nodes of the previous level */
        target_index = source_index + (level_width * tree->node_length);

        /* we always handle two elements at once */
        for(i = 0; i < level_width; i += 2)
        {
        	_HIP_DEBUG("calling node generator function...\n");

        	HIP_IFEL(node_gen(&tree->nodes[source_index + (i * tree->node_length)],
        			&tree->nodes[source_index + ((i + 1) * tree->node_length)],
        			tree->node_length,
        			&tree->nodes[target_index + ((i / 2) * tree->node_length)],
        			gen_args), -1,
        			"failed to calculate hashes of intermediate nodes\n");

        	// this means we're calculating the root node
        	if (level_width == 2)
        		tree->root = &tree->nodes[target_index + ((i / 2) * tree->node_length)];
        }

        // next level has got half the elements
        level_width = level_width / 2;

        /* use target index of this level as new source field */
        source_index = target_index;
    }

  out_err:
    return err;
}

int htree_has_more_data(hash_tree_t *tree)
{
	return tree->data_position < tree->num_data_blocks;
}

int htree_get_next_data_offset(hash_tree_t *tree)
{
	return tree->data_position++;
}

unsigned char * htree_get_branch(hash_tree_t *tree, int data_index, unsigned char * nodes,
		int *branch_length)
{
	int tree_level = 0;
	int level_width = 0;
	int source_index = 0;
    int sibling_offset = 0;
    unsigned char * branch_nodes = NULL;
    int err = 0;

    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(data_index >= 0 && data_index < tree->num_data_blocks);

    // branch includes all elements excluding the root
    *branch_length = tree->depth * tree->node_length;

    HIP_DEBUG("tree->depth: %i\n", tree->depth);

    // use provided buffer, if available; else alloc
    if (!nodes)
    	branch_nodes = (unsigned char *) malloc(*branch_length);
    else
    	branch_nodes = nodes;

    // traverse bottom up
    level_width = tree->leaf_set_size;

    // don't include root
    while (level_width > 1)
    {
    	HIP_DEBUG("level_width: %i\n", level_width);

    	// for an uneven data_index the previous node is the sibling, else the next
    	sibling_offset = data_index & 1 ? -1 : 1;

        // copy branch-node from node-array to buffer
        memcpy(&branch_nodes[tree_level * tree->node_length],
               &tree->nodes[source_index +
               ((data_index + sibling_offset) * tree->node_length)],
               tree->node_length);

        // proceed by one level
        source_index += level_width * tree->node_length;
        level_width = level_width >> 1;
        data_index = data_index >> 1;
        tree_level++;
    }

    _HIP_HEXDUMP("verification branch: ", branch_nodes, tree->depth * tree->node_length);

  out_err:
    if (err)
    {
    	free(branch_nodes);
    	branch_nodes = NULL;
    }

    return branch_nodes;
}

unsigned char* htree_get_data(hash_tree_t *tree, int data_index,
		int *data_length)
{
	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(data_index >= 0 && data_index < tree->num_data_blocks);
	HIP_ASSERT(data_length != NULL);

	*data_length = tree->max_data_length;

	return &tree->data[data_index * tree->max_data_length];
}

unsigned char* htree_get_secret(hash_tree_t *tree, int secret_index,
		int *secret_length)
{
	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(secret_index >= 0 && secret_index < tree->num_data_blocks);
	HIP_ASSERT(secret_length != NULL);

	*secret_length = tree->secret_length;

	if (tree->secret_length > 0)
		return &tree->secrets[secret_index * tree->secret_length];
	else
		return NULL;
}

unsigned char* htree_get_root(hash_tree_t *tree, int *root_length)
{
	HIP_ASSERT(tree != NULL);

	if (tree->root)
		*root_length = tree->node_length;
	else
		*root_length = 0;

	return tree->root;
}

int htree_verify_branch(unsigned char *root, int root_length,
		unsigned char *branch_nodes, uint32_t branch_length,
		unsigned char *verify_data, int data_length, uint32_t data_index,
		unsigned char *secret, int secret_length,
		htree_leaf_gen_t leaf_gen, htree_node_gen_t node_gen,
		htree_gen_args_t *gen_args)
{
    /* space for two nodes to be hashed together */
    unsigned char buffer[2 * root_length];
    int num_nodes = 0;
    int sibling_offset = 0;
    int err = 0, i;

    HIP_ASSERT(root != NULL);
    HIP_ASSERT(root_length > 0);
    HIP_ASSERT(branch_nodes != NULL);
    HIP_ASSERT(branch_length > 0);
    HIP_ASSERT(verify_data != NULL);
    HIP_ASSERT(data_length > 0);
    HIP_ASSERT(data_index >= 0);

    if (secret_length > 0)
    	HIP_ASSERT(secret != NULL);

    num_nodes = branch_length / root_length;

    _HIP_DEBUG("num_nodes: %i\n", num_nodes);
    _HIP_DEBUG("data_index: %i\n", data_index);
    _HIP_DEBUG("data_length: %i\n", data_length);
    _HIP_HEXDUMP("verify_data: ", verify_data, data_length);
    _HIP_DEBUG("branch_length: %i\n", branch_length);
	_HIP_HEXDUMP("verify_data: ", branch_nodes, branch_length);

    // +1 as we have to calculate the leaf too
	for(i = 0; i < num_nodes + 1; i++)
	{
        HIP_DEBUG("round %i\n", i);

        // determines where to put the sibling in the buffer
        sibling_offset = data_index & 1 ? 0 : 1;

        /* in first round we have to calculate the leaf */
        if (i > 0)
        {
            /* hash previous buffer and overwrite partially */
            HIP_IFEL(node_gen(&buffer[0], &buffer[root_length], root_length,
            		&buffer[(1 - sibling_offset) * root_length], gen_args),
            		-1, "failed to calculate node hash\n");

        } else
        {
            /* hash data in order to derive the hash tree leaf */
            HIP_IFEL(leaf_gen(verify_data, data_length, secret, secret_length,
            		&buffer[(1 - sibling_offset) * root_length], gen_args), -1,
            		"failed to calculate leaf hash\n");
        }

        if (i < num_nodes)
        {
			// copy i-th branch node to the free slot in the buffer
			memcpy(&buffer[sibling_offset * root_length], &branch_nodes[i * root_length],
					root_length);

			// proceed to next level
			data_index = data_index / 2;
        }

        HIP_HEXDUMP("buffer slot 1: ", &buffer[0], root_length);
		HIP_HEXDUMP("buffer slot 2: ", &buffer[root_length], root_length);
    }

    HIP_HEXDUMP("calculated root: ", &buffer[(1 - sibling_offset) * root_length],
    		root_length);
    HIP_HEXDUMP("stored root: ", root, root_length);

	// check if the calculated root matches the stored one
    if(!memcmp(&buffer[(1 - sibling_offset) * root_length], root, root_length))
    {
        HIP_DEBUG("branch successfully verified\n");

    } else
    {
    	HIP_DEBUG("branch invalid\n");

		err = 1;
    }

  out_err:
    return err;
}

int htree_leaf_generator(unsigned char *data, int data_length,
		unsigned char *secret, int secret_length,
		unsigned char *dst_buffer, htree_gen_args_t *gen_args)
{
	int err = 0;
	unsigned char buffer[data_length + secret_length];
	unsigned char *hash_data = NULL;
	int hash_data_length = 0;

	if (secret && secret_length > 0)
	{
		memcpy(&buffer[0], data, data_length);
		memcpy(&buffer[data_length], secret, secret_length);

		hash_data = buffer;
		hash_data_length = data_length + secret_length;

	} else
	{
		hash_data = data;
		hash_data_length = data_length;
	}

	HIP_IFEL(!SHA1(hash_data, hash_data_length, dst_buffer), -1,
			"failed to calculate hash\n");

  out_err:
	return err;
}

int htree_node_generator(unsigned char *left_node, unsigned char *right_node,
		int node_length, unsigned char *dst_buffer, htree_gen_args_t *gen_args)
{
	int err = 0;

	/* the calling function has to ensure that left and right node are in
	 * subsequent memory blocks */
	HIP_IFEL(!SHA1(left_node, 2 * node_length, dst_buffer), -1,
			"failed to calculate hash\n");

  out_err:
	return err;
}

/*!
 * \brief Print all leaves of a tree.
 *
 *  Print all leaves of a tree.
 *
 * \author  Tobias Heer
 *
 * \param tree 		Pointer to the MT
 * \return 0
 */
void htree_print_data(hash_tree_t *tree)
{
    int i;

    HIP_ASSERT(tree != NULL);

    HIP_DEBUG("printing data blocks...\n");

    for(i = 0; i < tree->num_data_blocks; i++)
    {
        HIP_HEXDUMP("data block: ", &tree->data[i * tree->max_data_length],
        		tree->max_data_length);
    }
}

/*!
 * \brief Print all nodes of a tree.
 *
 *  Print all nodes of a tree.
 *
 * \author  Tobias Heer
 *
 * \param tree 		Pointer to the MT
 * \return 0
 */
void htree_print_nodes(hash_tree_t *tree)
{
    int level_width = 0;
    int target_index = 0;
    int source_index = 0;
    int i = 0, j;

    HIP_ASSERT(tree != NULL);

    level_width = tree->leaf_set_size;

    HIP_DEBUG("printing hash tree nodes...\n");

    while (level_width > 0)
    {
        i++;
        HIP_DEBUG("printing level %i:\n", i);

        target_index = source_index + (level_width * tree->node_length);

        for(i = 0; i < level_width; i++){
            HIP_HEXDUMP("node: ", &tree->nodes[source_index + (i * tree->node_length)],
            		tree->node_length);
        }

        source_index = target_index;
        level_width = level_width / 2;
    }
}

double log_x(int base, double value)
{
	return log(value) / log(base);
}
