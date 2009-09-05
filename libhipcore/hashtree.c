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

    // check here that it's a power of 2
    HIP_ASSERT(num_data_blocks > 0 &&
    		floor(log_x(2, num_data_blocks)) == ceil(log_x(2, num_data_blocks)));
    HIP_ASSERT(max_data_length > 0);
    HIP_ASSERT(node_length > 0);

    // allocate the memory for the tree
    HIP_IFEL(!(tree = (hash_tree_t *) malloc(sizeof(hash_tree_t))), -1, "failed to allocate memory\n");
    bzero(tree, sizeof(hash_tree_t));

    HIP_IFEL(!(tree->data = (unsigned char *) malloc(num_data_blocks * max_data_length)), -1,
    		"failed to allocate memory\n");
    // a binary tree with n leafs has got 2n-1 total nodes
    HIP_IFEL(!(tree->nodes = (unsigned char *) malloc(node_length * num_data_blocks * 2)), -1,
    		"failed to allocate memory\n");

    // if link_tree is set, overwrite secret_length
	if (link_tree)
	{
		HIP_DEBUG("link_tree set\n");

		secret_length = link_tree->node_length;
	}

    // init array elements to 0
    bzero(tree->data, num_data_blocks * max_data_length);
    bzero(tree->nodes, node_length * num_data_blocks * 2);

    tree->is_open = 1;
    tree->data_position = 0;
    tree->num_data_blocks = num_data_blocks;
    tree->max_data_length = max_data_length;
    tree->node_length = node_length;
    tree->secret_length = secret_length;
    tree->depth = ceil(log_x(2, num_data_blocks));
    // set the link tree
	tree->link_tree = link_tree;
	tree->hierarchy_level = hierarchy_level;

    HIP_DEBUG("tree->depth: %i\n", tree->depth);

    tree->root = NULL;

    // now we can init the secret array
    if (secret_length > 0)
	{
		HIP_IFEL(!(tree->secrets = (unsigned char *) malloc(secret_length * num_data_blocks)), -1,
				"failed to allocate memory\n");

		if (link_tree)
		{
			// add the root as secret for each leaf
			for (i = 0; i < num_data_blocks; i++)
			{
				HIP_IFEL(htree_add_secret(tree, link_tree->root, secret_length, i), -1,
						"failed to add linking root as secrets\n");
			}

		} else
		{
			bzero(tree->secrets, secret_length * num_data_blocks);
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
	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(data != NULL);
	HIP_ASSERT(data_length > 0 && data_length <= tree->max_data_length);
    HIP_ASSERT(tree->is_open > 0);
    HIP_ASSERT(tree->data_position < tree->num_data_blocks);

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
        tree->is_open = 0;
        tree->data_position = 0;
    }

    return 0;
}

int htree_add_random_data(hash_tree_t *tree, int num_random_blocks)
{
	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(num_random_blocks > 0);
    HIP_ASSERT(tree->is_open > 0);
    HIP_ASSERT(tree->data_position + num_random_blocks <= tree->num_data_blocks);

    // add num_random_blocks random data to the data-array
    RAND_bytes(&tree->data[tree->data_position * tree->max_data_length],
    		num_random_blocks * tree->max_data_length);
    // move to next free position
    tree->data_position += num_random_blocks;
    HIP_DEBUG("added random data block\n");

    // close the tree, if it is full
    if(tree->data_position == tree->num_data_blocks)
    {
        HIP_DEBUG("tree is full! closing...\n");
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
	// tree has to be full
	HIP_ASSERT(tree->is_open == 0);
	HIP_ASSERT(tree->data_position == 0);

    /* traverse all data blocks and create the leafs */
    HIP_DEBUG("computing leaf nodes: %i\n", tree->num_data_blocks);

    for(i = 0; i < tree->num_data_blocks; i++)
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
    level_width = tree->num_data_blocks;

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
        level_width = level_width >> 1;

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

int htree_get_branch(hash_tree_t *tree, int data_index, unsigned char *branch_nodes,
		int *branch_length)
{
	int tree_level = 0;
	int level_width = 0;
	int source_index = 0;
    int sibling_offset = 0;
    int err = 0;

    HIP_ASSERT(tree != NULL);
    HIP_ASSERT(branch_nodes != NULL);
    HIP_ASSERT(data_index >= 0);

    // branch includes all elements excluding the root
    *branch_length = tree->depth * tree->node_length;

    HIP_DEBUG("tree->depth: %i\n", tree->depth);

    // traverse bottom up
    level_width = tree->num_data_blocks;

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
    return err;
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

unsigned char* htree_get_secret(hash_tree_t *tree, int data_index,
		int *secret_length)
{
	HIP_ASSERT(tree != NULL);
	HIP_ASSERT(data_index >= 0 && data_index < tree->num_data_blocks);
	HIP_ASSERT(secret_length != NULL);

	*secret_length = tree->secret_length;

	if (tree->secret_length > 0)
		return &tree->secrets[data_index * tree->secret_length];
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
			data_index = data_index >> 1;
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

    level_width = tree->num_data_blocks;

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
        level_width = level_width >> 1;
    }
}

double log_x(int base, double value)
{
	return log(value) / log(base);
}

#if 0
/*!
 * \brief Create empty acknowledgement MT tree.
 *
 *  Create empty MT tree. This is the first step when Acknowledging packets.
 *
 * \author  Tobias Heer
 *
 * \param treeSize Size of the tree (number of leaf elements)
 * \param secretSize Size of each secret (part of the leaf node)
 * \param nodeSize Size of the MT nodes (size of hash function).
 *
 *
 * \return A pointer to the tree.
 *
 * \note The memory must be freed elsewhere.
 */
hash_tree_t* ht_createAckTree(size_t treeSize, size_t secretSize, size_t nodeSize){
    hash_tree_t* tree;

    tree =  malloc(sizeof(hash_tree_t));

    tree->leaf = (char*) malloc(secretSize*treeSize);
    RAND_bytes(tree->leaf, secretSize*treeSize);

    tree->node = (char*) malloc(nodeSize*treeSize);
    // TODO: This can be removed after testing
    bzero(tree->node, nodeSize*treeSize);



    tree->isOpen    = FALSE;
    tree->pos       = 0;
    tree->size      = treeSize;
    tree->depth = ceil(log2(treeSize));
    tree->leafSize  = secretSize;
    tree->nodeSize  = nodeSize;


    return tree;
}
#endif

#if 0
ht_hash* ht_generateSecrets(size_t numSecrets, size_t nodeSize){

	hash* stash = malloc(numSecrets * nodeSize);

	//check if memory was allocated
	if(stash == NULL)
		return 0;

	// fill stash with secrets
	get_random_bytes(stash, numSecrets * nodeSize);
	return stash;
}
#endif

#if 0
/*!
 * \brief Generate a node from a ack leaf.
 *
 *  Generate a node from a signature leaf. Used in ack trees.
 *
 * \author  Tobias Heer
 *
 * \param leaf  			Pointer to the leaf
 * \param index 			Leaf number
 * \param destinationBuffer Pointer to the node buffer location
 * \param leafSize 			Size of the Leaf
 * \param args				Variable argument field for using function pointers
 * \return Error code (see code for details).
 */
ht_err ht_ackLeafGenerator(unsigned char* leaf,
						uint16_t index,
						unsigned char* destinationBuffer,
						size_t leafSize,
						void* generatorArgs){

	assert(leaf != NULL);
	assert(generatorArgs != NULL);
	char* tempBuffer = (char *) generatorArgs;
	assert(destinationBuffer != NULL);
	HIP_DEBUG("Setting bit 1,2\n");
	uint16_t netIndex = htonl(index);
	// copy index to buffer
	HIP_DEBUG("Setting bit 1,2\n");
	memcpy(tempBuffer, &netIndex, sizeof(netIndex));
	HIP_DEBUG("Copy Buffer\n");
	// copy hash value to buffer
	memcpy(tempBuffer+2, leaf, leafSize);

    HIP_DEBUG("Temp Buffer %d: ", index);
    hexdump(tempBuffer, leafSize+2);
    HIP_DEBUG("\n");

	if(SHA1(tempBuffer, leafSize, destinationBuffer))
		return ht_STht_SUCCESS;
	return ht_STht_ERR_UNSPECIFIED;
}
#endif

#if 0
/*!
 * \brief Generate a node from a signature leaf.
 *
 *  Generate a node from a signature leaf. Used in signature trees.
 *
 * \author  Tobias Heer
 *
 * \param leaf  			Pointer to the leaf
 * \param index 			Leaf number
 * \param destinationBuffer Pointer to the node buffer location
 * \param leafSize 			Size of the Leaf
 * \param args				Variable argument field for using function pointers
 * \return Error code.
 */
ht_err ht_sigLeafGenerator(unsigned char* leaf,
						uint16_t index,
						unsigned char* destinationBuffer,
						size_t leafSize,
						void* args){

	if(SHA1(leaf, leafSize, destinationBuffer))
		return ht_STht_SUCCESS;
	return ht_STht_ERR_UNSPECIFIED;

}
#endif

#if 0
/*!
 * \brief Generate a node from a ack node.
 *
 *  Generate a node from a signature node. Used in signature trees.
 *
 * \author  Tobias Heer
 *
 * \param leftNode 			Pointer to the left node
 * \param rightNode 		Pointer to the right node
 * \param index 			Left node number
 * \param destinationBuffer Pointer to the node buffer location
 * \param nodeSize 			Size of the node
 * \param args				Variable argument field for using function pointers
 * \return Error code (see code for details).
 */
ht_err ht_sigNodeGenerator(unsigned char* leftNode,
						unsigned char* rightNode,
						uint16_t index,
						unsigned char* destinationBuffer,
						size_t nodeSize,
						void* args){
	/** @NOTE: We assume that the left and the right node
	 *  are contained in a sequential byte buffer that starts
	 *  with leftNode. Hence, we ignore rightNode completely
	 */
	if(SHA1(leftNode, nodeSize*2, destinationBuffer))
		return ht_STht_SUCCESS;
	return ht_STht_ERR_UNSPECIFIED;
}
#endif

#if 0
/*!
 * \brief Create a root element for the tree and the corresponding tree.
 *
 * Create a root element for the tree. This is the first step when VERIFYING data.
 *
 * \author  Tobias Heer
 *
 * \param buffer Root data of the tree.
 * \param nodeSize Size of the MT nodes (size of hash function).
 * \param treeSize Size of the tree (number of leaf elements)
 *
 * \return A pointer to the root.
 *
 * \note The memory must be freed elsewhere.
 */
ht_root_t* ht_createRoot(char* buffer, size_t nodeSize, size_t treeSize)
{
    ht_root_t *root = NULL;

    if(treeSize == 0){
        HIP_DEBUG("Root can not belong to 0 tree");
        exit(1);
    }

    root =  malloc(sizeof(hash_tree_t));
    bzero(root, sizeof(hash_tree_t));


    root->node = (char*) malloc(nodeSize);
    bzero(root->node, nodeSize);

    memcpy(root->node, (const void*) buffer, nodeSize);

    root->treeSize  = treeSize;
    root->treeDepth = ceil(log2(treeSize));
    root->nodeSize  = nodeSize;

    return root;
}
#endif

#if 0
/*!
 * \brief Get the root element from a computed tree.
 *
 *  Get the root element from a computed tree.
 *
 * \author  Tobias Heer
 *
 * \param tree 		Pointer to the MT
 * \param buffer	Destination buffer
 * \param len		Destination buffer length
 * \return 0
 */
int ht_getRoot(hash_tree_t* tree, char* buffer, int len)
{
    if(len != tree->nodeSize){
        HIP_DEBUG("getRoot: insufficient buffer space (%d != %d)",
               len,
               tree->nodeSize);
        exit(1);
    }
    memcpy(buffer, tree->node + 2 * (tree->size-1) * tree->nodeSize, tree->nodeSize);
    return 0;
}
#endif
