/**
 * Hash tree functions for packet authentication and
 * packet signatures
 *
 * Description:
 *
 * Authors:
 *   - Tobias Heer <heer@tobobox.de> 2008
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef HASH_TREE_H_
#define HASH_TREE_H_

#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <inttypes.h>

typedef struct htree_gen_args
{
	int index;
} htree_gen_args_t;

/* leaf generator function pointer
 *
 * @note if you need more arguments here, add them to the gen_args struct
 */
typedef int (*htree_leaf_gen_t) (unsigned char *data, int data_length,
								unsigned char *secret, int secret_length,
								unsigned char *dst_buffer, htree_gen_args_t *gen_args);

typedef int (*htree_node_gen_t) (unsigned char *left_node, unsigned char *right_node,
								int node_length, unsigned char *dst_buffer,
								htree_gen_args_t *gen_args);

typedef struct hash_tree
{
	// data variables
	int num_data_blocks; /* number of data blocks to be verified with the tree */
	int max_data_length; /* max length for a single leaf element */
	unsigned char *data; /* array containing the data to be validated with the tree */
	int secret_length;	/* length of the secret */
	unsigned char *secrets; /* individual secrets to be revealed with each data block */

	struct hash_tree *link_tree;
	int hierarchy_level;

	// tree elements variables
	int node_length; /* length of a single node element */
	unsigned char *nodes; /* array containing the nodes of the tree */
	unsigned char *root; /* the root of the tree -> points into nodes-array */

	// management variables
	int depth; /* depth of the tree */
	int data_position; /* index of the next free leaf */
	int is_open; /* can one enter new entries?
					This is only true if the nodes have not been
					computed yet. */
} hash_tree_t;

/** creates an empty hash tree.
 *
 * @param	num_data_blocks number of leaf node
 * @param	max_data_length the maximum data length hashed in a leaf node
 * @param	node_length the length of a hash value
 * @param	secret_length length of the eventual secrets
 * @param	link_tree the link tree in case of HHL-based linking
 * @param	hierarchy_level the hierarchy level of the created hash tree
 * @return	pointer to the tree, NULL in case of an error.
 */
hash_tree_t* htree_init(int num_data_blocks, int max_data_length, int node_length,
		int secret_length, hash_tree_t *link_tree, int hierarchy_level);

/** frees the hash tree
 *
 * @param	tree the hash tree to be freed
 */
void htree_free(hash_tree_t *tree);

/** adds a data item to the tree.
 *
 * @param	tree pointer to the tree
 * @param 	data the data to be added
 * @param	data_length length of the data item
 * @return	always 0
 */
int htree_add_data(hash_tree_t *tree, char *data, int data_length);

/** adds random data item to the tree.
 *
 * @param	tree pointer to the tree
 * @param	num_random_blocks number of random blocks to be added
 * @return	always 0
 */
int htree_add_random_data(hash_tree_t *tree, int num_random_blocks);

/** adds a secret to the tree.
 *
 * @param	tree pointer to the tree
 * @param 	secret the secret to be added
 * @param	secret_length length of the secret
 * @param	secret_index position of the secret in the leaf set
 * @return	always 0
 */
int htree_add_secret(hash_tree_t *tree, char *secret, int secret_length, int secret_index);

/** adds random secrets to the tree.
 *
 * @param	tree pointer to the tree
 * @return	always 0
 */
int htree_add_random_secrets(hash_tree_t *tree);

/** generates the nodes for a tree with completely filled leaf set
 *
 * @param	tree pointer to the tree
 * @param	leaf_gen the leaf generator function pointer
 * @param	node_gen the node generator function pointer
 * @param	gen_args arguments for the generators
 * @return	0 on success, -1 otherwise
 */
int htree_calc_nodes(hash_tree_t *tree, htree_leaf_gen_t leaf_gen,
		htree_node_gen_t node_gen, htree_gen_args_t *gen_args);

/** checks if the hash tree contains further unrevealed data items
 *
 * @param	tree pointer to the tree
 * @return	1 if more elements, else 0
 */
int htree_has_more_data(hash_tree_t *tree);

/** gets the offset of the next unrevealed data item
 *
 * @param	tree pointer to the tree
 * @return	offset of the data item
 */
int htree_get_next_data_offset(hash_tree_t *tree);

/** gets the elements of the verification branch from a computed tree
 *
 * @param	tree pointer to the hash tree
 * @param	data_index leaf position for which the verification branch is fetched
 * @param	branch_nodes destination buffer for the branch nodes
 * @param	branch_length destination buffer length, returns used space
 * @return	always 0
 */
int htree_get_branch(hash_tree_t *tree, int data_index, unsigned char *branch_nodes,
		int *branch_length);

/** gets the data item at the specified position
 *
 * @param	tree pointer to the hash tree
 * @param	data_index leaf position for which the data item is returned
 * @param	data_length length of the returned data item
 * @return	pointer to the data item, NULL in case of an error
 */
unsigned char* htree_get_data(hash_tree_t *tree, int data_index,
		int *data_length);

/** gets the secret at the specified position
 *
 * @param	tree pointer to the hash tree
 * @param	data_index leaf position for which the secret is returned
 * @param	secret_length length of the returned secret
 * @return	pointer to the secret, NULL in case of an error
 */
unsigned char* htree_get_secret(hash_tree_t *tree, int data_index,
		int *secret_length);

/** gets the root node of the hash tree
 *
 * @param	tree pointer to the hash tree
 * @param	root_length length of the returned root element
 * @return	pointer to the root element, NULL in case of an error
 */
unsigned char* htree_get_root(hash_tree_t *tree, int *root_length);

/** checks the data item and an verification branch against the root
 *
 * @param	root pointer to the root
 * @param	root_length length of the root node
 * @param	branch_nodes buffer containing the branch nodes
 * @param	branch_length length of the verification branch
 * @param	verify_data the data item to be verified
 * @param	data_length length of the data item
 * @param	data_index index of the data item in the leaf set
 * @param	secret potentially incorporated secret
 * @param	secret_length length of the secret
 * @param	leaf_gen the leaf generator function pointer
 * @param	node_gen the node generator function pointer
 * @param	gen_args arguments for the generators
 * @return	0 if successful, 1 if invalid, -1 in case of an error
 */
int htree_verify_branch(unsigned char *root, int root_length,
		unsigned char *branch_nodes, uint32_t branch_length,
		unsigned char *verify_data, int data_length, uint32_t data_index,
		unsigned char *secret, int secret_length,
		htree_leaf_gen_t leaf_gen, htree_node_gen_t node_gen,
		htree_gen_args_t *gen_args);

/** generates a leaf node from a given data item
 *
 * @param	data data item to be hashed
 * @param	data_length length of the data item
 * @param	secret potentially incorporated secret
 * @param	secret_length length of the secret
 * @param	dst_buffer buffer for the generated leaf node
 * @param	gen_args arguments for the generator
 * @return	always 0
 */
int htree_leaf_generator(unsigned char *data, int data_length,
		unsigned char *secret, int secret_length,
		unsigned char *dst_buffer, htree_gen_args_t *gen_args);

/** generates an intermediate node from two hash tree nodes
 *
 * @param	left_node the left node to be hashed
 * @param	right_node the right node to be hashed
 * @param	node_length length of each node
 * @param	dst_buffer buffer for the generated intermediate node
 * @param	gen_args arguments for the generator
 * @return	0 on success, -1 in case of an error
 */
int htree_node_generator(unsigned char *left_node, unsigned char *right_node,
		int node_length, unsigned char *dst_buffer, htree_gen_args_t *gen_args);

/** prints the data set
 *
 * @param	tree pointer to the tree
 */
void htree_print_data(hash_tree_t *tree);

/** prints a hash tree
 *
 * @param	tree pointer to the tree
 */
void htree_print_nodes(hash_tree_t *tree);

/** calculates the logarithm for a given base
 *
 * @param	base the base of the logarithm
 * @param	value value for which the log should be computed
 * return	the log
 */
double log_x(int base, double value);

#endif /* HASH_TREE_H_ */
