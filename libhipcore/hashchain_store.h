/*
 * Store for pre-created hash structures
 *
 * Description:
 * Stores a number of pre-created hash structures and supports HHL-based
 * linking of hash structures in different hierarchy levels.
 *
 * Authors:
 * - Tobias Heer <heer@tobibox.de>
 * - René Hummen <rene.hummen@rwth-aachen.de>
 *
 * Licence: GNU/GPL
 */

#ifndef HASHCHAIN_STORE_H
#define HASHCHAIN_STORE_H

#include "hashchain.h"
#include "hashtree.h"
#include "builder.h"
#include "linkedlist.h"


// max amount of different hash-functions that can be stored
#define MAX_FUNCTIONS			5
// max amount of different hash lengths that can be stored
#define MAX_NUM_HASH_LENGTH		5
// this includes the BEX-item
#define MAX_NUM_HCHAIN_LENGTH	5
// max number of hierarchies for which hchains can be linked
#define MAX_NUM_HIERARCHIES		4000
/* max amount of hchains that can be stored per hchain_item
 *
 * @note we are using a list here, so we might also use some other
 *       mechanism to stop the hcstore_refill() */
#define MAX_HCHAINS_PER_ITEM	6

/* determines when to refill a store
 *
 * @note this is a reverse threshold -> 1 - never refill, 0 - always
 */
#define ITEM_THRESHOLD			0.5


typedef struct hchain_shelf
{
	/* number of different hchain lengths currently used for this
	 * (hash-function, hash_length)-combination */
	int num_hchain_lengths;
	/* the different hchain lengths */
	int hchain_lengths[MAX_NUM_HCHAIN_LENGTH];
	/* number of hierarchies in this shelf */
	int num_hierarchies[MAX_NUM_HCHAIN_LENGTH];
	/* hchains with the respective hchain length */
	hip_ll_t hchains[MAX_NUM_HCHAIN_LENGTH][MAX_NUM_HIERARCHIES];
} hchain_shelf_t;

typedef struct hchain_store
{
	/* amount of currently used hash-functions */
	int num_functions;
	/* pointer to the hash-function used to create and verify the hchain
	 *
	 * @note params: (in_buffer, in_length, out_buffer)
	 * @note out_buffer should be size MAX_HASH_LENGTH */
	hash_function_t hash_functions[MAX_FUNCTIONS];
	/* amount of different hash_lengths per hash-function */
	int num_hash_lengths[MAX_FUNCTIONS];
	/* length of the hashes, of which the respective hchain items consist */
	int hash_lengths[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
	/* contains hchains and meta-information about how to process them */
	hchain_shelf_t hchain_shelves[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
} hchain_store_t;

/** initializes a new hash structure store
 *
 * @param	hcstore the store to be initialized
 * @return	always returns 0
 */
int hcstore_init(hchain_store_t *hcstore);

/** un-initializes a hash structure store
 *
 * @param	hcstore the store to be un-initialized
 * @param	use_hash_trees indicates whether hash chains or hash trees are stored
 */
void hcstore_uninit(hchain_store_t *hcstore, int use_hash_trees);

/** helper function to free a hash chain
 *
 * @param	hchain the the hash chain to be freed
 */
void hcstore_free_hchain(void *hchain);

/** helper function to free a hash tree
 *
 * @param	htree the the hash tree to be freed
 */
void hcstore_free_htree(void *htree);

/** registers a new hash function for utilization in the store
 *
 * @param	hcstore the store, where the function should be added
 * @param	hash_function function pointer to the hash function
 * @return	returns the index to the hash function in the store,
 *          -1 if MAX_FUNCTIONS is reached
 */
int hcstore_register_function(hchain_store_t *hcstore, hash_function_t hash_function);

/** registers a new hash length for utilization in the store
 *
 * @param	hcstore the store, where the hash length should be added
 * @param	function_id index to the hash function, where the length should be added
 * @param	hash_length hash length to be added
 * @return	returns the index to the hash length in the store,
 *          -1 if MAX_NUM_HASH_LENGTH is reached
 */
int hcstore_register_hash_length(hchain_store_t *hcstore, int function_id,
		int hash_length);

/** registers a new hash structure length for utilization in the store
 *
 * @param	hcstore the store, where the hash structure length should be added
 * @param	function_id index to the hash function, where the structure length should be added
 * @param	hash_length_id index to the hash length, where the structure length should be added
 * @param	hchain_length hash length to be added
 * @return	returns the index to the hash structure length in the store,
 *          -1 if MAX_NUM_HCHAIN_LENGTH is reached
 */
int hcstore_register_hchain_length(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length);

/** registers additional hierarchy levels for utilization in the store
 *
 * @param	hcstore the store, where the hierarchy levels should be added
 * @param	function_id index to the hash function, where the structure length should be added
 * @param	hash_length_id index to the hash length, where the structure length should be added
 * @param	hchain_length hash length to be added
 * @return	returns the hierarchy count, -1 if MAX_NUM_HIERARCHIES is reached
 */
int hcstore_register_hchain_hierarchy(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length, int addtional_hierarchies);

/** helper function to refill the store
 *
 * @param	hcstore store to be refilled
 * @param	hash_func_id index to the hash function
 * @param	hash_length_id index to the hash length
 * @param	hchain_length_id index to the hash structure length
 * @param	hierarchy_level hierarchy level to be refilled, in case HHL is used
 * @param	update_higher_level needed for the recursion of the refill operation, start with 0
 * @param	use_hash_trees indicates whether hash chains or hash trees are stored
 * @return	number of created hash structures, -1 in case of an error
 */
int hcstore_fill_item(hchain_store_t *hcstore, int hash_func_id, int hash_length_id,
		int hchain_length_id, int hierarchy_level, int update_higher_level, int use_hash_trees);

/** refills the store in case it contains less than ITEM_THRESHOLD * MAX_HCHAINS_PER_ITEM
 *  hash structures
 *
 * @param	hcstore store to be refilled
 * @param	use_hash_trees indicates whether hash chains or hash trees are stored
 * @return	number of created hash structures, -1 in case of an error
 */
int hcstore_refill(hchain_store_t *hcstore, int use_hash_trees);

/** gets a stored hash structure with the provided properties
 *
 * @param	hcstore store from which the hash structure should be returned
 * @param	function_id index of the hash function used to create the hash structure
 * @param	hash_length_id index of the hash length of the hash elements
 * @param	hchain_length length of the hash structure
 * @return	pointer to the hash structure, NULL in case of an error or no such structure
 */
void * hcstore_get_hash_item(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length);

/** gets a stored hash structure for the provided anchor element
 *
 * @param	hcstore store from which the hash structure should be returned
 * @param	function_id index of the hash function used to create the hash structure
 * @param	hash_length_id index of the hash length of the hash elements
 * @param	hierarchy_level hierarchy level at which the hash structure is located
 * @param	anchor the anchor element of the hash structure
 * @param	indicates whether hash chains or hash trees are stored
 * @return	pointer to the hash structure, NULL in case of an error or no such structure
 */
void * hcstore_get_item_by_anchor(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hierarchy_level, unsigned char *anchor, int use_hash_trees);

/** gets a pointer to the hash function for a given index
 *
 * @param	hcstore store from which the hash function should be returned
 * @param	function_id index of the hash function
 * @return	pointer to the hash function, NULL if no such hash function
 */
hash_function_t hcstore_get_hash_function(hchain_store_t *hcstore, int function_id);

/** gets the hash length for a given index
 *
 * @param	hcstore store from which the hash length should be returned
 * @param	function_id index of the hash function
 * @param	hash_length_id index of the hash length
 * @return	the hash length, 0 if no such hash length
 */
int hcstore_get_hash_length(hchain_store_t *hcstore, int function_id, int hash_length_id);

#endif /* HASHCHAIN_STORE_H */
