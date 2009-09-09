/**
 * Hash chain functions for packet authentication and
 * packet signatures
 *
 * Description:
 *
 * Authors:
 *   - Tobias Heer <heer@tobobox.de> 2006
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef HASH_CHAIN_H
#define HASH_CHAIN_H

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "hashtree.h"

/* longest digest in openssl lib */
#ifdef SHA512_DIGEST_LENGTH
# define MAX_HASH_LENGTH SHA512_DIGEST_LENGTH
#else
# define MAX_HASH_LENGTH 64
#endif

/* hash function used for the creation and verification of the hash chain */
typedef unsigned char * (*hash_function_t)(const unsigned char *, size_t,
		unsigned char *);

typedef struct hash_chain
{
	/* pointer to the hash-function used to create and verify the hchain
	 *
	 * @note params: (in_buffer, in_length, out_buffer)
	 * @note out_buffer should be size MAX_HASH_LENGTH */
	hash_function_t hash_function;
	int hash_length;	/* length of the hashes, of which the hchain consist */
	int hchain_length;	/* number of initial elements in the hash-chain */
	int hchain_hierarchy; /* hierarchy this hchain belongs to */
	int current_index; /* index to currently revealed element for hchain traversal*/
	unsigned char * elements; /* array containing the elements of the hash chain*/
	hash_tree_t *link_tree; /* pointer to a hash tree for linking hchains */
} hash_chain_t;

/** prints the hash chain
 *
 * @param	hash_chain the hash chain to be printed
 */
void hchain_print(const hash_chain_t * hash_chain);

/** checks if a hash is part of a hash chain
 *
 * @param	current_hash the hash value to be verified
 * @param	lasl_hash the last known hash value
 * @param	hash function the hash function to be used
 * @param	hash_length length of the hash values
 * @param	tolerance the maximum number of hash calculations
 * @param	secret the potentially incorporated secret
 * @param	secret_length length og the secret
 * @return	hash distance if the hash authentication was successful, 0 otherwise
 */
int hchain_verify(const unsigned char * current_hash, const unsigned char * last_hash,
		hash_function_t hash_function, int hash_length, int tolerance,
		unsigned char *secret, int secret_length);

/** creates a new hash chain
 *
 * @param	hash_function hash function to be used to generate the hash values
 * @param	hash_length length of the hash values
 * @param	hchain_length number of hash elements
 * @param	hchain_hierarchy the hierarchy level this hash chain will belong to
 * @param	link_tree the link tree, if HHL is used
 * @return  pointer to the newly created hash chain
 */
hash_chain_t * hchain_create(hash_function_t hash_function, int hash_length,
		int hchain_length, int hchain_hierarchy, hash_tree_t *link_tree);

unsigned char * hchain_get_anchor(const hash_chain_t *hash_chain);
unsigned char * hchain_get_seed(const hash_chain_t *hash_chain);

unsigned char * hchain_element_by_index(const hash_chain_t *hash_chain, int index);
int hchain_set_current_index(hash_chain_t *hash_chain, int index);

/** removes and returns the next element from the hash chain
 *
 * @param	hash_chain the hash chain which has to be popped
 * @return	pointer to the current hashchain element or NULL if the hash chain is depleted
 */
unsigned char * hchain_pop(hash_chain_t * hash_chain);

/** returns the next element of the hash chain but does not advance the current element
 * pointer. This function should only be used if the next element is kept secret and has to
 * be used for special purposes like message signatures.
 *
 * @param	hash_chain the hash chain
 * @return	next element of the hash chain or NULL if the hash chain is depleted
 */
unsigned char * hchain_next(const hash_chain_t *hash_chain);

unsigned char * hchain_previous(hash_chain_t * hash_chain);

/** returns the current element of the hash chain
 *
 * @param	hash_chain the hash chain
 * @return	current element of the hash chain or NULL if the hash chain is depleted
 */
unsigned char * hchain_current(const hash_chain_t *hash_chain);

/** delete hash chain and free memory
 *
 * @param	hash_chain the hash chain which has to be removed
 * @return	0 in case of success
 */
int hchain_free(hash_chain_t *hash_chain);

unsigned char * hchain_push(hash_chain_t * hash_chain);
int hchain_reset(hash_chain_t *hash_chain);

/** accessor function which returns the number of remaining hash chain elements
 *
 * @param	hash_chain the hash chain
 * @return number of remaining elements
 */
int hchain_get_num_remaining(const hash_chain_t * hash_chain);

#if 0
/*************** Helper functions ********************/
int concat_n_hash_SHA(unsigned char *hash, unsigned char** parts, int* part_length,
		int num_parts);
#endif

#endif /*HASH_CHAIN_H*/
