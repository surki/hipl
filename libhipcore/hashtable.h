#ifndef HIP_LHASHTABLE_H
#define HIP_LHASHTABLE_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include "debug.h"
#include "list.h"

#undef MIN_NODES
#define MIN_NODES	16
#define UP_LOAD		(2*LH_LOAD_MULT) /* load times 256  (default 2) */
#define DOWN_LOAD	(LH_LOAD_MULT)   /* load times 256  (default 1) */

// XX FIXME: HAS TO BE CONVERTED

static LHASH *amih;
static LHASH *tblhash=NULL;
static uint reclength=37;

typedef LHASH hip_ht_common;
typedef hip_ht_common HIP_HASHTABLE;

static inline HIP_HASHTABLE *hip_ht_init(LHASH_HASH_FN_TYPE hashfunc, LHASH_COMP_FN_TYPE cmpfunc)
{
	return lh_new(hashfunc, cmpfunc);
}

#define hip_ht_uninit(head) lh_free(head)

#define hip_ht_find(head, data) lh_retrieve(head, data)
static inline int hip_ht_add(HIP_HASHTABLE *head, void *data)
{
	if (lh_insert(head, data)) {
	        HIP_DEBUG("hash replace not occured\n");
	}
	return 0;
}
#define hip_ht_delete(head, data) lh_delete(head, data)

#define HIP_LOCK_HT(hash)
#define HIP_UNLOCK_HT(hash)

#endif /* LHASHTABLE_H */

