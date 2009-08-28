/**
 * @file
 * This file contains KEYMAT handling functions for HIPL.
 * Licence: GNU/GPL
 * 
 * @author Mika Kousa <mkousa#iki.fi>
 * @author Kristian Slavov <ksl#iki.fi>
 * @author Tobias Heer <heer#tobibox.de>
 */
#include "keymat.h"

u8 *hip_create_keymat_buffer(char *kij, size_t kij_len, size_t hash_len, 
			     struct in6_addr *smaller_hit,
			     struct in6_addr *bigger_hit,
			     uint64_t I, uint64_t J)

{
	u8 *buffer = NULL, *cur = NULL;
	size_t requiredmem;

	HIP_DEBUG("\n");
	/* 2*sizeof(uint64_t) added to take care of I and J. */
	if (2 * sizeof(struct in6_addr) < hash_len)
		requiredmem = kij_len + hash_len + sizeof(u8) + 2*sizeof(uint64_t);
	else
		requiredmem = kij_len + 2 * sizeof(struct in6_addr) +
			sizeof(u8) + 2*sizeof(uint64_t);
	buffer = (u8 *)HIP_MALLOC(requiredmem, GFP_KERNEL);
	if (!buffer) {
		HIP_ERROR("Out of memory\n");
		return buffer;
	}

	cur = buffer;
	memcpy(cur, kij, kij_len);
	cur += kij_len;
	memcpy(cur, (u8 *)smaller_hit, sizeof(struct in6_addr));
	cur += sizeof(struct in6_addr);
	memcpy(cur,(u8 *)bigger_hit, sizeof(struct in6_addr));
	cur += sizeof(struct in6_addr);
	memcpy(cur, &I, sizeof(uint64_t)); // XX CHECK: network byte order?
	cur += sizeof(uint64_t);
	memcpy(cur, &J, sizeof(uint64_t)); // XX CHECK: network byte order?
	cur += sizeof(uint64_t);
	*(cur) = 1;
	cur += sizeof(u8);

	_HIP_HEXDUMP("beginning of keymat", buffer, cur - buffer);

	return buffer;
}

void hip_update_keymat_buffer(u8 *keybuf, u8 *Kold, size_t Kold_len, 
			      size_t Kij_len, u8 cnt)
{
	HIP_ASSERT(keybuf);

	memcpy(keybuf+Kij_len, Kold, Kold_len);
	*(keybuf + Kij_len + Kold_len) = cnt;

	return;
}

/**
 * hip_make_keymat - generate HIP keying material
 * @param kij Diffie-Hellman Kij (as in the HIP drafts)
 * @param kij_len the length of the Kij material
 * @param keymat pointer to a keymat structure which will be updated according
 *           to the generated keymaterial
 * @param dstbuf the generated keymaterial will be written here
 * @param hit1 source HIT
 * @param hit2 destination HIT
 * @param calc_index where the one byte index is stored (n of Kn)
 *
 */
void hip_make_keymat(char *kij, size_t kij_len,
		     struct hip_keymat_keymat *keymat, 
		     void *dstbuf, size_t dstbuflen, struct in6_addr *hit1,
		     struct in6_addr *hit2, u8 *calc_index,
		     uint64_t I, uint64_t J)
{
	int bufsize, err = 0;
	uint8_t index_nbr = 1;
	int dstoffset = 0;
	void *seedkey;
	struct in6_addr *smaller_hit, *bigger_hit;
	int hit1_is_bigger;
	u8 *shabuffer = NULL;

	HIP_DEBUG("\n");
	if (dstbuflen < HIP_AH_SHA_LEN) {
		HIP_ERROR("dstbuf is too short (%d)\n", dstbuflen);
		return;
	}

	_HIP_ASSERT(dstbuflen % 32 == 0);
	HIP_ASSERT(sizeof(index_nbr) == HIP_KEYMAT_INDEX_NBR_SIZE);

	hit1_is_bigger = hip_hit_is_bigger(hit1, hit2);

	bigger_hit =  hit1_is_bigger ? hit1 : hit2;
	smaller_hit = hit1_is_bigger ? hit2 : hit1;

	_HIP_HEXDUMP("kij", kij, kij_len);
	_HIP_DEBUG("I=0x%llx J=0x%llx\n", I, J);
	_HIP_HEXDUMP("bigger hit", bigger_hit, 16);
	_HIP_HEXDUMP("smaller hit", smaller_hit, 16);
	_HIP_HEXDUMP("index_nbr", (char *) &index_nbr,
		     HIP_KEYMAT_INDEX_NBR_SIZE);

	shabuffer = hip_create_keymat_buffer(kij, kij_len, HIP_AH_SHA_LEN,
					     smaller_hit, bigger_hit, I, J);
	if (!shabuffer) {
		HIP_ERROR("No memory for keymat\n");
		return;
	}

	bufsize = kij_len + 2 * sizeof(struct in6_addr) +
		2 * sizeof(uint64_t) + 1;
	//bufsize = kij_len+2*sizeof(struct in6_addr)+ 1;

	// XX FIXME: is this correct
	hip_build_digest(HIP_DIGEST_SHA1, shabuffer, bufsize, dstbuf);

	_HIP_HEXDUMP("keymat digest", dstbuf, HIP_AH_SHA_LEN);

	dstoffset = HIP_AH_SHA_LEN;
	index_nbr++;

	/*
	 * K2 = SHA1(Kij | K1 | 2)
	 * K3 = SHA1(Kij | K2 | 3)
	 * ...
	 */
	seedkey = dstbuf;
	hip_update_keymat_buffer(shabuffer, seedkey, HIP_AH_SHA_LEN,
				 kij_len, index_nbr);

	while (dstoffset < dstbuflen) {
		hip_build_digest(HIP_DIGEST_SHA1, shabuffer,
				 kij_len + HIP_AH_SHA_LEN + 1,
				 dstbuf + dstoffset);
		seedkey = dstbuf + dstoffset;
		dstoffset += HIP_AH_SHA_LEN;
		index_nbr++;
		hip_update_keymat_buffer(shabuffer, seedkey, HIP_AH_SHA_LEN,
					 kij_len, index_nbr);
	}

	keymat->offset = 0;
	keymat->keymatlen = dstoffset;
	keymat->keymatdst = dstbuf;

	if (calc_index)
		*calc_index = index_nbr;
	else
		HIP_ERROR("NULL calc_index\n");

	_HIP_DEBUG("keymat index_nbr=%u\n", index_nbr);
	_HIP_HEXDUMP("GENERATED KEYMAT: ", dstbuf, dstbuflen);
	if (shabuffer)
		HIP_FREE(shabuffer);

	return;
}

/**
 * hip_keymat_draw - draw keying material
 * @param keymat pointer to the keymat structure which contains information
 *          about the actual
 * @param length size of keymat structure
 *
 * @return pointer the next point where one can draw the next keymaterial
 */
void* hip_keymat_draw(struct hip_keymat_keymat* keymat, int length)
{
	/* todo: remove this function */
	void *ret = NULL;

	if (length > keymat->keymatlen - keymat->offset) {
		HIP_DEBUG("Tried to draw more keys than are available\n");
		goto out_err;
	}

	ret = keymat->keymatdst + keymat->offset;

	keymat->offset += length;

 out_err:
	return ret;
}

/**
 * hip_keymat_draw_and_copy - draw keying material and copy it to the given buffer
 * @param dst destination buffer
 * @param keymat pointer to the keymat structure which contains information
 *          about the actual
 * @param length size of keymat structure
 *
 * @return pointer the next point where one can draw the next keymaterial
 */
int hip_keymat_draw_and_copy(char *dst,
			     struct hip_keymat_keymat *keymat, 
			     int len){
	int err  = 0;
	void *p = hip_keymat_draw(keymat, len);
	HIP_IFEL(!p, -EINVAL, "Could not draw from keymat\n");
	memcpy(dst, p, len);
out_err:
	return err;
}
/** 
 * Calculates new keying material.
 *
 * This function gets next @c key_len bytes of KEYMAT to @c key starting from
 * requested offset @c keymat_index. On entry of this function @c calc_index
 * tells the one byte index value which is related to @c calc_index_keymat (for
 * example, if @c calc_index_keymat is K3, then @c calc_index is 3).
 *
 * On successful return, @c keymat_index and @c calc_index contain the values
 * used in the last round of calculating Kn of KEYMAT, @c calc_index_keymat
 * contains the last Kn, and @c Kn_is_at contains the byte offset value of
 * @c calc_index_keymat.
 *
 * @param key               buffer where the created KEYMAT is stored.
 * @param key_len           length of @c key in bytes.
 * @param kij               shared key.
 * @param kij_len           length of @c kij in bytes.
 * @param keymat_index      keymat index.
 * @param calc_index        the one byte index value.
 * @param calc_index_keymat Kn.
 * @param Kn_is_at          the byte offset where @c calc_index_keymat starts.
 * @return                  0 on success, < 0 otherwise.
 */
int hip_keymat_get_new(void *key, size_t key_len, char *kij, size_t kij_len,
		       uint16_t *keymat_index, uint8_t *calc_index,
		       unsigned char *calc_index_keymat, uint16_t *Kn_is_at)
{
	/* must have the hadb lock when calling this function */
	int err = 0;
	int copied = 0;
	u8 *tmp_data = NULL;
	size_t tmp_data_len;

	_HIP_DEBUG("key_len=%d, requested keymat_index=%u calc_index=%u Kn_is_at=%u\n",
		   key_len, *keymat_index, *calc_index, *Kn_is_at);
	_HIP_HEXDUMP("calc_index_keymat", calc_index_keymat, HIP_AH_SHA_LEN);

 	if (key_len == 0 || kij_len == 0) {
		HIP_ERROR("key_len = 0 or kij_len = 0\n");
		err = -EINVAL;
		goto out_err;
	}

	_HIP_DEBUG("one byte index at req'd index in the end should be %u\n",
		  (*keymat_index / HIP_AH_SHA_LEN + 1) % 256);

	if (*keymat_index < *Kn_is_at) {
		HIP_ERROR("requested keymat index %u is lower than lowest keymat index of Kn (%u)\n",
			  *keymat_index, *Kn_is_at);
		err = -EINVAL;
		goto out_err;
	}
	/** @todo Check here if we have to test *keymat_index <
	    entry->current_keymat_index ? */
	
	/* before calculating any hashes test if we already have
	 * needed amount of ready keymat
	 *
	 * must first check that the requested keymat_index is within the ready keymat
	 */
	if (*keymat_index - *Kn_is_at < HIP_AH_SHA_LEN) {
		int tmp = HIP_AH_SHA_LEN - (*keymat_index - *Kn_is_at);
		_HIP_DEBUG("test: can copy %d bytes from the end of sha K\n", tmp);
		if (tmp > HIP_AH_SHA_LEN) {
			HIP_ERROR("bug: tmp > 20\n");
			err = -EINVAL;
			goto out_err;
		}

		if (tmp > 0) {
			memcpy(key, calc_index_keymat + HIP_AH_SHA_LEN - tmp, tmp);
			copied += tmp;
		}
	}

	_HIP_DEBUG("copied=%d\n", copied);
	_HIP_HEXDUMP("KEY (0)", key, copied);

	if (copied == key_len) {
		_HIP_DEBUG("copied all, return\n");
		goto out;
	}

	_HIP_DEBUG("need %d bytes more data\n", key_len-copied);

	tmp_data_len = kij_len + HIP_AH_SHA_LEN + 1;
	tmp_data = (u8 *)HIP_MALLOC(tmp_data_len, GFP_KERNEL);
	if (!tmp_data) {
		HIP_ERROR("HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(tmp_data, kij, kij_len); /* fixed part of every Kn round */

	while (copied < key_len) {
		(*calc_index)++;
		_HIP_DEBUG("calc_index=%u\n", *calc_index);
		/* create Kn = SHA-1( Kij | Kn-1 | calc_index) */

		/* Kij | Kn-1 */
		memcpy(tmp_data+kij_len, calc_index_keymat, HIP_AH_SHA_LEN);
		/* Kij | Kn-1 | calc_index */
		memcpy(tmp_data+kij_len+HIP_AH_SHA_LEN, calc_index, HIP_KEYMAT_INDEX_NBR_SIZE);
		/* SHA-1( Kij | Kn-1 | calc_index) */
		err = hip_build_digest(HIP_DIGEST_SHA1, tmp_data, tmp_data_len, calc_index_keymat);
		if (err) {
			HIP_ERROR("build_digest failed (K%u)\n", *calc_index);
			goto out_err;
		}
		*Kn_is_at += HIP_AH_SHA_LEN;
		if (*Kn_is_at + HIP_AH_SHA_LEN < *keymat_index) {
			HIP_DEBUG("skip until we are at right offset\n");
			continue;
		}

		_HIP_DEBUG("copied=%u, key_len=%u calc_index=%u dst to 0x%p\n", copied, key_len, *calc_index, key+copied);
		if (copied + HIP_AH_SHA_LEN <= key_len) {
			_HIP_DEBUG("copy whole sha block\n");
			memcpy(key+copied, calc_index_keymat, HIP_AH_SHA_LEN);
			copied += HIP_AH_SHA_LEN;
		} else {
			int t = HIP_AH_SHA_LEN - key_len % HIP_AH_SHA_LEN;
			t = key_len - copied;
			_HIP_DEBUG("copy partial %d bytes\n", t);
			memcpy(key+copied, calc_index_keymat, t);
			copied += t;
		}
	}

	_HIP_DEBUG("end: copied=%u\n", copied);

 out:
	_HIP_HEXDUMP("CALCULATED KEY", key, key_len);
	_HIP_DEBUG("at end: *keymat_index=%u *calc_index=%u\n",
		   *keymat_index, *calc_index);
 out_err:
	if(tmp_data)
		HIP_FREE(tmp_data);
	return err;
}


/** hip_update_entry_keymat - update HADB's KEYMAT related information
 * @param entry HADB entry to be update
 * @param new_keymat_index new Keymat Index value
 * @param new_calc_index new one byte value
 * @param new_current_keymat Kn related to @c new_calc_index
 */
void hip_update_entry_keymat(struct hip_hadb_state *entry, 
			     uint16_t new_keymat_index,
			     uint8_t new_calc_index,
			     uint16_t esp_keymat_index,
			     unsigned char *new_current_keymat)
{
	/* must have the hadb lock when calling this function */
	entry->current_keymat_index = new_keymat_index;
	entry->keymat_calc_index = new_calc_index;
	entry->esp_keymat_index = esp_keymat_index;
	_HIP_DEBUG("New Entry keymat data: current_keymat_index=%u keymat_calc_index=%u\n",
		   entry->current_keymat_index, entry->keymat_calc_index);
	if (new_current_keymat) {
		memcpy(entry->current_keymat_K, new_current_keymat, HIP_AH_SHA_LEN);
		_HIP_HEXDUMP("new_current_keymat", new_current_keymat, HIP_AH_SHA_LEN);
	}
}

