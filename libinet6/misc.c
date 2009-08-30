/**@file
 * This file defines miscellaneous utility functions
 *
 * @author Miika Komu
 * @author Mika Kousa
 * @author Bing Zhou
 * @note   Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see    misc.h
 */
#include "misc.h"

// needed due to missing system inlcude for openWRT
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX		64
#endif

/** Port numbers for NAT traversal of hip control packets. */
in_port_t hip_local_nat_udp_port = 50500;
in_port_t hip_peer_nat_udp_port = 50500;

#ifdef CONFIG_HIP_OPPORTUNISTIC
int hip_opportunistic_ipv6_to_hit(const struct in6_addr *ip,
				  struct in6_addr *hit,
				  int hit_type){
  int err = 0;
  u8 digest[HIP_AH_SHA_LEN];
  char *key = (char *) (ip);
  unsigned int key_len = sizeof(struct in6_addr);

  HIP_IFE(hit_type != HIP_HIT_TYPE_HASH100, -ENOSYS);
  _HIP_HEXDUMP("key", key, key_len);
  HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, key, key_len, digest)), err,
	   "Building of digest failed\n");

  memcpy(hit, digest + (HIP_AH_SHA_LEN - sizeof(struct in6_addr)),
	 sizeof(struct in6_addr));

  hit->s6_addr32[3] = 0; // this separates phit from normal hit

  set_hit_prefix(hit);

 out_err:

       return err;
}
#endif //CONFIG_HIP_OPPORTUNISTIC


/** hip_timeval_diff - calculate difference between two timevalues
 * @param t1 timevalue 1
 * @param t2 timevalue 2
 * @param result where the result is stored
 *
 * ** CHECK comments **
 * result = t1 - t2
 *
 * Code taken from http://www.gnu.org/manual/glibc-2.2.5/html_node/Elapsed-Time.html
 *
 * @return 1 if t1 is equal or later than t2, else 0.
 */
int hip_timeval_diff(const struct timeval *t1,
		     const struct timeval *t2,
		     struct timeval *result){
	struct timeval _t1, _t2;
	_t1 = *t1;
	_t2 = *t2;

	if (_t1.tv_usec < _t2.tv_usec) {
		int nsec = (_t2.tv_usec - _t1.tv_usec) / 1000000 + 1;
		_t2.tv_usec -= 1000000 * nsec;
		_t2.tv_sec += nsec;
	}
	if (_t1.tv_usec - _t2.tv_usec > 1000000) {
		int nsec = (_t1.tv_usec - _t2.tv_usec) / 1000000;
		_t2.tv_usec += 1000000 * nsec;
		_t2.tv_sec -= nsec;
	}

	result->tv_sec = _t2.tv_sec - _t1.tv_sec;
	result->tv_usec = _t2.tv_usec - _t1.tv_usec;

	return _t1.tv_sec >= _t2.tv_sec;
}


int hip_convert_hit_to_str(const hip_hit_t *hit, const char *prefix, char *hit_str){
	int err = 0;

	HIP_ASSERT(hit);

	memset(hit_str, 0, INET6_ADDRSTRLEN);
	err = !hip_in6_ntop(hit, hit_str);

	if (prefix)
		memcpy(hit_str + strlen(hit_str), prefix, strlen(prefix));


 out_err:

	return err;
}


/*
 * function maxof()
 *
 * in:          num_args = number of items
 *              ... = list of integers
 * out:         Returns the integer with the largest value from the
 *              list provided.
 */
int maxof(int num_args, ...){
        int max, i, a;
        va_list ap;

        va_start(ap, num_args);
        max = va_arg(ap, int);
        for (i = 2; i <= num_args; i++) {
                if ((a = va_arg(ap, int)) > max)
                        max = a;
        }
        va_end(ap);
        return(max);
}


int hip_lsi_are_equal(const hip_lsi_t *lsi1,
		      const hip_lsi_t *lsi2){
	return (ipv4_addr_cmp(lsi1, lsi2) == 0);
}


/**
 * hip_hit_is_bigger - compare two HITs
 * @param hit1 the first HIT to be compared
 * @param hit2 the second HIT to be compared
 *
 * @return 1 if hit1 was bigger than hit2, or else 0
 */
int hip_hit_is_bigger(const struct in6_addr *hit1,
		      const struct in6_addr *hit2){
	return (ipv6_addr_cmp(hit1, hit2) > 0);
}


int hip_hit_are_equal(const struct in6_addr *hit1,
		      const struct in6_addr *hit2){
	return (ipv6_addr_cmp(hit1, hit2) == 0);
}


/*
 * return value: 0 = match, >0 means non-match, -1 = error
 */
int hip_id_type_match(const struct in6_addr *id, int id_type) {
  int ret = 0, is_lsi = 0, is_hit = 0;
  hip_lsi_t lsi;

  if (ipv6_addr_is_hit(id)) {
    is_hit = 1;
  } else if (IN6_IS_ADDR_V4MAPPED(id)) {
    IPV6_TO_IPV4_MAP(id, &lsi);
    if (IS_LSI32(lsi.s_addr))
      is_lsi = 1;
  }

  HIP_ASSERT(!(is_lsi && is_hit));

  if (id_type == HIP_ID_TYPE_HIT)
    ret = (is_hit ? 1 : 0);
  else if (id_type == HIP_ID_TYPE_LSI)
    ret = (is_lsi ? 1 : 0);
  else
    ret = ((is_hit || is_lsi) ? 0 : 1);

  return ret;
}

char* hip_in6_ntop(const struct in6_addr *in6, char *buf){
        if (!buf)
                return NULL;
        sprintf(buf,
                "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                ntohs(in6->s6_addr16[0]), ntohs(in6->s6_addr16[1]),
                ntohs(in6->s6_addr16[2]), ntohs(in6->s6_addr16[3]),
                ntohs(in6->s6_addr16[4]), ntohs(in6->s6_addr16[5]),
                ntohs(in6->s6_addr16[6]), ntohs(in6->s6_addr16[7]));
        return buf;
}


int hip_in6_ntop2(const struct in6_addr *in6, char *buf){
	if(!buf)
		return 0;
	return sprintf(buf,
		       "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		       ntohs(in6->s6_addr16[0]), ntohs(in6->s6_addr16[1]),
		       ntohs(in6->s6_addr16[2]), ntohs(in6->s6_addr16[3]),
		       ntohs(in6->s6_addr16[4]), ntohs(in6->s6_addr16[5]),
		       ntohs(in6->s6_addr16[6]), ntohs(in6->s6_addr16[7]));
}


void hip_xor_hits(hip_hit_t *res, const hip_hit_t *hit1, const hip_hit_t *hit2){
	res->s6_addr32[0] = hit1->s6_addr32[0] ^ hit2->s6_addr32[0];
	res->s6_addr32[1] = hit1->s6_addr32[1] ^ hit2->s6_addr32[1];
	res->s6_addr32[2] = hit1->s6_addr32[2] ^ hit2->s6_addr32[2];
	res->s6_addr32[3] = hit1->s6_addr32[3] ^ hit2->s6_addr32[3];
}


/**
 * hip_hash_spi - calculate a hash from SPI value
 * @param key 32-bit SPI value
 * @param range range of the hash
 *
 * Returns value in range: 0 <= x < range
 */
unsigned long hip_hash_spi(const void *ptr){
	unsigned long hash = (unsigned long)(*((uint32_t *)ptr));
	return (hash % ULONG_MAX);
}


/**
 * Match spis.
 */
int hip_match_spi(const void *ptr1, const void *ptr2){
	unsigned long hash1 = (unsigned long)(*((uint32_t *)ptr1));
	unsigned long hash2 = (unsigned long)(*((uint32_t *)ptr2));

	/* SPIs are random, so simple modulo is enough? */
	return (hash1 != hash2);
}


/**
 * hip_hash_hit - calculate a hash from a HIT
 * @param key pointer to a HIT
 * @param range range of the hash
 *
 * Returns value in range: 0 <= x < range
 */
unsigned long hip_hash_hit(const void *ptr){
      uint8_t hash[HIP_AH_SHA_LEN];

      hip_build_digest(HIP_DIGEST_SHA1, ptr + sizeof(uint16_t),
	7 * sizeof(uint16_t), hash);
      //hip_build_digest(HIP_DIGEST_SHA1, ptr, sizeof(hip_hit_t), hash);

      return *((unsigned long *)hash);
}


int hip_match_hit(const void *ptr1, const void *ptr2){
	return (hip_hash_hit(ptr1) != hip_hash_hit(ptr2));
}


/*
unsigned long hip_hidb_hash(const void *ptr){
	hip_hit_t *hit = &(((struct hip_host_id_entry *) ptr)->lhi.hit);
	unsigned long hash;

	hip_build_digest(HIP_DIGEST_SHA1, hit, sizeof(hip_hit_t), &hash);

	return hash;
}

int hip_hidb_match(const void *ptr1, const void *ptr2){
	return (hip_hidb_hash(ptr1) != hip_hidb_hash(ptr2));
}
*/


const char *hip_algorithm_to_string(int algo){
	const char *str = "UNKNOWN";
	static const char *algos[] = { "DSA", "RSA" };
	if(algo == HIP_HI_DSA)
		str = algos[0];
	else if(algo == HIP_HI_RSA)
		str = algos[1];
	return str;
}


/**
 * hip_birthday_success - compare two birthday counters
 * @param old_bd birthday counter
 * @param new_bd birthday counter used when comparing against old_bd
 *
 * @return 1 (true) if new_bd is newer than old_bd, 0 (false) otherwise.
 */
int hip_birthday_success(uint64_t old_bd, uint64_t new_bd){
	return new_bd > old_bd;
}


/**
 * hip_enc_key_length - get encryption key length of a transform
 * @param tid transform
 *
 * @return the encryption key length based on the chosen transform,
 * otherwise < 0 on error.
 */
int hip_enc_key_length(int tid){
	int ret = -1;

	switch(tid) {
	case HIP_ESP_AES_SHA1:
		ret = 16;
		break;
	case HIP_ESP_3DES_SHA1:
		ret = 24;
		break;
	case HIP_ESP_NULL_SHA1:
	case HIP_ESP_NULL_NULL:
		ret = 0;
		break;
	default:
		HIP_ERROR("unknown tid=%d\n", tid);
		HIP_ASSERT(0);
		break;
	}

	return ret;
}


int hip_hmac_key_length(int tid){
	int ret = -1;
	switch(tid) {
       	case HIP_ESP_AES_SHA1:
	case HIP_ESP_3DES_SHA1:
	case HIP_ESP_NULL_SHA1:
		ret = 20;
		break;
	case HIP_ESP_NULL_NULL:
		ret = 0;
		break;
	default:
		HIP_ERROR("unknown tid=%d\n", tid);
		HIP_ASSERT(0);
		break;
	}

	return ret;
}


/**
 * hip_transform_key_length - get transform key length of a transform
 * @param tid transform
 *
 * @return the transform key length based on the chosen transform,
 * otherwise < 0 on error.
 */
int hip_transform_key_length(int tid){
	int ret = -1;

	switch(tid) {
	case HIP_HIP_AES_SHA1:
		ret = 16;
		break;
	case HIP_HIP_3DES_SHA1:
		ret = 24;
		break;
	case HIP_HIP_NULL_SHA1: // XX FIXME: SHOULD BE NULL_SHA1?
		ret = 0;
		break;
	default:
		HIP_ERROR("unknown tid=%d\n", tid);
		HIP_ASSERT(0);
		break;
	}

	return ret;
}


/**
 * hip_auth_key_length_esp - get authentication key length of a transform
 * @param tid transform
 *
 * @return the authentication key length based on the chosen transform.
 * otherwise < 0 on error.
 */
int hip_auth_key_length_esp(int tid){
	int ret = -1;

	switch(tid) {
	case HIP_ESP_AES_SHA1:
		//ret = 16;
		//break;
	case HIP_ESP_NULL_SHA1:
	case HIP_ESP_3DES_SHA1:
		ret = 20;
		break;
	case HIP_ESP_NULL_NULL:
		ret = 0;
		break;
	default:
		HIP_ERROR("unknown tid=%d\n", tid);
		HIP_ASSERT(0);
		break;
	}

	return ret;
}


/**
 * hip_select_hip_transform - select a HIP transform to use
 * @param ht HIP_TRANSFORM payload where the transform is selected from
 *
 * @return the first acceptable Transform-ID, otherwise < 0 if no
 * acceptable transform was found. The return value is in host byte order.
 */
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht){
	hip_transform_suite_t tid = 0;
	int i;
	int length;
	hip_transform_suite_t *suggestion;

	length = ntohs(ht->length);
	suggestion = (hip_transform_suite_t *) &ht->suite_id[0];

	if ( (length >> 1) > 6) {
		HIP_ERROR("Too many transforms (%d)\n", length >> 1);
		goto out;
	}

	for (i=0; i<length; i++) {
		switch(ntohs(*suggestion)) {

		case HIP_HIP_AES_SHA1:
		case HIP_HIP_3DES_SHA1:
		case HIP_HIP_NULL_SHA1:
			tid = ntohs(*suggestion);
			goto out;
			break;

		default:
			/* Specs don't say what to do when unknown are found.
			 * We ignore.
			 */
			HIP_ERROR("Unknown HIP suite id suggestion (%u)\n",
				  ntohs(*suggestion));
			break;
		}
		suggestion++;
	}

 out:
	if(tid == 0)
		HIP_ERROR("None HIP transforms accepted\n");
	else
		HIP_DEBUG("Chose HIP transform: %d\n", tid);

	return tid;
}


/**
 * hip_select_esp_transform - select an ESP transform to use
 * @param ht ESP_TRANSFORM payload where the transform is selected from
 *
 * @return the first acceptable Suite-ID. otherwise < 0 if no
 * acceptable Suite-ID was found.
 */
hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht){
	hip_transform_suite_t tid = 0;
	int i;
	int length;
	hip_transform_suite_t *suggestion;

	length = hip_get_param_contents_len(ht);
	suggestion = (uint16_t*) &ht->suite_id[0];

	if (length > sizeof(struct hip_esp_transform) -
	    sizeof(struct hip_common)) {
		HIP_ERROR("Too many transforms\n");
		goto out;
	}

	for (i=0; i<length; i++) {
		switch(ntohs(*suggestion)) {

		case HIP_ESP_AES_SHA1:
		case HIP_ESP_NULL_NULL:
		case HIP_ESP_3DES_SHA1:
		case HIP_ESP_NULL_SHA1:
			tid = ntohs(*suggestion);
			goto out;
			break;
		default:
			/* Specs don't say what to do when unknowns are found.
			 * We ignore.
			 */
			HIP_ERROR("Unknown ESP suite id suggestion (%u)\n",
				  ntohs(*suggestion));
			break;
		}
		suggestion++;
	}

 out:
	HIP_DEBUG("Took ESP transform %d\n", tid);

	if(tid == 0)
		HIP_ERROR("Faulty ESP transform\n");

	return tid;
}

#ifndef __KERNEL__
int convert_string_to_address_v4(const char *str, struct in_addr *ip){
	int ret = 0, err = 0;

	ret = inet_pton(AF_INET, str, ip);
	HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -1,
		 "inet_pton: not a valid address family\n");
	HIP_IFEL((ret == 0), -1,
		 "inet_pton: %s: not a valid network address\n", str);
 out_err:
	return err;
}

int convert_string_to_address(const char *str,
			      struct in6_addr *ip6){
	int ret = 0, err = 0;
	struct in_addr ip4;

	ret = inet_pton(AF_INET6, str, ip6);
	HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -1,
		 "\"%s\" is not of valid address family.\n", str);
	if (ret > 0) {
                /* IPv6 address conversion was ok */
		_HIP_DEBUG_IN6ADDR("Converted IPv6", ip6);
		goto out_err;
	}

	/* Might be an ipv4 address (ret == 0). Lets catch it here. */
	err = convert_string_to_address_v4(str, &ip4);
	if (err)
		goto out_err;

	IPV4_TO_IPV6_MAP(&ip4, ip6);
	HIP_DEBUG("Mapped v4 to v6.\n");
	HIP_DEBUG_IN6ADDR("mapped v6", ip6);

 out_err:
	return err;
}


/* the lengths are in bits */
int khi_encode(unsigned char *orig, int orig_len,
	       unsigned char *encoded,
	       int encoded_len){
	BIGNUM *bn = NULL;
	int err = 0, shift = (orig_len - encoded_len) / 2,
	  len = encoded_len / 8 + ((encoded_len % 8) ? 1 : 0);

	HIP_IFEL((encoded_len > orig_len), -1, "len mismatch\n");
	HIP_IFEL((!(bn = BN_bin2bn(orig, orig_len / 8, NULL))), -1,
		 "BN_bin2bn\n");
	HIP_IFEL(!BN_rshift(bn, bn, shift), -1, "BN_lshift\n");
	HIP_IFEL(!BN_mask_bits(bn, encoded_len), -1,
		"BN_mask_bits\n");
	HIP_IFEL((bn2bin_safe(bn, encoded, len) != len), -1,
		  "BN_bn2bin_safe\n");

	_HIP_HEXDUMP("encoded: ", encoded, len);

 out_err:
	if(bn)
		BN_free(bn);
	return err;
}

/**
 * Calculates a Host Identity Tag (HIT) from a Host Identifier (HI).
 *
 * Calculates a Host Identity Tag (HIT) from a Host Identifier (HI) using DSA
 * encryption.
 *
 * @param  host_id  a pointer to a Host Identifier
 * @param  hit      a target buffer where to put the calculated HIT.
 * @param  hit_type type of the HIT (must be HIP_HIT_TYPE_HASH100).
 * @return          zero on success, negative otherwise.
 */
int hip_dsa_host_id_to_hit(const struct hip_host_id *host_id,
			   struct in6_addr *hit,
			   int hit_type){
       int err = 0, index;
       u8 digest[HIP_AH_SHA_LEN];
       u8 *key_rr = (u8 *) (host_id + 1); /* skip the header */
       /* hit excludes rdata but it is included in hi_length;
	  subtract rdata */
       unsigned int key_rr_len = ntohs(host_id->hi_length) -
 	 sizeof(struct hip_host_id_key_rdata);
       u8 *khi_data = NULL;
       u8 khi_context_id[] = HIP_KHI_CONTEXT_ID_INIT;
       int khi_data_len = key_rr_len + sizeof(khi_context_id);
       int khi_index = 0;

       _HIP_DEBUG("key_rr_len=%u\n", key_rr_len);
       HIP_IFE(hit_type != HIP_HIT_TYPE_HASH100, -ENOSYS);
       _HIP_HEXDUMP("key_rr", key_rr, key_rr_len);

       /* Hash Input :=  Context ID | Input */
       khi_data = HIP_MALLOC(khi_data_len, 0);
       khi_index = 0;
       memcpy(khi_data + khi_index, khi_context_id, sizeof(khi_context_id));
       khi_index += sizeof(khi_context_id);
       memcpy(khi_data + khi_index, key_rr, key_rr_len);
       khi_index += key_rr_len;

       HIP_ASSERT(khi_index == khi_data_len);

       _HIP_HEXDUMP("khi data", khi_data, khi_data_len);

       /* Hash :=  SHA1( Expand( Hash Input ) ) */
       HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, khi_data,
					khi_data_len, digest)), err,
		"Building of digest failed\n");

       _HIP_HEXDUMP("digest", digest, sizeof(digest));

       memset(hit, 0, sizeof(hip_hit_t));
       HIP_IFEL(khi_encode(digest, sizeof(digest) * 8,
			   ((u8 *) hit) + 3,
			   sizeof(hip_hit_t) * 8 - HIP_HIT_PREFIX_LEN),
		-1, "encoding failed\n");

       _HIP_DEBUG_HIT("HIT before prefix: ", hit);
       set_hit_prefix(hit);
       _HIP_DEBUG_HIT("HIT after prefix: ", hit);

 out_err:
       if (khi_data)
	       HIP_FREE(khi_data);

       return err;
}


int hip_host_id_to_hit(const struct hip_host_id *host_id,
		       struct in6_addr *hit,
		       int hit_type){
	int algo = hip_get_host_id_algo(host_id);
	int err = 0;

	if (algo == HIP_HI_DSA) {
		err = hip_dsa_host_id_to_hit(host_id, hit, hit_type);
	} else if (algo == HIP_HI_RSA) {
		err = hip_rsa_host_id_to_hit(host_id, hit, hit_type);
	} else {
		err = -ENOSYS;
	}

	return err;
}


int hip_private_dsa_host_id_to_hit(const struct hip_host_id *host_id,
				   struct in6_addr *hit,
				   int hit_type){
	int err = 0;
	struct hip_host_id *host_id_pub = NULL;
	int contents_len;
	int total_len;

	contents_len = hip_get_param_contents_len(host_id);
	total_len = hip_get_param_total_len(host_id);

	/*! \todo add an extra check for the T val */

	HIP_IFEL(contents_len <= 20, -EMSGSIZE, "Host id too short\n");

	/* Allocate enough space for host id; there will be 20 bytes extra
	   to avoid hassle with padding. */
	host_id_pub = (struct hip_host_id *)HIP_MALLOC(total_len, GFP_KERNEL);
	HIP_IFE(!host_id_pub, -EFAULT);
	memset(host_id_pub, 0, total_len);

	memcpy(host_id_pub, host_id,
	       sizeof(struct hip_tlv_common) + contents_len - DSA_PRIV);

	host_id_pub->hi_length = htons(ntohs(host_id_pub->hi_length) - DSA_PRIV);
	hip_set_param_contents_len(host_id_pub, contents_len - DSA_PRIV);

	_HIP_HEXDUMP("extracted pubkey", host_id_pub,
		     hip_get_param_total_len(host_id_pub));

	if (err = hip_dsa_host_id_to_hit(host_id_pub, hit, hit_type)) {
		HIP_ERROR("Failed to convert HI to HIT.\n");
		goto out_err;
	}

 out_err:

	if (host_id_pub)
		HIP_FREE(host_id_pub);

	return err;
}


int hip_private_rsa_host_id_to_hit(const struct hip_host_id *host_id,
				   struct in6_addr *hit,
				   int hit_type){
	int err = 0;
	struct hip_host_id *host_id_pub = NULL;
	int contents_len;
	int total_len;
	int rsa_priv_len;
	struct hip_rsa_keylen keylen;

	contents_len = hip_get_param_contents_len(host_id);
	total_len = hip_get_param_total_len(host_id);

	/* Allocate space for public key */
	host_id_pub = (struct hip_host_id *)HIP_MALLOC(total_len, GFP_KERNEL);
	HIP_IFE(!host_id_pub, -EFAULT);
	memset(host_id_pub, 0, total_len);

	/* Length of the private part of the RSA key d + p + q
	   is twice the length of the public modulus. 
	   dmp1 + dmq1 + iqmp is another 1.5 times */

	hip_get_rsa_keylen(host_id, &keylen, 1);
	rsa_priv_len = keylen.n * 7 / 2;

	memcpy(host_id_pub, host_id,
	       sizeof(struct hip_tlv_common) + contents_len - rsa_priv_len);

	host_id_pub->hi_length = htons(ntohs(host_id_pub->hi_length) - rsa_priv_len);
	hip_set_param_contents_len(host_id_pub, contents_len - rsa_priv_len);

	_HIP_HEXDUMP("extracted pubkey", host_id_pub,
				 hip_get_param_total_len(host_id_pub));

	if (err = hip_rsa_host_id_to_hit(host_id_pub, hit, hit_type)) {
		HIP_ERROR("Failed to convert HI to HIT.\n");
		goto out_err;
	}

 out_err:

	if (host_id_pub)
		HIP_FREE(host_id_pub);

	return err;
}


int hip_private_host_id_to_hit(const struct hip_host_id *host_id,
			       struct in6_addr *hit,
			       int hit_type){
	int algo = hip_get_host_id_algo(host_id);
	int err = 0;

	if (algo == HIP_HI_DSA) {
		err = hip_private_dsa_host_id_to_hit(host_id, hit,
						     hit_type);
	} else if (algo == HIP_HI_RSA) {
		err = hip_private_rsa_host_id_to_hit(host_id, hit,
						     hit_type);
	} else {
		err = -ENOSYS;
	}

	return err;
}


/**
 * check_and_create_dir - check and create a directory
 * @param dirname the name of the directory
 * @param mode creation mode for the directory, if it does not exist
 *
 * @return 0 if successful, or negative on error.
 */
int check_and_create_dir(char *dirname, mode_t mode){
	int err = 0;
	struct stat dir_stat;

	HIP_INFO("dirname=%s mode=%o\n", dirname, mode);
	err = stat(dirname, &dir_stat);
	if (err && errno == ENOENT) { /* no such file or directory */
		err = mkdir(dirname, mode);
		if (err) {
			HIP_ERROR("mkdir %s failed: %s\n", dirname,
				  strerror(errno));
		}
	} else if (err) {
		HIP_ERROR("stat %s failed: %s\n", dirname,
			  strerror(errno));
	}

	return err;
}


int hip_host_id_contains_private_key(struct hip_host_id *host_id){
	uint16_t len = hip_get_param_contents_len(host_id);
	u8 *buf = (u8 *)(host_id + 1);
	u8 t = *buf;

	return len >= 3 * (64 + 8 * t) + 2 * 20; /* PQGXY 3*(64+8*t) + 2*20 */
}


void change_key_file_perms(char *filenamebase){
  char *pubfilename = NULL;
  int pubfilename_len;

  pubfilename_len =
    strlen(filenamebase) + strlen(DEFAULT_PUB_FILE_SUFFIX) + 1;
  pubfilename = malloc(pubfilename_len);
  if (!pubfilename) {
    HIP_ERROR("malloc(%d) failed\n", pubfilename_len);
    goto out_err;
  }

  /* check retval */
  snprintf(pubfilename, pubfilename_len, "%s%s", filenamebase,
	   DEFAULT_PUB_FILE_SUFFIX);

  chmod(filenamebase, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
  chmod(pubfilename, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);

 out_err:
  if (pubfilename)
    HIP_FREE(pubfilename);

  return;
}

int hip_serialize_host_id_action(struct hip_common *msg, int action, int anon,
				 int use_default, const char *hi_fmt,
				 const char *hi_file, int rsa_key_bits,
				 int dsa_key_bits)
{
	int err = 0, ret = 0, dsa_key_rr_len = 0, rsa_key_rr_len = 0;
	int dsa_pub_key_rr_len = 0, rsa_pub_key_rr_len = 0;
	int fmt = HIP_KEYFILE_FMT_HIP_PEM;
	hip_hdr_type_t numeric_action = 0;
	char addrstr[INET6_ADDRSTRLEN], hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
	char *dsa_filenamebase = NULL, *rsa_filenamebase = NULL;
	char *dsa_filenamebase_pub = NULL, *rsa_filenamebase_pub = NULL;
	unsigned char *dsa_key_rr = NULL, *rsa_key_rr = NULL;
	unsigned char *dsa_pub_key_rr = NULL, *rsa_pub_key_rr = NULL;
	DSA *dsa_key = NULL, *dsa_pub_key = NULL;
	RSA *rsa_key = NULL, *rsa_pub_key = NULL;
	struct hip_lhi rsa_lhi, dsa_lhi, rsa_pub_lhi, dsa_pub_lhi;
	struct hip_host_id *dsa_host_id = NULL, *rsa_host_id = NULL;
	struct hip_host_id *dsa_pub_host_id = NULL, *rsa_pub_host_id = NULL;
	struct endpoint_hip *endpoint_dsa_hip = NULL;
	struct endpoint_hip *endpoint_dsa_pub_hip = NULL;
	struct endpoint_hip *endpoint_rsa_hip = NULL;
	struct endpoint_hip *endpoint_rsa_pub_hip = NULL;
	struct in6_addr *dsa_hit = NULL;

	memset(addrstr, '\0', INET6_ADDRSTRLEN);
	memset(hostname, '\0', HIP_HOST_ID_HOSTNAME_LEN_MAX);

	if (err = -gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1)) {
		HIP_ERROR("Failed to get hostname. Err is (%d).\n", err);
		goto out_err;
	}

	HIP_INFO("Using hostname: %s\n", hostname);

	HIP_IFEL((!use_default && strcmp(hi_fmt, "rsa") && strcmp(hi_fmt, "dsa")),
		 -ENOSYS, "Only RSA and DSA keys are supported\n");

	/* Set filenamebase (depending on whether the user supplied a
	   filenamebase or not) */
	if (!use_default) {
		if(!strcmp(hi_fmt, "dsa")) {
			dsa_filenamebase = malloc(strlen(hi_file) + 1);
			HIP_IFEL(!dsa_filenamebase, -ENOMEM,
				 "Could not allocate DSA filename.\n");
			memcpy(dsa_filenamebase, hi_file, strlen(hi_file));
		} else /*rsa*/ {
			rsa_filenamebase = malloc(strlen(hi_file) + 1);
			HIP_IFEL(!rsa_filenamebase, -ENOMEM,
				 "Could not allocate RSA filename.\n");
			memcpy(rsa_filenamebase, hi_file, strlen(hi_file));
		}
	} else { /* create dynamically default filenamebase */
		int rsa_filenamebase_len = 0, dsa_filenamebase_len = 0, ret;

		HIP_INFO("No key file given, using default.\n");

		/* Default_config_dir/default_host_dsa_key_file_base/
		   default_anon_hi_file_name_suffix\0 */
		/* Creation of default keys is called with hi_fmt = NULL,
		   adding is called separately for DSA, RSA anon and RSA pub */
		if (hi_fmt == NULL || !strcmp(hi_fmt, "dsa")) {
			dsa_filenamebase_len =
				strlen(DEFAULT_CONFIG_DIR) + strlen("/") +
				strlen(DEFAULT_HOST_DSA_KEY_FILE_BASE) + 1;
			dsa_filenamebase = malloc(HOST_ID_FILENAME_MAX_LEN);
			HIP_IFEL(!dsa_filenamebase, -ENOMEM,
				 "Could not allocate DSA filename.\n");

			ret = snprintf(dsa_filenamebase,
				       dsa_filenamebase_len +
				       strlen(DEFAULT_ANON_HI_FILE_NAME_SUFFIX),
				       "%s/%s%s",
				       DEFAULT_CONFIG_DIR,
				       DEFAULT_HOST_DSA_KEY_FILE_BASE,
				       DEFAULT_ANON_HI_FILE_NAME_SUFFIX);
			HIP_IFE(ret <= 0, -EINVAL);

			dsa_filenamebase_pub = malloc(HOST_ID_FILENAME_MAX_LEN);
			HIP_IFEL(!dsa_filenamebase_pub, -ENOMEM,
				 "Could not allocate DSA (pub) filename.\n");

			ret = snprintf(dsa_filenamebase_pub,
				       HOST_ID_FILENAME_MAX_LEN, "%s/%s%s",
				       DEFAULT_CONFIG_DIR,
				       DEFAULT_HOST_DSA_KEY_FILE_BASE,
				       DEFAULT_PUB_HI_FILE_NAME_SUFFIX);
			HIP_IFE(ret <= 0, -EINVAL);

			HIP_DEBUG("Using dsa (anon hi) filenamebase: %s\n",
				  dsa_filenamebase);
			HIP_DEBUG("Using dsa (pub hi) filenamebase: %s\n",
				  dsa_filenamebase_pub);
		}

		if (hi_fmt == NULL || !strcmp(hi_fmt, "rsa")) {
			rsa_filenamebase_len =
				strlen(DEFAULT_CONFIG_DIR) + strlen("/") +
				strlen(DEFAULT_HOST_RSA_KEY_FILE_BASE) + 1;

			if (anon || hi_fmt == NULL) {
				rsa_filenamebase =
					malloc(HOST_ID_FILENAME_MAX_LEN);
				HIP_IFEL(!rsa_filenamebase, -ENOMEM,
					 "Could not allocate RSA filename.\n");

				ret = snprintf(
					rsa_filenamebase,
					HOST_ID_FILENAME_MAX_LEN, "%s/%s%s",
					DEFAULT_CONFIG_DIR,
					DEFAULT_HOST_RSA_KEY_FILE_BASE,
					DEFAULT_ANON_HI_FILE_NAME_SUFFIX);

				HIP_IFE(ret <= 0, -EINVAL);

				HIP_DEBUG("Using RSA (anon HI) filenamebase: "\
					  "%s.\n", rsa_filenamebase);
			}

			if (!anon || hi_fmt == NULL) {
				rsa_filenamebase_pub =
					malloc(HOST_ID_FILENAME_MAX_LEN);
				HIP_IFEL(!rsa_filenamebase_pub, -ENOMEM,
					 "Could not allocate RSA (pub) "\
					 "filename.\n");

				ret = snprintf(
					rsa_filenamebase_pub,
					rsa_filenamebase_len +
					strlen(DEFAULT_PUB_HI_FILE_NAME_SUFFIX),
					"%s/%s%s", DEFAULT_CONFIG_DIR,
					DEFAULT_HOST_RSA_KEY_FILE_BASE,
					DEFAULT_PUB_HI_FILE_NAME_SUFFIX);

				HIP_IFE(ret <= 0, -EINVAL);

				HIP_DEBUG("Using RSA (pub HI) filenamebase: "\
					  "%s\n", rsa_filenamebase_pub);
			}
		}
	}

	switch(action) {
	case ACTION_NEW:
		/* zero means "do not send any message to hipd */
		numeric_action = 0;

		/* Default directory is created only in "hipconf new default hi" */
		if (use_default) {
			if (err = check_and_create_dir(
				    DEFAULT_CONFIG_DIR,
				    DEFAULT_CONFIG_DIR_MODE)) {
				HIP_ERROR("Could not create default "\
					  "directory.\n");
				goto out_err;
			}
		} else if (!use_default) {

			if (!strcmp(hi_fmt, "dsa")) {
				dsa_key = create_dsa_key(dsa_key_bits);
				HIP_IFEL(!dsa_key, -EINVAL,
					 "Creation of DSA key failed.\n");
				if (err = save_dsa_private_key(
					    dsa_filenamebase, dsa_key)) {

					HIP_ERROR("Saving of DSA key failed.\n");
					goto out_err;
				}
			} else { /*RSA*/
				rsa_key = create_rsa_key(rsa_key_bits);
				HIP_IFEL(!rsa_key, -EINVAL,
					 "Creation of RSA key failed.\n");
				if (err = save_rsa_private_key(rsa_filenamebase,
							       rsa_key)) {
					HIP_ERROR("Saving of RSA key failed.\n");
					goto out_err;
				}
			}
			HIP_DEBUG("Key saved.\n");
			break;
		}

		/* Using default */
		dsa_key = create_dsa_key(dsa_key_bits);
		HIP_IFEL(!dsa_key, -EINVAL,
			 "Creation of DSA key failed.\n");

		dsa_pub_key = create_dsa_key(dsa_key_bits);
		HIP_IFEL(!dsa_pub_key, -EINVAL,
			 "Creation of public DSA key failed.\n");

		rsa_key = create_rsa_key(rsa_key_bits);
		HIP_IFEL(!rsa_key, -EINVAL,
			 "Creation of RSA key failed.\n");

		rsa_pub_key = create_rsa_key(rsa_key_bits);
		HIP_IFEL(!dsa_pub_key, -EINVAL,
			 "Creation of public RSA key failed.\n");

		if (err = save_dsa_private_key(dsa_filenamebase, dsa_key)) {
			HIP_ERROR("Saving of DSA key failed.\n");
			goto out_err;
		}

		if (err = save_dsa_private_key(dsa_filenamebase_pub,
					       dsa_pub_key)) {
			HIP_ERROR("Saving of public DSA key failed.\n");
			goto out_err;
		}

		if (err = save_rsa_private_key(rsa_filenamebase, rsa_key)) {
			HIP_ERROR("Saving of RSA key failed.\n");
			goto out_err;
		}

		if (err = save_rsa_private_key(rsa_filenamebase_pub,
					       rsa_pub_key)) {
			HIP_ERROR("Saving of public RSA key failed.\n");
			goto out_err;
		}

		break;

	case ACTION_ADD:
	  numeric_action = SO_HIP_ADD_LOCAL_HI;

    if (!use_default) {
      if (!strcmp(hi_fmt, "dsa")) {
	if (err = load_dsa_private_key(dsa_filenamebase, &dsa_key)) {
	    HIP_ERROR("Loading of the DSA key failed\n");
	    goto out_err;
	}
	dsa_key_rr_len = dsa_to_dns_key_rr(dsa_key, &dsa_key_rr);
	HIP_IFEL(dsa_key_rr_len <= 0, -EFAULT, "dsa_key_rr_len <= 0\n");

	if (err = dsa_to_hip_endpoint(dsa_key, &endpoint_dsa_hip,
				anon ? HIP_ENDPOINT_FLAG_ANON : 0, hostname)) {
	    HIP_ERROR("Failed to allocate and build DSA endpoint.\n");
	    goto out_err;
	}
	if (err = hip_build_param_eid_endpoint(msg, endpoint_dsa_hip)) {
	    HIP_ERROR("Building of host id failed\n");
	    goto out_err;
	}

      } else { /*RSA*/
	if (err = load_rsa_private_key(rsa_filenamebase, &rsa_key)) {
	    HIP_ERROR("Loading of the RSA key failed\n");
	    goto out_err;
	}
	rsa_key_rr_len = rsa_to_dns_key_rr(rsa_key, &rsa_key_rr);
	HIP_IFEL(rsa_key_rr_len <= 0, -EFAULT, "rsa_key_rr_len <= 0\n");

	if (err = rsa_to_hip_endpoint(rsa_key, &endpoint_rsa_hip,
				  anon ? HIP_ENDPOINT_FLAG_ANON : 0,
				  hostname)) {
	    HIP_ERROR("Failed to allocate and build RSA endpoint.\n");
	    goto out_err;
	}
	if (err = hip_build_param_eid_endpoint(msg, endpoint_rsa_hip)) {
	    HIP_ERROR("Building of host id failed\n");
	    goto out_err;
	}

      }
      goto skip_host_id;
    }

    /* using default */

    HIP_IFEL(hi_fmt == NULL, -1, "Key type is null.\n");

    if (!strcmp(hi_fmt, "dsa")) {
	if (err = load_dsa_private_key(dsa_filenamebase, &dsa_key)) {
	    HIP_ERROR("Loading of the DSA key failed\n");
	    goto out_err;
	}

	dsa_key_rr_len = dsa_to_dns_key_rr(dsa_key, &dsa_key_rr);
	HIP_IFEL(dsa_key_rr_len <= 0, -EFAULT, "dsa_key_rr_len <= 0\n");

	if (err = dsa_to_hip_endpoint(dsa_key, &endpoint_dsa_hip,
			      HIP_ENDPOINT_FLAG_ANON, hostname)) {
	    HIP_ERROR("Failed to allocate and build DSA endpoint (anon).\n");
	    goto out_err;
	}

	if (err = hip_private_dsa_to_hit(dsa_key, dsa_key_rr,
				 HIP_HIT_TYPE_HASH100, &dsa_lhi.hit)) {
	    HIP_ERROR("Conversion from DSA to HIT failed\n");
	    goto out_err;
	}

	if (err = load_dsa_private_key(dsa_filenamebase_pub, &dsa_pub_key)) {
	    HIP_ERROR("Loading of the DSA key (pub) failed\n");
	    goto out_err;
	}

	dsa_pub_key_rr_len = dsa_to_dns_key_rr(dsa_pub_key, &dsa_pub_key_rr);
	HIP_IFEL(dsa_pub_key_rr_len <= 0, -EFAULT, "dsa_pub_key_rr_len <= 0\n");

	HIP_DEBUG_HIT("DSA HIT", &dsa_lhi.hit);

	if (err = hip_private_dsa_to_hit(dsa_pub_key, dsa_pub_key_rr,
				 HIP_HIT_TYPE_HASH100, &dsa_pub_lhi.hit)) {
	    HIP_ERROR("Conversion from DSA to HIT failed\n");
	    goto out_err;
	}
	HIP_DEBUG_HIT("DSA HIT", &dsa_pub_lhi.hit);

	if (err = dsa_to_hip_endpoint(dsa_pub_key,
					&endpoint_dsa_pub_hip, 0, hostname)) {
	    HIP_ERROR("Failed to allocate and build DSA endpoint (pub).\n");
	    goto out_err;
	}

    } else if (anon) { /* rsa anon */

	if (err = load_rsa_private_key(rsa_filenamebase, &rsa_key)) {
	    HIP_ERROR("Loading of the RSA key failed\n");
	    goto out_err;
	}

	rsa_key_rr_len = rsa_to_dns_key_rr(rsa_key, &rsa_key_rr);
	HIP_IFEL(rsa_key_rr_len <= 0, -EFAULT, "rsa_key_rr_len <= 0\n");

	if (err = rsa_to_hip_endpoint(rsa_key, &endpoint_rsa_hip,
					HIP_ENDPOINT_FLAG_ANON, hostname)) {
	    HIP_ERROR("Failed to allocate and build RSA endpoint (anon).\n");
	    goto out_err;
	}

	if (err = hip_private_rsa_to_hit(rsa_key, rsa_key_rr,
					HIP_HIT_TYPE_HASH100,  &rsa_lhi.hit)) {
	    HIP_ERROR("Conversion from RSA to HIT failed\n");
	    goto out_err;
	}
	HIP_DEBUG_HIT("RSA HIT", &rsa_lhi.hit);

    } else { /* rsa pub */

	if (err = load_rsa_private_key(rsa_filenamebase_pub, &rsa_pub_key)) {
	    HIP_ERROR("Loading of the RSA key (pub) failed\n");
	    goto out_err;
	}

	rsa_pub_key_rr_len = rsa_to_dns_key_rr(rsa_pub_key, &rsa_pub_key_rr);
	HIP_IFEL(rsa_pub_key_rr_len <= 0, -EFAULT, "rsa_pub_key_rr_len <= 0\n");

	if (err = rsa_to_hip_endpoint(rsa_pub_key,
					&endpoint_rsa_pub_hip, 0, hostname)) {
	    HIP_ERROR("Failed to allocate and build RSA endpoint (pub).\n");
	    goto out_err;
	}

	if (err = hip_private_rsa_to_hit(rsa_pub_key, rsa_pub_key_rr,
				 HIP_HIT_TYPE_HASH100, &rsa_pub_lhi.hit)) {
	    HIP_ERROR("Conversion from RSA to HIT failed\n");
	    goto out_err;
	}
	HIP_DEBUG_HIT("RSA HIT", &rsa_pub_lhi.hit);

    }

    break;
  } /* end switch */

  if (numeric_action == 0)
    goto skip_msg;

  if (!strcmp(hi_fmt, "dsa")) {

	if (err = hip_build_param_eid_endpoint(msg, endpoint_dsa_hip)) {
	    HIP_ERROR("Building of host id failed\n");
	    goto out_err;
	}
	if (err = hip_build_param_eid_endpoint(msg, endpoint_dsa_pub_hip)) {
	    HIP_ERROR("Building of host id failed\n");
	    goto out_err;
	}

  } else if (anon) {

	if (err = hip_build_param_eid_endpoint(msg, endpoint_rsa_hip)) {
	    HIP_ERROR("Building of host id failed\n");
	    goto out_err;
	}

  } else {

	if (err = hip_build_param_eid_endpoint(msg, endpoint_rsa_pub_hip)) {
	    HIP_ERROR("Building of host id failed\n");
	    goto out_err;
	}

  }

 skip_host_id:
  if (err = hip_build_user_hdr(msg, numeric_action, 0)) {
      HIP_ERROR("build hdr error %d\n", err);
      goto out_err;
  }

 skip_msg:

 out_err:
  if (dsa_filenamebase != NULL)
          change_key_file_perms(dsa_filenamebase);
  if (rsa_filenamebase != NULL)
          change_key_file_perms(rsa_filenamebase);
  if (dsa_filenamebase_pub != NULL)
          change_key_file_perms(dsa_filenamebase_pub);
  if (rsa_filenamebase_pub != NULL)
          change_key_file_perms(rsa_filenamebase_pub);

  if (dsa_host_id)
    free(dsa_host_id);
  if (dsa_pub_host_id)
    free(dsa_pub_host_id);
  if (rsa_host_id)
    free(rsa_host_id);
  if (rsa_pub_host_id)
    free(rsa_pub_host_id);
  if (dsa_key)
    DSA_free(dsa_key);
  if (rsa_key)
    RSA_free(rsa_key);
  if (dsa_pub_key)
    DSA_free(dsa_pub_key);
  if (rsa_pub_key)
    RSA_free(rsa_pub_key);
  if (dsa_key_rr)
    free(dsa_key_rr);
  if (rsa_key_rr)
    free(rsa_key_rr);
  if (dsa_pub_key_rr)
    free(dsa_pub_key_rr);
  if (rsa_pub_key_rr)
    free(rsa_pub_key_rr);
  if (dsa_filenamebase)
    free(dsa_filenamebase);
  if (rsa_filenamebase)
    free(rsa_filenamebase);
  if (dsa_filenamebase_pub)
    free(dsa_filenamebase_pub);
  if (rsa_filenamebase_pub)
    free(rsa_filenamebase_pub);
  if (endpoint_dsa_hip)
    free(endpoint_dsa_hip);
  if (endpoint_rsa_hip)
    free(endpoint_rsa_hip);
  if (endpoint_dsa_pub_hip)
    free(endpoint_dsa_pub_hip);
  if (endpoint_rsa_pub_hip)
    free(endpoint_rsa_pub_hip);

  return err;
}


int hip_any_sa_to_hit_sa(const struct sockaddr *from,
		         const hip_hit_t *use_hit,
		         struct sockaddr_in6 *to){
	to->sin6_family = AF_INET6;
	ipv6_addr_copy(&to->sin6_addr, use_hit);
	if (from->sa_family == AF_INET)
		to->sin6_port = ((struct sockaddr_in *) from)->sin_port;
	else if (from->sa_family == AF_INET6)
		to->sin6_port = ((struct sockaddr_in6 *) from)->sin6_port;
	else
		return -1;

	return 0;
}


void get_random_bytes(void *buf, int n)
{
	RAND_bytes(buf, n);
}


/**
 * hip_build_digest - calculate a digest over given data
 * @param type the type of digest, e.g. "sha1"
 * @param in the beginning of the data to be digested
 * @param in_len the length of data to be digested in octets
 * @param out the digest
 *
 * @param out should be long enough to hold the digest. This cannot be
 * checked!
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_digest(const int type, const void *in, int in_len, void *out){
	SHA_CTX sha;
	MD5_CTX md5;

	switch(type) {
	case HIP_DIGEST_SHA1:
		SHA1_Init(&sha);
		SHA1_Update(&sha, in, in_len);
		SHA1_Final(out, &sha);
		break;

	case HIP_DIGEST_MD5:
		MD5_Init(&md5);
		MD5_Update(&md5, in, in_len);
		MD5_Final(out, &md5);
		break;

	default:
		HIP_ERROR("Unknown digest: %x\n",type);
		return -EFAULT;
	}

	return 0;
}

/**
 * dsa_to_dns_key_rr - create DNS KEY RR record from host DSA key
 * @param dsa the DSA structure from where the KEY RR record is to be created
 * @param dsa_key_rr where the resultin KEY RR is stored
 *
 * Caller must free dsa_key_rr when it is not used anymore.
 *
 * @return On successful operation, the length of the KEY RR buffer is
 * returned (greater than zero) and pointer to the buffer containing
 * DNS KEY RR is stored at dsa_key_rr. On error function returns negative
 * and sets dsa_key_rr to NULL.
 */
int dsa_to_dns_key_rr(DSA *dsa, unsigned char **dsa_key_rr){
  int err = 0;
  int dsa_key_rr_len = -1;
  signed char t; /* in units of 8 bytes */
  unsigned char *p;
  int key_len;

  HIP_ASSERT(dsa != NULL); /* should not happen */

  *dsa_key_rr = NULL;

  _HIP_DEBUG("numbytes p=%d\n", BN_num_bytes(dsa->p));
  _HIP_DEBUG("numbytes q=%d\n", BN_num_bytes(dsa->q));
  _HIP_DEBUG("numbytes g=%d\n", BN_num_bytes(dsa->g));
  _HIP_DEBUG("numbytes pubkey=%d\n", BN_num_bytes(dsa->pub_key)); // shouldn't this be NULL also?

  /* notice that these functions allocate memory */
  _HIP_DEBUG("p=%s\n", BN_bn2hex(dsa->p));
  _HIP_DEBUG("q=%s\n", BN_bn2hex(dsa->q));
  _HIP_DEBUG("g=%s\n", BN_bn2hex(dsa->g));
  _HIP_DEBUG("pubkey=%s\n", BN_bn2hex(dsa->pub_key));

  /* ***** is use of BN_num_bytes ok ? ***** */
  t = (BN_num_bytes(dsa->p) - 64) / 8;
  HIP_IFEL((t < 0 || t > 8), -EINVAL,
			"Invalid RSA key length %d bits\n", (64 + t * 8) * 8);
  _HIP_DEBUG("t=%d\n", t);

  /* RFC 2536 section 2 */
  /*
           Field     Size
           -----     ----
            T         1  octet
            Q        20  octets
            P        64 + T*8  octets
            G        64 + T*8  octets
            Y        64 + T*8  octets
	  [ X        20 optional octets (private key hack) ]

  */
  key_len = 64 + t * 8;
  dsa_key_rr_len = 1 + DSA_PRIV + 3 * key_len;

  if (dsa->priv_key) {
    dsa_key_rr_len += DSA_PRIV; /* private key hack */
    _HIP_DEBUG("Private key included\n");
  } else {
    _HIP_DEBUG("No private key\n");
  }

  _HIP_DEBUG("dsa key rr len = %d\n", dsa_key_rr_len);
  *dsa_key_rr = malloc(dsa_key_rr_len);
  HIP_IFEL(!*dsa_key_rr, -ENOMEM, "Malloc for *dsa_key_rr failed\n");
  memset(*dsa_key_rr, 0, dsa_key_rr_len);

  p = *dsa_key_rr;

  /* set T */
  memset(p, t, 1); // XX FIX: WTF MEMSET?
  p++;
  _HIP_HEXDUMP("DSA KEY RR after T:", *dsa_key_rr, p - *dsa_key_rr);

  /* add given dsa_param to the *dsa_key_rr */

  bn2bin_safe(dsa->q, p, DSA_PRIV);
  p += DSA_PRIV;
  _HIP_HEXDUMP("DSA KEY RR after Q:", *dsa_key_rr, p-*dsa_key_rr);

  bn2bin_safe(dsa->p, p, key_len);
  p += key_len;
  _HIP_HEXDUMP("DSA KEY RR after P:", *dsa_key_rr, p-*dsa_key_rr);

  bn2bin_safe(dsa->g, p, key_len);
  p += key_len;
  _HIP_HEXDUMP("DSA KEY RR after G:", *dsa_key_rr, p-*dsa_key_rr);

  bn2bin_safe(dsa->pub_key, p, key_len);
  p += key_len;
  _HIP_HEXDUMP("DSA KEY RR after Y:", *dsa_key_rr, p-*dsa_key_rr);

  if(dsa->priv_key){
      bn2bin_safe(dsa->priv_key, p, DSA_PRIV);
      _HIP_HEXDUMP("DSA KEY RR after X:", *dsa_key_rr, p-*dsa_key_rr);
  }

 out_err:

  if (err) {
    if (*dsa_key_rr)
	free(*dsa_key_rr);
    return err;
  }
  else
    return dsa_key_rr_len;
}


/**
 * rsa_to_dns_key_rr - This is a new version of the function above. This function
 *                     assumes that RSA given as a parameter is always public (Laura/10.4.2006)
                       Creates DNS KEY RR record from host RSA public key
 * @param rsa the RSA structure from where the KEY RR record is to be created
 * @param rsa_key_rr where the resultin KEY RR is stored
 *
 * Caller must free rsa_key_rr when it is not used anymore.
 *
 * @return On successful operation, the length of the KEY RR buffer is
 * returned (greater than zero) and pointer to the buffer containing
 * DNS KEY RR is stored at rsa_key_rr. On error function returns negative
 * and sets rsa_key_rr to NULL.
 */
int rsa_to_dns_key_rr(RSA *rsa, unsigned char **rsa_key_rr){
  int err = 0;
  int rsa_key_rr_len = -1;
  unsigned char *c;
  int public = -1;
  int e_len_bytes = 1;
  int e_len, key_len;

  HIP_ASSERT(rsa != NULL); // should not happen

  *rsa_key_rr = NULL;

  e_len = BN_num_bytes(rsa->e);
  key_len = RSA_size(rsa);

  /* RFC 3110 limits e to 4096 bits */
  HIP_IFEL(e_len > 512, -EINVAL,  "Invalid rsa->e length %d bytes\n", e_len);
  if (e_len > 255)
	e_len_bytes = 3;

  /* let's check if the RSA key is public or private
     private exponent is NULL in public keys */
  if(rsa->d == NULL) {
    public = 1;
    rsa_key_rr_len = e_len_bytes + e_len + key_len;

    /*
       See RFC 2537 for flags, protocol and algorithm and check RFC 3110 for
       the RSA public key part ( 1-3 octets defining length of the exponent,
       exponent is as many octets as the length defines and the modulus is
       all the rest of the bytes).

       2 bytes for flags, 1 byte for protocol and 1 byte for algorithm = 4 bytes
    */
    /* Doesn't the rdata struct hold this? Function doesn't write it. */
    // rsa_key_rr_len += 4;

  } else{
    public = 0;
    rsa_key_rr_len = e_len_bytes + e_len + key_len * 9 / 2;

  }

  *rsa_key_rr = malloc(rsa_key_rr_len);
  HIP_IFEL(!*rsa_key_rr, -ENOMEM, "Malloc for *rsa_key_rr failed\n");
  memset(*rsa_key_rr, 0, rsa_key_rr_len);

  c = *rsa_key_rr;

  if (e_len_bytes == 1) {
	*c = (unsigned char) e_len;
  }
  c++; /* If e_len is more than one byte, first byte is 0. */
  if (e_len_bytes == 3) {
	*c = htons((u16) e_len);
	c += 2;
  }

  bn2bin_safe(rsa->e, c, e_len);
  c += e_len;
  bn2bin_safe(rsa->n, c, key_len);
  c += key_len;

  if(!public){
          bn2bin_safe(rsa->d, c, key_len);
          c += key_len;
          bn2bin_safe(rsa->p, c, key_len / 2);
          c += key_len / 2;
          bn2bin_safe(rsa->q, c, key_len / 2);
          c += key_len / 2;
          bn2bin_safe(rsa->dmp1, c, key_len / 2);
          c += key_len / 2;
          bn2bin_safe(rsa->dmq1, c, key_len / 2);
          c += key_len / 2;
          bn2bin_safe(rsa->iqmp, c, key_len / 2);
  }

 out_err:

  if (err) {
    if (*rsa_key_rr)
	free(*rsa_key_rr);
    return err;
  }

  return rsa_key_rr_len;
}

/**
 * Casts a socket address to an IPv4 or IPv6 address.
 *
 * The parameter @c sockaddr is first cast to a struct sockaddr and the IP
 * address cast is then done based on the value of the sa_family field in the
 * struct sockaddr. If sa_family is neither AF_INET nor AF_INET6, the cast
 * fails.
 *
 * @param  sockaddr a pointer to a socket address that holds the IP address.
 * @return          a pointer to an IPv4 or IPv6 address inside @c sockaddr or
 *                  NULL if the cast fails.
 */

void *hip_cast_sa_addr(void *sockaddr) {
	struct sockaddr *sa = (struct sockaddr *) sockaddr;
	void *ret = NULL;

	switch(sa->sa_family) {
	case AF_INET:
		ret = &(((struct sockaddr_in *) sockaddr)->sin_addr);
		break;
	case AF_INET6:
		ret = &(((struct sockaddr_in6 *) sockaddr)->sin6_addr);
		break;
	default:
		ret = NULL;
	}

	return ret;
}

int hip_sockaddr_is_v6_mapped(struct sockaddr *sa) {
  int family = sa->sa_family;

  HIP_ASSERT(family == AF_INET || family == AF_INET6);
  if (family != AF_INET6)
    return 0;
  else
    return IN6_IS_ADDR_V4MAPPED((struct in6_addr *)hip_cast_sa_addr(sa));
}

int hip_sockaddr_len(const void *sockaddr) {
  struct sockaddr *sa = (struct sockaddr *) sockaddr;
  int len;

  switch(sa->sa_family) {
  case AF_INET:
    len = sizeof(struct sockaddr_in);
    break;
  case AF_INET6:
    len = sizeof(struct sockaddr_in6);
    break;
  case_AF_UNIX:
    len = sizeof(struct sockaddr_un);
    break;
  default:
    len = 0;
  }
  return len;
}


int hip_sa_addr_len(void *sockaddr){
  struct sockaddr *sa = (struct sockaddr *) sockaddr;
  int len;

  switch(sa->sa_family){
  case AF_INET:
    len = 4;
    break;
  case AF_INET6:
    len = 16;
    break;
  default:
    len = 0;
  }
  return len;
}


/* conversion function from in6_addr to sockaddr_storage
 *
 * NOTE: sockaddr too small to store sockaddr_in6 */
void hip_addr_to_sockaddr(struct in6_addr *addr, struct sockaddr_storage *sa)
{
	memset(sa, 0, sizeof(struct sockaddr_storage));

	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		struct sockaddr_in *in = (struct sockaddr_in *) sa;
		in->sin_family = AF_INET;
		IPV6_TO_IPV4_MAP(addr, &in->sin_addr);
	} else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) sa;
		in6->sin6_family = AF_INET6;
		ipv6_addr_copy(&in6->sin6_addr, addr);
	}
}


int hip_remove_lock_file(char *filename){
	return unlink(filename);
}


int hip_create_lock_file(char *filename, int killold) {

	int err = 0, fd = 0, old_pid = 0, new_pid_str_len = 0;
	char old_pid_str[64], new_pid_str[64];

	memset(old_pid_str, 0, sizeof(old_pid_str));
	memset(new_pid_str, 0, sizeof(new_pid_str));

	/* New pid */
	snprintf(new_pid_str, sizeof(new_pid_str)-1, "%d\n", getpid());
	new_pid_str_len = strnlen(new_pid_str, sizeof(new_pid_str) - 1);
	HIP_IFEL((new_pid_str_len <= 0), -1, "pID length error.\n");

	/* Read old pid */

	fd = HIP_CREATE_FILE(filename);
	HIP_IFEL((fd <= 0), -1, "opening lock file failed\n");

	read(fd, old_pid_str, sizeof(old_pid_str) - 1);
	old_pid = atoi(old_pid_str);

	if (lockf(fd, F_TLOCK, 0) < 0)
	{
		HIP_IFEL(!killold, -12,
			 "\nHIP daemon already running with pid %d\n"
			 "Give: -k option to kill old daemon.\n", old_pid);

		HIP_INFO("\nDaemon is already running with pid %d\n"
			 "-k option given, terminating old one...\n", old_pid);
		/* Erase the old lock file to avoid having multiple pids
		   in the file */
		lockf(fd, F_ULOCK, 0);
		close(fd);
		HIP_IFEL(hip_remove_lock_file(filename), -1,
			 "Removing lock file failed.\n");

                /* fd = open(filename, O_RDWR | O_CREAT, 0644); */
		fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);

                /* Don't close file descriptor because new started process is
		   running. */
		HIP_IFEL((fd <= 0), -1, "Opening lock file failed.\n");
		HIP_IFEL(lockf(fd, F_TLOCK, 0), -1, "Lock attempt failed.\n");

		err = kill(old_pid, SIGKILL);
		if (err != 0) {
			HIP_ERROR("\nError when trying to send signal SIGKILL "\
				  "process identified by process identifier "\
				  "%d.\n", old_pid);
			HIP_PERROR("errno after kill() is: ");
		}
	}
	/* else if (killold)
	   {
	   lseek(fd,0,SEEK_SET);
	   write(fd, new_pid_str, new_pid_str_len);
	   system("NEW_PID=$(sudo awk NR==1 /var/lock/hipd.lock)");
	   system("OLD_PID=$(/bin/pidof -o $NEW_PID hipd)");
	   system("kill -9 $OLD_PID");
	   } */

	lseek(fd, 0, SEEK_SET);

	HIP_IFEL((write(fd, new_pid_str, new_pid_str_len) != new_pid_str_len),
		 -1, "Writing new process identifier failed.\n");

 out_err:
	if (err == -12) {
		exit(0);
	}

	return err;
}

/**
 * hip_solve_puzzle - Solve puzzle.
 * @param puzzle_or_solution Either a pointer to hip_puzzle or hip_solution structure
 * @param hdr The incoming R1/I2 packet header.
 * @param mode Either HIP_VERIFY_PUZZLE of HIP_SOLVE_PUZZLE
 *
 * The K and I is read from the @c puzzle_or_solution.
 *
 * The J that solves the puzzle is returned, or 0 to indicate an error.
 * NOTE! I don't see why 0 couldn't solve the puzzle too, but since the
 * odds are 1/2^64 to try 0, I don't see the point in improving this now.
 */
uint64_t hip_solve_puzzle(void *puzzle_or_solution,
			  struct hip_common *hdr,
			  int mode){
	uint64_t mask = 0;
	uint64_t randval = 0;
	uint64_t maxtries = 0;
	uint64_t digest = 0;
	u8 cookie[48];
	int err = 0;
	union {
		struct hip_puzzle pz;
		struct hip_solution sl;
	} *u;

	HIP_HEXDUMP("puzzle", puzzle_or_solution,
		    (mode == HIP_VERIFY_PUZZLE ? sizeof(struct hip_solution) : sizeof(struct hip_puzzle)));

	_HIP_DEBUG("\n");
	/* pre-create cookie */
	u = puzzle_or_solution;

	_HIP_DEBUG("current hip_cookie_max_k_r1=%d\n", max_k);
	HIP_IFEL(u->pz.K > HIP_PUZZLE_MAX_K, 0,
		 "Cookie K %u is higher than we are willing to calculate"
		 " (current max K=%d)\n", u->pz.K, HIP_PUZZLE_MAX_K);

	mask = hton64((1ULL << u->pz.K) - 1);
	memcpy(cookie, (u8 *)&(u->pz.I), sizeof(uint64_t));

	HIP_DEBUG("(u->pz.I: 0x%llx\n", u->pz.I);

	if (mode == HIP_VERIFY_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hits);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hitr);
		//randval = ntoh64(u->sl.J);
		randval = u->sl.J;
		_HIP_DEBUG("u->sl.J: 0x%llx\n", randval);
		maxtries = 1;
	} else if (mode == HIP_SOLVE_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hitr);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hits);
		maxtries = 1ULL << (u->pz.K + 3);
		get_random_bytes(&randval, sizeof(u_int64_t));
	} else {
		HIP_IFEL(1, 0, "Unknown mode: %d\n", mode);
	}

	HIP_DEBUG("K=%u, maxtries (with k+2)=%llu\n", u->pz.K, maxtries);
	/* while loops should work even if the maxtries is unsigned
	 * if maxtries = 1 ---> while(1 > 0) [maxtries == 0 now]...
	 * the next round while (0 > 0) [maxtries > 0 now]
	 */
	while(maxtries-- > 0) {
	 	u8 sha_digest[HIP_AH_SHA_LEN];

		/* must be 8 */
		memcpy(cookie + 40, (u8*) &randval, sizeof(uint64_t));

		hip_build_digest(HIP_DIGEST_SHA1, cookie, 48, sha_digest);

                /* copy the last 8 bytes for checking */
		memcpy(&digest, sha_digest + 12, sizeof(uint64_t));

		/* now, in order to be able to do correctly the bitwise
		 * AND-operation we have to remember that little endian
		 * processors will interpret the digest and mask reversely.
		 * digest is the last 64 bits of the sha1-digest.. how that is
		 * ordered in processors registers etc.. does not matter to us.
		 * If the last 64 bits of the sha1-digest is
		 * 0x12345678DEADBEEF, whether we have 0xEFBEADDE78563412
		 * doesn't matter because the mask matters... if the mask is
		 * 0x000000000000FFFF (or in other endianness
		 * 0xFFFF000000000000). Either ways... the result is
		 * 0x000000000000BEEF or 0xEFBE000000000000, which the cpu
		 * interprets as 0xBEEF. The mask is converted to network byte
		 * order (above).
		 */
		if ((digest & mask) == 0) {
			_HIP_DEBUG("*** Puzzle solved ***: 0x%llx\n",randval);
			_HIP_HEXDUMP("digest", sha_digest, HIP_AH_SHA_LEN);
			_HIP_HEXDUMP("cookie", cookie, sizeof(cookie));
			return randval;
		}

		/* It seems like the puzzle was not correctly solved */
		HIP_IFEL(mode == HIP_VERIFY_PUZZLE, 0, "Puzzle incorrect\n");
		randval++;
	}

	HIP_ERROR("Could not solve the puzzle, no solution found\n");
 out_err:
	return err;
}

/**
 * Gets the state of the bex for a pair of ip addresses.
 * @param *src_ip	input for finding the correct entries
 * @param *dst_ip	input for finding the correct entries
 * @param *src_hit	output data of the correct entry
 * @param *dst_hit	output data of the correct entry
 * @param *src_lsi	output data of the correct entry
 * @param *dst_lsi	output data of the correct entry
 *
 * @return		the state of the bex if the entry is found
 *			otherwise returns -1
 */
int hip_get_bex_state_from_LSIs(hip_lsi_t       *src_lsi,
				hip_lsi_t       *dst_lsi,
				struct in6_addr *src_ip,
				struct in6_addr *dst_ip,
				struct in6_addr *src_hit,
				struct in6_addr *dst_hit){
	int err = 0, res = -1;
	struct hip_tlv_common *current_param = NULL;
	struct hip_common *msg = NULL;
	struct hip_hadb_user_info_state *ha;

	HIP_ASSERT(src_ip != NULL && dst_ip != NULL);

	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0),
			-1, "Building of daemon header failed\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send recv daemon info\n");

	while((current_param = hip_get_next_param(msg, current_param)) != NULL) {
		ha = hip_get_param_contents_direct(current_param);

		if( (ipv4_addr_cmp(dst_lsi, &ha->lsi_our) == 0)  &&
		    (ipv4_addr_cmp(src_lsi, &ha->lsi_peer) == 0)    ){
			*src_hit = ha->hit_peer;
			*dst_hit = ha->hit_our;
			*src_ip = ha->ip_peer;
			*dst_ip = ha->ip_our;
			res = ha->state;
			break;
		}else if( (ipv4_addr_cmp(src_lsi, &ha->lsi_our) == 0)  &&
		          (ipv4_addr_cmp(dst_lsi, &ha->lsi_peer) == 0)    ){
			*src_hit = ha->hit_our;
			*dst_hit = ha->hit_peer;
			*src_ip = ha->ip_our;
			*dst_ip = ha->ip_peer;
			res = ha->state;
			break;
		}
	}

 out_err:
        if(msg)
                HIP_FREE(msg);
        return res;

}

/**
 * Obtains the information needed by the dns proxy, based on the ip addr
 * 
 * @param *ip_addr	input, the ip address to look for
 * @param *hit		output, the corresponding hit
 * @param *lsi		output, the corresponding lsi	
 * 
 * @return		1 - if a corresponding entry is found
 * 			0 - is returned if there is no entry
 */
/*int hip_get_info_for_dnsproxy_from_ip(
				struct in6_addr *ip_addr,
				struct in6_addr *hit,
				hip_lsi_t       *lsi){
	int err = 0, res = 0;
	hip_lsi_t src_ip4, dst_ip4;
	struct hip_tlv_common *current_param = NULL;
	struct hip_common *msg = NULL;
	struct hip_hadb_user_info_state *ha;
  
	HIP_ASSERT(ip_addr != NULL);

	HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0),
				-1, "Building of daemon header failed\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send recv daemon info\n");

	while((current_param = hip_get_next_param(msg, current_param)) != NULL){
		ha = hip_get_param_contents_direct(current_param);
		if(ipv6_addr_cmp(ip_addr, &ha->ip_our) == 0){
			*hit = ha->hit_our;
			*lsi = ha->lsi_our;
			res = 1;
			break;
		}
		else if(ipv6_addr_cmp(ip_addr, &ha->ip_peer) == 0){
			*hit = ha->hit_peer;
			*lsi = ha->lsi_peer;
			res = 1;
			break;
		}
	}
out_err:
        if(msg)
                HIP_FREE(msg);  
        return res;
}
*/

/**
 * Obtains the information needed by the dns proxy, based on the hostname
 * 
 * @param *hostname	input, the ip address to look for
 * @param *hit		output, the corresponding hit
 * @param *lsi		output, the corresponding lsi	
 * 
 * @return		1 - if a corresponding entry is found
 * 			0 - is returned if there is no entry
 */
/*int hip_get_info_for_dnsproxy_from_hostname(
				const char      *hostname,
				struct in6_addr *ip,
				struct in6_addr *hit,
				hip_lsi_t       *lsi){
	int err = 0, res = 0;
	hip_lsi_t src_ip4, dst_ip4;
	struct hip_tlv_common *current_param = NULL;
	struct hip_common *msg = NULL;
	struct hip_hadb_user_info_state *ha;
  
	HIP_ASSERT(hostname != NULL);

	HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0),
				-1, "Building of daemon header failed\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send recv daemon info\n");

	while((current_param = hip_get_next_param(msg, current_param)) != NULL){
		ha = hip_get_param_contents_direct(current_param);

		if(strcmp(hostname, &ha->peer_hostname) == 0){
			*ip =  ha->ip_peer;
			*hit = ha->hit_peer;
			*lsi = ha->lsi_peer;
			res = 1;
			break;
		}
	}

out_err:
        if(msg)
                HIP_FREE(msg);  
        return res;
}
*/











/* This builds a msg which will be sent to the HIPd in order to trigger
 * a BEX there.
 *
 * TODO move that to useripsec.c?
 *         No, because this function is called by hip_fw_handle_outgoing_lsi too.
 *
 * NOTE: Either destination HIT or IP (for opportunistic BEX) has to be provided */
int hip_trigger_bex(struct in6_addr *src_hit, struct in6_addr *dst_hit,
		    struct in6_addr *src_lsi, struct in6_addr *dst_lsi,
		    struct in6_addr *src_ip,  struct in6_addr *dst_ip){
        struct hip_common *msg = NULL;
        int err = 0;

        HIP_IFE(!(msg = hip_msg_alloc()), -1);
        HIP_IFEL(!dst_hit && !dst_ip, -1,
		 "neither destination hit nor ip provided\n");

        /* NOTE: we need this sequence in order to process the incoming
	   message correctly */

        // destination HIT is obligatory or opportunistic BEX
        if(dst_hit) {
		HIP_DEBUG_HIT("dst_hit: ", dst_hit);
	        HIP_IFEL(hip_build_param_contents(msg, (void *)(dst_hit),
                                                  HIP_PARAM_HIT,
					          sizeof(struct in6_addr)),
				-1, "build param HIP_PARAM_HIT failed\n");
	}

        // source HIT is optional
        if(src_hit) {
		HIP_DEBUG_HIT("src_hit: ", src_hit);
	        HIP_IFEL(hip_build_param_contents(msg, (void *)(src_hit),
						  HIP_PARAM_HIT,
						  sizeof(struct in6_addr)),
				-1, "build param HIP_PARAM_HIT failed\n");
	}

        // destination LSI is obligatory
        if(dst_lsi) {
		HIP_DEBUG_IN6ADDR("dst lsi: ", dst_lsi);
                HIP_IFEL(hip_build_param_contents(msg, (void *)(dst_lsi),
                                                  HIP_PARAM_LSI,
                                                  sizeof(struct in6_addr)),
				-1, "build param HIP_PARAM_LSI failed\n");
	}

        // source LSI is optional
        if(src_lsi) {
		HIP_DEBUG_IN6ADDR("src lsi: ", src_lsi);
		HIP_IFEL(hip_build_param_contents(msg, (void *)(src_lsi),
						  HIP_PARAM_LSI,
						  sizeof(struct in6_addr)),
				-1, "build param HIP_PARAM_LSI failed\n");
	}

        // if no destination HIT is provided this has to be there
        if(dst_ip) {
		HIP_DEBUG_IN6ADDR("dst_ip: ", dst_ip);
                HIP_IFEL(hip_build_param_contents(msg, (void *)(dst_ip),
                                                  HIP_PARAM_IPV6_ADDR,
                                                  sizeof(struct in6_addr)),
				-1, "build param HIP_PARAM_IPV6_ADDR failed\n");
	}

        // this again is optional
        if (src_ip) {
		HIP_DEBUG_IN6ADDR("src_ip: ", src_ip);
        	HIP_IFEL(hip_build_param_contents(msg, (void *)(src_ip),
						  HIP_PARAM_IPV6_ADDR,
						  sizeof(struct in6_addr)),
				-1, "build param HIP_PARAM_IPV6_ADDR failed\n");
	}

        /* build the message header */
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_TRIGGER_BEX, 0),
					-1, "build hdr failed\n");

        HIP_DUMP_MSG(msg);

        /* send msg to hipd and receive corresponding reply */
        HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");

        /* check error value */
        HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
        HIP_DEBUG("Send_recv msg succeed \n");

 out_err:
        if (msg)
                HIP_FREE(msg);
        return err;
}

/**
 * Checks whether there is a local ipv6 socket that is:
 *   connected to a particular port
 *   connected to an lsi ip address.
 *
 * @param port_dest	the port number of the socket
 * @param *proto	protocol type
 *
 * @return		1 if it finds the required socket
 * 			0 otherwise
 */
int hip_get_proto_info(in_port_t port_dest, char *proto) {
        FILE *fd = NULL;
        char line[500], sub_string_addr_hex[8], path[11+sizeof(proto)];
        char *fqdn_str = NULL, *separator = NULL, *sub_string_port_hex = NULL;
	int lineno = 0, index_addr_port = 0, exists = 0, result;
        uint32_t result_addr;
	struct in_addr addr;
        List list;

	if (!proto)
		return 0;

	if (!strcmp(proto, "tcp6") || !strcmp(proto, "tcp"))
		index_addr_port = 15;
	else if (!strcmp(proto, "udp6") || !strcmp(proto,"udp"))
		index_addr_port = 10;
	else
		return 0;

	strcpy(path,"/proc/net/"); 
	strcat(path, proto);
        fd = fopen(path, "r");		
        
	initlist(&list);
        while (fd && getwithoutnewline(line, 500, fd) != NULL && !exists) {
		lineno++;

		destroy(&list);
		initlist(&list);
		
		if (lineno == 1 || strlen(line) <=1)
			continue;

	        extractsubstrings(line, &list); 

	        fqdn_str = getitem(&list, index_addr_port);
	        if (fqdn_str)
			separator = strrchr(fqdn_str, ':');

	        if (!separator)
			continue;

		sub_string_port_hex = strtok(separator, ":");
		//sprintf(port_dest_hex, "%x", port_dest);
		//HIP_DEBUG("sub_string_port_hex %s\n",sub_string_port_hex);
		sscanf(sub_string_port_hex,"%X", &result);
		HIP_DEBUG("Result %i\n", result);
		HIP_DEBUG("port dest %i\n", port_dest);
		if (result == port_dest) {
			strncpy(sub_string_addr_hex, fqdn_str, 8);
			sscanf(sub_string_addr_hex, "%X", &result_addr);
			addr.s_addr = result_addr;
			if (IS_LSI32(addr.s_addr)) {
				exists = 2;
				break;
			} else {
				exists = 1;
				break;
			}
		}
	} /* end of while */
		if (fd)
			fclose(fd);
		destroy(&list);

        return exists;
}

void hip_get_rsa_keylen(const struct hip_host_id *host_id, 
			struct hip_rsa_keylen *ret,
			int is_priv){
	int bytes;
	u8 *tmp = (u8 *) (host_id + 1);
	int offset = 0;
	int e_len = tmp[offset++];

	/* Check for public exponent longer than 255 bytes (see RFC 3110) */
	if (e_len == 0) {
		e_len = ntohs((u16)tmp[offset]);
		offset += 2;
	}

	/*
	 hi_length is the total length of:
	 rdata struct (4 bytes), length of e (1 byte for e < 255 bytes, 3 bytes otherwise),
	 e (normally 3 bytes), followed by public n, private d, p, q
	 n_len == d_len == 2 * p_len == 2 * q_len
	*/
	if (is_priv)
		bytes = (ntohs(host_id->hi_length) - sizeof(struct hip_host_id_key_rdata) -
				//offset - e_len) / 3;
				offset - e_len) * 2 / 9;
	else
		bytes = (ntohs(host_id->hi_length) - sizeof(struct hip_host_id_key_rdata) -
				offset - e_len);

	ret->e_len = offset;
	ret->e = e_len;
	ret->n = bytes;
}

#ifndef __KERNEL__
RSA *hip_key_rr_to_rsa(struct hip_host_id *host_id, int is_priv) {
	int offset;
	struct hip_rsa_keylen keylen;
	RSA *rsa = NULL;
	char *rsa_key = host_id + 1;

	hip_get_rsa_keylen(host_id, &keylen, is_priv);

	rsa = RSA_new();
	if (!rsa) {
		HIP_ERROR("Failed to allocate RSA\n");
		return NULL;
	}

	offset = keylen.e_len;
	rsa->e = BN_bin2bn(&rsa_key[offset], keylen.e, 0);
	offset += keylen.e;
	rsa->n = BN_bin2bn(&rsa_key[offset], keylen.n, 0);
	
	if (is_priv) {
		offset += keylen.n;
		rsa->d = BN_bin2bn(&rsa_key[offset], keylen.n, 0);
		offset += keylen.n;
		rsa->p = BN_bin2bn(&rsa_key[offset], keylen.n / 2, 0);
		offset += keylen.n / 2;
		rsa->q = BN_bin2bn(&rsa_key[offset], keylen.n / 2, 0);
		offset += keylen.n / 2;
		rsa->dmp1 = BN_bin2bn(&rsa_key[offset], keylen.n / 2, 0);
		offset += keylen.n / 2;
		rsa->dmq1 = BN_bin2bn(&rsa_key[offset], keylen.n / 2, 0);
		offset += keylen.n / 2;
		rsa->iqmp = BN_bin2bn(&rsa_key[offset], keylen.n / 2, 0);
	}

  out_err:
	return rsa;
}

DSA *hip_key_rr_to_dsa(struct hip_host_id *host_id, int is_priv) {
	int offset = 0;
	DSA *dsa = NULL;
	char *dsa_key = host_id + 1;
	u8 t = dsa_key[offset++];
	int key_len = 64 + (t * 8);

	dsa = DSA_new();
	if (!dsa) {
		HIP_ERROR("Failed to allocate DSA\n");
		return NULL;
	}

	dsa->q = BN_bin2bn(&dsa_key[offset], DSA_PRIV, 0);
	offset += DSA_PRIV;
	dsa->p = BN_bin2bn(&dsa_key[offset], key_len, 0);
	offset += key_len;
	dsa->g = BN_bin2bn(&dsa_key[offset], key_len, 0);
	offset += key_len;
	dsa->pub_key = BN_bin2bn(&dsa_key[offset], key_len, 0);

	if (is_priv) {
		offset += key_len;
		dsa->priv_key = BN_bin2bn(&dsa_key[offset], DSA_PRIV, 0);

		/* Precompute values for faster signing */
		DSA_sign_setup(dsa, NULL, &dsa->kinv, &dsa->r);
	}

	return dsa;
}
#endif /* !__KERNEL__ */

int hip_string_to_lowercase(char *to, const char *from, const size_t count){
	if(to == NULL || from == NULL || count == 0)
		return -1;

	int i = 0;

	for(; i < count; i++) {
		if(isalpha(from[i])) {
			to[i] = tolower(from[i]);
		} else {
			to[i] = from[i];
		}
	}
	return 0;
}


int hip_string_is_digit(const char *string){
	if(string == NULL)
		return -1;

	int i = 0;

	while(string[i] != '\0') {
		if(!isdigit(string[i])) {
			return -1;
		}
		i++;
	}
	return 0;
}

int hip_map_first_id_to_hostname_from_hosts(const struct hosts_file_line *entry,
					    const void *arg,
					    void *result) {
  int err = 1;

  if (!ipv6_addr_cmp((struct in6_addr *) arg, &entry->id)) {
    _HIP_DEBUG("Match on line %d\n", entry->lineno);
    memcpy(result, entry->hostname, strnlen(entry->hostname, HOST_NAME_MAX));
    err = 0; /* Stop at the first match */
  }

  return err;
}

int hip_map_first_lsi_to_hostname_from_hosts(const struct hosts_file_line *entry,
					    const void *arg,
					    void *result) {
  int err = 1;
  int is_lsi = hip_id_type_match(&entry->id, 2);

  if (!ipv6_addr_cmp((struct in6_addr *) arg, &entry->id) && is_lsi) {
    _HIP_DEBUG("Match on line %d\n", entry->lineno);
    memcpy(result, entry->hostname, strnlen(entry->hostname, HOST_NAME_MAX));
    err = 0; /* Stop at the first match */
  }

  return err;
}

int hip_map_lsi_to_hostname_from_hosts(hip_lsi_t *lsi, char *hostname) {
	return hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
					    hip_map_first_lsi_to_hostname_from_hosts,
					    lsi, hostname);
}

int hip_map_first_hostname_to_hit_from_hosts(const struct hosts_file_line *entry,
					     const void *arg,
					     void *result) {
  int err = 1;
  int is_lsi, is_hit;

  /* test if hostname/alias matches and the type is hit */
  if (!strncmp(arg, entry->hostname, HOST_NAME_MAX) ||
      (entry->alias && !strncmp(arg, entry->alias, HOST_NAME_MAX))) {
    is_hit = hip_id_type_match(&entry->id, 1);
    is_lsi = hip_id_type_match(&entry->id, 2);

    HIP_IFE(!is_hit, 1);

    _HIP_DEBUG("Match on line %d\n", entry->lineno);
    ipv6_addr_copy(result, &entry->id);
    err = 0; /* Stop at the first match */
  }

 out_err:

  return err;
}

int hip_map_first_hostname_to_lsi_from_hosts(const struct hosts_file_line *entry,
					     const void *arg,
					     void *result) {
  int err = 1;
  int is_lsi, is_hit;

  /* test if hostname/alias matches and the type is lsi */
  if (!strncmp(arg, entry->hostname, HOST_NAME_MAX) ||
      (entry->alias && !strncmp(arg, entry->alias, HOST_NAME_MAX))) {
    is_hit = hip_id_type_match(&entry->id, 1);
    is_lsi = hip_id_type_match(&entry->id, 2);

    HIP_IFE(!is_lsi, 1);

    _HIP_DEBUG("Match on line %d\n", entry->lineno);
    ipv6_addr_copy(result, &entry->id);
    err = 0; /* Stop at the first match */
  }

 out_err:

  return err;
}

int hip_map_first_hostname_to_ip_from_hosts(const struct hosts_file_line *entry,
					    const void *arg,
					    void *result) {
  int err = 1;
  int is_lsi, is_hit;

  /* test if hostname/alias matches and the type is routable ip */
  if (!strncmp(arg, entry->hostname, HOST_NAME_MAX) ||
      (entry->alias && !strncmp(arg, entry->alias, HOST_NAME_MAX))) {
    is_hit = hip_id_type_match(&entry->id, 1);
    is_lsi = hip_id_type_match(&entry->id, 2);

    HIP_IFE((is_hit || is_lsi), 1);

    _HIP_DEBUG("Match on line %d\n", entry->lineno);
    ipv6_addr_copy(result, &entry->id);
    err = 0; /* Stop at the first match */
  }

 out_err:

  return err;
}


int hip_calc_lines_in_hosts(const struct hosts_file_line *entry,
				 const void *arg,
				 void *result) {
	int *res = (int *) result;
	(*res)++;
	return 1;
}

int hip_get_nth_id_from_hosts(const struct hosts_file_line *entry,
			      const void *arg,
			      void *result) {
  int err = 1;
  const int *nth = (const int *) arg;
  int *total_past = (int *) result;

  if (*nth == *total_past) {
	  ipv6_addr_copy(result, &entry->id);
	  err = 0;
  } else {
	  (*total_past)++;
  }
  return err;
}

int hip_for_each_hosts_file_line(char *hosts_file,
				 int (*func)(const struct hosts_file_line *line,
					     const void *arg,
					     void *result),
				 void *arg, void *result) {
  FILE *hip_hosts = NULL,*hosts = NULL;
  List mylist;
  uint8_t line[500];
  int err = 0, lineno = 0;
  struct in_addr in_addr;
  struct hosts_file_line entry;
  uint8_t *hostname, *alias, *addr_ptr;

  initlist(&mylist);
  memset(line, 0, sizeof(line));

  /* check whether  given hit_str is actually a HIT */

  hip_hosts = fopen(hosts_file, "r");

  HIP_IFEL(!hip_hosts, -1, "Failed to open hosts file\n");

  /* For each line in the given hosts file, convert the line into binary format and
     call the given the handler  */

  err = 1;
  while (fgets(line, sizeof(line) - 1, hip_hosts) != NULL) {
    uint8_t *eofline, *c, *comment;
    int len;

    lineno++;
    c = line;

    /* Remove whitespace */
    while (*c == ' ' || *c == '\t')
      c++;

    /* Line is a comment or empty */
    if (*c =='#' || *c =='\n' || *c == '\0')
      continue;

    eofline = strchr(c, '\n');
    if (eofline)
      *eofline = '\0';

    /* Terminate before (the first) trailing comment */
    comment = strchr(c, '#');
    if (comment)
      *comment = '\0';

    /* shortest hostname: ":: a" = 4 */
    if ((len = strnlen(c, sizeof(line))) < 4) {
      HIP_DEBUG("skip line\n");
      continue;
    }

    _HIP_DEBUG("lineno=%d, str=%s\n", lineno, c);

    /* Split line into list */
    extractsubstrings(c, &mylist);

    len = length(&mylist);
    if (len < 2 || len > 3) {
      HIP_ERROR("Bad number of items on line %d in %s, skipping\n",
		lineno, hosts_file);
      continue;
    }

    /* The list contains hosts line in reverse order. Let's sort it. */
    if (len == 2) {
      alias = NULL;
      hostname = getitem(&mylist, 0);
      addr_ptr = getitem(&mylist, 1);
    } else if (len == 3) {
      alias = getitem(&mylist, 0);
      hostname = getitem(&mylist, 1);
      addr_ptr = getitem(&mylist, 2);
    }

    /* Initialize entry */

    memset(&entry, 0, sizeof(entry));

    HIP_ASSERT(addr_ptr);
    err = inet_pton(AF_INET6, addr_ptr, &entry.id);
    if (err <= 0) {
      err = inet_pton(AF_INET, addr_ptr, &in_addr);
      if (err <= 0) {
	HIP_ERROR("Bad address %s on line %d in %s, skipping\n",
		  addr_ptr, lineno, hosts_file);
	continue;
      }
      IPV4_TO_IPV6_MAP(&in_addr, &entry.id);
    }

    entry.hostname = hostname;
    HIP_ASSERT(entry.hostname)

    entry.alias = alias;
    entry.lineno = lineno;

    /* Finally, call the handler function to handle the line */

    if (func(&entry, arg, result) == 0) {
      _HIP_DEBUG("Match on line %d in %s\n", lineno, hosts_file);
      err = 0;
      break;
    }

    memset(line, 0, sizeof(line));
    destroy(&mylist);
  }

 out_err:

  destroy(&mylist);

  if (hip_hosts)
    fclose(hip_hosts);

  return err;
}

int hip_map_lsi_to_hit_from_hosts_files(hip_lsi_t *lsi, hip_hit_t *hit)
{
	int err = 0;
	uint8_t hostname[HOST_NAME_MAX];
	struct in6_addr mapped_lsi;
	
	memset(hostname, 0, sizeof(hostname));
	HIP_ASSERT(lsi && hit);
	
	IPV4_TO_IPV6_MAP(lsi, &mapped_lsi);
	
	err = hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
					   hip_map_first_id_to_hostname_from_hosts,
					   &mapped_lsi, hostname);
	HIP_IFEL(err, -1, "Failed to map id to hostname\n");
	
	err = hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
					   hip_map_first_hostname_to_hit_from_hosts,
					   hostname, hit);
	HIP_IFEL(err, -1, "Failed to map id to hostname\n");
	
	HIP_DEBUG_HIT("Found hit: ", hit);
	
 out_err:
	
	return err;
}

int hip_map_hit_to_lsi_from_hosts_files(hip_hit_t *hit, hip_lsi_t *lsi)
{
	int err = 0;
	uint8_t hostname[HOST_NAME_MAX];
	struct in6_addr mapped_lsi;
	
	memset(hostname, 0, sizeof(hostname));
	HIP_ASSERT(lsi && hit);
	
	err = hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
					   hip_map_first_id_to_hostname_from_hosts,
					   hit, hostname);
	HIP_IFEL(err, -1, "Failed to map id to hostname\n");
	
	err = hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
					   hip_map_first_hostname_to_lsi_from_hosts,
					   hostname, &mapped_lsi);
	HIP_IFEL(err, -1, "Failed to map id to hostname\n");
	
	IPV6_TO_IPV4_MAP(&mapped_lsi, lsi);
	
	HIP_DEBUG_LSI("Found lsi: ", lsi);
	
 out_err:
	
	return err;
}

int hip_get_random_hostname_id_from_hosts(char *filename,
					  char *hostname,
					  char *id_str) {

	int lines = 0, err = 0, nth;
	struct in6_addr id = {0};

	/* ignore return value, returns always error */
	hip_for_each_hosts_file_line(filename,
				     hip_calc_lines_in_hosts,
				     NULL,
				     &lines);
	HIP_IFEL((lines == 0), -1,
		 "No lines in host file %s\n", filename);

	srand(time(NULL));
	nth = rand() % lines;

	err = hip_for_each_hosts_file_line(filename,
					   hip_get_nth_id_from_hosts,
					   &nth,
					   &id);
	HIP_IFEL(err, -1, "Failed to get random id\n");

	err = hip_for_each_hosts_file_line(filename,
					   hip_map_first_id_to_hostname_from_hosts,
					   &id,
					   hostname);
	HIP_IFEL(err, -1, "Failed to map to hostname\n");

	if (IN6_IS_ADDR_V4MAPPED(&id)) {
		struct in_addr id4;
		IPV6_TO_IPV4_MAP(&id, &id4);
		HIP_IFEL(!inet_ntop(AF_INET, &id4, id_str,
				    INET_ADDRSTRLEN), -1,
			 "inet_ntop failed\n");
	} else {
		HIP_IFEL(!inet_ntop(AF_INET6, &id, id_str,
				    INET6_ADDRSTRLEN), -1,
			 "inet_ntop failed\n");
	}

 out_err:
	return err;
}


/**
 *
 * This function maps a HIT or a LSI (nodename) to an IP address using the two hosts files.
 * The function implements this in two steps. First, it maps the HIT or LSI to an hostname
 * from /etc/hip/hosts. Second, it maps the hostname to a IP address from /etc/hosts. The IP
 * address is return in the res argument.
 *
 */
int hip_map_id_to_ip_from_hosts_files(hip_hit_t *hit, hip_lsi_t *lsi, struct in6_addr *ip) {
	int err = 0;
	uint8_t hostname[HOST_NAME_MAX];
	
	HIP_ASSERT((hit || lsi) && ip);
	
	memset(hostname, 0, sizeof(hostname));
	
	if (hit && !ipv6_addr_any(hit)) {
		err = hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
						   hip_map_first_id_to_hostname_from_hosts,
						   hit, hostname);
	} else {
		struct in6_addr mapped_lsi;
		IPV4_TO_IPV6_MAP(lsi, &mapped_lsi);
		err = hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
						   hip_map_first_id_to_hostname_from_hosts,
						   &mapped_lsi, hostname);
	}
	HIP_IFEL(err, -1, "Failed to map id to hostname\n");
	
	err = hip_for_each_hosts_file_line(HOSTS_FILE,
					   hip_map_first_hostname_to_ip_from_hosts,
					   hostname, ip);
	HIP_IFEL(err, -1, "Failed to map id to ip\n");

 out_err:
	return err;
}
#endif /* !__KERNEL__ */

void hip_copy_in6addr_null_check(struct in6_addr *to, struct in6_addr *from) {
	HIP_ASSERT(to);
	if (from)
		ipv6_addr_copy(to, from);
	else
		memset(to, 0, sizeof(*to));
}

void hip_copy_inaddr_null_check(struct in_addr *to, struct in_addr *from) {
	HIP_ASSERT(to);
	if (from)
		memcpy(to, from, sizeof(*to));
	else
		memset(to, 0, sizeof(*to));
}

in_port_t hip_get_local_nat_udp_port()
{
	return hip_local_nat_udp_port;
}

in_port_t hip_get_peer_nat_udp_port()
{
	return hip_peer_nat_udp_port;
}

int hip_set_local_nat_udp_port(in_port_t port)
{
	int err = 0;

	if (port < 0 || port > 65535)
	{
		HIP_ERROR("Invalid port number %d. The port should be between 1 to 65535", port);
		err = -EINVAL;
		goto out_err;
	}

	HIP_DEBUG("set local nat udp port %d\n", port);
	hip_local_nat_udp_port = port;
	
out_err:
	return err;
}

int hip_set_peer_nat_udp_port(in_port_t port)
{
	int err = 0;

	if (port < 0 || port > 65535)
	{
		HIP_ERROR("Invalid port number %d. The port should be between 1 to 65535", port);
		err = -EINVAL;
		goto out_err;
	}

	HIP_DEBUG("set peer nat udp port %d\n", port);
	hip_peer_nat_udp_port = port;
	
out_err:
	return err;
}
