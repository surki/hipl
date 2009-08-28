/**
 * @file
 * HIP cookie handling. Licence: GNU/GPL
 * 
 * @author Kristian Slavov <ksl#iki.fi>
 * @author Miika Komu <miika#iki.fi>
 */

#include "cookie.h"

int hip_cookie_difficulty = HIP_DEFAULT_COOKIE_K;

#ifndef CONFIG_HIP_ICOOKIE /* see also spam.c for overriding functions */

#if 0
void hip_init_puzzle_defaults() {
	return;
}
#endif

int hip_get_cookie_difficulty(hip_hit_t *not_used) {
	/* Note: we could return a higher value if we detect DoS */
	return hip_cookie_difficulty;
}

int hip_set_cookie_difficulty(hip_hit_t *not_used, int k) {
	if (k > HIP_PUZZLE_MAX_K || k < 1) {
		HIP_ERROR("Bad cookie value (%d), min=%d, max=%d\n",
			  k, 1, HIP_PUZZLE_MAX_K);
		return -1;
	}
	hip_cookie_difficulty = k;
	HIP_DEBUG("HIP cookie value set to %d\n", k);
	return k;
}

int hip_inc_cookie_difficulty(hip_hit_t *not_used) {
	int k = hip_get_cookie_difficulty(NULL) + 1;
	return hip_set_cookie_difficulty(NULL, k);
}

int hip_dec_cookie_difficulty(hip_hit_t *not_used) {
	int k = hip_get_cookie_difficulty(NULL) - 1;
	return hip_set_cookie_difficulty(NULL, k);
}

/**
 * hip_calc_cookie_idx - get an index
 * @param ip_i Initiator's IPv6 address
 * @param ip_r Responder's IPv6 address
 * @param hit_i Initiators HIT
 *
 * @return 0 <= x < HIP_R1TABLESIZE
 */
int hip_calc_cookie_idx(struct in6_addr *ip_i, struct in6_addr *ip_r,
			       struct in6_addr *hit_i)
{
	register u32 base=0;
	int i;

	for(i = 0; i < 4; i++) {
		base ^= ip_i->s6_addr32[i];
		base ^= ip_r->s6_addr32[i];
	}

	for(i = 0; i < 3; i++) {
		base ^= ((base >> (24 - i * 8)) & 0xFF);
	}

	/* base ready */

	return (base) % HIP_R1TABLESIZE;
}
#endif /* !CONFIG_HIP_ICOOKIE */

/**
 * hip_fetch_cookie_entry - Get a copy of R1entry structure
 * @param ip_i Initiator's IPv6
 * @param ip_r Responder's IPv6
 *
 * Comments for the if 0 code are inlined below. 
 * 
 * Returns NULL if error.
 */
struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r,
			      struct in6_addr *our_hit,
			      struct in6_addr *peer_hit)
{
	struct hip_common *err = NULL, *r1 = NULL;
	struct hip_r1entry * hip_r1table;
	struct hip_host_id_entry *hid;
	int idx, len;

	/* Find the proper R1 table and copy the R1 message from the table */
	HIP_READ_LOCK_DB(HIP_DB_LOCAL_HID);	
	HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID, our_hit, HIP_ANY_ALGO, -1)), 
		 NULL, "Unknown HIT\n");

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
	   hip_r1table = hid->blindr1;
        }
#endif
	if (!hip_blind_get_status()) {
	   hip_r1table = hid->r1;
        }
	
	// BLIND TODO: indexing?
	idx = hip_calc_cookie_idx(ip_i, ip_r, peer_hit);
	HIP_DEBUG("Calculated index: %d\n", idx);

	/* the code under if 0 periodically changes the puzzle. It is not included
	   in compilation as there is currently no easy way of signing the R1 packet
	   after having changed its puzzle.
	*/
#if 0
	/* generating opaque data */
	do_gettimeofday(&tv);

	/* extract the puzzle */
	if (!(pz = hip_get_param(err->r1, HIP_PARAM_PUZZLE)), NULL, 
	    "Internal error: Could not find PUZZLE parameter in precreated R1 packet\n");

	ts = pz->opaque[0];
	ts |= ((int)pz->opaque[1] << 8);

	if (ts != 0) {
		/* check if the cookie is too old */
		diff = (tv.tv_sec & 0xFFFFFF) - ts;
		if (diff < 0)
			diff += 0x1000000;

		HIP_DEBUG("Old puzzle still valid\n");
		if (diff <= HIP_PUZZLE_MAX_LIFETIME)
			return err;
	}

	/* either ts == 0 or diff > HIP_PUZZLE_MAX_LIFETIME */
	_HIP_DEBUG("Creating new puzzle\n");
	hip_create_new_puzzle(pz, r1, &tv);

	/* XXX: sign the R1 */
#endif
	/* Create a copy of the found entry */
	len = hip_get_msg_total_len(hip_r1table[idx].r1);
	r1 = hip_msg_alloc();
	memcpy(r1, hip_r1table[idx].r1, len);
	err = r1;

 out_err:	
	if (!err && r1)
		HIP_FREE(r1);

	HIP_READ_UNLOCK_DB(HIP_DB_LOCAL_HID);
	return err;
}


struct hip_r1entry * hip_init_r1(void)
{
	struct hip_r1entry *err;

	HIP_IFE(!(err = (struct hip_r1entry *)HIP_MALLOC(sizeof(struct hip_r1entry) * HIP_R1TABLESIZE,
							 GFP_KERNEL)), NULL); 
	memset(err, 0, sizeof(struct hip_r1entry) * HIP_R1TABLESIZE);

 out_err:
	return err;
}


#ifndef CONFIG_HIP_ICOOKIE
/*
 * @sign the signing function to use
 */
int hip_precreate_r1(struct hip_r1entry *r1table, struct in6_addr *hit, 
		     int (*sign)(struct hip_host_id *p, struct hip_common *m),
		     void *privkey, struct hip_host_id *pubkey)
{
	int i=0;
	for(i = 0; i < HIP_R1TABLESIZE; i++) {
		int cookie_k;

		cookie_k = hip_get_cookie_difficulty(NULL);

		r1table[i].r1 = hip_create_r1(hit, sign, privkey, pubkey,
					      cookie_k);
		if (!r1table[i].r1) {
			HIP_ERROR("Unable to precreate R1s\n");
			goto err_out;
		}

		HIP_DEBUG("Packet %d created\n", i);
	}

	return 1;

 err_out:
	return 0;
}
#endif /* !CONFIG_HIP_ICOOKIE */

void hip_uninit_r1(struct hip_r1entry *hip_r1table)
{
	int i;

	/* The R1 packet consist of 2 memory blocks. One contains the actual
	 * buffer where the packet is formed, while the other contains
	 * pointers to different TLVs to speed up parsing etc.
	 * The r1->common is the actual buffer, and r1 is the structure
	 * holding only pointers to the TLVs.
	 */
	if (hip_r1table) {
		for(i=0; i < HIP_R1TABLESIZE; i++) {
			if (hip_r1table[i].r1) {
				HIP_FREE(hip_r1table[i].r1);
			}
		}
		HIP_FREE(hip_r1table);
		hip_r1table = NULL;
	}
}

/**
 * Verifies the solution of a puzzle. First we check that K and I are the same
 * as in the puzzle we sent. If not, then we check the previous ones (since the
 * puzzle might just have been expired). 
 * 
 * @param ip_i     a pointer to Initiator's IP address.
 * @param ip_r     a pointer to Responder's IP address.
 * @param hdr      a pointer to HIP packet common header
 * @param solution a pointer to a solution structure
 * @return         Zero if the cookie was verified succesfully, negative
 *                 otherwise.
 */ 
int hip_verify_cookie(in6_addr_t *ip_i, in6_addr_t *ip_r, 
		      hip_common_t *hdr, struct hip_solution *solution)
{
	/* In a effort to conform the HIPL coding convention, the return value
	   of this function was inverted. I.e. This function now returns
	   negative for error conditions, zero otherwise. It used to be the
	   other way around. -Lauri 23.07.2008. */
	struct hip_puzzle *puzzle = NULL;
	struct hip_r1entry *result = NULL;
	struct hip_host_id_entry *hid = NULL;
	struct in6_addr *plain_local_hit = NULL;
	int err = 0;
	uint16_t nonce = 0;
	
#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
		HIP_IFEL((plain_local_hit = HIP_MALLOC(sizeof(struct in6_addr), 0)) == NULL,
			 -1, "Couldn't allocate memory.\n");
		HIP_IFEL(hip_blind_get_nonce(hdr, &nonce), -1,
			 "hip_blind_get_nonce failed\n");
		HIP_IFEL(hip_plain_fingerprint(&nonce,
					       &hdr->hitr, plain_local_hit), 
			 -1, "hip_plain_fingerprint failed\n");
		
		/* Find the proper R1 table, use plain hit */
		HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(
				   HIP_DB_LOCAL_HID, plain_local_hit,
				   HIP_ANY_ALGO, -1)), 
			 -1, "Requested source HIT not (any more) available.\n");
		
		result = &hid->blindr1[hip_calc_cookie_idx(ip_i, ip_r, &hdr->hits)];
	}
#endif
	
	/* Find the proper R1 table, no blind used */
	if (!hip_blind_get_status()) {
		
		HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(
				   HIP_DB_LOCAL_HID, &hdr->hitr, HIP_ANY_ALGO,
				   -1)), 
			 -1, "Requested source HIT not (any more) available.\n");
		result = &hid->r1[hip_calc_cookie_idx(ip_i, ip_r, &hdr->hits)];
	}

	puzzle = hip_get_param(result->r1, HIP_PARAM_PUZZLE);
	HIP_IFEL(!puzzle, -1, "Internal error: could not find the cookie\n");

	_HIP_HEXDUMP("opaque in solution", solution->opaque,
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("Copaque in result", result->Copaque,
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("opaque in puzzle", puzzle->opaque,
		     HIP_PUZZLE_OPAQUE_LEN);

	HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
			HIP_PUZZLE_OPAQUE_LEN), -1, 
		 "Received cookie opaque does not match the sent opaque\n");
	
	HIP_DEBUG("Solution's I (0x%llx), sent I (0x%llx)\n",
		  solution->I, puzzle->I);

	_HIP_HEXDUMP("opaque in solution", solution->opaque, 
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("opaque in result", result->Copaque, 
		     HIP_PUZZLE_OPAQUE_LEN);
	_HIP_HEXDUMP("opaque in puzzle", puzzle->opaque, 
		     HIP_PUZZLE_OPAQUE_LEN);

	if (solution->K != puzzle->K) {
		HIP_INFO("Solution's K (%d) does not match sent K (%d)\n",
			 solution->K, puzzle->K);
		
		HIP_IFEL(solution->K != result->Ck, -1,
			 "Solution's K did not match any sent Ks.\n");
		HIP_IFEL(solution->I != result->Ci, -1, 
			 "Solution's I did not match the sent I\n");
		HIP_IFEL(memcmp(solution->opaque, result->Copaque,
				HIP_PUZZLE_OPAQUE_LEN), -1,
			 "Solution's opaque data does not match sent opaque "\
			 "data.\n");
		HIP_DEBUG("Received solution to an old puzzle\n");

	} else {
		HIP_HEXDUMP("solution", solution, sizeof(*solution));
		HIP_HEXDUMP("puzzle", puzzle, sizeof(*puzzle));
		HIP_IFEL(solution->I != puzzle->I, -1,
			 "Solution's I did not match the sent I\n");
		HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
				HIP_PUZZLE_OPAQUE_LEN), -1, 
			 "Solution's opaque data does not match the opaque "\
			 "data sent\n");
	}
	
	HIP_IFEL(!hip_solve_puzzle(solution, hdr, HIP_VERIFY_PUZZLE), -1, 
		 "Puzzle incorrectly solved.\n");
	
 out_err:
	if(plain_local_hit != NULL) {
		free(plain_local_hit);
	}
	
	return err;
}

int hip_recreate_r1s_for_entry_move(struct hip_host_id_entry *entry, void *new_hash)
{
	int err = 0;

	hip_uninit_r1(entry->r1);
	HIP_IFE(!(entry->r1 = hip_init_r1()), -ENOMEM);
	HIP_IFE(!hip_precreate_r1(entry->r1, &entry->lhi.hit,
			(hip_get_host_id_algo(entry->host_id) ==
			HIP_HI_RSA ? hip_rsa_sign : hip_dsa_sign),
			entry->private_key, entry->host_id), -1);

#ifdef CONFIG_HIP_BLIND
	hip_uninit_r1(entry->blindr1);
	HIP_IFE(!(entry->r1 = hip_init_blindr1()), -ENOMEM);
	HIP_IFE(!hip_precreate_r1(entry->blindr1, &entry->lhi.hit,
			(hip_get_host_id_algo(entry->host_id) ==
			HIP_HI_RSA ? hip_rsa_sign : hip_dsa_sign),
			entry->private_key, entry->host_id), -1);
#endif

out_err:
	return err;
}


int hip_recreate_all_precreated_r1_packets()
{
	HIP_HASHTABLE *ht = hip_ht_init(hip_hidb_hash, hip_hidb_match);
	hip_list_t *curr, *iter;
	struct hip_host_id *tmp;
	int c;

	hip_for_each_hi(hip_recreate_r1s_for_entry_move, ht);

	list_for_each_safe(curr, iter, ht, c)
	{
		tmp = list_entry(curr);
		hip_ht_add(HIP_DB_LOCAL_HID, tmp);
		list_del(tmp, ht);
	}

	hip_ht_uninit(ht);
	return 0;
}
