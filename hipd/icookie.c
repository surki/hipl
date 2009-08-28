 /*
  * HIPL extensions for indexing cookies with just peer HITs. Currently
  * used only for spam related experimentation.
  *
  * See also cookie.c for overriding functions.
  *
  * Author: Miika Komu <miika@iki.fi>
  *
  */

#ifdef CONFIG_HIP_ICOOKIE
#include "icookie.h"

/* We need maintain a separate table for the K values of cookies because
   otherwise they are just overwritten when R1s are recreated periodically. */
int hip_puzzle_k[HIP_R1TABLESIZE];

void hip_init_puzzle_defaults() {
	int i;
	for (i = 0; i < HIP_R1TABLESIZE; i++)
		hip_puzzle_k[i] = HIP_DEFAULT_COOKIE_K;
}

int hip_calc_cookie_idx(struct in6_addr *ip_i, struct in6_addr *ip_r,
			       struct in6_addr *hit_i)
{
	register u32 base=0;
	int i;

	/* Indexing based on the initiator HIT only: however, this may happen
	   on the expense of DoS protection against zombies. */
	for(i = 0; i < 4; i++) {
		base ^= hit_i->s6_addr32[i];
	}

	for(i = 0; i < 3; i++) {
		base ^= ((base >> (24 - i * 8)) & 0xFF);
	}

	/* base ready */

	HIP_DEBUG("idx=%d\n", ((base) % HIP_R1TABLESIZE));

	return (base) % HIP_R1TABLESIZE;
}

int hip_get_cookie_difficulty(hip_hit_t *hit_i) {
	return hip_puzzle_k[hip_calc_cookie_idx(NULL, NULL, hit_i)];
}

int hip_get_cookie_difficulty_by_index(int r1_index) {
	return hip_puzzle_k[r1_index];
}

int hip_set_cookie_difficulty(hip_hit_t *hit_i, int k) {
	if (k > HIP_PUZZLE_MAX_K || k < 1) {
		HIP_ERROR("Bad cookie value (%d), min=%d, max=%d\n",
			  k, 1, HIP_PUZZLE_MAX_K);
		return -1;
	}

	hip_puzzle_k[hip_calc_cookie_idx(NULL, NULL, hit_i)] = k;

	HIP_DEBUG("HIP cookie value set to %d\n", k);
	return k;
}

int hip_inc_cookie_difficulty(hip_hit_t *hit_i) {
	int k = hip_get_cookie_difficulty(hit_i) + 1;
	return hip_set_cookie_difficulty(hit_i, k);
}

int hip_dec_cookie_difficulty(hip_hit_t *hit_i) {
	int k = hip_get_cookie_difficulty(hit_i) - 1;
	return hip_set_cookie_difficulty(hit_i, k);
}

int hip_precreate_r1(struct hip_r1entry *r1table, struct in6_addr *hit, 
		     int (*sign)(struct hip_host_id *p, struct hip_common *m),
		     void *privkey, struct hip_host_id *pubkey)
{
	int i;

	for(i = 0; i < HIP_R1TABLESIZE; i++) {
		int cookie_k;

		cookie_k = hip_get_cookie_difficulty_by_index(i);

		r1table[i].r1 = hip_create_r1(hit, sign, privkey, pubkey,
					      cookie_km);
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

#endif /* CONFIG_HIP_ICOOKIE */
