#ifndef HIP_KEYMAT_H
#define HIP_KEYMAT_H

#include "list.h"
#include "misc.h"
#include "crypto.h"
#include "state.h"

void hip_make_keymat(char *kij, size_t kij_len,
		     struct hip_keymat_keymat *keymat,
		     void *dstbuf, size_t dstbuflen, struct in6_addr *hit1,
		     struct in6_addr *hit2, u8 *calc_index, uint64_t I, uint64_t J);
void hip_update_entry_keymat(struct hip_hadb_state *entry,
			     uint16_t new_keymat_index,
			     uint8_t new_calc_index,
			     uint16_t esp_keymat_index,
			     unsigned char *new_current_keymat);
void* hip_keymat_draw(struct hip_keymat_keymat* keymat, int length);
int hip_keymat_draw_and_copy(char *dst,
			     struct hip_keymat_keymat *keymat, 
			     int len);
int hip_keymat_get_new(void *key, size_t key_len, char *kij, size_t kij_len,
		       uint16_t *keymat_offset, uint8_t *calc_index,
		       unsigned char *calc_index_keymat, uint16_t *Kn_is_at);
#endif /* HIP_KEYMAT_H */
