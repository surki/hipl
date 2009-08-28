/**
 * Connection tracking extension needed for TPA
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef ESP_PROT_CONNTRACK_H_
#define ESP_PROT_CONNTRACK_H_

#include "builder.h"
#include "conntrack.h"

typedef struct esp_prot_conntrack_tfm
{
	hash_function_t hash_function; /* pointer to the hash function */
	int hash_length; /* hash length for this transform */
	int is_used; /* needed as complete transform array is initialized */
} esp_prot_conntrack_tfm_t;

/** initializes the connection tracking as required for the handling of TPA and HHL
 *
 * @return always 0
 */
int esp_prot_conntrack_init(void);

/** un-initializes the TPA-specific parts of the connection tracking
 *
 * @return always 0
 */
int esp_prot_conntrack_uninit(void);

/** resolves a transform to the specified hash function and hash length
 *
 * @param	transform TPA transform
 * @return	resolved transform, NULL for UNUSED transform
 */
esp_prot_conntrack_tfm_t * esp_prot_conntrack_resolve_transform(uint8_t transform);

/** processes the transform list enclosed in the R1
 *
 * @param	common the HIP message
 * @param	tuple connection state of the connection tracking mechanism
 * @return	always 0
 */
int esp_prot_conntrack_R1_tfms(struct hip_common * common, const struct tuple * tuple);

/** processes the anchor element of the I2
 *
 * @param	common the HIP message
 * @param	tuple connection state of the connection tracking mechanism
 * @return	0 on success, 1 if non-matching anchor element properties, -1 in case
 *          of an error
 */
int esp_prot_conntrack_I2_anchor(const struct hip_common *common,
		struct tuple *tuple);

/** helper function to get the correct state for the R2
 *
 * @param	other_dir_esps maintained connection tracking state for this connection
 * @return	correct state
 */
struct esp_tuple * esp_prot_conntrack_R2_esp_tuple(SList *other_dir_esps);

/** processes the anchor element of the R2
 *
 * @param	common the HIP message
 * @param	tuple connection state of the connection tracking mechanism
 * @return	0 on success, 1 if non-matching anchor element properties, -1 in case
 *          of an error
 */
int esp_prot_conntrack_R2_anchor(const struct hip_common *common,
		struct tuple *tuple);

/** processes an update message
 *
 * @param	update the HIP message
 * @param	tuple connection state of the connection tracking mechanism
 * @return	0 on success, -1 in case of an error or unsupported update
 */
int esp_prot_conntrack_update(const hip_common_t *update, struct tuple * tuple);

/** caches an anchor element found in a update messages
 *
 * @param	tuple state maintained for this connection
 * @param	seq the sequence number parameter of the HIP message
 * @param	esp_anchor the anchor element parameter of the HIP message
 * @param	esp_root the root element parameter of the HIP message
 * @return	0 on success, -1 in case of an error
 */
int esp_prot_conntrack_cache_anchor(struct tuple * tuple, struct hip_seq *seq,
		struct esp_prot_anchor *esp_anchor, struct esp_prot_root *esp_root);

/** stores and enables update anchor element, if an acknowledgement for the
 *  update is received
 *
 * @param	tuple state maintained for this connection
 * @param	ack the acknowledgement parameter of the HIP message
 * @param	esp_info the esp info parameter of the HIP message
 * @return	-1 on error, 1 if cached update not found, 0 if ok
 */
int esp_prot_conntrack_update_anchor(struct tuple *tuple, struct hip_ack *ack,
		struct hip_esp_info *esp_info);

/** tracks an HHL-based update message
 *
 * @param	ip6_src the source address of the packet
 * @param	ip6_dst the destination address of the packet
 * @param	common the HIP message
 * @param	tuple state maintained for this connection
 * @return	0 on success, -1 in case of an error
 */
int esp_prot_conntrack_lupdate(const struct in6_addr * ip6_src,
		const struct in6_addr * ip6_dst, const struct hip_common * common,
		struct tuple * tuple);

/** verifies the enclosed TPA tokens
 *
 * @param	esp_tuple corresponding esp state of the connection
 * @param	ctx context of the currently processed packet
 * @return	0 on success, -1 on error
 */
int esp_prot_conntrack_verify(hip_fw_context_t * ctx, struct esp_tuple *esp_tuple);

/** verifies the anchor element of a HHL-based update
 *
 * @param	tuple state maintained for this connection
 * @param	esp_anchor the anchor element parameter of the HIP message
 * @param	esp_branch the verification branch parameter
 * @param	esp_secret the secret parameter
 * @return	0 on success, -1 on error
 */
int esp_prot_conntrack_verify_branch(struct tuple * tuple,
		struct esp_prot_anchor *esp_anchor, struct esp_prot_branch *esp_branch,
		struct esp_prot_secret *esp_secret);

/** finds the matching esp state in the connection state
 *
 * @param	tuple state maintained for this connection
 * @param	active_anchor the active anchor element of the TPA tokens
 * @param	hash_length length of the anchor element
 */
struct esp_tuple * esp_prot_conntrack_find_esp_tuple(struct tuple * tuple,
		unsigned char *active_anchor, int hash_length);

#endif /* ESP_PROT_CONNTRACK_H_ */
