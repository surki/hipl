/**
 * hipd messages to the hipfw and additional parameters for BEX and
 * UPDATE messages
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef ESP_PROT_HIPD_MSG_H_
#define ESP_PROT_HIPD_MSG_H_

#include "misc.h"


/********************** user-messages *********************/

/** sets the preferred ESP protection extension transforms array transferred
 * from the firewall
 *
 * @param	msg the user-message sent by the firewall
 * @return	0 if ok, != 0 else
 */
int esp_prot_set_preferred_transforms(struct hip_common *msg);

/** handles the user-message sent by fw when a new anchor has to be set
 * up at the peer host
 *
 * @param	msg the user-message sent by the firewall
 * @return	0 if ok, != 0 else
 */
int esp_prot_handle_trigger_update_msg(struct hip_common *msg);

/** handles the user-message sent by fw when the anchors have changed in
 * the sadb from next to active
 *
 * @param	msg the user-message sent by the firewall
 * @return	0 if ok, != 0 else
 */
int esp_prot_handle_anchor_change_msg(struct hip_common *msg);

/** sets the ESP protection extension transform and anchor in user-messages
 * sent to the firewall in order to add a new SA
 *
 * @param	entry the host association entry for this connection
 * @param	msg the user-message sent by the firewall
 * @param	direction direction of the entry to be created
 * @param	update this was triggered by an update
 * @return	0 if ok, != 0 else
 */
int esp_prot_sa_add(hip_ha_t *entry, struct hip_common *msg, int direction,
		int update);

/********************* BEX parameters *********************/

int esp_prot_r1_add_transforms(hip_common_t *msg);
int esp_prot_r1_handle_transforms(hip_ha_t *entry, struct hip_context *ctx);
int esp_prot_i2_add_anchor(hip_common_t *i2, hip_ha_t *entry, struct hip_context *ctx);
int esp_prot_i2_handle_anchor(hip_ha_t *entry, struct hip_context *ctx);
int esp_prot_r2_add_anchor(hip_common_t *r2, hip_ha_t *entry);
int esp_prot_r2_handle_anchor(hip_ha_t *entry, struct hip_context *ctx);

/******************** UPDATE parameters *******************/

int esp_prot_handle_update(hip_common_t *recv_update, hip_ha_t *entry,
		in6_addr_t *src_ip, in6_addr_t *dst_ip);
int esp_prot_update_add_anchor(hip_common_t *update, hip_ha_t *entry);
int esp_prot_update_handle_anchor(hip_common_t *recv_update, hip_ha_t *entry,
		in6_addr_t *src_ip, in6_addr_t *dst_ip, uint32_t *spi);
int esp_prot_send_update_response(hip_common_t *recv_update, hip_ha_t *entry,
		in6_addr_t *src_ip, in6_addr_t *dst_ip, uint32_t spi);

/******************** helper functions ********************/

/** selects the preferred ESP protection extension transform from the set of
 * local and peer preferred transforms
 *
 * @param	num_transforms amount of transforms in the transforms array passed
 * @param	transforms the transforms array
 * @return	the overall preferred transform
 */
uint8_t esp_prot_select_transform(int num_transforms, uint8_t *transforms);

#endif /*ESP_PROT_HIPD_MSG_H_*/
