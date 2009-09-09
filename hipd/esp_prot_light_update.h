/**
 * Messaging required for HHL-based anchor element updates
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef ESP_PROT_LIGHT_UPDATE_H_
#define ESP_PROT_LIGHT_UPDATE_H_

#include "builder.h"

/** sends an HHL-based update message */
int esp_prot_send_light_update(hip_ha_t *entry, int anchor_offset[NUM_PARALLEL_CHAINS],
		unsigned char *secret[NUM_PARALLEL_CHAINS], int secret_length[NUM_PARALLEL_CHAINS],
		unsigned char *branch_nodes[NUM_PARALLEL_CHAINS], int branch_length[NUM_PARALLEL_CHAINS]);

/** receives and processes an HHL-based update message */
int esp_prot_receive_light_update(hip_common_t *msg, in6_addr_t *src_addr,
	       in6_addr_t *dst_addr, hip_ha_t *entry);

/** sends an ack for a received HHL-based update message */
int esp_prot_send_light_ack(hip_ha_t *entry, in6_addr_t *src_addr, in6_addr_t *dst_addr,
		uint32_t spi);


#endif /* ESP_PROT_LIGHT_UPDATE_H_ */
