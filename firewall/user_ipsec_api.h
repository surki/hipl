/**
 * API for the userspace IPsec functionality
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef USER_IPSEC_API_H_
#define USER_IPSEC_API_H_

#include "firewall.h"
#include "user_ipsec_sadb.h"
#include "user_ipsec_esp.h"
#include "user_ipsec_fw_msg.h"
#include "esp_prot_api.h"

/* this is the maximum buffer-size needed for an userspace ipsec esp packet
 * including the initialization vector for ESP and the hash value of the
 * ESP protection extension */
#define MAX_ESP_PADDING 255
#define ESP_PACKET_SIZE (HIP_MAX_PACKET + sizeof(struct udphdr) \
		+ sizeof(struct hip_esp) + AES_BLOCK_SIZE + MAX_ESP_PADDING \
		+ sizeof(struct hip_esp_tail) + EVP_MAX_MD_SIZE) + MAX_HASH_LENGTH


/** initializes the sadb, packet buffers and the sockets and notifies
 * the hipd about the activation of userspace ipsec
 *
 * @return	0, if correct, else != 0
 */
int userspace_ipsec_init(void);

/** uninits the sadb, frees packet buffers and notifies
 * the hipd about the deactivation of userspace ipsec
 *
 * @return 0, if correct, else != 0
 */
int userspace_ipsec_uninit(void);

/** prepares the context for performing the ESP transformation
 *
 * @param	ctx the firewall context of the packet to be processed
 * @return	0, if correct, else != 0
 */
int hip_firewall_userspace_ipsec_input(hip_fw_context_t *ctx);

/** prepares the context for performing the ESP transformation
 *
 * @param	ctx the firewall context of the packet to be processed
 * @return	0, if correct, else != 0
 */
int hip_firewall_userspace_ipsec_output(hip_fw_context_t *ctx);
int  hip_fw_userspace_hip_datapacket_input(hip_fw_context_t *ctx);
int  hip_fw_userspace_hip_datapacket_output(hip_fw_context_t *ctx);
#endif /* USER_IPSEC_API_H_ */
