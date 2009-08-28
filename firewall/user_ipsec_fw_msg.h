/**
 * Inter-process communication with the hipd for userspace IPsec
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef USER_IPSEC_FW_MSG_H_
#define USER_IPSEC_FW_MSG_H_

#include "builder.h"

extern int hip_fw_sock;

/** sends a userspace ipsec (de-)activation user-message to the hipd
 *
 * @param	activate 1 - activate, 0 - deactivate
 * @return	0, if message sent and received ok, != 0 else
 */
int send_userspace_ipsec_to_hipd(int activate);

/** handles a SA add request sent by the hipd
 *
 * @param 	msg the received message
 * @return	0, if message sent and received ok, != 0 else
 */
int handle_sa_add_request(struct hip_common * msg);

/** handles a SA delete request sent by the hipd
 *
 * @param 	msg the received message
 * @return	0, if message sent and received ok, != 0 else
 */
int handle_sa_delete_request(struct hip_common * msg);

/** handles a SA flush request sent by the hipd
 *
 * @param 	msg the received message
 * @return	0, if message sent and received ok, != 0 else
 */
int handle_sa_flush_all_request(struct hip_common * msg);

#endif /* USER_IPSEC_FW_MSG_H_ */
