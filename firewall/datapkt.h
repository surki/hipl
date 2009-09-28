#ifndef HIP_DATAPKT_H
#define HIP_DATAPKT_H

#include "firewall.h"
#include "firewall_defines.h"

int hip_fw_userspace_datapacket_input(hip_fw_context_t *ctx);
int hip_data_packet_mode_output(hip_fw_context_t *ctx, 
		                struct in6_addr *preferred_local_addr, struct in6_addr *preferred_peer_addr,
		                unsigned char *hip_data_packet, uint16_t *hip_packet_len);
int hip_data_packet_mode_input(hip_fw_context_t *ctx, unsigned char *hip_packet, uint16_t *hip_data_len,
			       struct in6_addr *preferred_local_addr, struct in6_addr *preferred_peer_addr);

#endif /* HIP_DATAPKT_H */
