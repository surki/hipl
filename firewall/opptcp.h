#include "firewall.h"

int hip_request_send_i1_to_hip_peer_from_hipd(struct in6_addr *peer_hit,
					       struct in6_addr *peer_ip);
int hip_request_unblock_app_from_hipd(const struct in6_addr *peer_ip);
int hipd_unblock_app_AND_oppipdb_add_entry(const struct in6_addr *peer_ip);
int hip_request_oppipdb_add_entry(struct in6_addr *peer_ip);
int hip_fw_examine_incoming_tcp_packet(void *hdr,
				       int ip_version,
				       int header_size);
