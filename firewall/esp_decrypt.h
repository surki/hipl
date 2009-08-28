#ifndef ESP_DECRYPT_H
#define ESP_DECRYPT_H

#include "crypto.h"
#include "firewall_defines.h"

int decrypt_packet(const struct in6_addr * dst_addr, 
	struct esp_tuple *esp_tuple, struct hip_esp_packet * esp);


#endif //ESP_DECRYPT_H
