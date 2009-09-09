#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <netinet/in.h>
#include <netinet/ip.h>
#ifndef ANDROID_CHANGES
#include <netinet/ip6.h>
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>

#include "debug.h"
#include "firewall_defines.h"
#include "esp_decrypt.h"
#include "rule_management.h"
#include "misc.h"
#include "hadb.h"
#include "pk.h"
#include "common_types.h"


/*-------------- CONNECTION TRACKING ------------*/
enum{
  ORIGINAL_DIR,
  REPLY_DIR,
    };

enum{
  STATE_NEW,
  STATE_ESTABLISHED,
  STATE_ESTABLISHING_FROM_UPDATE,
  STATE_CLOSING
};

extern int hip_proxy_status;


void print_data(struct hip_data * data);
int filter_esp_state(hip_fw_context_t * ctx, struct rule * rule, int use_escrow);
int filter_state(const struct in6_addr * ip6_src,
		 const struct in6_addr * ip6_dst,
		 struct hip_common * buf,
		 const struct state_option * rule,
		 int accept);
void conntrack(const struct in6_addr * ip6_src,
        const struct in6_addr * ip6_dst,
	       struct hip_common * buf);

int add_esp_decryption_data(const struct in6_addr * hit_s,
			    const struct in6_addr * hit_r, const struct in6_addr * dst_addr,
			    uint32_t spi, int dec_alg, int auth_len, int key_len,
			    struct hip_crypto_key	* dec_key);

int remove_esp_decryption_data(const struct in6_addr * addr, uint32_t spi);

void init_timeout_checking(long int timeout_val);

struct esp_tuple * find_esp_tuple(const SList * esp_list, uint32_t spi);

#ifdef CONFIG_HIP_OPPORTUNISTIC
/*
 * replaces the pseudo-hits of the opportunistic entries
 * related to a particular peer with the real hit
*/
void update_peer_opp_info(struct hip_data * data,
			  struct in6_addr * ip6_from);
#endif
#endif
