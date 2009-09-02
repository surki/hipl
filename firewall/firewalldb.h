#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#ifndef ANDROID_CHANGES
#include <linux/icmpv6.h>
#else
#include <linux/icmp.h>
#include <linux/coda.h>
#include "icmp6.h"
#define icmp6hdr icmp6_hdr
#endif
#include "ife.h"
#include "state.h"
#include "debug.h"
#include "helpers.h"
#include "conntrack.h"
//#include "utils.h"
#include "misc.h"

/*Initializes the firewall database*/
void firewall_init_hldb(void);

/*Comparation definition for the db structure*/
unsigned long hip_firewall_hash_lsi(const void *ptr);
int hip_firewall_match_lsi(const void *ptr1, const void *ptr2);

/*Consult/Modify operations in firewall database*/
firewall_hl_t *firewall_ip_db_match(struct in6_addr *ip_peer);
firewall_hl_t *firewall_hit_lsi_db_match(hip_lsi_t *lsi_peer);
int firewall_add_hit_lsi_ip(struct in6_addr *hit_our, struct in6_addr *hit_peer, hip_lsi_t *lsi, struct in6_addr *ip, int state);
int firewall_set_bex_state(struct in6_addr *hit_s, struct in6_addr *hit_r, int state);
void hip_firewall_delete_hldb(void);

/*Raw sockets operations*/
void firewall_init_raw_sockets(void);
/*icmp*/
int firewall_init_raw_sock_icmp_outbound(int *firewall_raw_sock_v6);
int firewall_init_raw_sock_icmp_v4(int *firewall_raw_sock_v4);
int firewall_init_raw_sock_icmp_v6(int *firewall_raw_sock_v6);
/*udp*/
int firewall_init_raw_sock_udp_v4(int *firewall_raw_sock_v4);
int firewall_init_raw_sock_udp_v6(int *firewall_raw_sock_v6);
/*tcp*/
int firewall_init_raw_sock_tcp_v6(int *firewall_raw_sock_v6);
int firewall_init_raw_sock_tcp_v4(int *firewall_raw_sock_v4);

#endif /* HIP_FIREWALL_H */
