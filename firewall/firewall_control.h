#ifndef FIREWALL_CONTROL_H_
#define FIREWALL_CONTROL_H_

#include <stdio.h>
//#include <glib/gthread.h>
#ifdef ANDROID_CHANGES
#include <sys/socket.h>
#endif
#include <sys/un.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

#include "builder.h"
#include "protodefs.h"
#include "firewalldb.h"
#include "user_ipsec_fw_msg.h"

typedef struct pseudo_v6 {
       struct  in6_addr src;
        struct in6_addr dst;
        u16 length;
        u16 zero1;
        u8 zero2;
        u8 next;
} pseudo_v6;

void* run_control_thread(void* data);
int control_thread_init(void);
int hip_fw_sendto_hipd(void *msg);
int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr);
int firewall_init_raw_sock_v6();
int request_hipproxy_status(void);
extern int hip_proxy_status;
extern int hip_sava_client;
extern int hip_sava_router;
extern int hip_opptcp;
extern int hip_fw_sock;
extern int accept_hip_esp_traffic_by_default;
extern int filter_traffic;
extern int restore_filter_traffic;
extern int restore_accept_hip_esp_traffic;

#endif /*FIREWALL_CONTROL_H_*/
