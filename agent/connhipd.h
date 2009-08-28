/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef CONNHIPD_H
#define CONNHIPD_H

/******************************************************************************/
/* INCLUDES */
#include <fcntl.h>
//#include <socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
//#include "workqueue.h"
#include "icomm.h"

#include "agent.h"
#include "debug.h"
#include "tools.h"
#include "hitdb.h"
#include "gui_interface.h"

/******************************************************************************/
/* DEFINES */
#define CONNHIPD_IN		0
#define CONNHIPD_OUT	1


/******************************************************************************/
/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************/

/******************************************************************************/
/* FUNCTION DEFINITIONS */
int connhipd_init(void);
int connhipd_sendto_hipd(char *, size_t len);
int connhipd_handle_msg(struct hip_common *, struct sockaddr_un *);
void *connhipd_thread(void *);
void connhipd_quit(void);
int connhipd_send_hitdata_to_daemon(struct hip_common * msg , struct in6_addr * hitr, struct in6_addr * hitl);

/******************************************************************************/
/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif
/******************************************************************************/


#endif /* END OF HEADER FILE */
/******************************************************************************/

