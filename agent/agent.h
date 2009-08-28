/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef AGENT_H
#define AGENT_H


/******************************************************************************/
/* DEFINES */

/**
 * HIP agent lock file is used to prevent multiple instances
 * of the agent to start and to record current daemon pid.
 */ 
#define HIP_AGENT_LOCK_FILE		"/var/lock/hipagent.lock"


/******************************************************************************/
/* INCLUDES */
#include <fcntl.h>
//#include <socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <wait.h> 
#include <unistd.h>

#ifndef __u32
/* Fedore Core 3/4 and Enterprise linux 4 is broken. */
#  include <linux/types.h>
#endif
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
//#include "workqueue.h"

#include "tools.h"
#include "gui_interface.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */



#endif /* END OF HEADER FILE */
/******************************************************************************/

