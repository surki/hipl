/** @file
 * This file defines TCP timeout parameters setting for the Host Identity
 * Protocol (HIP) in order to overcome the application time out when handover taking 
 * long time.
 *      
 * @author  Tao Wan  <twan_cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * */


#ifndef HIP_TCPTIMEOUT
#define HIP_TCPTIMEOUT

#include <stdio.h>
#include <stdlib.h>
#include "debug.h"
#include "string.h"

#define SYSCTL_SET_COMMAND "sysctl -w "


/* tcp_slow_start_after_idle - Boolean value (1 is true, 0 is false)
 *
 * If set, provide RFC2861 behavior and time out the congestion window after an idle period. 
 * An idle period is defined at the current RTO. If unset, the congestion window will not be 
 * timeout after an idle period.Default: 1
 *  
 * Linux value: net.ipv4.tcp_slow_start_after_idle = 1
 *
 * */

#define TCP_SLOW_START_AFTER_IDLE_STRING "net.ipv4.tcp_slow_start_after_idle"

/* default value*/
#define TCP_SLOW_START_AFTER_IDLE_DEFAULT "1"

/* New value*/
#define TCP_SLOW_START_AFTER_IDLE_NEW "0"



/* tcp_retries1 - Integer; default:3 
 * The number of times TCP will attemp to retransmit a packet on an establish 
 * connection normally, without the extra effort of getting the network layers 
 * involved. Once we exceed this number of retransmits, we first have the network layer 
 * update the route if possible before each new retransmit. The default is the RFC 
 * specified mimum of 3 
 *
 * Linux value: net.ipv4.tcp_retries1 = 3
 */

#define TCP_RETRIES_1_STRING "net.ipv4.tcp_retries1"

#define TCP_RETRIES_1_DEFAULT "3"

/* you could change this value depends on your needs*/
#define TCP_RETRIES_1_NEW "50"



/* tcp_retries2 -Interger; default 15
 * 
 * The maximum number of times a TCP packet is retransmitted in established 
 * state before giving up. The default value is 15, which corresponds to a 
 * duration of approximately between 13 to 30 minutes, depending on the retransmission 
 * timeout. The RFC 1122 specified minimum limit of 100 seconds is typically deemed 
 * too short.
 *
 * Linux value: net.ipv4.tcp_retries2 = 15
 *
 */

#define TCP_RETRIES_2_STRING "net.ipv4.tcp_retries2"

#define TCP_RETRIES_2_DEFAULT "15"

/* you could change this value depends on your needs*/

#define TCP_RETRIES_2_NEW "65"



int set_new_tcptimeout_parameters_value(void);

int reset_default_tcptimeout_parameters_value(void);

void sysctl_set_command(char const *sysctl_with_options, char const *paras, char const *value, char *command_string);


#endif /* HIP_TCPTIMEOUT */


