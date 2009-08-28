/** @file
 * A header file for nat.c
 *  
 * @author  (version 1.0) Abhinav Pathak
 * @author  (version 1.1) Lauri Silvennoinen
 * @version 1.1
 * @date    27.10.2006
 * @note    Related drafts:
 *          <ul>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-schmitt-hip-nat-traversal-02.txt">
 *          draft-schmitt-hip-nat-traversal-02</a></li>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-irtf-hiprg-nat-03.txt">
 *          draft-irtf-hiprg-nat-03</a></li>
 *          </ul>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note    All Doxygen comments have been added in version 1.1.
 */
#ifndef __NAT_H__
#define __NAT_H__

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "user.h"
#include "debug.h"
#include "state.h"

//end add

//add by santtu
#define HIP_USE_ICE

#define HIP_REFLEXIVE_LOCATOR_ITEM_AMOUNT_MAX 1


#define ICE_ROLE_CONTROLLING  	PJ_ICE_SESS_ROLE_CONTROLLING
#define ICE_ROLE_CONTROLLED  	PJ_ICE_SESS_ROLE_CONTROLLED


#define ICE_CAND_TYPE_HOST 	PJ_ICE_CAND_TYPE_HOST
#define ICE_CAND_TYPE_SRFLX 	PJ_ICE_CAND_TYPE_SRFLX
#define ICE_CAND_TYPE_PRFLX 	PJ_ICE_CAND_TYPE_PRFLX
#define ICE_CAND_TYPE_RELAYED 	PJ_ICE_CAND_TYPE_RELAYED

#define ICE_CAND_PRE_HOST 65535 
#define ICE_CAND_PRE_SRFLX 65534
#define ICE_CAND_PRE_RELAYED 65533

/* reference of PJ constants
 * 
enum pj_ice_cand_type

This enumeration describes the type of an ICE candidate.

Enumerator:
    PJ_ICE_CAND_TYPE_HOST 	ICE host candidate. A host candidate represents the actual local transport address in the host.
    PJ_ICE_CAND_TYPE_SRFLX 	ICE server reflexive candidate, which represents the public mapped address of the local address, and is obtained by sending STUN Binding request from the host candidate to a STUN server.
    PJ_ICE_CAND_TYPE_PRFLX 	ICE peer reflexive candidate, which is the address as seen by peer agent during connectivity check.
    PJ_ICE_CAND_TYPE_RELAYED 	ICE relayed candidate, which represents the address allocated in TURN server.


enum pj_ice_sess_check_state

This enumeration describes the state of ICE check.

Enumerator:
    PJ_ICE_SESS_CHECK_STATE_FROZEN 	A check for this pair hasn't been performed, and it can't yet be performed until some other check succeeds, allowing this pair to unfreeze and move into the Waiting state.
    PJ_ICE_SESS_CHECK_STATE_WAITING 	A check has not been performed for this pair, and can be performed as soon as it is the highest priority Waiting pair on the check list.
    PJ_ICE_SESS_CHECK_STATE_IN_PROGRESS 	A check has not been performed for this pair, and can be performed as soon as it is the highest priority Waiting pair on the check list.
    PJ_ICE_SESS_CHECK_STATE_SUCCEEDED 	A check has not been performed for this pair, and can be performed as soon as it is the highest priority Waiting pair on the check list.
    PJ_ICE_SESS_CHECK_STATE_FAILED 	A check for this pair was already done and failed, either never producing any response or producing an unrecoverable failure response.

enum pj_ice_sess_checklist_state

This enumeration describes ICE checklist state.

Enumerator:
    PJ_ICE_SESS_CHECKLIST_ST_IDLE 	The checklist is not yet running.
    PJ_ICE_SESS_CHECKLIST_ST_RUNNING 	In this state, ICE checks are still in progress for this media stream.
    PJ_ICE_SESS_CHECKLIST_ST_COMPLETED 	In this state, ICE checks have completed for this media stream, either successfully or with failure.


enum pj_ice_sess_role

This enumeration describes the role of the ICE agent.

Enumerator:
    PJ_ICE_SESS_ROLE_UNKNOWN 	The ICE agent is in controlled role.
    PJ_ICE_SESS_ROLE_CONTROLLED 	The ICE agent is in controlled role.
    PJ_ICE_SESS_ROLE_CONTROLLING 	The ICE agent is in controlling role.
    
pj_status_t : PJ_SUCCESS    
    

*/












//end add
#define HIP_NAT_SLEEP_TIME 2
/** Maximum length of a UDP packet. */
#define HIP_MAX_LENGTH_UDP_PACKET 2000
/** Time interval between consecutive NAT Keep-Alive packets in seconds.
    @note According to [draft-schmitt-hip-nat-traversal-02], the default
    keep-alive interval for control channels must be 20 seconds. However, for
    debugging purposes a smaller value is used here.
    @todo Change this value. */
#define HIP_NAT_KEEP_ALIVE_INTERVAL 20
/** Number of retransmissions to try if hip_send_udp() fails. */
#define HIP_NAT_NUM_RETRANSMISSION 2
/** Port number for NAT traversal of hip control packets. */
#define HIP_NAT_UDP_PORT 50500
#define HIP_NAT_TURN_PORT 50500

/** default value for ICE pacing, unit is 0.001 s**/
#define HIP_NAT_RELAY_LATENCY  200
#define HIP_NAT_PACING_DEFAULT 200



/** For setting socket to listen for beet-udp packets. */
#define HIP_UDP_ENCAP 100
/** UDP encapsulation type. */
#define HIP_UDP_ENCAP_ESPINUDP 2
/** UDP encapsulation type. */ 
#define HIP_UDP_ENCAP_ESPINUDP_NONIKE 1 
/** Boolean which indicates if random port simulation is on.
    <ul>
    <li>0: port randomizing is off.</li>
    <li>1: port randomizing is on.</li>
    </ul>
    @note Not used currently.
    @note This is needed only for simulation purposes and can be removed from
          released versions of HIPL.*/
#define HIP_UDP_PORT_RANDOMIZING 0
/** Boolean to indicate if a NATed network is simulated.
    <ul>
    <li>0: NATed network is not simulated, real life NATs exist in the network.
    </li>
    <li>1: NATed network is simulated, real life NATs do not exist in the
    network, but UDP encapsulation is still used.</li>
    </ul>
    @note This has no effect if HIP_UDP_PORT_RANDOMIZING is off 
    @note Not used currently.
    @note This is needed only for simulation purposes and can be removed from
          released versions of HIPL.*/
#define HIP_SIMULATE_NATS 0
/** Minimum port number a NAT can randomize.
    Has to be float as it is used in rand().
    @note This is needed only for simulation purposes and can be removed from
          released versions of HIPL.*/
#define HIP_UDP_PORT_RAND_MIN 49152.0
/** Maximum port number a NAT can randomize.
    Has to be float as it is used in rand().
    @note This is needed only for simulation purposes and can be removed from
          released versions of HIPL.*/
#define HIP_UDP_PORT_RAND_MAX 65535.0
/** File descriptor of socket used for hip control packet NAT traversal on
    UDP/IPv4. Defined in hipd.c */
extern int hip_nat_sock_udp;
/** Specifies the NAT status of the daemon. This value indicates if the current
    machine is behind a NAT. Defined in hipd.c */
extern hip_transform_suite_t hip_nat_status;
extern HIP_HASHTABLE *hadb_hit;


/*
int hip_nat_on();
int hip_nat_off();
int hip_nat_is();
int hip_nat_off_for_ha(hip_ha_t *, void *);
int hip_nat_on_for_ha(hip_ha_t *, void *);
*/

int hip_ha_set_nat_mode(hip_ha_t *entry, hip_transform_suite_t mode);

hip_transform_suite_t hip_get_nat_mode();
void hip_set_nat_mode(hip_transform_suite_t mode);


void hip_nat_randomize_nat_ports();
int hip_nat_refresh_port();
int hip_nat_send_keep_alive(hip_ha_t *, void *);

int hip_nat_handle_transform_in_client(struct hip_common *msg , hip_ha_t *entry);
int hip_nat_handle_transform_in_server(struct hip_common *msg , hip_ha_t *entry);


hip_transform_suite_t hip_nat_get_control(hip_ha_t *entry);
hip_transform_suite_t hip_nat_set_control(hip_ha_t *entry, hip_transform_suite_t mode);


int hip_external_ice_receive_pkt(void * msg,int len, 
		hip_ha_t *entry, in6_addr_t * src_addr,in_port_t port );

char* get_nat_username(void* buf, const struct in6_addr *hit);
char* get_nat_password(void* buf, const char *key);

uint32_t ice_calc_priority(uint32_t type, uint16_t pref, uint8_t comp_id);

int poll_event_all( );

#endif /* __NAT_H__ */

