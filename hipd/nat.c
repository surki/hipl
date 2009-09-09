/** @file
 * This file defines extensions to Host Identity Protocol (HIP) to support
 * traversal of Network Address Translator (NAT) middleboxes.
 * 
 * The traversal mechanism tunnels HIP control and data traffic over UDP
 * and enables HIP initiators which may be behind NATs to contact HIP
 * responders which may be behind another NAT. Three basic cases exist for NAT
 * traversal. In the first case, only the initiator of a HIP base exchange is
 * located behind a NAT. In the second case, only the responder of a HIP base
 * exchange is located behind a NAT. In the third case, both parties are
 * located behind (different) NATs. The use rendezvous server is mandatory
 * when the responder is behind a NAT.
 * 
 * @author  (version 1.0) Abhinav Pathak
 * @author  (version 1.1) Lauri Silvennoinen
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
#include "nat.h"
#include <string.h>

//Pollutes libc namespace by undefining s6_addr (pj/sock.h)
#include "pjnath.h"
#include "pjlib.h"

#if defined(ANDROID_CHANGES) && !defined(s6_addr)
#  define s6_addr                 in6_u.u6_addr8
#  define s6_addr16               in6_u.u6_addr16
#  define s6_addr32               in6_u.u6_addr32
#endif

//add by santtu
/** the database for all the ha */
/** the constant value of the reflexive address amount,
 *  since there is only one RVS server, we use 1 here */
//end add
/** component ID for ICE*/
#define PJ_COM_ID 1 
#define HIP_ICE_FOUNDATION "hip_ice"
#define HIP_LOCATOR_REMOTE_MAX 10

pj_caching_pool * cpp;
pj_caching_pool cp;

/** A transmission function set for NAT traversal. */
extern hip_xmit_func_set_t nat_xmit_func_set;
/** A transmission function set for sending raw HIP packets. */
extern hip_xmit_func_set_t default_xmit_func_set;

#if 0
/** Port used for NAT travelsal random port simulation.
    If random port simulation is of, hip_nat_udp_port is used.
    @note This is needed only for simulation purposes and can be removed from
    released versions of HIPL. */
in_port_t hip_nat_rand_port1 = hip_nat_udp_port;
/** Port used for NAT travelsal random port simulation.
    If random port simulation is of, hip_nat_udp_port is used.
    @note This is needed only for simulation purposes and can be removed from
    released versions of HIPL. */
in_port_t hip_nat_rand_port2 = hip_nat_udp_port;
#endif 

#if 0
/**
 * Sets NAT status "on".
 * 
 * Sets NAT status "on" for each host association in the host association
 * database.
 *
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 */ 
int hip_nat_on()
{
	int err = 0;
	_HIP_DEBUG("hip_nat_on() invoked.\n");
#if HIP_UDP_PORT_RANDOMIZING 
	hip_nat_randomize_nat_ports();
#endif
	hip_nat_status = 1;
	
	HIP_IFEL(hip_for_each_ha(hip_nat_on_for_ha, NULL), 0,
	         "Error from for_each_ha().\n");

out_err:
	return err;
}

/**
 * Sets NAT status "off".
 *
 * Sets NAT status "off" for each host association in the host association
 * database.
 * 
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 */
int hip_nat_off()
{
	int err = 0;

	hip_nat_status = 0;
	HIP_IFEL(hip_for_each_ha(hip_nat_off_for_ha, NULL), 0,
		 "Error from for_each_ha().\n");
 out_err:
	return err;
}


/**
 * Get HIP NAT status.
 */
int hip_nat_is()
{
	return hip_nat_status;
}


/**
 * Sets NAT status "on" for a single host association.
 *
 * @param entry    a pointer to a host association for which to set NAT status.
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero.
 * @note           the status is changed just for the parameter host 
 *                 association. This function does @b not insert the host
 *                 association into the host association database.
 */
int hip_nat_on_for_ha(hip_ha_t *entry, void *not_used)
{
	/* Parameter not_used is needed because this function is called from
	   hip_nat_on() which calls hip_for_each_ha(). hip_for_each_ha()
	   requires a function pointer as parameter which in turn has two
	   parameters. */
	int err = 0;
	HIP_DEBUG("hip_nat_on_for_ha() invoked.\n");

	if(entry)
	{
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
		//entry->nat_mode = 1;
		HIP_DEBUG("NAT status of host association %p: %d\n",
			  entry, entry->nat_mode);
	}
 out_err:
	return err;
}

/**
 * Sets NAT status "off" for a single host association.
 *
 * @param entry    a pointer to a host association for which to set NAT status.
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero.
 * @note           the status is changed just for the parameter host 
 *                 association. This function does @b not insert the host
 *                 association into the host association database.
 */
int hip_nat_off_for_ha(hip_ha_t *entry, void *not_used)
{
	/* Check hip_nat_on_for_ha() for further explanation on "not_used". */
	int err = 0;
	_HIP_DEBUG("hip_nat_off_for_ha() invoked.\n");

	if(entry)
	{
		entry->nat_mode = 0;
		hip_hadb_set_xmit_function_set(entry, &default_xmit_func_set);
	}
out_err:
	return err;
}
#endif
/**
 * Refreshes the port state of all NATs related to this host.
 *
 * Refreshes the port state of all NATs between current host and all its peer
 * hosts by calling hip_nat_send_keep_alive() for each host association in
 * the host association database.
 *
 * @return zero on success, or negative error value on error.
 */ 
int hip_nat_refresh_port()
{
	int err = 0 ;
	
	HIP_DEBUG("Sending Keep-Alives to NAT.\n");
	HIP_IFEL(hip_for_each_ha(hip_nat_send_keep_alive, NULL),
		 -1, "for_each_ha() err.\n");
	
out_err:
	return err;
}

/**
 * Sends an NAT Keep-Alive packet.
 *
 * Sends an UPDATE packet with nothing but @c HMAC parameter in it to the peer's
 * preferred address. If the @c entry is @b not in state ESTABLISHED or if there
 * is no NAT between this host and the peer (@c entry->nat_mode = 0), then no
 * packet is sent. The packet is send on UDP with source and destination ports
 * set as @c hip_nat_udp_port.
 * 
 * @param entry    a pointer to a host association which links current host and
 *                 the peer.
 * @param not_used this parameter is not used (but it's needed).
 * @return         zero on success, or negative error value on error.
 * @note           If the state of @c entry is not ESTABLISHED or if
 *                 @c entry->nat_mode = 0 this function still returns zero
 *                 because these conditions are not errors. Negative error
 *                 value is only returned when the creation of the new UPDATE
 *                 message fails in some way.
 */
int hip_nat_send_keep_alive(hip_ha_t *entry, void *not_used)
{
	int err = 0;
	struct hip_common *msg = NULL;

	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "Alloc\n");
	
	_HIP_DEBUG("hip_nat_send_keep_alive() invoked.\n");
	_HIP_DEBUG("entry @ %p, entry->nat_mode %d.\n",
		  entry, entry->nat_mode);
	_HIP_DEBUG_HIT("&entry->hit_our", &entry->hit_our);

	/* Check that the host association is in correct state and that there is
	   a NAT between this host and the peer. Note, that there is no error
	   (err is set to zero) if the condition does not hold. We just don't
	   send the packet in that case. */
	if (entry->state != HIP_STATE_ESTABLISHED) {
		HIP_DEBUG("Not sending NAT keepalive state=%s\n", hip_state_str(entry->state));
		goto out_err;
        }

	if (!(entry->nat_mode)) {
		HIP_DEBUG("No nat between the localhost and the peer\n");
		goto out_err;
	}

	if (!IN6_IS_ADDR_V4MAPPED(&entry->our_addr)) {
		HIP_DEBUG("Not IPv4 address, skip NAT keepalive\n");
		goto out_err;
	}


	entry->hadb_misc_func->
		hip_build_network_hdr(msg, HIP_NOTIFY,
				      0, &entry->hit_our,
				      &entry->hit_peer);
	
	/* Calculate the HIP header length */
	hip_calc_hdr_len(msg);

	/* Send the UPDATE packet using hip_get_nat_udp_port() as source and destination ports.
	   Only outgoing traffic acts refresh the NAT port state. We could
	   choose to use other than hip_get_nat_udp_port() as source port, but we must use hip_get_nat_udp_port()
	   as destination port. However, because it is recommended to use
	   hip_get_nat_udp_port() as source port also, we choose to do so here. */
	entry->hadb_xmit_func->
		hip_send_pkt(&entry->our_addr, &entry->peer_addr,
			     entry->local_udp_port, entry->peer_udp_port, msg,
			     entry, 0);

out_err:
	if (msg)
		free(msg);

	return err;
}

#if HIP_UDP_PORT_RANDOMIZING
/**
 * Randomizes @b source ports 11111 and 22222.
 *
 * This function randomizes ports @c hip_nat_rand_port1 and
 * @c hip_nat_rand_port2 used in NAT-travelsal. NATs choose randomly a port
 * when HIP control traffic goes through them. Internet Draft 
 * [draft-schmitt-hip-nat-traversal-02] defines these random chosen ports as
 * 11111 and 22222. This function serves as a helper function to simulate
 * these random chosen ports in a non-NATed environment where UPD encapsulation
 * is used.
 *
 * @note According to [draft-schmitt-hip-nat-traversal-02] HIP daemons use
 *       one random port and NATs use two random ports. The value of
 *       @c hip_nat_rand_port1 can be considered as the random port of
 *       HIP daemon also. A scenario where HIP daemons use random source port
 *       and real life NATs randomize the NAT-P and NAT-P' ports is achieved by
 *       removing the @c hip_nat_rand_port2 randomization from this function.
 * @note Not used currently.
 * @note This is needed only for simulation purposes and can be removed from
 *       released versions of HIPL.
 */ 
void hip_nat_randomize_nat_ports()
{
	unsigned int secs_since_epoch = (unsigned int) time(NULL);
	HIP_DEBUG("Randomizing UDP ports to be used.\n");
	srand(secs_since_epoch);
	hip_nat_rand_port1 = HIP_UDP_PORT_RAND_MIN + (int)
		(((HIP_UDP_PORT_RAND_MAX - HIP_UDP_PORT_RAND_MIN + 1) * 
		  rand()) / (RAND_MAX + 1.0));
#if HIP_SIMULATE_NATS
	hip_nat_rand_port2 = HIP_UDP_PORT_RAND_MIN + (int)
		(((HIP_UDP_PORT_RAND_MAX - HIP_UDP_PORT_RAND_MIN + 1) *
		  rand()) / (RAND_MAX + 1.0));
#else
	hip_nat_rand_port2 = hip_nat_rand_port1;
#endif
	HIP_DEBUG("Randomized ports are NAT-P: %u, NAT-P': %u.\n",
		  hip_nat_rand_port1, hip_nat_rand_port2);
}
#endif

#if 0
//add by santtu from here
int hip_nat_handle_transform_in_client(struct hip_common *msg , hip_ha_t *entry){
	int err = 0;
	struct hip_nat_transform *nat_transform  = NULL;
	
    
    nat_transform = hip_get_param(msg, HIP_PARAM_NAT_TRANSFORM);
    
    if(nat_transform ){
    	// in the furtue, we should check all the transform type and pick only one
    	// but now, we have only one choice, which is ICE, so the code is the same as
    	//in the server side.
	    	HIP_DEBUG("in handle i %d",ntohs(nat_transform->suite_id[1]));
	    	if (hip_nat_get_control(NULL) == (ntohs(nat_transform->suite_id[1])))
	    		hip_nat_set_control(entry, ntohs(nat_transform->suite_id[1]));
    		else  hip_nat_set_control(entry, 0);  
	    	
	    	HIP_DEBUG("nat control is %d\n",hip_nat_get_control(entry));
		   
    }
    else 
	    hip_nat_set_control(entry, 0);    
out_err:
	return err;
	  
}

int hip_nat_handle_transform_in_server(struct hip_common *msg , hip_ha_t *entry){
	int err = 0;
	struct hip_nat_transform *nat_transform = NULL;
	
	    nat_transform = hip_get_param(msg, HIP_PARAM_NAT_TRANSFORM);
	    
	    if(nat_transform ){
	    	// in the furtue, we should check all the transform type and pick only one
	    	// but now, we have only one choice, which is ICE, so the code is the same as
	    	//in the server side.
		    	HIP_DEBUG("in handle i %d\n",ntohs(nat_transform->suite_id[1]));
		    	if (hip_nat_get_control(NULL) == (ntohs(nat_transform->suite_id[1])))
		    	
		    		hip_nat_set_control(entry, ntohs(nat_transform->suite_id[1]));
		    	else  hip_nat_set_control(entry, 0);  
		    	
		    	HIP_DEBUG("nat control is %d\n",hip_nat_get_control(entry));
			   
	    }
	    else 
		    hip_nat_set_control(entry, 0);   
	out_err:
		return err;
}
#endif

int hip_nat_handle_pacing(struct hip_common *msg , hip_ha_t *entry){
	int err = 0;
	struct hip_nat_pacing *nat_pacing = NULL;
	
	nat_pacing = hip_get_param(msg, HIP_PARAM_NAT_PACING);
	
	if(nat_pacing != NULL && entry != NULL){
		// check if the requested tranform is also supported in the server.
		entry->pacing = ntohl(nat_pacing->min_ta);
		_HIP_DEBUG("*****************nat pacing is %d", entry->pacing);
	} else {
		if(entry != NULL) entry->pacing = HIP_NAT_PACING_DEFAULT;
		HIP_DEBUG("handle nat pacing failed: entry %d, "\
			  "nat pacing %d\n", entry, nat_pacing);
	}
	
out_err:
	return err;
}


/**
 * get the NAT mode for a host association
 * 
 *
 * Simlimar to hip_ha_set, but skip the setting when RVS mode is on, this 
 * function is for ICE code 
 * 
 * @param entry    a pointer to a host association which links current host and
 *                 the peer.
 * @return         the value of the NAT mode.
 */
hip_transform_suite_t hip_nat_get_control(hip_ha_t *entry){
	
	_HIP_DEBUG("check nat mode for ice: %d, %d, %d\n",
		  (entry ? hip_get_nat_mode(entry) : 0),
			hip_get_nat_mode(NULL),HIP_NAT_MODE_ICE_UDP);
#ifdef HIP_USE_ICE
	return hip_get_nat_mode(entry);
#else
	return hip_get_nat_mode(entry);
#endif

}


/**
 * Set the NAT mode for a host association
 * 
 *
 * Simlimar to hip_ha_set_nat_mode, but skip the setting when RVS mode is on, this 
 * function is for ICE code 
 * 
 * @param entry    a pointer to a host association which links current host and
 *                 the peer.
 * @param mode 	   a integer for NAT mode.
 * @return         zero on success.
 */
hip_transform_suite_t hip_nat_set_control(hip_ha_t *entry, hip_transform_suite_t mode){
	
#ifdef HIP_USE_ICE
	/*
	 if(hip_relay_get_status() == HIP_RELAY_ON)
		 return 0;
		 */
	 hip_ha_set_nat_mode(entry, &mode);
#endif
	return 0;


}


/**
 * Sets NAT status
 * 
 * Sets NAT mode for each host association in the host association
 * database.
 *
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 *
int hip_user_nat_mode(int nat_mode)
{
	int err = 0, nat;
	HIP_DEBUG("hip_user_nat_mode() invoked. mode: %d\n", nat_mode);
#if HIP_UDP_PORT_RANDOMIZING 
	hip_nat_randomize_nat_ports();
#endif
	
	nat = nat_mode;
	switch (nat) {
	case SO_HIP_SET_NAT_PLAIN_UDP:
		nat = HIP_NAT_MODE_PLAIN_UDP;
		break;
	case SO_HIP_SET_NAT_NONE:
		nat = HIP_NAT_MODE_NONE;
		break;
	case SO_HIP_SET_NAT_ICE_UDP:
		nat = HIP_NAT_MODE_ICE_UDP;
		break;
	default:
		err = -1;
		HIP_IFEL(1, -1, "Unknown nat mode %d\n", nat_mode);
	} 
	HIP_IFEL(hip_for_each_ha(hip_ha_set_nat_mode, nat), 0,
	         "Error from for_each_ha().\n");
	//set the nat mode for the host
	hip_set_nat_mode(nat);
	
	HIP_DEBUG("hip_user_nat_mode() end. mode: %d\n", hip_nat_status);

out_err:
	return err;
}
*/
 
//pj_caching_pool *cpp;

/* 
pj_status_t status;
pj_pool_t *pool = 0;
*/





  


hip_ha_t * hip_get_entry_from_ice(void * ice){ 

	hip_ha_t *ha_n, *entry;
	hip_list_t *item = NULL, *tmp = NULL;
	int i;
	
	entry = NULL;
	// found the right entry. 
	
	list_for_each_safe(item, tmp, hadb_hit, i) {
	    ha_n = list_entry(item);
	    if(ha_n->ice_session == ice){
	    	entry = ha_n;
	    	break;
	    }
	}
	
	return entry;
}  


/***
 * this the call back interface when check complete.
 * */
void  hip_on_ice_complete(pj_ice_sess *ice, pj_status_t status) {
	pj_ice_sess_checklist *	valid_list;
	int err = 0;
	int i =0, j =0, k=0;
	pj_ice_sess_cand	*rcand;
	pj_sockaddr		 addr;
	hip_ha_t *ha_n, *entry;
	hip_list_t *item = NULL, *tmp = NULL;
	hip_list_t *item1 = NULL, *tmp1 = NULL;
	struct hip_peer_addr_list_item * peer_addr_list_item;
//	struct hip_spi_out_item* spi_out;
	uint32_t spi_out, spi_in = 0;
	struct in6_addr peer_addr;
	
	HIP_DEBUG("hip_on_ice_complete\n");

	entry = hip_get_entry_from_ice(ice);
	if(!entry) {
		HIP_DEBUG("entry not found in ice complete\n");
		return;
	}
	spi_out = hip_hadb_get_outbound_spi(entry);

	if(!spi_out) {
		HIP_DEBUG("spi_out not found in ice complete\n");
		return;
	}


	// the verified list 
	//if(status == PJ_TRUE){
	valid_list = &ice->valid_list;
	//}
	
	HIP_DEBUG("there are %d pairs in valid list\n", valid_list->count);
	//read all the element from the list
	HIP_IFEL((valid_list->count <= 0), 0, "No items on list");
			
	//	for(i = 0; i< valid_list->count; i++){
	//	if (valid_list->checks[i].nominated == PJ_TRUE){
	//set the prefered peer
	HIP_DEBUG("find a nominated candiate\n");
	
	//	if(valid_list->checks[0].lcand->type = ICE_CAND_TYPE_PRFLX){
	if(0){
		HIP_DEBUG("it is peer reflexive\n");
		addr = valid_list->checks[0].lcand->addr;
	}
	else{	
		HIP_DEBUG("it is not peer reflexive\n");
		addr = valid_list->checks[0].rcand->addr;
	}
	
	
	//	hip_print_lsi("set prefered the peer_addr : ", &addr.ipv4.sin_addr.s_addr );
	
	peer_addr.s6_addr32[0] = (uint32_t)0;
	peer_addr.s6_addr32[1] = (uint32_t)0;
	peer_addr.s6_addr32[2] = (uint32_t)htonl (0xffff);
	peer_addr.s6_addr32[3] = (uint32_t)addr.ipv4.sin_addr.s_addr;
	
	//tobe checked. the address type can be fatched. I put 0 here as a hack.
	hip_hadb_add_udp_addr_to_spi(entry, spi_out, &peer_addr, 1, 0, 1,addr.ipv4.sin_port, HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI_PRIORITY,0);
	memcpy(&entry->peer_addr, &peer_addr, sizeof(struct in6_addr));
	entry->peer_udp_port = ntohs(addr.ipv4.sin_port);
	HIP_DEBUG("set prefered the peer_addr port: %d\n",ntohs(addr.ipv4.sin_port ));
	
	if (entry->state == HIP_STATE_ESTABLISHED)
		spi_in = hip_hadb_get_latest_inbound_spi(entry);
	
	/* XX FIXME */
	/* Use hip_sendto_firewall() to notify the firewall if the chosen address/port is
	   for TURN */
	
	/* If TURN is used, change entry->port HIP_TURN_PORT */
	
	err = hip_add_sa(&entry->our_addr, &entry->peer_addr,
			 &entry->hit_our, &entry->hit_peer,
			 spi_out, entry->esp_transform,
			 &entry->esp_out, &entry->auth_out, 1,
			 HIP_SPI_DIRECTION_OUT, 0, entry);
	if (err) {
		HIP_ERROR("Failed to setup outbound SA with SPI=%d\n",
			  entry->default_spi_out);
		hip_hadb_delete_inbound_spi(entry, 0);
		hip_hadb_delete_outbound_spi(entry, 0);
	}
	
	err = hip_add_sa(&entry->peer_addr, &entry->our_addr, 
			 &entry->hit_peer,&entry->hit_our, 
			 spi_in,
			 entry->esp_transform,
			 &entry->esp_in, 
			 &entry->auth_in, 
			 1,
			 HIP_SPI_DIRECTION_IN, 0, entry);
	if (err) {
		HIP_ERROR("Failed to setup inbound SA with SPI=%d\n", spi_in);
		/* if (err == -EEXIST)
		   HIP_ERROR("SA for SPI 0x%x already exists, this is perhaps a bug\n",
		   spi_in); */
		err = -1;
		hip_hadb_delete_inbound_spi(entry, 0);
		hip_hadb_delete_outbound_spi(entry, 0);
		goto out_err;
	}
	
	err = hip_setup_hit_sp_pair(&entry->hit_peer, &entry->hit_our,
				    &entry->peer_addr,
				    &entry->our_addr,  IPPROTO_ESP, 1, 1);
	if(err) 
		HIP_DEBUG("Setting up SP pair failed\n");

	//TODO decide if we should save the paired local address also.

 out_err:
	return;
}


/**
 * this is the call back interface to send package.
 * */
pj_status_t hip_on_tx_pkt(pj_ice_sess *ice, unsigned comp_id, unsigned transport_id, const void *pkt, pj_size_t size, const pj_sockaddr_t *dst_addr, unsigned dst_addr_len){
	struct hip_common *msg = NULL;
	pj_status_t err = PJ_SUCCESS;
	hip_ha_t *entry;
	struct in6_addr *local_addr = 0;
	struct in6_addr peer_addr;
	in_port_t src_port = hip_get_local_nat_udp_port(); 
	in_port_t dst_port;
	pj_sockaddr_in *addr;
	int msg_len ;
	int retransmit = 0;
	
	HIP_DEBUG("hip_send stun : \n");
	HIP_DEBUG("length of the stun package is %d\n", size );
	//hip_dump_pj_stun_msg(pkt,size);
	HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "Out of memory\n");	
	entry = hip_get_entry_from_ice(ice);
	if(entry==NULL) {
		err = -1;
		goto out_err;
	}

	
	hip_build_network_hdr(msg, HIP_UPDATE, 0, &entry->hit_our, &entry->hit_peer);
	hip_build_param_contents(msg,pkt,HIP_PARAM_STUN,size);
	
	addr =(pj_sockaddr_in *) dst_addr;
	peer_addr.s6_addr32[0] = (uint32_t)0;
	peer_addr.s6_addr32[1] = (uint32_t)0;
	peer_addr.s6_addr32[2] = (uint32_t)htonl (0xffff);
	peer_addr.s6_addr32[3] = (uint32_t)addr->sin_addr.s_addr;
	
	dst_port = ntohs(addr->sin_port);
	
//	if(err = hip_send_udp(local_addr, &peer_addr, src_port,dst_port, msg, msg->payload_len,0) )
//		goto out_err;
	if(err = hip_send_udp_stun(local_addr, &peer_addr, src_port,dst_port, pkt, size) )
		goto out_err;
out_err:
	 	if (msg)
	 		HIP_FREE(msg);
	  	return err;
}
/**
 * 
 * this is the call back interface when the received packet is not strun.
 * we ignire here.
 * */
void hip_on_rx_data(pj_ice_sess *ice, unsigned comp_id, void *pkt, pj_size_t size, const pj_sockaddr_t *src_addr, unsigned src_addr_len){
	HIP_DEBUG("failed stun\n");
}





/***
 * this function is added to create the ice seesion
 * currently we suppport only one session at one time.
 * only one component in the seesion.
 * 
 * return the pointer of the ice session 
 * */

void* hip_external_ice_init(pj_ice_sess_role role,const struct in_addr *hit_our,const char* ice_key){

	pj_ice_sess *  	p_ice;
	pj_status_t status;
	pj_pool_t *pool, *io_pool ;
	char user[17];
	char our_hit[8];
	char peer_hit[8];
	
	unsigned   comp_cnt = PJ_COM_ID;	
	pj_str_t    	local_ufrag = pj_str("user");
	pj_str_t   	local_passwd = pj_str("pass");
	const char *  name = "hip_ice";
	pj_stun_config  stun_cfg;
	pj_ice_sess_role   	 ice_role = role;
	struct pj_ice_sess_cb cb;
	pj_ioqueue_t *ioqueue;
	pj_timer_heap_t *timer_heap;	
	char dst8[16];
	char dst32[128];
	
	cpp = &cp;
	
	
	_HIP_DEBUG_HIT("our hit is ", hit_our);
	
	get_nat_username(dst8, hit_our);	
	HIP_DEBUG("our username is %s \n",dst8);
	get_nat_password(dst32, ice_key);
	HIP_DEBUG("our password is %s \n",dst32);
		
	local_ufrag = pj_str(dst8);
	local_passwd = pj_str(dst32);
	
	//configure the call back handle
	cb.on_ice_complete = &hip_on_ice_complete;
	cb.on_tx_pkt = &hip_on_tx_pkt;
	cb.on_rx_data= &hip_on_rx_data;
	
	//init for PJproject
	status = pj_init();
	pjlib_util_init();
	
		
	if (status != PJ_SUCCESS) {
		HIP_DEBUG("Error initializing PJLIB", status);
	        return 0;
	}
	pj_log_set_level(5);
	//init for memery pool factroy
	// using default pool policy.
	
	pj_dump_config();
	pj_caching_pool_init(&cp, NULL, 6024*6024 );
	
	pjnath_init();
 	// create a pool  	   
	pool = pj_pool_create(&cp.factory, NULL, 1000, 1000, NULL);
	// creata an IO pool
	io_pool = pj_pool_create(&cp.factory, NULL, 1000, 1000, NULL);
	// create an IO Queue
	status = pj_ioqueue_create(pool, 12, &ioqueue);
	
	
	if(status != PJ_SUCCESS){
		HIP_DEBUG("IO Queue create failed\n");
		goto out_err;
	}
	// create a Heap
	status = pj_timer_heap_create(io_pool, 100, &timer_heap);
	
	if(status != PJ_SUCCESS){
		HIP_DEBUG("timer heap create failed\n");
	   	goto out_err;
	}
	// init the stun config
	//status = pj_stun_config_init(&stun_cfg, &cp.factory, 0, ioqueue, timer_heap);	
	
	status = create_stun_config(pool, &stun_cfg, &cp.factory);
	if (status != PJ_SUCCESS) {
		 HIP_DEBUG("create_stun_config failed\n");
		 goto out_err;
	 }
	
	
	//HIP_DEBUG("cp factory address is %d\n", &cp.factory);

	//create ice session
	status =  pj_ice_sess_create( 
			&stun_cfg,
 			name,
 			ice_role,
 			comp_cnt,
 			&cb,
 			&local_ufrag,
 			&local_passwd,
 			&p_ice	 
	 		);
	
	 if(PJ_SUCCESS ==  status){
		 HIP_DEBUG("pj_ice_sess_create succeeds\n");
		 
		 return p_ice;
	  }
	 else {
		 HIP_DEBUG("pj_ice_sess_create failed\n");
		 goto out_err;
	 }

 	 
out_err: 
	HIP_DEBUG("ice init fail %d \n", status);
 	return NULL;
 	
}

/***
 * this function is called to add local candidates for the only component
 *  
 * */
int hip_external_ice_add_local_candidates(void* session, in6_addr_t * hip_addr, in6_addr_t * hip_addr_base, 
		in_port_t port,in_port_t port_base, int addr_type, int pre_var){
	
	pj_ice_sess * ice ;
	unsigned comp_id;
	pj_ice_cand_type type;
	uint32_t local_pref;
	pj_str_t foundation;

	int addr_len;
	unsigned p_cand_id;
	pj_sockaddr_in pj_addr;
	pj_sockaddr_in pj_addr_base;
	pj_status_t pj_status;
	int err= 0; 
	 	 
	//if (ipv6_addr_is_hit(hip_addr_base)) goto out_err;	 
	_HIP_DEBUG_HIT("coming address ",hip_addr);	 
	ice = session;	 
	comp_id = PJ_COM_ID;
	type = addr_type;
	foundation = pj_str(HIP_ICE_FOUNDATION);
	 
	 
	switch(type){
		case ICE_CAND_TYPE_HOST:
			local_pref = ICE_CAND_PRE_HOST;
			break;
		case ICE_CAND_TYPE_SRFLX:
			local_pref = ICE_CAND_PRE_SRFLX;
			break;
		case ICE_CAND_TYPE_RELAYED:
			local_pref = ICE_CAND_PRE_RELAYED;
			break;
		default: 
			HIP_DEBUG("wrong candidate type in add local \n");
			break;
	 }
	 
	 
	pj_addr.sin_family=PJ_AF_INET;
	pj_addr.sin_port = htons(port);
	pj_addr.sin_addr.s_addr =*((pj_uint32_t*) &hip_addr->s6_addr32[3]);
	 
	 
	pj_addr_base.sin_family=PJ_AF_INET;
	pj_addr_base.sin_port = htons(port_base);
	pj_addr_base.sin_addr.s_addr =*((pj_uint32_t*) &hip_addr_base->s6_addr32[3]);
	 
	addr_len = sizeof(pj_sockaddr_in);

	
	pj_status =  pj_ice_sess_add_cand(	ice,
			comp_id,
			1,
			type,
			local_pref,
			&foundation,
			&pj_addr,
			&pj_addr_base,
			NULL,
			addr_len,
			&p_cand_id	 
		);
	if(pj_status == PJ_SUCCESS)	{
		// 1 means successful
		return 1;
	}
	else return 0;
out_err:
	return err;
}


/*****
*  
*this function is called after the local candidates are added. 
* the check list will created inside the seesion object. 
*/
/// @todo: Check this function for the hip_get_nat_xxx_udp_port() calls!!!
int hip_external_ice_add_remote_candidates( void * session, HIP_HASHTABLE*  list, const struct in_addr *hit_peer,const char * ice_key){	
	pj_ice_sess *   	 ice = session;
	unsigned  	rem_cand_cnt;
	pj_ice_sess_cand *      temp_cand;
	pj_ice_sess_cand *  	rem_cand;
	struct hip_peer_addr_list_item * peer_addr_list_item;
	int i, err = 0;
	hip_list_t *item, *tmp;
	//username and passwd will be changed
	pj_str_t    	 ufrag = pj_str("user");
 	pj_str_t   	 passwd = pj_str("pass");
	pj_pool_t *pool ;
	pj_status_t t;
	
	char dammy;
	char dst32[128];
	char dst8[16];
	
	HIP_DEBUG("ICE add remote function\n");
	
	
	
	get_nat_username(dst8, hit_peer);
	_HIP_DEBUG("peer username is %s \n",ice_name);
	get_nat_password(dst32, ice_key);
	
	_HIP_DEBUG("\n**************************\n");
	_HIP_DEBUG("peer username is %s \n",ice_name);
	_HIP_DEBUG("peer password is %s \n",dst32);
	_HIP_DEBUG("\n**************************\n");	
	
	ufrag = pj_str(dst8);
	passwd = pj_str(dst32);
	
	
	//pj_caching_pool cp;
	//pj_caching_pool_init(&cp, NULL, 6024*2024 );
	//if(cpp == 0 )HIP_DEBUG("CPP is empty\n");
 	//pool = pj_pool_create(&cp.factory, NULL, 4000, 4000, NULL);
	
	
	//reuse the pool for the ice session
	pool = ((pj_ice_sess *) session)->pool;
	// set the remote candidate counter to 0
	rem_cand_cnt = 0;
	//reserve space for the remote candidates, only 10 remote locator item is supported
	rem_cand = pj_pool_calloc(pool,HIP_LOCATOR_REMOTE_MAX, sizeof(pj_ice_sess_cand));

	i=0;
	// init the temp candidate pointer to the  beginning of reserved space
	temp_cand = rem_cand;
	
	list_for_each_safe(item, tmp, list, i) {
		peer_addr_list_item = list_entry(item);	

		HIP_DEBUG_HIT("add Ice remote address:", &peer_addr_list_item->address);
		HIP_DEBUG("add Ice remote port: %d \n", peer_addr_list_item->port);
		//IPv6 address will not be counted
		if (ipv6_addr_is_hit(&peer_addr_list_item->address))
		    continue;

		if (IN6_IS_ADDR_V4MAPPED(&peer_addr_list_item->address)) {
			//check if the remote locator item are over the max
			if( rem_cand_cnt >= HIP_LOCATOR_REMOTE_MAX -1) break;
			
			
			temp_cand->comp_id = PJ_COM_ID;		
			temp_cand->addr.ipv4.sin_family = PJ_AF_INET;
			if (peer_addr_list_item->port)
				//UDP locator item
				temp_cand->addr.ipv4.sin_port = htons(peer_addr_list_item->port);
			else    //IP locator item, let's use 50500 as the port number
				temp_cand->addr.ipv4.sin_port = htons(hip_get_local_nat_udp_port());
			
			temp_cand->addr.ipv4.sin_addr.s_addr = *((pj_uint32_t *) &peer_addr_list_item->address.s6_addr32[3]) ;
			
			
			
			temp_cand->base_addr.ipv4.sin_family = PJ_AF_INET;
			if (peer_addr_list_item->port)
				temp_cand->base_addr.ipv4.sin_port = htons(peer_addr_list_item->port);
			else 
				temp_cand->base_addr.ipv4.sin_port = htons(hip_get_peer_nat_udp_port());
			temp_cand->base_addr.ipv4.sin_addr.s_addr = *((pj_uint32_t*) &peer_addr_list_item->address.s6_addr32[3]);
						
			
			
			temp_cand->comp_id = PJ_COM_ID;
			if ((peer_addr_list_item->port) == 0 ||
			    (peer_addr_list_item->port == hip_get_local_nat_udp_port())) {
				temp_cand->type = ICE_CAND_TYPE_HOST;
			} else {			
				// we can not get peer base address for the reflexive address. 
				// set all the peer address to host type for now.
				temp_cand->type = ICE_CAND_TYPE_HOST;
			}
			temp_cand->foundation = pj_str(HIP_ICE_FOUNDATION);
			
			/* Reverse the priority for pjsip. Otherwise we got
			   always a TURNed address in interops with hip4inter */
			temp_cand->prio = UINT_MAX - peer_addr_list_item->priority;
		//	temp_cand->prio = peer_addr_list_item->priority;
		//	temp_cand->prio = 1;
			temp_cand->type = peer_addr_list_item->kind;
			HIP_DEBUG("Add remote candidate priority original : %u\n", peer_addr_list_item->priority);
			HIP_DEBUG("Add remote candidate priority minus by MAX : %u\n\n", temp_cand->prio);
			temp_cand++;
			rem_cand_cnt++;
		}
	}
	
	HIP_DEBUG("complete remote list \n");
	
	HIP_DEBUG("add remote number: %d \n", rem_cand_cnt);
	pj_log_set_level(5);
	if (rem_cand_cnt > 0)
		t = pj_ice_sess_create_check_list(session,
						  &ufrag,
						  &passwd,
						  rem_cand_cnt,
						  rem_cand);
	
	pj_log_set_level(5);

	HIP_DEBUG("add remote result: %d \n", t);
out_err:
/*
	if(pool)
		pj_pool_release(pool);
		*/
	return err;
}



/**
 * 
 * called after check list is created
 * */

int hip_ice_start_check(void* ice){
	
	pj_ice_sess * session = ice;
	
	HIP_DEBUG("start checking\n");
	HIP_DEBUG("ice: %s \n", session->obj_name);
	HIP_DEBUG("ice: local c number %d \n", session->lcand_cnt);
	HIP_DEBUG("ice: remote candidate amount %d \n", session->rcand_cnt);
	HIP_DEBUG("ice: local candidate  amount %d \n", session->lcand_cnt);
	HIP_DEBUG("Ice: check list number: %d \n\n", session->clist.count);
		
	
	
	int j;
	HIP_DEBUG("*********print check Local candidate ************\n" );
	for(j= 0; j< session->lcand_cnt; j++ ){
		HIP_DEBUG("Ice: check local candidate : %d \n" , j);
		HIP_DEBUG("candidate 's foundation %s \n" ,(uint32_t) session->lcand[j].foundation.ptr );
		HIP_DEBUG("candidate 's prio %u \n" , session->lcand[j].prio );
	//	hip_print_lsi("candidate 's 	base addr:" , &(session->lcand[j].addr.ipv4.sin_addr.s_addr ));																	
		HIP_DEBUG("ca 's base addr port: %d \n\n" , ntohs(session->lcand[j].addr.ipv4.sin_port ));
	}
	if(session->lcand_cnt <= 0){
		HIP_DEBUG("local candidate number is or less than 0, quit ICE" );
		return -1;
	}
	
	HIP_DEBUG("*********print check remote candidate ************\n" );
	
	int i;
	for(i= 0; i< session->rcand_cnt; i++ ){
		HIP_DEBUG("Ice: check remote candidate : %d \n" , i);
		HIP_DEBUG("ca 's foundation %s \n" ,(uint32_t) session->rcand[i].foundation.ptr );
		HIP_DEBUG("ca 's prio %u \n" , session->rcand[i].prio );
//		hip_print_lsi("ca 's 	base addr:" , &(session->rcand[i].addr.ipv4.sin_addr.s_addr ));
		HIP_DEBUG("ca 's base addr port: %d \n" , ntohs(session->rcand[i].addr.ipv4.sin_port ));
	}
	if(session->rcand_cnt <= 0){
		HIP_DEBUG("remote candidate number is or less than 0, quit ICE" );
			return -1;
		}
					
	pj_status_t result;
	HIP_DEBUG("Ice: check dump end\n");
	HIP_DEBUG("*********end check  candidate ************\n" );
	pj_log_set_level(3);
	result = pj_ice_sess_start_check  	(  session  	 ) ; 
	HIP_DEBUG("Ice: check  end: check list number: %d \n", session->clist.count);
	
	if(result == PJ_SUCCESS) return 0;
	else return -1;
			
}
/*
int hip_external_ice_end(){
	//destory the pool
	if(pool)
		pj_pool_release(pool);
    //destory the pool factory
    pj_caching_pool_destroy(&cp);
}
*/
int hip_external_ice_receive_pkt(void * msg,int len, hip_ha_t *entry, in6_addr_t * src_addr,in_port_t port ){

    int i, addr_len;
    pj_sockaddr_in pj_addr;
   
    
    HIP_DEBUG_HIT("receive a stun  from:  " ,src_addr );
    HIP_DEBUG("receive a stun  port:  %d\n" ,port);
   // hip_dump_pj_stun_msg(msg, len);
    
    
    //TODO filter out ipv6
	 pj_addr.sin_family=PJ_AF_INET;
	 pj_addr.sin_port = htons(port);
	 pj_addr.sin_addr.s_addr =*((pj_uint32_t*) &src_addr->s6_addr32[3]);
	 
	 addr_len = sizeof(pj_sockaddr_in);
    

     if(entry->ice_session){
    	pj_ice_sess_on_rx_pkt(entry->ice_session,1,1,msg, len, &pj_addr,addr_len);
    }
    else{
    	HIP_DEBUG("ice is not init in entry.\n");
    }
    
	
     return 0;
}

int hip_external_ice_receive_pkt_all(void* msg, int len, in6_addr_t * src_addr,in_port_t port ){

	int i=0, addr_len, err= 0;
	pj_sockaddr_in pj_addr; 
	hip_ha_t *ha_n, *entry;
	hip_list_t *item = NULL, *tmp = NULL;

	if (pj_stun_msg_check(msg,len,PJ_STUN_IS_DATAGRAM) != PJ_SUCCESS){
		err = 0;
		goto out_err;
	}
	
	list_for_each_safe(item, tmp, hadb_hit, i) {
	    ha_n = list_entry(item);
	    if(ha_n->ice_session){
	    	entry = ha_n;
	    	hip_external_ice_receive_pkt(msg,len,entry,src_addr, port);
	    	err = 1;
	    }
	}
	
out_err:
	return err;
}

int hip_nat_parse_pj_addr(pj_sockaddr_in *pj_addr,in6_addr_t * hip_addr, in_port_t *port, int *priority,int *type ){
	return 0;
	
}
/*

int hip_nat_create_pj_session_cand(pj_ice_sess_cand *pj_cand,in6_addr_t * hip_addr, in_port_t *port, int *priority, int *type ){
	
	int err = 0;
	//TODO check IPV6
	if(pj_cand == NULL) goto out_err;
	//constant  pj_cand
	
	pj_cand->type = *type;
	pj_cand->status;
	
	pj_cand->comp_id = 1;
	pj_cand->transport_id;
	pj_cand->local_pref;
	pj_cand->foundation = pj_str("ice");
	pj_cand->prio = *priority;
	
	memcpy(&pj_cand->addr, addr, sizeof(pj_sockaddr));
	memcpy(&pj_cand->base_addr, base_addr, sizeof(pj_sockaddr));
	
out_err:	
	return err;
	
}
*/


/**
 * Sets NAT status
 * 
 * Sets NAT mode for each host association in the host association
 * database.
 *
 * @return zero on success, or negative error value on error.
 * @todo   Extend this to handle peer_hit case for
 *         <code>"hipconf hip nat peer_hit"</code> This would be helpful in
 *         multihoming case.
 */ 
int hip_user_nat_mode(int nat_mode)
{
	int err = 0, nat;
	HIP_DEBUG("hip_user_nat_mode() invoked. mode: %d\n", nat_mode);
#if HIP_UDP_PORT_RANDOMIZING 
	hip_nat_randomize_nat_ports();
#endif
	
        nat = nat_mode;
	switch (nat) {
	case SO_HIP_SET_NAT_PLAIN_UDP:
		nat = HIP_NAT_MODE_PLAIN_UDP;
		break;
	case SO_HIP_SET_NAT_NONE:
		nat = HIP_NAT_MODE_NONE;
		break;
	case SO_HIP_SET_NAT_ICE_UDP:
		nat = HIP_NAT_MODE_ICE_UDP;
		break;
	default:
		err = -1;
		HIP_IFEL(1, -1, "Unknown nat mode %d\n", nat_mode);
	} 
	HIP_IFEL(hip_for_each_ha(hip_ha_set_nat_mode, &nat), 0,
	         "Error from for_each_ha().\n");
	//set the nat mode for the host
	hip_set_nat_mode(nat);
	
	HIP_DEBUG("hip_user_nat_mode() end. mode: %d\n", hip_nat_status);

out_err:
	return err;
}

/**
 * Get HIP NAT status.
 */
hip_transform_suite_t hip_get_nat_mode(hip_ha_t *entry)
{
	if (entry) {
		return entry->nat_mode;
		
	}
	return hip_nat_status;
}

/**
 * Set HIP NAT status.
 */
void hip_set_nat_mode(hip_transform_suite_t mode)
{
	hip_nat_status = mode;
}


/**
 * Sets NAT status "on" for a single host association.
 *
 * @param entry    a pointer to a host association for which to set NAT status.
 * @param mode     nat mode
 * @return         zero.
 * @note           the status is changed just for the parameter host 
 *                 association. This function does @b not insert the host
 *                 association into the host association database.
 */
int hip_ha_set_nat_mode(hip_ha_t *entry, hip_transform_suite_t mode)
{
	int err = 0;

	if(entry && mode != HIP_NAT_MODE_NONE)
	{
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
		entry->nat_mode = mode;
		HIP_DEBUG("NAT status of host association %p: %d\n",
			  entry, entry->nat_mode);
	}
 out_err:
	return err;
}

hip_transform_suite_t hip_select_nat_transform(hip_ha_t *entry,
					       hip_transform_suite_t *suite,
					       int suite_count) {
	hip_transform_suite_t pref_tfm, last_tfm = 0;
	int i, match = 0;

	HIP_HEXDUMP("", suite, suite_count * sizeof(hip_transform_suite_t));

	pref_tfm = hip_nat_get_control(entry);

	for (i = 0; i < suite_count; i++) {
		HIP_DEBUG("Pref=%d, suite=%d, ntohs=%d\n",
			  pref_tfm, suite[i], ntohs(suite[i]));
		if (pref_tfm == ntohs(suite[i])) {
			match = 1;
			pref_tfm = ntohs(suite[i]);
			break;
		}
	}

	if (suite_count == 0)
		pref_tfm = 0;
	else if (!match)
		pref_tfm = ntohs(suite[i-1]);

	//hip_ha_set_nat_mode(entry, pref_tfm);

	HIP_DEBUG("preferred nat tfm: %d\n", pref_tfm);

	return pref_tfm;
}

int hip_nat_start_ice(hip_ha_t *entry, struct hip_context *ctx){
	
	int err = 0, i = 0, index = 0;
	hip_list_t *item, *tmp;
	struct netdev_address *n;
	struct hip_spi_out_item* spi_out;
	hip_ha_t *ha_n;
	void* ice_session;
	struct hip_esp_info *esp_info = ctx->esp_info;

	HIP_IFEL(!hip_nat_get_control(entry), 0,
		 "nat_control is not set to ice on \n");
	
	//init the session right after the locator receivd
	HIP_DEBUG("ICE init \n");
	ice_session = hip_external_ice_init(entry->ice_control_role,
					    &entry->hit_our,
					    entry->hip_nat_key);
	
	/* R2 sent through relay might arrive before STUN packets.
	   Introduce additional delay for R2. */
	if (entry->ice_control_role == ICE_ROLE_CONTROLLED)
		usleep(HIP_NAT_RELAY_LATENCY * 1000);
	
	HIP_IFEL(!ice_session, 0, "No ice session\n");
	
	entry->ice_session = ice_session;
	
	HIP_DEBUG("ICE pacing is %d \n", entry->pacing);
	((pj_ice_sess*)ice_session)->pacing = entry->pacing;
	
	//pacing value
	HIP_DEBUG("ICE add local \n");
	//add the type 1 address first
	index = 0;
	list_for_each_safe(item, tmp, addresses, i) {
		index++;
		n = list_entry(item);
		// filt out IPv6 address
		if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
			continue;
		HIP_DEBUG_HIT("add Ice local address", hip_cast_sa_addr(&n->addr));
	        		
		if (hip_sockaddr_is_v6_mapped(&n->addr) &&
		    !(n->flags & HIP_FLAG_CONTROL_TRAFFIC_ONLY)) {
			hip_external_ice_add_local_candidates(ice_session,
							      hip_cast_sa_addr(&n->addr),hip_cast_sa_addr(&n->addr),
							      hip_get_local_nat_udp_port(),hip_get_peer_nat_udp_port(),
							      ICE_CAND_TYPE_HOST, index);
		}		
        		
	}

	//add reflexive address 
	HIP_DEBUG("ICE add local reflexive\n");
	i = 0;           
	list_for_each_safe(item, tmp, hadb_hit, i) {
                ha_n = list_entry(item);
                // check if the reflexive udp port. if it not 0. it means addresses found
                if(!ha_n->local_reflexive_udp_port)
			continue;
		if (IN6_IS_ADDR_V4MAPPED(&ha_n->local_reflexive_address)) {
			hip_external_ice_add_local_candidates(ice_session,
							      &ha_n->local_reflexive_address,
							      &ha_n->our_addr,
							      ha_n->local_reflexive_udp_port,
							      hip_get_local_nat_udp_port(),
							      ICE_CAND_TYPE_PRFLX,
							      ha_n->local_reflexive_udp_port);
                }
	}
            
	//TODO add relay address
        	
	HIP_DEBUG("ICE add remote IN R2, spi is %d\n",
		  ntohl(esp_info->new_spi));
	HIP_IFEL(!(spi_out = hip_hadb_get_spi_list(entry,
						   ntohl(esp_info->new_spi))), -1,
		 "Bug: outbound SPI 0x%x does not exist\n", ntohl(esp_info->new_spi)); 
	
	HIP_DEBUG("ICE add remote IN R2, peer list mem address is %d\n",
		  spi_out->peer_addr_list);
	hip_external_ice_add_remote_candidates(ice_session,
					       spi_out->peer_addr_list,
					       &entry->hit_peer,
					       entry->hip_nat_key);
	
	HIP_DEBUG("ICE start checking\n");
	
	hip_ice_start_check(ice_session);

	//poll_events(&((pj_ice_sess*)ice_session)->stun_cfg, 5000, 0);
    
out_err:
	return err;
	
	
}

/*
int hip_dump_pj_stun_msg(void* pdu, int len){
	
	int err = 0;
	pj_stun_password_attr * stun_password;
	pj_stun_username_attr * stun_username;
	pj_stun_msg * msg, *response;
	pj_pool_t *pool ;
	pj_size_t parse_len;
	char buffer[1000];
	unsigned print_len = 1000;
	pj_caching_pool cp;
	HIP_DEBUG("dump_pj_stun_msg\n");
	
	pj_caching_pool_init(&cp, NULL, 6024*2024 );
 	pool = pj_pool_create(&cp.factory, NULL, 4000, 4000, NULL);	
 	pj_stun_msg_decode(pool,pdu,len, 0, &msg, &parse_len,&response);
		
	HIP_DEBUG("official dump\n %s\n",pj_stun_msg_dump(msg,buffer,1000,&print_len));
	HIP_HEXDUMP("hex dump for stun",pdu,20);
	HIP_DEBUG("stun len is %d \n",len);
	
	
out_err:
 	if(pool)
 			pj_pool_release(pool);
 		return err;
 		
	
 	
}
*/
char *get_nat_username(void* buf, const struct in6_addr *hit){
	if (!buf)
	                return NULL;
        sprintf(buf,
                "%04x%04x",
                ntohs(hit->s6_addr16[6]), ntohs(hit->s6_addr16[7]));
        _HIP_DEBUG("the nat user is %d\n",buf);
        return buf;
}

char* get_nat_password(void* buf, const char *key){
	int i;

	if (!buf)
	                return NULL;
	
	_HIP_HEXDUMP("hip nat key in get nat passwd:", key, 16);

	for (i=0; i < 16; i++) {
		sprintf(buf + i*2, "%02x", (0xff) & *(key + i));
	}        

        _HIP_DEBUG("the nat passwd is %d\n",buf);
        return buf;
}

uint32_t ice_calc_priority(uint32_t type, uint16_t pref, uint8_t comp_id) {
    return (0x1000000 * type + 0x100 * pref + 256 - comp_id);
}

pj_status_t create_stun_config(pj_pool_t *pool, pj_stun_config *stun_cfg, pj_pool_factory *mem)
{
    pj_ioqueue_t *ioqueue;
    pj_timer_heap_t *timer_heap;
    pj_status_t status;

    status = pj_ioqueue_create(pool, 64, &ioqueue);
    if (status != PJ_SUCCESS) {
	HIP_DEBUG("   pj_ioqueue_create()\n", status);
	return status;
    }

    status = pj_timer_heap_create(pool, 256, &timer_heap);
    if (status != PJ_SUCCESS) {
	HIP_DEBUG("   pj_timer_heap_create()\n", status);
	pj_ioqueue_destroy(ioqueue);
	return status;
    }

    pj_stun_config_init(stun_cfg, mem, 0, ioqueue, timer_heap);

    return PJ_SUCCESS;
}

int hip_poll_ice_event(hip_ha_t *ha, void *unused) {
	int err = 0;
	pj_time_val timeout = {0, 1};  

	HIP_IFE(!ha->ice_session, 0);

	pj_timer_heap_poll(((pj_ice_sess*)ha->ice_session)->stun_cfg.timer_heap, NULL);
	pj_ioqueue_poll(((pj_ice_sess*)ha->ice_session)->stun_cfg.ioqueue, &timeout);

	/* ICE requires fast outputting of STUN packets, but currently
	   hipd select loop introduces one second delays. This is a workaround
	   to make hipd select loop to expire faster during ICE connectivity
	   checks so that ICE outputs packets faster in maintenance loop. */
	if (!(((pj_ice_sess*)ha->ice_session)->is_complete)) {
		hip_common_t msg;
		struct sockaddr_in6 dst;
		struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;

		memset(&dst, 0, sizeof(&dst));
		dst.sin6_family = AF_INET6;
		ipv6_addr_copy(&dst.sin6_addr, &loopback);
		dst.sin6_port = htons(HIP_DAEMON_LOCAL_PORT);

		hip_build_user_hdr(&msg, SO_HIP_NULL_OP, 0);
		hip_set_msg_response(&msg, 0);
		HIP_IFEL(hip_sendto_user(&msg, (struct sockaddr *) &dst), -1,
			 "Failed to send packet\n");
		usleep(500 * 1000); /* 500 ms RTO */
	}
	
 out_err:
	return err;
}

int hip_poll_ice_event_all() {
	return hip_for_each_ha(hip_poll_ice_event, NULL);
}
