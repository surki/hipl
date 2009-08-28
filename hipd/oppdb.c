/*
 * hipd oppdb.c
 *
 * Licence: GNU/GPL
 * Authors: 
 * - Bing Zhou <bingzhou@cc.hut.fi>
 *
 */

#ifdef CONFIG_HIP_OPPORTUNISTIC

#include "oppdb.h"
#include "hadb.h"

HIP_HASHTABLE *oppdb;
//static hip_list_t oppdb_list[HIP_OPPDB_SIZE]= { 0 };
extern unsigned int opportunistic_mode;

unsigned long hip_oppdb_hash_hit(const void *ptr)
{
	hip_opp_block_t *entry = (hip_opp_block_t *)ptr;
	uint8_t hash[HIP_AH_SHA_LEN];

	hip_build_digest(HIP_DIGEST_SHA1, &entry->peer_phit, sizeof(hip_hit_t) + sizeof(struct sockaddr_in6), hash);

	return *((unsigned long *)hash);
}

int hip_oppdb_match_hit(const void *ptr1, const void *ptr2)
{
	return (hip_hash_hit(ptr1) != hip_hash_hit(ptr2));
}

int hip_oppdb_entry_clean_up(hip_opp_block_t *opp_entry)
{
	hip_ha_t *hadb_entry;
	int err = 0;

	/* XX FIXME: this does not support multiple multiple opp
	   connections: a better solution might be trash collection  */

	HIP_ASSERT(opp_entry);
	err = hip_del_peer_info(&opp_entry->peer_phit,
				&opp_entry->our_real_hit);
	HIP_DEBUG("Del peer info returned %d\n", err);
	hip_oppdb_del_entry_by_entry(opp_entry);
	return err;
}

int hip_for_each_opp(int (*func)(hip_opp_block_t *entry, void *opaq), void *opaque)
{
	int i = 0, fail = 0;
	hip_opp_block_t *this;
	hip_list_t *item, *tmp;
	
	if (!func) return -EINVAL;
	
	HIP_LOCK_HT(&opp_db);
	list_for_each_safe(item, tmp, oppdb, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("List_for_each_entry_safe\n");
		hip_hold_ha(this);
		fail = func(this, opaque);
		//hip_db_put_ha(this, hip_oppdb_del_entry_by_entry);
		if (fail)
			goto out_err;
	}
 out_err:
	HIP_UNLOCK_HT(&opp_db);
	return fail;
}

#if 0
inline void hip_oppdb_hold_entry(void *entry)
{
  	HIP_DB_HOLD_ENTRY(entry, struct hip_opp_blocking_request_entry);
}

inline void hip_oppdb_put_entry(void *entry)
{  	
	HIP_DB_PUT_ENTRY(entry, struct hip_opp_blocking_request_entry,
			 hip_oppdb_del_entry_by_entry);
}

inline void *hip_oppdb_get_key(void *entry)
{
	return &(((hip_opp_block_t *)entry)->hash_key);
}
#endif

//void hip_hadb_delete_hs(struct hip_hit_spi *hs)
void hip_oppdb_del_entry_by_entry(hip_opp_block_t *entry)
{
	_HIP_HEXDUMP("caller", &entry->caller, sizeof(struct sockaddr_un));
	
	HIP_LOCK_OPP(entry);
	hip_ht_delete(oppdb, entry);
	HIP_UNLOCK_OPP(entry);
	//HIP_FREE(entry);
}

int hip_oppdb_uninit_wrap(hip_opp_block_t *entry, void *unused)
{
	hip_oppdb_del_entry_by_entry(entry);
	return 0;
}

void hip_oppdb_uninit()
{
	hip_for_each_opp(hip_oppdb_uninit_wrap, NULL);
}

int hip_oppdb_unblock_group(hip_opp_block_t *entry, void *ptr)
{
	hip_opp_info_t *opp_info = (hip_opp_info_t *) ptr;
	int err = 0;

	if (ipv6_addr_cmp(&entry->peer_phit, &opp_info->pseudo_peer_hit) != 0)
		goto out_err;

	HIP_IFEL(hip_opp_unblock_app(&entry->caller, opp_info, 0), -1,
		 "unblock failed\n");

	hip_oppdb_del_entry_by_entry(entry);
	
 out_err:
	return err;
}


hip_opp_block_t *hip_create_opp_block_entry() 
{
	hip_opp_block_t * entry = NULL;

	entry = (hip_opp_block_t *)malloc(sizeof(hip_opp_block_t));
	if (!entry){
		HIP_ERROR("hip_opp_block_t memory allocation failed.\n");
		return NULL;
	}
  
	memset(entry, 0, sizeof(*entry));
  
//	INIT_LIST_HEAD(&entry->next_entry);
  
	HIP_LOCK_OPP_INIT(entry);
	//atomic_set(&entry->refcnt,0);
	time(&entry->creation_time);
	HIP_UNLOCK_OPP_INIT(entry);
 out_err:
        return entry;
}

//int hip_hadb_add_peer_info(hip_hit_t *peer_hit, struct in6_addr *peer_addr)
int hip_oppdb_add_entry(const hip_hit_t *phit_peer,
			const hip_hit_t *hit_our,
			const struct in6_addr *ip_peer,
			const struct in6_addr *ip_our,
			const struct sockaddr_in6 *caller)
{
	int err = 0;
	hip_opp_block_t *tmp = NULL;
	hip_opp_block_t *new_item = NULL;
	
	new_item = hip_create_opp_block_entry();
	if (!new_item) {
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}

//	hip_xor_hits(&new_item->hash_key, hit_peer, hit_our);

	if(phit_peer)
	        ipv6_addr_copy(&new_item->peer_phit, phit_peer);
	ipv6_addr_copy(&new_item->our_real_hit, hit_our);
	if (ip_peer)
		ipv6_addr_copy(&new_item->peer_ip, ip_peer);
	if (ip_our)
		ipv6_addr_copy(&new_item->our_ip, ip_our);
	memcpy(&new_item->caller, caller, sizeof(struct sockaddr_in6));
	
	err = hip_ht_add(oppdb, new_item);
	hip_oppdb_dump();
	
	return err;
}


void hip_init_opp_db()
{
	oppdb = hip_ht_init(hip_oppdb_hash_hit, hip_oppdb_match_hit);
}

void hip_oppdb_dump()
{
	int i;
	//  char peer_real_hit[INET6_ADDRSTRLEN] = "\0";
	hip_opp_block_t *this;
	hip_list_t *item, *tmp;
	
	HIP_DEBUG("start oppdb dump\n");
	HIP_LOCK_HT(&oppdb);

	list_for_each_safe(item, tmp, oppdb, i)
	{
		this = list_entry(item);

		//hip_in6_ntop(&this->peer_real_hit, peer_real_hit);
		//HIP_DEBUG("hash_key=%d  lock=%d refcnt=%d\n", this->hash_key, this->lock, this->refcnt);
		HIP_DEBUG_HIT("this->peer_phit",
					&this->peer_phit);
		HIP_DEBUG_HIT("this->our_real_hit",
					&this->our_real_hit);
	}

	HIP_UNLOCK_HT(&oppdb);
	HIP_DEBUG("end oppdb dump\n");
}

int hip_opp_unblock_app(const struct sockaddr_in6 *app_id, hip_opp_info_t *opp_info,
			int reject) {
	struct hip_common *message = NULL;
	int err = 0, n;

	HIP_IFEL((app_id->sin6_port == 0), 0, "Zero port, ignore\n");

	HIP_IFE(!(message = hip_msg_alloc()), -1);
	HIP_IFEL(hip_build_user_hdr(message, SO_HIP_GET_PEER_HIT, 0), -1,
		 "build user header failed\n");

	if (!opp_info)
		goto skip_hit_addr;

	if (!ipv6_addr_any(&opp_info->real_peer_hit))
		HIP_IFEL(hip_build_param_contents(message, &opp_info->real_peer_hit,
						  HIP_PARAM_HIT_PEER,
						  sizeof(hip_hit_t)), -1,
			 "building peer real hit failed\n");

	if (!ipv6_addr_any(&opp_info->local_hit))
		HIP_IFEL(hip_build_param_contents(message, &opp_info->local_hit,
						  HIP_PARAM_HIT_LOCAL,
						  sizeof(hip_hit_t)), -1,
			 "building local hit failed\n");

	if (!ipv6_addr_any(&opp_info->peer_addr))
		HIP_IFEL(hip_build_param_contents(message, &opp_info->peer_addr,
						  HIP_PARAM_IPV6_ADDR_PEER,
						  sizeof(struct in6_addr)), -1,
			 "building peer addr failed\n");

	if (!ipv6_addr_any(&opp_info->local_addr))
		HIP_IFEL(hip_build_param_contents(message, &opp_info->local_addr,
						  HIP_PARAM_IPV6_ADDR_LOCAL,
						  sizeof(struct in6_addr)), -1,
			 "building local addr failed\n");

skip_hit_addr:
	
	if (reject) {
		n = 1;
		HIP_DEBUG("message len: %d\n", hip_get_msg_total_len(message));
		HIP_IFEL(hip_build_param_contents(message, &n,
		                                  HIP_PARAM_AGENT_REJECT,
		                                  sizeof(n)), -1,
		         "build param HIP_PARAM_HIT  failed\n");
		HIP_DEBUG("message len: %d\n", hip_get_msg_total_len(message));
	}
	/* Switched from hip_sendto() to hip_sendto_user() due to
	   namespace collision. Both message.h and user.c had functions
	   hip_sendto(). Introducing a prototype hip_sendto() to user.h
	   led to compiler errors --> user.c hip_sendto() renamed to
	   hip_sendto_user().

	   Lesson learned: use function prototypes unless functions are
	   ment only for local (inside the same file where defined) use.
	   -Lauri 11.07.2008 */
	HIP_DEBUG("Unblocking caller at port %d\n", ntohs(app_id->sin6_port));
	n = hip_sendto_user(message, app_id);
	
	if(n < 0){
		HIP_ERROR("hip_sendto() failed.\n");
		err = -1;
		goto out_err;
	}
 out_err:
	if (message)
		HIP_FREE(message);
	return err;
}

hip_ha_t *hip_oppdb_get_hadb_entry(hip_hit_t *init_hit,
				   struct in6_addr *resp_addr)
{
	hip_ha_t *entry_tmp = NULL;
	hip_hit_t phit;
	int err = 0;

	HIP_DEBUG_HIT("resp_addr=", resp_addr);
	HIP_IFEL(hip_opportunistic_ipv6_to_hit(resp_addr, &phit,
					       HIP_HIT_TYPE_HASH100), -1,
		 "hip_opportunistic_ipv6_to_hit failed\n");

	HIP_ASSERT(hit_is_opportunistic_hashed_hit(&phit));
	
	entry_tmp = hip_hadb_find_byhits(init_hit, &phit);

 out_err:
	return entry_tmp;
}

hip_ha_t *hip_oppdb_get_hadb_entry_i1_r1(struct hip_common *msg,
					struct in6_addr *src_addr,
					struct in6_addr *dst_addr,
					hip_portpair_t *msg_info)
{
	hip_hdr_type_t type = hip_get_msg_type(msg);
	hip_ha_t *entry = NULL;

	if (type == HIP_I1) {
		if(!hit_is_opportunistic_null(&msg->hitr)){
			goto out_err;
		}
		hip_get_default_hit(&msg->hitr);
		//hip_get_any_localhost_hit(&msg->hitr, HIP_HI_DEFAULT_ALGO, 0);
	} else if (type == HIP_R1) {
		entry = hip_oppdb_get_hadb_entry(&msg->hitr, src_addr);
	} else {
		HIP_ASSERT(0);
	}

 out_err:
	return entry;
}

int hip_receive_opp_r1(struct hip_common *msg,
		       struct in6_addr *src_addr,
		       struct in6_addr *dst_addr,
		       hip_ha_t *opp_entry,
		       hip_portpair_t *msg_info){
	hip_opp_info_t opp_info;
	hip_ha_t *entry;
	hip_hit_t phit;
	int n = 0, err = 0;
	
#if 0
	opp_entry = hip_oppdb_get_hadb_entry(&msg->hitr, src_addr);
	if (!opp_entry){
		HIP_ERROR("Cannot find HA entry after receive r1\n");
		err = -1;
		goto out_err;
	}
#endif

	// add new HA with real hit
	//err = hip_hadb_add_peer_info(&msg->hits, src_addr);
	
	HIP_DEBUG_HIT("!!!! peer hit=", &msg->hits);
	HIP_DEBUG_HIT("!!!! local hit=", &msg->hitr);
	HIP_DEBUG_IN6ADDR("!!!! peer addr=", src_addr);
	HIP_DEBUG_IN6ADDR("!!!! local addr=", dst_addr);
	
	HIP_IFEL(hip_hadb_add_peer_info_complete(&msg->hitr, &msg->hits,
						 NULL, dst_addr, src_addr, NULL), -1,
		 "Failed to insert peer map\n");
	
	HIP_IFEL(!(entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr)), -1,
		 "Did not find opp entry\n");

	HIP_IFEL(hip_init_us(entry, &msg->hitr), -1,
		 "hip_init_us failed\n");
	/* old HA has state 2, new HA has state 1, so copy it */
	entry->state = opp_entry->state;
	/* For service registration routines */
	entry->local_controls = opp_entry->local_controls;
	entry->peer_controls = opp_entry->peer_controls;

	if(hip_replace_pending_requests(opp_entry, entry) == -1){
		HIP_DEBUG("RVS: Error moving the pending requests to a new HA");
	}

	//memcpy(sava_serving_gateway, &msg->hits, sizeof(struct in6_addr));
	
	HIP_DEBUG_HIT("!!!! peer hit=", &msg->hits);
	HIP_DEBUG_HIT("!!!! local hit=", &msg->hitr);
	HIP_DEBUG_HIT("!!!! peer addr=", src_addr);
	HIP_DEBUG_HIT("!!!! local addr=", dst_addr);

	HIP_IFEL(hip_opportunistic_ipv6_to_hit(src_addr, &phit,
					       HIP_HIT_TYPE_HASH100), -1,
		 "pseudo hit conversion failed\n");

	
	ipv6_addr_copy(&opp_info.real_peer_hit, &msg->hits);
	ipv6_addr_copy(&opp_info.pseudo_peer_hit, &phit);
	ipv6_addr_copy(&opp_info.local_hit, &msg->hitr);
	ipv6_addr_copy(&opp_info.local_addr, dst_addr);
	ipv6_addr_copy(&opp_info.peer_addr, src_addr);
	hip_for_each_opp(hip_oppdb_unblock_group, &opp_info);

	
	/* why is the receive entry still pointing to hip_receive_opp_r1 ? */
	entry->hadb_rcv_func->hip_receive_r1 = hip_receive_r1;
	HIP_IFCS(entry,
		 (err = entry->hadb_rcv_func->hip_receive_r1(msg,
							    src_addr,
							    dst_addr,
							    entry,
							     msg_info)));
	hip_del_peer_info_entry(opp_entry);

 out_err:

	return err;
}

hip_ha_t * hip_opp_add_map(const struct in6_addr *dst_ip,
			   const struct in6_addr *hit_our) {
  int err = 0;
  struct in6_addr opp_hit, src_ip;
  hip_ha_t *ha = NULL;
  hip_oppip_t *oppip_entry = NULL;

  HIP_DEBUG_INADDR("Peer's IP ", dst_ip);

  HIP_IFEL(hip_select_source_address(&src_ip,
				     dst_ip), -1,
	   "Cannot find source address\n");

  HIP_IFEL(hip_opportunistic_ipv6_to_hit(dst_ip, &opp_hit,
					 HIP_HIT_TYPE_HASH100),
	   -1, "Opp HIT conversion failed\n");
  
  HIP_ASSERT(hit_is_opportunistic_hashed_hit(&opp_hit)); 
  
  HIP_DEBUG_HIT("opportunistic hashed hit", &opp_hit);
  
  if (oppip_entry = hip_oppipdb_find_byip((struct in6_addr *)dst_ip))
    {      
      HIP_DEBUG("Old mapping exist \n");

      if (ha = hip_hadb_find_byhits(hit_our, &opp_hit))
	goto out_err;

      HIP_DEBUG("No entry found. Adding new map.\n");
      hip_oppipdb_del_entry_by_entry(oppip_entry);
    }
  
  /* No previous contact, new host. Let's do the opportunistic magic */

  err = hip_hadb_add_peer_info_complete(hit_our, &opp_hit, NULL, &src_ip, dst_ip, NULL);
  
  HIP_IFEL(!(ha = hip_hadb_find_byhits(hit_our, &opp_hit)), NULL,
	   "Did not find entry\n");
  
  /* Override the receiving function */
  ha->hadb_rcv_func->hip_receive_r1 = hip_receive_opp_r1;
  
  HIP_IFEL(hip_oppdb_add_entry(&opp_hit, hit_our, dst_ip, NULL,
			       &src_ip), NULL, "Add db failed\n");
  
  ha->tcp_opptcp_src_port = 0;
  ha->tcp_opptcp_dst_port = 0;
  
 out_err:

  return ha;
}

/**
 * No description.
 */
int hip_opp_get_peer_hit(struct hip_common *msg,
			 const struct sockaddr_in6 *src){
	int n = 0, err = 0, alen = 0;
	struct in6_addr phit, dst_ip, hit_our, id, our_addr;
	void *ptr = NULL;
	hip_opp_block_t *entry = NULL;
	hip_ha_t *ha = NULL;
	in_port_t src_tcp_port = 0;
	in_port_t dst_tcp_port = 0;

	HIP_DUMP_MSG(msg);
	
	memset(&hit_our, 0, sizeof(struct in6_addr));

	if(!opportunistic_mode) {
		hip_msg_init(msg);
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT, 0), -1, 
			 "Building of user header failed\n");
		err = -11; /* Force immediately to send message to app */
		goto out_err;
	}

	/* Check each HA for the peer hit, if so, create the header of the message */

	/* Create an opportunistic HIT from the peer's IP  */

	if (hip_get_opportunistic_tcp_status() &&
	    (ptr = hip_get_param_contents(msg, HIP_PARAM_SRC_TCP_PORT))) {
		/*get the src tcp port from the message for the TCP SYN
		  i1 packet*/
		HIP_IFEL(!ptr, -1, "No peer port in msg\n");
		src_tcp_port = *((in_port_t *) ptr);
		
		/*get the dst tcp port from the message for the TCP SYN
		  i1 packet*/
		ptr = hip_get_param_contents(msg, HIP_PARAM_DST_TCP_PORT);
		HIP_IFEL(!ptr, -1, "No peer port in msg\n");
		dst_tcp_port = *((in_port_t *) ptr);
		HIP_DEBUG("port src=%d dst=%d", src_tcp_port, dst_tcp_port);

		hip_get_default_hit(&hit_our);
	} else {
		ptr = hip_get_param_contents(msg, HIP_PARAM_HIT_LOCAL);
		HIP_IFEL(!ptr, -1, "No local hit in msg\n");
		memcpy(&hit_our, ptr, sizeof(hit_our));
	}

	HIP_DEBUG_HIT("hit_our=", &hit_our);
	ptr = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_PEER);
	HIP_IFEL(!ptr, -1, "No ip in msg\n");
	memcpy(&dst_ip, ptr, sizeof(dst_ip));
	HIP_DEBUG_HIT("dst_ip=", &dst_ip);

	HIP_IFEL(hip_select_source_address(&our_addr,
					   &dst_ip), -1,
		 "Cannot find source address\n");

	hip_msg_init(msg);

	/* Return the HIT immediately if we have already a host
	   association with the peer host */
	ipv6_addr_copy(&id, &dst_ip);
	if (hip_for_each_ha(hip_hadb_map_ip_to_hit, &id)) {
		HIP_DEBUG_HIT("existing HA found with HIT", &id);
		HIP_IFEL(hip_build_param_contents(msg,
					       (void *)(&id),
					       HIP_PARAM_HIT_PEER,
					       sizeof(struct in6_addr)), -1,
			 "build param HIP_PARAM_HIT  failed: %s\n");
		HIP_IFEL(hip_build_param_contents(msg,
					       (void *)(&hit_our),
					       HIP_PARAM_HIT_LOCAL,
					       sizeof(struct in6_addr)), -1,
			 "build param HIP_PARAM_HIT  failed: %s\n");
		HIP_IFEL(hip_build_param_contents(msg,
					       (void *)(&our_addr),
					       HIP_PARAM_IPV6_ADDR_PEER,
					       sizeof(struct in6_addr)), -1,
			 "build param HIP_PARAM_HIT  failed: %s\n");
		HIP_IFEL(hip_build_param_contents(msg,
					       (void *)(&dst_ip),
					       HIP_PARAM_IPV6_ADDR_LOCAL,
					       sizeof(struct in6_addr)), -1,
			 "build param HIP_PARAM_HIT  failed: %s\n");
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT, 0), -1,
			 "Building of msg header failed\n");
		err = -11;
		goto out_err;
	}

	/* Fallback if we have contacted peer before the peer did not
	   support HIP the last time */
	if (hip_oppipdb_find_byip((struct in6_addr *)&dst_ip))
	{
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT, 0), -1, 
		         "Building of user header failed\n");
		err = -11; /* Force immediately to send message to app */
		
		goto out_err;
	}


	/* No previous contact, new host. Let's do the opportunistic magic */
	
	HIP_IFEL(hip_opportunistic_ipv6_to_hit(&dst_ip, &phit,
					       HIP_HIT_TYPE_HASH100),
		 -1, "Opp HIT conversion failed\n");

	HIP_ASSERT(hit_is_opportunistic_hashed_hit(&phit)); 

	HIP_DEBUG_HIT("phit", &phit);

	err = hip_hadb_add_peer_info_complete(&hit_our,  &phit,   NULL,
					      &our_addr, &dst_ip, NULL);

	HIP_IFEL(!(ha = hip_hadb_find_byhits(&hit_our, &phit)), -1,
		 "Did not find entry\n");

	/* Override the receiving function */
	ha->hadb_rcv_func->hip_receive_r1 = hip_receive_opp_r1;

	//entry = hip_oppdb_find_byhits(&phit, src);
	//HIP_ASSERT(!entry);
	HIP_IFEL(hip_oppdb_add_entry(&phit, &hit_our, &dst_ip, NULL,
				     src), -1, "Add db failed\n");

	ha->tcp_opptcp_src_port = src_tcp_port;
	ha->tcp_opptcp_dst_port = dst_tcp_port;

	HIP_IFEL(hip_send_i1(&hit_our, &phit, ha), -1,
		 "sending of I1 failed\n");

 out_err:
	return err;
}

/**
 * Processes a message that has been sent to hipd from the firewall,
 * telling it to unblock the applications that connect to a particular peer
 * and to add the ip of a peer to the blacklist database.
 * 
 * @param *msg  the message.
 * @param *src  the source of the message.
 * @return      an error, if any, during the processing.
 */
int hip_opptcp_unblock_and_blacklist(struct hip_common *msg, const struct sockaddr_in6 *src){
        int n = 0, err = 0, alen = 0;
        struct in6_addr phit, dst_ip, hit_our, id, our_addr;
        struct in6_addr *ptr = NULL;
        hip_opp_block_t *entry = NULL;
        hip_ha_t *ha = NULL;

        if(!opportunistic_mode) {
                hip_msg_init(msg);
                HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OPPTCP_UNBLOCK_AND_BLACKLIST, 0),
                         -1, "Building of user header failed\n");
        }

        memset(&dst_ip, 0, sizeof(struct in6_addr *));
        ptr = (struct in6_addr *) hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
        HIP_IFEL(!ptr, -1, "No ip in msg\n");
        memcpy(&dst_ip, ptr, sizeof(dst_ip));
        HIP_DEBUG_HIT("dst ip = ", &dst_ip);

        //hip_msg_init(msg);//?????

        err = hip_for_each_opp(hip_force_opptcp_fallback, &dst_ip);
        HIP_IFEL(err, 0, "for_each_ha err.\n");

        err = hip_oppipdb_add_entry(&dst_ip);
        HIP_IFEL(err, 0, "for_each_ha err.\n");

 out_err:
        return err;
}

/**
 * Processes a message that has been sent to hipd from the firewall,
 * telling it to send a tcp packet.
 * 
 * @param *msg	the message.
 * @param *src	the source of the message.
 * @return	an error, if any, during the processing.
 */
int hip_opptcp_send_tcp_packet(struct hip_common *msg, const struct sockaddr_in6 *src){
	int n = 0, err = 0, alen = 0;
	struct in6_addr phit, hit_our, id, our_addr;
	void *ptr = NULL;
	hip_opp_block_t *entry = NULL;
	hip_ha_t *ha = NULL;

	char *hdr	  = NULL;
	int  *packet_size = NULL;
	int  *trafficType = NULL;
	int  *addHit      = NULL;
	int  *addOption   = NULL;

	if(!opportunistic_mode) {
		HIP_DEBUG("Opportunistic mode disabled\n");
		return -1;
	}

	//get the size of the packet
	memset(&packet_size, 0, sizeof(int));
	ptr = (int *) hip_get_param_contents(msg, HIP_PARAM_PACKET_SIZE);
	HIP_IFEL(!ptr, -1, "No packet size in msg\n");
	memcpy(&packet_size, ptr, sizeof(packet_size));

	//get the pointer to the ip header that is to be sent
	hdr = HIP_MALLOC((int)packet_size, 0);
	memset(hdr, 0, (int)packet_size);
	ptr = (void *) hip_get_param_contents(msg, HIP_PARAM_IP_HEADER);
	HIP_IFEL(!ptr, -1, "No ip header in msg\n");
	memcpy(hdr, ptr, (int)packet_size);

	//get the type of traffic
	memset(&trafficType, 0, sizeof(int));
	ptr = (int *) hip_get_param_contents(msg, HIP_PARAM_TRAFFIC_TYPE);
	HIP_IFEL(!ptr, -1, "No traffic type in msg\n");
	memcpy(&trafficType, ptr, sizeof(trafficType));

	//get whether hit option is to be added
	memset(&addHit, 0, sizeof(int));
	ptr = (int *) hip_get_param_contents(msg, HIP_PARAM_ADD_HIT);
	HIP_IFEL(!ptr, -1, "No add Hit in msg\n");
	memcpy(&addHit, ptr, sizeof(addHit));

	//get the size of the packet
	memset(&addOption, 0, sizeof(int));
	ptr = (int *) hip_get_param_contents(msg, HIP_PARAM_ADD_OPTION);
	HIP_IFEL(!ptr, -1, "No add Hit in msg\n");
	memcpy(&addOption, ptr, sizeof(addOption));

	hip_msg_init(msg);

	err = send_tcp_packet(/*&hip_nl_route, */(void*)hdr, (int)packet_size, (int)trafficType, hip_raw_sock_output_v4, (int)addHit, (int)addOption);

	HIP_IFEL(err, -1, "error sending tcp packet\n");

 out_err:
	return err;
}

/*
 * Used by opportunistic tcp option to force an application fallback
 * immediately (without timeout) to non-hip communications. This occurs
 * when the firewall detects that peer does not support HIP.
 */
int hip_force_opptcp_fallback(hip_opp_block_t *entry, void *data)
{
	int err = 0;
	struct in6_addr *resp_ip = data;
	hip_opp_info_t info;
		
	if (ipv6_addr_cmp(&entry->peer_ip, resp_ip)) goto out_err;

	memset(&info, 0, sizeof(info));
	ipv6_addr_copy(&info.peer_addr, &entry->peer_ip);
	
	HIP_DEBUG_HIT("entry initiator hit:", &entry->our_real_hit);
	HIP_DEBUG_HIT("entry responder ip:", &entry->peer_ip);
	HIP_DEBUG("Rejecting blocked opp entry\n");
	err = hip_opp_unblock_app(&entry->caller, &info, 0);
	HIP_DEBUG("Reject returned %d\n", err);
	err = hip_oppdb_entry_clean_up(entry);
	
out_err:
	return err;
}


int hip_handle_opp_fallback(hip_opp_block_t *entry,
                            void *current_time) {
        int err = 0, disable_fallback = 0;
        time_t *now = (time_t*) current_time;
        struct in6_addr *addr;
        //HIP_DEBUG("now=%d e=%d\n", *now, entry->creation_time);

#if defined(CONFIG_HIP_AGENT) && defined(CONFIG_HIP_OPPORTUNISTIC)
        /* If agent is prompting user, let's make sure that
           the death counter in maintenance does not expire */
        if (hip_agent_is_alive()) {
                hip_ha_t *ha = NULL;
                ha = hip_oppdb_get_hadb_entry(&entry->our_real_hit,
                                              &entry->peer_ip);
                if (ha)
                        disable_fallback = ha->hip_opp_fallback_disable;
        }
#endif
        if(!disable_fallback && (*now - HIP_OPP_WAIT > entry->creation_time)) {
		hip_opp_info_t info;

		memset(&info, 0, sizeof(info));
		ipv6_addr_copy(&info.peer_addr, &entry->peer_ip);

                addr = (struct in6_addr *) &entry->peer_ip;
                hip_oppipdb_add_entry(addr);
                HIP_DEBUG("Timeout for opp entry, falling back to\n");
                err = hip_opp_unblock_app(&entry->caller, &info, 0);
                HIP_DEBUG("Fallback returned %d\n", err);
                err = hip_oppdb_entry_clean_up(entry);
                memset(&now,0,sizeof(now));
                
        }
        
 out_err:
        return err;
}

int hip_handle_opp_reject(hip_opp_block_t *entry, void *data)
{
	int err = 0;
	struct in6_addr *resp_ip = data;
	
	if (ipv6_addr_cmp(&entry->peer_ip, resp_ip)) goto out_err;

	HIP_DEBUG_HIT("entry initiator hit:", &entry->our_real_hit);
	HIP_DEBUG_HIT("entry responder ip:", &entry->peer_ip);
	HIP_DEBUG("Rejecting blocked opp entry\n");
	err = hip_opp_unblock_app(&entry->caller, NULL, 1);
	HIP_DEBUG("Reject returned %d\n", err);
	err = hip_oppdb_entry_clean_up(entry);
	
out_err:
	return err;
}

#endif /* CONFIG_HIP_OPPORTUNISTIC */


/**
 * hip_oppdb_find_byip:
 * Seeks an ip within the oppdb hash table.
 * If the ip is found in the table, that host is not HIP capable.
 *
 * @param ip_peer: pointer to the ip of the host to check whether 
 *                 it is HIP capable
 * @return pointer to the entry if the ip is found in the table; NULL otherwise
 */
hip_opp_block_t *hip_oppdb_find_by_ip(const struct in6_addr *ip_peer)
{
	int i = 0;
	hip_opp_block_t *this, *ret = NULL;
	hip_list_t *item, *tmp;

	HIP_LOCK_HT(&opp_db);
	list_for_each_safe(item, tmp, oppdb, i)
	{
		this = list_entry(item);
		if(ipv6_addr_cmp(&this->peer_ip, ip_peer) == 0){
			HIP_DEBUG("The ip was found in oppdb. Peer non-HIP capable.\n");
			ret = this;
			break;
		}
	}

 out_err:
	HIP_UNLOCK_HT(&opp_db);
	return ret;
}

