/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "maintenance.h"

int hip_firewall_sock_lsi_fd = -1;

float retrans_counter = HIP_RETRANSMIT_INIT;
float opp_fallback_counter = HIP_OPP_FALLBACK_INIT;
float precreate_counter = HIP_R1_PRECREATE_INIT;
int nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_INTERVAL;
float opendht_counter = OPENDHT_REFRESH_INIT;
float queue_counter = QUEUE_CHECK_INIT;
int force_exit_counter = FORCE_EXIT_COUNTER_START;
int cert_publish_counter = CERTIFICATE_PUBLISH_INTERVAL;
int heartbeat_counter = 0;
int hip_firewall_status = 0;
int fall, retr;

extern int hip_opendht_inuse;
extern char opendht_name_mapping;
extern int opendht_serving_gateway_port;
extern int opendht_serving_gateway_ttl;
extern int hip_opendht_error_count;
extern int opendht_error;
extern char opendht_host_name[];
extern struct addrinfo * opendht_serving_gateway; 
extern int hip_icmp_interval;
extern int hip_icmp_sock;
extern char opendht_current_key[];
extern hip_common_t * opendht_current_hdrr;
extern unsigned char opendht_hdrr_secret;
extern unsigned char opendht_hash_of_value;

#ifdef CONFIG_HIP_AGENT
extern sqlite3* daemon_db;
#endif

/**
 * Handle packet retransmissions.
 */
int hip_handle_retransmission(hip_ha_t *entry, void *current_time)
{
	int err = 0;
	time_t *now = (time_t*) current_time;

	if (entry->hip_msg_retrans.buf == NULL)
		goto out_err;

	_HIP_DEBUG("Time to retrans: %d Retrans count: %d State: %s\n",
		   entry->hip_msg_retrans.last_transmit + HIP_RETRANSMIT_WAIT - *now,
		   entry->hip_msg_retrans.count, hip_state_str(entry->state));

	_HIP_DEBUG_HIT("hit_peer", &entry->hit_peer);
	_HIP_DEBUG_HIT("hit_our", &entry->hit_our);

	/* check if the last transmision was at least RETRANSMIT_WAIT seconds ago */
	if(*now - HIP_RETRANSMIT_WAIT > entry->hip_msg_retrans.last_transmit){
		_HIP_DEBUG("%d %d %d\n",entry->hip_msg_retrans.count,
			  entry->state, entry->retrans_state);
		if ((entry->hip_msg_retrans.count > 0) && entry->hip_msg_retrans.buf &&
		    ((entry->state != HIP_STATE_ESTABLISHED && entry->retrans_state != entry->state) ||
		     (entry->update_state != 0 && entry->retrans_state != entry->update_state) ||
		     entry->light_update_retrans == 1)) {
			HIP_DEBUG("state=%d, retrans_state=%d, update_state=%d\n",
				  entry->state, entry->retrans_state, entry->update_state, entry->retrans_state);

			/* @todo: verify that this works over slow ADSL line */
			err = entry->hadb_xmit_func->
				hip_send_pkt(&entry->hip_msg_retrans.saddr,
					     &entry->hip_msg_retrans.daddr,
					     (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
						     entry->peer_udp_port,
					     entry->hip_msg_retrans.buf,
					     entry, 0);

			/* Set entry state, if previous state was unassosiated
			   and type is I1. */
			if (!err && hip_get_msg_type(entry->hip_msg_retrans.buf)
			    == HIP_I1 && entry->state == HIP_STATE_UNASSOCIATED) {
				HIP_DEBUG("Resent I1 succcesfully\n");
				entry->state = HIP_STATE_I1_SENT;
			}

			entry->hip_msg_retrans.count--;
			/* set the last transmission time to the current time value */
			time(&entry->hip_msg_retrans.last_transmit);
		} else {
			if (entry->hip_msg_retrans.buf)
				HIP_FREE(entry->hip_msg_retrans.buf);
			entry->hip_msg_retrans.buf = NULL;
			entry->hip_msg_retrans.count = 0;

			if (entry->state == HIP_STATE_ESTABLISHED)
				entry->retrans_state = entry->update_state;
			else
				entry->retrans_state = entry->state;
		}
	}

 out_err:

	return err;
}

#ifdef CONFIG_HIP_OPPORTUNISTIC
int hip_scan_opp_fallback()
{
	int err = 0;
	time_t current_time;
	time(&current_time);

	HIP_IFEL(hip_for_each_opp(hip_handle_opp_fallback, &current_time), 0,
		 "for_each_ha err.\n");
 out_err:
	return err;
}
#endif

/**
 * Find packets, that should be retransmitted.
 */
int hip_scan_retransmissions()
{
	int err = 0;
	time_t current_time;
	time(&current_time);
	HIP_IFEL(hip_for_each_ha(hip_handle_retransmission, &current_time), 0,
		 "for_each_ha err.\n");
 out_err:
	return err;
}

/**
 * Send one local HIT to agent, enumerative function.
 */
int hip_agent_add_lhit(struct hip_host_id_entry *entry, void *msg)
{
	int err = 0;

	err = hip_build_param_contents(msg, (void *)&entry->lhi.hit,
				       HIP_PARAM_HIT,
	                               sizeof(struct in6_addr));
	if (err)
	{
		HIP_ERROR("build param hit failed: %s\n", strerror(err));
		goto out_err;
	}

out_err:
	return (err);
}


/**
 * Send local HITs to agent.
 */
int hip_agent_add_lhits(void)
{
	struct hip_common *msg = NULL;
	int err = 0, n;
	socklen_t alen;

#ifdef CONFIG_HIP_AGENT
/*	if (!hip_agent_is_alive())
	{
		return (-ENOENT);
	}*/

	msg = malloc(HIP_MAX_PACKET);
	if (!msg)
	{
		HIP_ERROR("malloc failed\n");
		goto out_err;
	}
	hip_msg_init(msg);

	HIP_IFEL(hip_for_each_hi(hip_agent_add_lhit, msg), 0,
	         "for_each_hi err.\n");

	err = hip_build_user_hdr(msg, SO_HIP_ADD_DB_HI, 0);
	if (err)
	{
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out_err;
	}

	n = hip_send_agent(msg);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}
	else {
		HIP_DEBUG("Sendto() OK.\n");
	}

#endif

out_err:
	if (msg)
		free(msg);
	return (err);
}


/**
 * Send one used remote HIT to agent, enumerative function.
 */
int hip_agent_send_rhit(hip_ha_t *entry, void *msg)
{
	int err = 0;

	if (entry->state != HIP_STATE_ESTABLISHED) return (err);

	err = hip_build_param_contents(msg, (void *)&entry->hit_peer, HIP_PARAM_HIT,
	                               sizeof(struct in6_addr));
/*	err = hip_build_param_contents(msg, (void *)&entry->hit_our, HIP_PARAM_HIT,
	                               sizeof(struct in6_addr));*/
	if (err)
	{
		HIP_ERROR("build param hit failed: %s\n", strerror(err));
		goto out_err;
	}

out_err:
	return (err);
}


/**
 * Send remote HITs in use (hadb entrys) to agent.
 */
int hip_agent_send_remote_hits(void)
{
	struct hip_common *msg = NULL;
	int err = 0, n;

#ifdef CONFIG_HIP_AGENT
	msg = malloc(HIP_MAX_PACKET);
	if (!msg)
	{
		HIP_ERROR("malloc failed\n");
		goto out_err;
	}
	hip_msg_init(msg);

	HIP_IFEL(hip_for_each_ha(hip_agent_send_rhit, msg), 0,
	         "for_each_ha err.\n");

	err = hip_build_user_hdr(msg, SO_HIP_UPDATE_HIU, 0);
	if (err)
	{
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out_err;
	}

	n = hip_send_agent(msg);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}
//	else HIP_DEBUG("Sendto() OK.\n");

#endif

out_err:
	if (msg)
		free(msg);
	return (err);
}


/**
 * Filter packet trough agent.
 */
int hip_agent_filter(struct hip_common *msg,
                     struct in6_addr *src_addr,
                     struct in6_addr *dst_addr,
	                 hip_portpair_t *msg_info)
{
	struct hip_common *user_msg = NULL;
	int err = 0;
	int n, sendn;
	hip_ha_t *ha_entry;
	struct in6_addr hits;

	if (!hip_agent_is_alive())
	{
		return (-ENOENT);
	}

	HIP_DEBUG("Filtering hip control message trough agent,"
	          " message body size is %d bytes.\n",
	          hip_get_msg_total_len(msg) - sizeof(struct hip_common));

	/* Create packet for agent. */
	HIP_IFE(!(user_msg = hip_msg_alloc()), -1);
	HIP_IFE(hip_build_user_hdr(user_msg, hip_get_msg_type(msg), 0), -1);
	HIP_IFE(hip_build_param_contents(user_msg, msg, HIP_PARAM_ENCAPS_MSG,
	                                 hip_get_msg_total_len(msg)), -1);
	HIP_IFE(hip_build_param_contents(user_msg, src_addr, HIP_PARAM_SRC_ADDR,
	                                 sizeof(*src_addr)), -1);
	HIP_IFE(hip_build_param_contents(user_msg, dst_addr, HIP_PARAM_DST_ADDR,
	                                 sizeof(*dst_addr)), -1);
	HIP_IFE(hip_build_param_contents(user_msg, msg_info, HIP_PARAM_PORTPAIR,
	                                 sizeof(*msg_info)), -1);

	n = hip_send_agent(user_msg);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}

	HIP_DEBUG("Sent %d bytes to agent for handling.\n", n);

out_err:
	if (user_msg)
		free(user_msg);
	return (err);
}


/**
 * Send new status of given state to agent.
 */
int hip_agent_update_status(int msg_type, void *data, size_t size)
{
	struct hip_common *user_msg = NULL;
	int err = 0;
	int n;

	if (!hip_agent_is_alive())
	{
		return (-ENOENT);
	}

	/* Create packet for agent. */
	HIP_IFE(!(user_msg = hip_msg_alloc()), -1);
	HIP_IFE(hip_build_user_hdr(user_msg, msg_type, 0), -1);
	if (size > 0 && data != NULL)
	{
		HIP_IFE(hip_build_param_contents(user_msg, data, HIP_PARAM_ENCAPS_MSG,
		                                 size), -1);
	}

	n = hip_send_agent(user_msg);
	if (n < 0)
	{
		HIP_ERROR("Sendto() failed.\n");
		err = -1;
		goto out_err;
	}

out_err:
	if (user_msg)
		free(user_msg);
	return err;
}


/**
 * Update different items status to agent.
 */
int hip_agent_update(void)
{
	hip_agent_add_lhits();
	/* remove by santtu
	if (hip_nat_is())
		hip_agent_update_status(SO_HIP_SET_NAT_ON, NULL, 0);
	else
		hip_agent_update_status(SO_HIP_SET_NAT_OFF, NULL, 0);
		*/
	//add by santtu
	hip_agent_update_status(hip_get_nat_mode(), NULL, 0);
	//end add

	return 0;
}


/**
 * register_to_dht - Insert mapping for local host IP addresses to HITs to the queue.
 */
void register_to_dht()
{  
#ifdef CONFIG_HIP_OPENDHT
	int i, pub_addr_ret = 0, err = 0;
	char tmp_hit_str[INET6_ADDRSTRLEN + 2];
	struct in6_addr tmp_hit;
	
	/* Check if OpenDHT is off then out_err*/
	HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);
	
	HIP_IFEL(hip_get_default_hit(&tmp_hit), -1, "No HIT found\n");

	hip_convert_hit_to_str(&tmp_hit, NULL, opendht_current_key);
	hip_convert_hit_to_str(&tmp_hit, NULL, tmp_hit_str);

	publish_hit(&opendht_name_mapping, tmp_hit_str);
	pub_addr_ret = publish_addr(tmp_hit_str);

#endif	/* CONFIG_HIP_OPENDHT */             
 out_err:
	return;
}
/**
 * publish_hit
 * This function creates HTTP packet for publish HIT
 * and writes it in the queue for sending
 * @param *hostname
 * @param *hit_str
 *
 * @return void
 */
void publish_hit(char *hostname, char *tmp_hit_str)
{
	char out_packet[HIP_MAX_PACKET]; /*Assuming HIP Max packet length, max for DHT put*/
	int err = 0;
	
#ifdef CONFIG_HIP_OPENDHT
	HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);

	memset(out_packet, '\0', HIP_MAX_PACKET);
	opendht_error = opendht_put((unsigned char *)hostname,
				    (unsigned char *)tmp_hit_str, 
				    (unsigned char *)opendht_host_name,
				    opendht_serving_gateway_port,
				    opendht_serving_gateway_ttl,out_packet);
	
        if (opendht_error < 0) {
        	HIP_DEBUG("HTTP packet creation for FDQN->HIT PUT failed.\n");
	} else {
		HIP_DEBUG("Sending FDQN->HIT PUT packet to queue. Packet Length: %d\n",strlen(out_packet)+1);
		opendht_error = hip_write_to_opendht_queue(out_packet,strlen(out_packet)+1);
		if (opendht_error < 0) {
        		HIP_DEBUG ("Failed to insert FDQN->HIT PUT data in queue \n");
		}
	}
#endif	/* CONFIG_HIP_OPENDHT */
                       
 out_err:
        return;
}

/**
 * publish address
 * This function creates HTTP packet for publish address
 * and writes it in the queue for sending
 * @param *hit_str
 * @param *addr_str
 * @param *netdev_address
 *
 * @return int 0 connect unfinished, -1 error, 1 success
 */
int publish_addr(char *tmp_hit_str)
{
	char out_packet[HIP_MAX_PACKET]; /*Assuming HIP Max packet length, max for DHT put*/
	int err = 0;

#ifdef CONFIG_HIP_OPENDHT        
	HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);

	memset(out_packet, '\0', HIP_MAX_PACKET);
	opendht_error = opendht_put_hdrr((unsigned char *)tmp_hit_str, 
					    (unsigned char *)opendht_host_name,
					    opendht_serving_gateway_port,
					    opendht_serving_gateway_ttl,out_packet);
	if (opendht_error < 0) {
		HIP_DEBUG("HTTP packet creation for HIT->IP PUT failed.\n");
		return -1;
	} else {
		HIP_DEBUG("Sending HTTP HIT->IP PUT packet to queue.\n");
		opendht_error = hip_write_to_opendht_queue(out_packet,strlen(out_packet)+1);
		if (opendht_error < 0) {
			HIP_DEBUG ("Failed to insert HIT->IP PUT data in queue \n");
			return -1;
		}
	}
#endif	/* CONFIG_HIP_OPENDHT */
 out_err:
	return 0;
}

/**
 * send_queue_data - This function reads the data from hip_queue
 * and sends it to the lookup service for publishing
 * 
 * @param *socket socket to be initialized
 * @param *socket_status updates the status of the socket after every socket oepration
 *
 * @return int
 */
int send_queue_data(int *socket, int *socket_status)
{
	char packet[2048];
	int err = 0;

#ifdef CONFIG_HIP_OPENDHT
	HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);
		
	if (*socket_status == STATE_OPENDHT_IDLE) {
		HIP_DEBUG("Connecting to the DHT with socket no: %d \n", *socket);
		if (*socket < 1)
			*socket = init_dht_gateway_socket_gw(*socket, opendht_serving_gateway);
		opendht_error = 0;
		opendht_error = connect_dht_gateway(*socket, 
						    opendht_serving_gateway, 0); 
		if (opendht_error == -1) {
			HIP_DEBUG("Error connecting to the DHT. Socket No: %d\n", *socket);
			hip_opendht_error_count++;
		} else if (opendht_error > -1 && opendht_error != EINPROGRESS) {
			/*Get packet from queue, if there then proceed*/
			memset(packet, '\0', sizeof(packet));
			opendht_error = hip_read_from_opendht_queue(packet);
			_HIP_DEBUG("Packet: %s\n",packet);
			if (opendht_error < 0 && strlen(packet)>0) {
				HIP_DEBUG("Packet reading from queue failed.\n");
			} else {
				opendht_error = opendht_send(*socket,packet);
				if (opendht_error < 0) {
					HIP_DEBUG("Error sending data to the DHT. Socket No: %d\n",
						  *socket);
					hip_opendht_error_count++;
				} else
					*socket_status = STATE_OPENDHT_WAITING_ANSWER;
			}
		} 
		if (opendht_error == EINPROGRESS) {
			*socket_status = STATE_OPENDHT_WAITING_CONNECT; 
			/* connect not ready */
			HIP_DEBUG("OpenDHT connect unfinished. Socket No: %d \n",*socket);
		}
	} else if (*socket_status == STATE_OPENDHT_START_SEND) {
		/* connect finished send the data */
		/*Get packet from queue, if there then proceed*/
		memset(packet, '\0', sizeof(packet));
		opendht_error = hip_read_from_opendht_queue(packet);
		_HIP_DEBUG("Packet: %s\n",packet);
		if (opendht_error < 0  && strlen (packet)>0) {
			HIP_DEBUG("Packet reading from queue failed.\n");
		} else {
			opendht_error = opendht_send(*socket,packet);
			if (opendht_error < 0) {
				HIP_DEBUG("Error sending data to the DHT. Socket No: %d\n", 
					  *socket);
				hip_opendht_error_count++;
			} else
				*socket_status = STATE_OPENDHT_WAITING_ANSWER;
		}
	}
#endif	/* CONFIG_HIP_OPENDHT */
 out_err:
	return err;
}


/** 
 * This function goes through the HA database and sends an icmp echo to all of them
 *
 * @param socket to send with
 *
 * @return 0 on success negative on error
 */
int hip_send_heartbeat(hip_ha_t *entry, void *opaq) {
	int err = 0;
	int *sockfd = (int *) opaq;

	if (entry->state == HIP_STATE_ESTABLISHED) {
	    if (entry->outbound_sa_count > 0) {
		    _HIP_DEBUG("list_for_each_safe\n");
		    HIP_IFEL(hip_send_icmp(*sockfd, entry), 0,
			     "Error sending heartbeat, ignore\n");
	    } else {
		    /* This can occur when ESP transform is not negotiated
		       with e.g. a HIP Relay or Rendezvous server */
		    HIP_DEBUG("No SA, sending NOTIFY instead of ICMPv6\n");
		    err = hip_nat_send_keep_alive(entry, NULL);
	    }
        }

out_err:
	return err;
}

/**
 * Periodic maintenance.
 *
 * @return ...
 */
int periodic_maintenance()
{
	int err = 0;

	if (hipd_get_state() == HIPD_STATE_CLOSING) {
		if (force_exit_counter > 0) {
			err = hip_count_open_connections();
			if (err < 1) hipd_set_state(HIPD_STATE_CLOSED);
		} else {
			hip_exit(SIGINT);
			exit(SIGINT);
		}
		force_exit_counter--;
	}

#ifdef CONFIG_HIP_AGENT
	if (hip_agent_is_alive())
	{
		hip_agent_send_remote_hits();
	}
#endif
	
#ifdef HIP_USE_ICE
	if (hip_nat_get_control(NULL) == HIP_NAT_MODE_ICE_UDP)
		hip_poll_ice_event_all();
#endif
	
	if (retrans_counter < 0) {
		HIP_IFEL(hip_scan_retransmissions(), -1,
			 "retransmission scan failed\n");
		retrans_counter = HIP_RETRANSMIT_INIT;
	} else {
		retrans_counter--;
	}

#ifdef CONFIG_HIP_OPPORTUNISTIC

	if (opp_fallback_counter < 0) {
		HIP_IFEL(hip_scan_opp_fallback(), -1,
			 "retransmission scan failed\n");
		opp_fallback_counter = HIP_OPP_FALLBACK_INIT;
	} else {
		opp_fallback_counter--;

	}
#endif

	if (precreate_counter < 0) {
		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1,
			 "Failed to recreate puzzles\n");
		precreate_counter = HIP_R1_PRECREATE_INIT;
	} else {
		precreate_counter--;
	}

	/* is heartbeat support on */
	if (hip_icmp_interval > 0) {
		/* Check if there are any msgs in the ICMPv6 socket */
		/*
		HIP_IFEL(hip_icmp_recvmsg(hip_icmp_sock), -1,
			 "Failed to recvmsg from ICMPv6\n");
		*/
		/* Check if the heartbeats should be sent */
		if (heartbeat_counter < 1) {
			hip_for_each_ha(hip_send_heartbeat, &hip_icmp_sock);
			heartbeat_counter = hip_icmp_interval;
		} else {
			heartbeat_counter--;
		}
	} else if (hip_nat_status) {
		/* Send NOTIFY keepalives for NATs only when ICMPv6
		   keepalives are disabled */
		if (nat_keep_alive_counter < 0) {
			HIP_IFEL(hip_nat_refresh_port(),
				 -ECOMM,
				 "Failed to refresh NAT port state.\n");
			nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_INTERVAL;
		} else {
			nat_keep_alive_counter--;
		}
	}

	if (hip_opendht_inuse == SO_HIP_DHT_ON) {
		if (opendht_counter < 0) {
			register_to_dht();
			opendht_counter = OPENDHT_REFRESH_INIT;
		} else {
			opendht_counter--;
			}
		if (queue_counter < 0) {
			send_packet_to_lookup_from_queue();
        	queue_counter = QUEUE_CHECK_INIT;
		} else {
			queue_counter--;
			}
		if (hip_buddies_inuse == SO_HIP_BUDDIES_ON) {
			if(cert_publish_counter < 0) {
				err = publish_certificates();
				if(err < 0)
				{
					HIP_ERROR("Publishing certificates to the lookup returned an error\n");
					err = 0 ;
				}
				cert_publish_counter = opendht_serving_gateway_ttl ;
			} else {
				cert_publish_counter-- ;
				}
		}
                		
	}

//#ifdef CONFIG_HIP_UDPRELAY
	/* Clear the expired records from the relay hashtable. */
	hip_relht_maintenance();
//#endif
	/* Clear the expired pending service requests. This is by no means time
	   critical operation and is not needed to be done on every maintenance
	   cycle. Once every 10 minutes or so should be enough. Just for the
	   record, if periodic_maintenance() is ever to be optimized. */
	hip_registration_maintenance();

 out_err:

	return err;
}

int hip_get_firewall_status(){
	return hip_firewall_status;
}

int hip_firewall_is_alive()
{
#ifdef CONFIG_HIP_FIREWALL
	if (hip_firewall_status) {
		HIP_DEBUG("Firewall is alive.\n");
	}
	else {
		HIP_DEBUG("Firewall is not alive.\n");
	}
	return hip_firewall_status;
#else
	HIP_DEBUG("Firewall is disabled.\n");
	return 0;
#endif // CONFIG_HIP_FIREWALL
}


int hip_firewall_add_escrow_data(hip_ha_t *entry, struct in6_addr * hit_s, 
        struct in6_addr * hit_r, struct hip_keys *keys) {
		hip_common_t *msg = NULL;
		int err = 0, n = 0;
		socklen_t alen;

		HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
		hip_msg_init(msg);
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ADD_ESCROW_DATA, 0), -1,
                        "Build hdr failed\n");

		HIP_IFEL(hip_build_param_contents(msg, (void *)hit_s, HIP_PARAM_HIT,
                        sizeof(struct in6_addr)), -1, "build param contents failed\n");
		HIP_IFEL(hip_build_param_contents(msg, (void *)hit_r, HIP_PARAM_HIT,
                        sizeof(struct in6_addr)), -1, "build param contents failed\n");

		HIP_IFEL(hip_build_param(msg, (struct hip_tlv_common *)keys), -1,
                        "hip build param failed\n");

		n = hip_sendto_firewall(msg);
		if (n < 0)
		{
			HIP_ERROR("Sendto firewall failed.\n");
			err = -1;
			goto out_err;
		}

		else HIP_DEBUG("Sendto firewall OK.\n");

out_err:
	return err;

}

int hip_firewall_set_i2_data(int action,  hip_ha_t *entry, 
			     struct in6_addr *hit_s, 
			     struct in6_addr *hit_r,
			     struct in6_addr *src,
			     struct in6_addr *dst) {

        struct hip_common *msg = NULL;
	struct sockaddr_in6 hip_firewall_addr;
	int err = 0, n = 0;
	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, action, 0), -1, 
                 "Build hdr failed\n");
	            
        HIP_IFEL(hip_build_param_contents(msg, (void *)hit_r, HIP_PARAM_HIT,
                 sizeof(struct in6_addr)), -1, "build param contents failed\n");
	HIP_IFEL(hip_build_param_contents(msg, (void *)src, HIP_PARAM_HIT,
                 sizeof(struct in6_addr)), -1, "build param contents failed\n");
	
	socklen_t alen = sizeof(hip_firewall_addr);

	bzero(&hip_firewall_addr, alen);
	hip_firewall_addr.sin6_family = AF_INET6;
	hip_firewall_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	hip_firewall_addr.sin6_addr = in6addr_loopback;

	//	if (hip_get_firewall_status()) {
	n = sendto(hip_firewall_sock_lsi_fd, msg, hip_get_msg_total_len(msg),
		   0, &hip_firewall_addr, alen);
		//}

	if (n < 0)
	  HIP_DEBUG("Send to firewall failed str errno %s\n",strerror(errno));
	HIP_IFEL( n < 0, -1, "Sendto firewall failed.\n");   

	HIP_DEBUG("Sendto firewall OK.\n");

out_err:
	if (msg)
		free(msg);

	return err;
}

int hip_firewall_set_savah_status(int status) {
  int n, err;
  struct sockaddr_in6 sock_addr;
  struct hip_common *msg = NULL;
  bzero(&sock_addr, sizeof(sock_addr));
  sock_addr.sin6_family = AF_INET6;
  sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
  sock_addr.sin6_addr = in6addr_loopback;

  HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
  hip_msg_init(msg);
    
  memset(msg, 0, sizeof(struct hip_common));
    
  hip_build_user_hdr(msg, status, 0);
  
  n = hip_sendto_user(msg, &sock_addr);
  
  HIP_IFEL(n < 0, 0, "sendto() failed\n");
  
  if (err == 0)
    {
      HIP_DEBUG("SEND SAVAH SERVER STATUS OK.\n");
    }
 out_err:
  return err;
}

int hip_firewall_set_bex_data(int action, hip_ha_t *entry, struct in6_addr *hit_s, struct in6_addr *hit_r)
{
        struct hip_common *msg = NULL;
	struct sockaddr_in6 hip_firewall_addr;
	int err = 0, n = 0, r_is_our;
	socklen_t alen = sizeof(hip_firewall_addr);

	/* Makes sure that the hits are sent always in the same order */
	r_is_our = hip_hidb_hit_is_our(hit_r);

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, action, 0), -1,
                 "Build hdr failed\n");

        HIP_IFEL(hip_build_param_contents(msg,
			    (void *)(r_is_our ? hit_s : hit_r), HIP_PARAM_HIT,
                sizeof(struct in6_addr)), -1, "build param contents failed\n");
	HIP_IFEL(hip_build_param_contents(msg,
		 (void *) (r_is_our ? hit_r : hit_s), HIP_PARAM_HIT,
                sizeof(struct in6_addr)), -1, "build param contents failed\n");

	bzero(&hip_firewall_addr, alen);
	hip_firewall_addr.sin6_family = AF_INET6;
	hip_firewall_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	hip_firewall_addr.sin6_addr = in6addr_loopback;

	if (hip_get_firewall_status()) {
	        n = sendto(hip_firewall_sock_lsi_fd, msg, hip_get_msg_total_len(msg),
			   0, &hip_firewall_addr, alen);
	}

	if (n < 0)
	  HIP_DEBUG("Send to firewall failed str errno %s\n",strerror(errno));
	HIP_IFEL( n < 0, -1, "Sendto firewall failed.\n");

	HIP_DEBUG("Sendto firewall OK.\n");

out_err:
	if (msg)
		free(msg);

	return err;
}

int hip_firewall_remove_escrow_data(struct in6_addr *addr, uint32_t spi)
{
        struct hip_common *msg;
        int err = 0;
        int n;
        socklen_t alen;
        struct in6_addr * hit_s;
        struct in6_addr * hit_r;

        HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DELETE_ESCROW_DATA, 0), -1,
                "Build hdr failed\n");

        HIP_IFEL(hip_build_param_contents(msg, (void *)addr, HIP_PARAM_HIT,
                sizeof(struct in6_addr)), -1, "build param contents failed\n");
        HIP_IFEL(hip_build_param_contents(msg, (void *)&spi, HIP_PARAM_UINT,
                sizeof(unsigned int)), -1, "build param contents failed\n");

	/* Switched from hip_sendto() to hip_sendto_user() due to
	   namespace collision. Both message.h and user.c had functions
	   hip_sendto(). Introducing a prototype hip_sendto() to user.h
	   led to compiler errors --> user.c hip_sendto() renamed to
	   hip_sendto_user().

	   Lesson learned: use function prototypes unless functions are
	   ment only for local (inside the same file where defined) use.
	   -Lauri 11.07.2008 */
	n = hip_sendto_user(msg, (struct sockaddr *)&hip_firewall_addr);

	if (n < 0)
        {
                HIP_ERROR("Sendto firewall failed.\n");
                err = -1;
                goto out_err;
        }
        else HIP_DEBUG("Sendto firewall OK.\n");

out_err:
        return err;
}


int hip_firewall_set_escrow_active(int activate)
{
        struct hip_common *msg;
        int err = 0;
        int n;
        socklen_t alen;
        HIP_DEBUG("Sending activate msg to firewall (value=%d)\n", activate);
        HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg,
                (activate ? SO_HIP_SET_ESCROW_ACTIVE : SO_HIP_SET_ESCROW_INACTIVE), 0),
                -1, "Build hdr failed\n");

        /* Switched from hip_sendto() to hip_sendto_user() due to
	   namespace collision. Both message.h and user.c had functions
	   hip_sendto(). Introducing a prototype hip_sendto() to user.h
	   led to compiler errors --> user.c hip_sendto() renamed to
	   hip_sendto_user().

	   Lesson learned: use function prototypes unless functions are
	   ment only for local (inside the same file where defined) use.
	   -Lauri 11.07.2008 */
	n = hip_sendto_user(msg, (struct sockaddr *)&hip_firewall_addr);

        if (n < 0) {
                HIP_ERROR("Sendto firewall failed.\n");
                err = -1;
                goto out_err;
        }
        else {
                HIP_DEBUG("Sendto firewall OK.\n");
        }
out_err:
        return err;
}


int opendht_put_hdrr(unsigned char * key, 
                   unsigned char * host,
                   int opendht_port,
                   int opendht_ttl,void *put_packet) 
{
    int err = 0, key_len = 0, value_len = 0, ret = 0;
    struct hip_common *hdrr_msg;
    char tmp_key[21];
    unsigned char *sha_retval; 

    hdrr_msg = hip_msg_alloc();
    value_len = hip_build_locators(hdrr_msg, 0, hip_get_nat_mode(NULL));
    
#ifdef CONFIG_HIP_OPENDHT
    /* The function below builds and appends Host Id
     * and signature to the msg */
    err = hip_build_host_id_and_signature(hdrr_msg, key);
    if( err != 0) {
    	HIP_DEBUG("Appending Host ID and Signature to HDRR failed.\n");
    	goto out_err;
    }
    
    _HIP_DUMP_MSG(hdrr_msg);        
    key_len = opendht_handle_key(key, tmp_key);
    value_len = hip_get_msg_total_len(hdrr_msg);
    _HIP_DEBUG("Value len %d\n",value_len);

    /* Debug info can be later removed from cluttering the logs */
    hip_print_locator_addresses(hdrr_msg);

    /* store for removals*/
    if (opendht_current_hdrr)
	    free(opendht_current_hdrr);
    opendht_current_hdrr = hip_msg_alloc();
    memcpy(opendht_current_hdrr, hdrr_msg, sizeof(hip_common_t));

    /* Put operation HIT->IP */
    if (build_packet_put_rm((unsigned char *)tmp_key,
			    key_len,
			    (unsigned char *)hdrr_msg,
			    value_len,
			    &opendht_hdrr_secret,
			    40,
			    opendht_port,
			    (unsigned char *)host,
			    put_packet, opendht_ttl) != 0) {
	    HIP_DEBUG("Put packet creation failed.\n");
	    err = -1;
    }
    HIP_DEBUG("Host address in OpenDHT put locator : %s\n", host);
    HIP_DEBUG("Actual OpenDHT send starts here\n");
   err = 0;
#endif	/* CONFIG_HIP_OPENDHT */
 out_err:
    HIP_FREE(hdrr_msg);
    return(err);
}
 
void opendht_remove_current_hdrr() {
	int err = 0, value_len = 0;
	char remove_packet[2048];

#ifdef CONFIG_HIP_OPENDHT
	HIP_DEBUG("Building a remove packet for the current HDRR and queuing it\n");
                           
	value_len = hip_get_msg_total_len(opendht_current_hdrr);
	err = build_packet_rm(opendht_current_key, 
			      strlen(opendht_current_key),
			      (unsigned char *)opendht_current_hdrr,
			      value_len, 
			      &opendht_hdrr_secret,
			      40,
			      opendht_serving_gateway_port,
			      opendht_host_name,
			      &remove_packet,
			      opendht_serving_gateway_ttl);
	if (err < 0) {
		HIP_DEBUG("Error creating the remove current HDRR packet\n");
		goto out_err;
	}

        err = hip_write_to_opendht_queue(remove_packet, strlen(remove_packet) + 1);
	if (err < 0) 
		HIP_DEBUG ("Failed to insert HDRR remove data in queue \n");
#endif	/* CONFIG_HIP_OPENDHT */
	
out_err:
	return(err);
}

/**
 * verify_hdrr - This function verifies host id in the value (HDRR) against HIT used as a key for DHT
 * And it also verifies the signature in HDRR
 * This works on the hip common message sent to the daemon
 * Modifies the message and sets the required flag if (or not) verified
 * 
 * @param msg HDRR to be verified
 * @param addrkey HIT key used for lookup
 * @return 0 on successful verification (OR of signature and host od verification)
 */
int verify_hdrr (struct hip_common *msg,struct in6_addr *addrkey)
{
	struct hip_host_id *hostid ; 
    struct in6_addr *hit_from_hostid ;
	struct in6_addr *hit_used_as_key ;
	struct hip_hdrr_info *hdrr_info = NULL;
	int alg = -1;
	int is_hit_verified  = -1;
	int is_sig_verified  = -1;
	int err = 0 ;
		
	hostid = hip_get_param (msg, HIP_PARAM_HOST_ID);
	if ( addrkey == NULL)
	{
     	hdrr_info = hip_get_param (msg, HIP_PARAM_HDRR_INFO);
       	hit_used_as_key = &hdrr_info->dht_key ; 
	}
	else
	{
	  	hit_used_as_key = addrkey;
	}
       
    //Check for algo and call verify signature from pk.c
    alg = hip_get_host_id_algo(hostid);
        
    /* Type of the hip msg in header has been modified to 
     * user message type SO_HIP_VERIFY_DHT_HDRR_RESP , to
     * get it here. Revert it back to HDRR to give it
     * original shape as returned by the DHT and
     *  then verify signature
     */
    hip_set_msg_type(msg,HIP_HDRR);
    _HIP_DUMP_MSG (msg);
    HIP_IFEL(!(hit_from_hostid = malloc(sizeof(struct in6_addr))), -1, "Malloc for HIT failed\n");
	switch (alg) {
		case HIP_HI_RSA:
			is_sig_verified = hip_rsa_verify(hostid, msg);
			err = hip_rsa_host_id_to_hit (hostid, hit_from_hostid, HIP_HIT_TYPE_HASH100);
			is_hit_verified = memcmp(hit_from_hostid, hit_used_as_key, sizeof(struct in6_addr)) ;
			break;
		case HIP_HI_DSA:
			is_sig_verified = hip_dsa_verify(hostid, msg);
			err = hip_dsa_host_id_to_hit (hostid, hit_from_hostid, HIP_HIT_TYPE_HASH100);
			is_hit_verified = memcmp(hit_from_hostid, hit_used_as_key, sizeof(struct in6_addr)) ; 
			break;
		default:
			HIP_ERROR("Unsupported HI algorithm used cannot verify signature (%d)\n", alg);
			break;
	}
	_HIP_DUMP_MSG (msg);
	if (err != 0)
	{
		HIP_DEBUG("Unable to convert host id to hit for host id verification \n");
	}
	if(hdrr_info)
	{
		hdrr_info->hit_verified = is_hit_verified ;
		hdrr_info->sig_verified = is_sig_verified ;
	}
	HIP_DEBUG ("Sig verified (0=true): %d\nHit Verified (0=true): %d \n"
		,is_sig_verified, is_hit_verified);
	return (is_sig_verified | is_hit_verified) ;
out_err:
	return err;
}

/** 
 * send_packet_to_lookup_from_queue - Calls to a function which
 * sends data from the queue to the dht
 */
void 
send_packet_to_lookup_from_queue ()
{
#ifdef CONFIG_HIP_OPENDHT
	int err = 0;

	HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);

	HIP_DEBUG("DHT error count now %d/%d.\n", 
			hip_opendht_error_count, OPENDHT_ERROR_COUNT_MAX);
	if (hip_opendht_error_count > OPENDHT_ERROR_COUNT_MAX) {
		HIP_DEBUG("DHT error count reached resolving trying to change gateway\n");
		hip_init_dht();
	}
	send_queue_data (&hip_opendht_sock_fqdn, &hip_opendht_fqdn_sent);
	send_queue_data (&hip_opendht_sock_hit, &hip_opendht_hit_sent);
#endif	/* CONFIG_HIP_OPENDHT */
out_err:
	return;
}

/* init_dht_sockets - The finction initalized two sockets used for
 * connection with lookup service(opendht)
 * @param *socket socket to be initialzied
 * @param *socket_status updates the status of the socket after every socket oepration
 */
 
void init_dht_sockets (int *socket, int *socket_status)
{
#ifdef CONFIG_HIP_OPENDHT
	if (hip_opendht_inuse == SO_HIP_DHT_ON) 
	{
		if (*socket_status == STATE_OPENDHT_IDLE) 
		{
			HIP_DEBUG("Connecting to the DHT with socket no: %d \n", *socket);
			if (*socket < 1)
				*socket = init_dht_gateway_socket_gw(*socket, 
								     opendht_serving_gateway);
			opendht_error = 0;
			opendht_error = connect_dht_gateway(*socket, 
							opendht_serving_gateway, 0); 
		}
		if (opendht_error == EINPROGRESS) 
		{
			*socket_status = STATE_OPENDHT_WAITING_CONNECT; 
			/* connect not ready */
			HIP_DEBUG("OpenDHT connect unfinished. Socket No: %d \n",*socket);
        }
        else if (opendht_error > -1 && opendht_error != EINPROGRESS)
        {
        	*socket_status = STATE_OPENDHT_START_SEND ;
        }
        
	}
#endif	/* CONFIG_HIP_OPENDHT */
}

/**
 * prepare_send_cert_put - builds xml rpc packet and then
 * sends it to the queue for sending to the opendht
 * 
 * @param *key key for cert publish
 * @param *value certificate
 * @param key_len length of the key (20 in case of SHA1)
 * @param valuelen length of the value content to be sent to the opendht
 * @return 0 on success, negative value on error
 */
int prepare_send_cert_put(unsigned char * key, unsigned char * value, int key_len, int valuelen)
{
	int value_len = valuelen;/*length of certificate*/
	char put_packet[2048];
	
#ifdef CONFIG_HIP_OPENDHT
	if (build_packet_put((unsigned char *)key,
			     key_len,
			     (unsigned char *)value,
			     value_len,
			     opendht_serving_gateway_port,
			     (unsigned char *)opendht_host_name,
			     (char*)put_packet, opendht_serving_gateway_ttl)
	    != 0)
	{
		HIP_DEBUG("Put packet creation failed.\n");
		return(-1);
	}
	opendht_error = hip_write_to_opendht_queue(put_packet,strlen(put_packet)+1);
	if (opendht_error < 0) 
		HIP_DEBUG ("Failed to insert CERT PUT data in queue \n");
#endif	/* CONFIG_HIP_OPENDHT */
	return 0;
}

/**
 * hip_sqlite_callback - callbacl function called by sqliteselect
 * The function processes the data returned by select
 * to be sent to key_handler and then for sending to lookup
 * 
 * @param *NotUsed
 * @param argc
 * @param **argv
 * @param **azColName
 * @return 0
 */
static int hip_sqlite_callback(void *NotUsed, int argc, char **argv, char **azColName) {
	int i;
	struct in6_addr lhit, rhit;
	unsigned char conc_hits_key[21] ;
	int err = 0 ;
	char cert[512]; /*Should be size of certificate*/
	int keylen = 0 ;
	
	memset(conc_hits_key, '\0', 21);
	for(i=0; i<argc; i++){
		_HIP_DEBUG("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
		if (!strcmp(azColName[i],"lhit"))
		{
        	/*convret hit to inet6_addr*/
          	err = inet_pton(AF_INET6, (char *)argv[i], &lhit.s6_addr);
		}
		else if (!strcmp(azColName[i],"rhit"))
		{
         	err = inet_pton(AF_INET6, (char *)argv[i], &rhit.s6_addr);
          	/*convret hit to inet6_addr*/
		}
		else if (!strcmp(azColName[i],"cert"))
		{
			if(!(char *)argv)
				err = -1 ;
			else
         		memcpy(cert, (char *)argv[i], 512/*should be size of certificate*/);
     	} 
	}
	if(err)
	{
#ifdef CONFIG_HIP_OPENDHT
		keylen = handle_cert_key(&lhit, &rhit, conc_hits_key);
		/*send key-value pair to dht*/
		if (keylen)
		{ 
			err = prepare_send_cert_put(conc_hits_key, cert, keylen, sizeof(cert) );
		}
		else
		{
			HIP_DEBUG ("Unable to handle publish cert key\n");
			err = -1 ;
		}
#endif	/* CONFIG_HIP_OPENDHT */
	} 
	return err;
}

/**
 * publish_certificates - Reads the daemon database
 * and then publishes certificate after regular interval defined
 * in hipd.h
 * 
 * @param
 * @return error value 0 on success and negative on error
 */
int publish_certificates ()
{
#ifdef CONFIG_HIP_AGENT
	 return hip_sqlite_select(daemon_db, HIP_CERT_DB_SELECT_HITS,hip_sqlite_callback);
#endif

     return 0;
}

/**
 * This function receives ICMPv6 msgs (heartbeats)
 *
 * @param sockfd to recv from
 *
 * @return 0 on success otherwise negative
 *
 * @note see RFC2292
 */
int hip_icmp_recvmsg(int sockfd) {
	int err = 0, ret = 0, identifier = 0;
	struct msghdr mhdr;
	struct cmsghdr * chdr;
	struct iovec iov[1];
	u_char cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	u_char iovbuf[HIP_MAX_ICMP_PACKET];
#ifdef ANDROID_CHANGES
	struct icmp6_hdr * icmph = NULL;
#else
	struct icmp6hdr * icmph = NULL;
#endif
	struct in6_pktinfo * pktinfo, * pktinfo_in6;
	struct sockaddr_in6 src_sin6;
	struct in6_addr * src = NULL, * dst = NULL;
	struct timeval * stval = NULL, * rtval = NULL, * ptr = NULL;

	/* malloc what you need */
	stval = malloc(sizeof(struct timeval));
	HIP_IFEL((!stval), -1, "Malloc for stval failed\n");
	rtval = malloc(sizeof(struct timeval));
	HIP_IFEL((!rtval), -1, "Malloc for rtval failed\n");
	src = malloc(sizeof(struct in6_addr));
	HIP_IFEL((!src), -1, "Malloc for dst6 failed\n");
	dst = malloc(sizeof(struct in6_addr));
	HIP_IFEL((!dst), -1, "Malloc for dst failed\n");

	/* cast */
	chdr = (struct cmsghdr *)cmsgbuf;
	pktinfo = (struct in6_pktinfo *)(CMSG_DATA(chdr));

	/* clear memory */
	memset(stval, 0, sizeof(struct timeval));
	memset(rtval, 0, sizeof(struct timeval));
	memset(src, 0, sizeof(struct in6_addr));
	memset(dst, 0, sizeof(struct in6_addr));
	memset (&src_sin6, 0, sizeof (struct sockaddr_in6));
	memset(&iov, 0, sizeof(&iov));
	memset(&iovbuf, 0, sizeof(iovbuf));
	memset(&mhdr, 0, sizeof(mhdr));

	/* receive control msg */
        chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_2292PKTINFO;
	chdr->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));

	/* Input output buffer */
	iov[0].iov_base = &iovbuf;
	iov[0].iov_len = sizeof(iovbuf);

	/* receive msg hdr */
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_name = (caddr_t) &src_sin6;
	mhdr.msg_namelen = sizeof (struct sockaddr_in6);
	mhdr.msg_control = (caddr_t) cmsgbuf;
	mhdr.msg_controllen = sizeof (cmsgbuf);

	ret = recvmsg (sockfd, &mhdr, MSG_DONTWAIT);
	_HIP_PERROR("RECVMSG ");
	if (errno == EAGAIN) {
		err = 0;
		_HIP_DEBUG("Asynchronous, maybe next time\n");
		goto out_err;
	}
	if (ret < 0) {
		HIP_DEBUG("Recvmsg on ICMPv6 failed\n");
		err = -1;
		goto out_err;
 	}

	/* Get the current time as the return time */
	gettimeofday(rtval, (struct timezone *)NULL);

	/* Check if the process identifier is ours and that this really is echo response */
#ifdef ANDROID_CHANGES
	icmph = (struct icmp6_hdr *)&iovbuf;
	if (icmph->icmp6_type != ICMP6_ECHO_REPLY) {
		err = 0;
		goto out_err;
	}
	identifier = getpid() & 0xFFFF;
	if (identifier != icmph->icmp6_id) {
		err = 0;
		goto out_err;
	}
#else
	icmph = (struct icmpv6hdr *)&iovbuf;
	if (icmph->icmp6_type != ICMPV6_ECHO_REPLY) {
		err = 0;
		goto out_err;
	}
	identifier = getpid() & 0xFFFF;
	if (identifier != icmph->icmp6_identifier) {
		err = 0;
		goto out_err;
	}
#endif

	/* Get the timestamp as the sent time*/
	ptr = (struct timeval *)(icmph + 1);
	memcpy(stval, ptr, sizeof(struct timeval));

	/* gather addresses */
	memcpy (src, &src_sin6.sin6_addr, sizeof (struct in6_addr));
	memcpy (dst, &pktinfo->ipi6_addr, sizeof (struct in6_addr));

	if (!ipv6_addr_is_hit(src) && !ipv6_addr_is_hit(dst)) {
	    HIP_DEBUG("Addresses are NOT HITs, this msg is not for us\n");
	}

	/* Calculate and store everything into the correct entry */
	HIP_IFEL(hip_icmp_statistics(src, dst, stval, rtval), -1,
		 "Failed to calculate the statistics and store the values\n");

out_err:
	
	if (stval) free(stval);
	if (rtval) free(rtval);
	if (src) free(src);
	if (dst) free(dst);
	
	return err;
}

#if 0
static long llsqrt(long long a)
{
        long long prev = ~((long long)1 << 63);
        long long x = a;

        if (x > 0) {
                while (x < prev) {
                        prev = x;
                        x = (x+(a/x))/2;
                }
        }

        return (long)x;
}
#endif

/**
 * This function calculates RTT and ... and then stores them to correct entry
 *
 * @param src HIT
 * @param dst HIT
 * @param time when sent
 * @param time when received
 *
 * @return 0 if success negative otherwise
 */
int hip_icmp_statistics(struct in6_addr * src, struct in6_addr * dst,
			struct timeval *stval, struct timeval *rtval) {
	int err = 0;
	uint32_t rcvd_heartbeats = 0;
	uint64_t rtt = 0;
	double avg = 0.0, std_dev = 0.0;
#if 0
	u_int32_t rtt = 0, usecs = 0, secs = 0, square = 0;
	u_int32_t sum1 = 0, sum2 = 0;
#endif
	char hit[INET6_ADDRSTRLEN];
	hip_ha_t * entry = NULL;

	hip_in6_ntop(src, hit);

	/* Find the correct entry */
	entry = hip_hadb_find_byhits(src, dst);
	HIP_IFEL((!entry), -1, "Entry not found\n");

	/* Calculate the RTT from given timevals */
	rtt = calc_timeval_diff(stval, rtval);

	/* add the heartbeat item to the statistics */
	add_statistics_item(&entry->heartbeats_statistics, rtt);

	/* calculate the statistics for immediate output */
	calc_statistics(&entry->heartbeats_statistics, &rcvd_heartbeats, NULL, NULL, &avg,
			&std_dev, STATS_IN_MSECS);

	HIP_DEBUG("\nHeartbeat from %s, RTT %.6f ms,\n%.6f ms mean, "
		  "%.6f ms std dev, packets sent %d recv %d lost %d\n",
		  hit, ((float)rtt / STATS_IN_MSECS), avg, std_dev, entry->heartbeats_sent,
		  rcvd_heartbeats, (entry->heartbeats_sent - rcvd_heartbeats));

#if 0
	secs = (rtval->tv_sec - stval->tv_sec) * 1000000;
	usecs = rtval->tv_usec - stval->tv_usec;
	rtt = secs + usecs;

	/* received count will vary from sent if errors */
	entry->heartbeats_received++;

	/* Calculate mean */
	entry->heartbeats_total_rtt += rtt;
	entry->heartbeats_total_rtt2 += rtt * rtt;
	if (entry->heartbeats_received > 1)
		entry->heartbeats_mean = entry->heartbeats_total_rtt / entry->heartbeats_received;

	/* Calculate variance  */
	if (entry->heartbeats_received > 1) {
		sum1 = entry->heartbeats_total_rtt;
		sum2 = entry->heartbeats_total_rtt2;
		sum1 /= entry->heartbeats_received;
		sum2 /= entry->heartbeats_received;
		entry->heartbeats_variance = llsqrt(sum2 - sum1 * sum1);
	}

	HIP_DEBUG("\nHeartbeat from %s, RTT %.6f ms,\n%.6f ms mean, "
		  "%.6f ms variance, packets sent %d recv %d lost %d\n",
		  hit, (rtt / 1000000.0), (entry->heartbeats_mean / 1000000.0),
		  (entry->heartbeats_variance / 1000000.0),
		  entry->heartbeats_sent, entry->heartbeats_received,
		  (entry->heartbeats_sent - entry->heartbeats_received));
#endif

out_err:
	return err;
}
