/** @file
 * This file defines a user message handling function for the Host Identity
 * Protocol (HIP).
 *
 * We don't currently have a workqueue. The functionality in this file mostly
 * covers catching userspace messages only.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Kristian Slavov <kslavov_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Tao Wan  <twan_cc.hut.fi>
 * @author	Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#include "user.h"


int hip_sendto_user(const struct hip_common *msg, const struct sockaddr *dst){
	HIP_DEBUG("Sending msg type %d\n", hip_get_msg_type(msg));
        return sendto(hip_user_sock, msg, hip_get_msg_total_len(msg),
		      0, (struct sockaddr *)dst, hip_sockaddr_len(dst));
}

/**
 * Handles a user message.
 *
 * @note If you added a SO_HIP_NEWMODE in libinet6/icomm.h, you also need to
 *       add a case block for your SO_HIP_NEWMODE constant in the
 *       switch(msg_type) block in this function.
 * @param  msg  a pointer to the received user message HIP packet.
 * @param  src
 * @return zero on success, or negative error value on error.
 * @see    hip_so.
 */
int hip_handle_user_msg(hip_common_t *msg, struct sockaddr_in6 *src)
{
	hip_hit_t *hit = NULL, *src_hit = NULL, *dst_hit = NULL;
	hip_lsi_t *lsi, *src_lsi = NULL, *dst_lsi = NULL;
	in6_addr_t *src_ip = NULL, *dst_ip = NULL;
	hip_ha_t *entry = NULL, *server_entry = NULL;
	int err = 0, msg_type = 0, n = 0, len = 0, state = 0, reti = 0;
	int access_ok = 0, is_root = 0, dhterr = 0;
	HIP_KEA * kea = NULL;
	struct hip_tlv_common *param = NULL;
	extern int hip_icmp_interval;
	struct hip_heartbeat * heartbeat;
	char host[NI_MAXHOST];
	int send_response;

	HIP_ASSERT(src->sin6_family == AF_INET6);
	HIP_DEBUG("User message from port %d\n", htons(src->sin6_port));

	err = hip_check_userspace_msg(msg);

	if (err) {
		HIP_ERROR("HIP socket option was invalid.\n");
		goto out_err;
	}

	send_response = hip_get_msg_response(msg);

	msg_type = hip_get_msg_type(msg);

	is_root = (ntohs(src->sin6_port) < 1024);
	if (is_root) {
		access_ok = 1;
	} else if (!is_root &&
 		   (msg_type >= HIP_SO_ANY_MIN && msg_type <= HIP_SO_ANY_MAX)) {
		access_ok = 1;
	}

	if (!access_ok) {
		HIP_ERROR("The user does not have privilege for this "
			  "operation. The operation is cancelled.\n");
		err = -1;
		goto out_err;

	}

	if (ntohs(src->sin6_port) == HIP_AGENT_PORT) {
		return hip_recv_agent(msg);
	}

	/* This prints numerical addresses until we have separate
	   print function for icomm.h and protodefs.h -miika */
	HIP_DEBUG("HIP user message type is: %d\n", msg_type);
		  //hip_message_type_name(msg_type));

	switch(msg_type)
	{
	case SO_HIP_NULL_OP:
		HIP_DEBUG("Null op\n");
		break;
	case SO_HIP_PING:
		break;
	case SO_HIP_ADD_LOCAL_HI:
		err = hip_handle_add_local_hi(msg);
		break;
	case SO_HIP_DEL_LOCAL_HI:
		err = hip_handle_del_local_hi(msg);
		break;
	case SO_HIP_ADD_PEER_MAP_HIT_IP:
		HIP_DEBUG("Handling SO_HIP_ADD_PEER_MAP_HIT_IP.\n");
		err = hip_add_peer_map(msg);
		if(err)
		{
			HIP_ERROR("add peer mapping failed.\n");
			goto out_err;
		}
		break;
	case SO_HIP_RST:
		//send_response = 0;
	  err = hip_send_close(msg, 1);
		break;
	case SO_HIP_BOS:
		err = hip_send_bos(msg);
		break;
	case SO_HIP_SET_NAT_ICE_UDP:
		HIP_DEBUG("Setting LOCATOR ON, when ice is on\n");
		hip_locator_status = SO_HIP_SET_LOCATOR_ON;
		HIP_DEBUG("hip_locator status =  %d (should be %d)\n",
			  hip_locator_status, SO_HIP_SET_LOCATOR_ON);
		/* no break statement here intentionally */
	case SO_HIP_SET_NAT_NONE:
	case SO_HIP_SET_NAT_PLAIN_UDP:
		HIP_IFEL(hip_user_nat_mode(msg_type), -1, "Error when setting daemon NAT status to \"on\"\n");
		hip_agent_update_status(msg_type, NULL, 0);

		HIP_DEBUG("Recreate all R1s\n");
		hip_recreate_all_precreated_r1_packets();
		break;
	case SO_HIP_STUN:
	{
		void *stun_param = hip_get_param(msg, HIP_PARAM_STUN);
		struct in6_addr *peer_addr = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR_PEER);
		in_port_t *peer_port = hip_get_param_contents(msg, HIP_PARAM_PEER_NAT_PORT);

		HIP_DEBUG("Received STUN message\n");

		if (stun_param && peer_addr && peer_port) {
			*peer_port = (ntohs(*peer_port));
			err = hip_external_ice_receive_pkt_all(hip_get_param_contents_direct(stun_param),
							       hip_get_param_contents_len(stun_param),
							       peer_addr, *peer_port);
			if (err) {
				HIP_ERROR("Error in handling STUN message\n");
			} else {
				HIP_DEBUG("STUN message handled ok\n");
			}
		} else {
			err = -1;
			HIP_ERROR("Missing STUN params\n");
		}
		break;
	}
        case SO_HIP_LOCATOR_GET:
		HIP_DEBUG("Got a request for locators\n");
		hip_msg_init(msg);
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_LOCATOR_GET, 0), -1,
			 "Failed to build user message header.: %s\n",
			 strerror(err));
		if ((err = hip_build_locators(msg, 0, hip_get_nat_mode(NULL))) < 0)
			HIP_DEBUG("LOCATOR parameter building failed\n");
		break;
        case SO_HIP_SET_LOCATOR_ON:
                HIP_DEBUG("Setting LOCATOR ON\n");
                hip_locator_status = SO_HIP_SET_LOCATOR_ON;
                HIP_DEBUG("hip_locator status =  %d (should be %d)\n",
                          hip_locator_status, SO_HIP_SET_LOCATOR_ON);
                HIP_DEBUG("Recreate all R1s\n");
                hip_recreate_all_precreated_r1_packets();
                break;
        case SO_HIP_SET_LOCATOR_OFF:
                HIP_DEBUG("Setting LOCATOR OFF\n");
                hip_locator_status = SO_HIP_SET_LOCATOR_OFF;
                HIP_DEBUG("hip_locator status =  %d (should be %d)\n",
                          hip_locator_status, SO_HIP_SET_LOCATOR_OFF);
                hip_recreate_all_precreated_r1_packets();
                break;
        case SO_HIP_HEARTBEAT:
		heartbeat = hip_get_param(msg, HIP_PARAM_HEARTBEAT);
		hip_icmp_interval = heartbeat->heartbeat;
		heartbeat_counter = hip_icmp_interval;
		HIP_DEBUG("Received heartbeat interval (%d seconds)\n",hip_icmp_interval);
		break;
	case SO_HIP_SET_DEBUG_ALL:
		/* Displays all debugging messages. */
		_HIP_DEBUG("Handling DEBUG ALL user message.\n");
		HIP_IFEL(hip_set_logdebug(LOGDEBUG_ALL), -1,
			 "Error when setting daemon DEBUG status to ALL\n");
		break;
	case SO_HIP_SET_DEBUG_MEDIUM:
		/* Removes debugging messages. */
		HIP_DEBUG("Handling DEBUG MEDIUM user message.\n");
		HIP_IFEL(hip_set_logdebug(LOGDEBUG_MEDIUM), -1,
			 "Error when setting daemon DEBUG status to MEDIUM\n");
		break;
	case SO_HIP_SET_DEBUG_NONE:
		/* Removes debugging messages. */
		HIP_DEBUG("Handling DEBUG NONE user message.\n");
		HIP_IFEL(hip_set_logdebug(LOGDEBUG_NONE), -1,
			 "Error when setting daemon DEBUG status to NONE\n");
		break;
	case SO_HIP_CONF_PUZZLE_NEW:
		err = hip_recreate_all_precreated_r1_packets();
		break;
	case SO_HIP_CONF_PUZZLE_GET:
		err = hip_get_puzzle_difficulty_msg(msg);
		break;
	case SO_HIP_CONF_PUZZLE_SET:
		err = hip_set_puzzle_difficulty_msg(msg);
		break;
	case SO_HIP_CONF_PUZZLE_INC:
		dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
		hip_inc_cookie_difficulty(dst_hit);
		break;
	case SO_HIP_CONF_PUZZLE_DEC:
		dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
		hip_dec_cookie_difficulty(dst_hit);
		break;
#ifdef CONFIG_HIP_I3
	case SO_HIP_SET_HI3_ON:
		err = hip_set_hi3_status(msg);
	break;
	case SO_HIP_SET_HI3_OFF:
		err = hip_set_hi3_status(msg);
	break;
#endif
#ifdef CONFIG_HIP_OPPORTUNISTIC
	case SO_HIP_SET_OPPORTUNISTIC_MODE:
	  	err = hip_set_opportunistic_mode(msg);
		break;
	case SO_HIP_GET_PEER_HIT:
		err = hip_opp_get_peer_hit(msg, src);
		if (err){
			_HIP_ERROR("get pseudo hit failed.\n");
			//send_response = 1;
			if (err == -11) /* immediate fallback, do not pass */
			 	err = 0;
			goto out_err;
		} else {
			//send_response = 0;
                }
		/* skip sending of return message; will be sent later in R1 */
		goto out_err;
		break;
	case SO_HIP_QUERY_IP_HIT_MAPPING:
	{
	    	err = hip_query_ip_hit_mapping(msg);
		if(err){
			HIP_ERROR("query ip hit mapping failed.\n");
			goto out_err;
		}
	}
	break;
	case SO_HIP_QUERY_OPPORTUNISTIC_MODE:
	{
	    	err = hip_query_opportunistic_mode(msg);
		if(err){
			HIP_ERROR("query opportunistic mode failed.\n");
			goto out_err;
		}

		HIP_DEBUG("opportunistic mode value is sent\n");
	}
	break;
#endif
#ifdef CONFIG_HIP_BLIND
	case SO_HIP_SET_BLIND_ON:
		HIP_DEBUG("Blind on!!\n");
		hip_encrypt_i2_hi = 1;
		HIP_IFEL(hip_set_blind_on(), -1, "hip_set_blind_on failed\n");
		break;
	case SO_HIP_SET_BLIND_OFF:
		hip_encrypt_i2_hi = 0;
		HIP_DEBUG("Blind off!!\n");
		HIP_IFEL(hip_set_blind_off(), -1, "hip_set_blind_off failed\n");
		break;
#endif
       case SO_HIP_SET_TCPTIMEOUT_ON:
               HIP_DEBUG("Setting TCP TIMEOUT ON\n");
               hip_tcptimeout_status = SO_HIP_SET_TCPTIMEOUT_ON;
               HIP_DEBUG("hip tcp timeout status =  %d (should be %d)\n",
                      hip_tcptimeout_status, SO_HIP_SET_TCPTIMEOUT_ON);

               /* paramters setting to do here */
               HIP_IFEL(set_new_tcptimeout_parameters_value(), -1,
                         "set new tcptimeout parameters error\n");
               break;

        case SO_HIP_SET_TCPTIMEOUT_OFF:
                HIP_DEBUG("Setting TCP TIMEOUT OFF\n");
                hip_tcptimeout_status = SO_HIP_SET_TCPTIMEOUT_OFF;
                HIP_DEBUG("hip tcp timeout status =  %d (should be %d)\n",
                        hip_tcptimeout_status, SO_HIP_SET_TCPTIMEOUT_OFF);

                /* paramters resetting */
                HIP_IFEL(reset_default_tcptimeout_parameters_value(), -1,
                         "reset tcptimeout parameters to be default error\n");

                break;

#ifdef CONFIG_HIP_OPENDHT
        case SO_HIP_DHT_GW:
	{
		char tmp_ip_str[20], tmp_ip_str6[39], tmp_host_name[256];
		int tmp_ttl, tmp_port, is_hostname = 0, is_ipv4 = 0, is_ipv6 = 0;
		const char *pret;
		int ret;
		struct in_addr tmp_v4;
		struct hip_opendht_gw_info *gw_info;

		HIP_IFEL(!(gw_info = hip_get_param(msg, HIP_PARAM_OPENDHT_GW_INFO)),
				-1, "No gw struct found\n");
		memset(&tmp_ip_str, '\0', 20);
		tmp_ttl = gw_info->ttl;
		tmp_port = htons(gw_info->port);
		memcpy(tmp_host_name, gw_info->host_name, strlen(gw_info->host_name));

		//hostname
		if (strlen(tmp_host_name) > 0) {
		    is_hostname = 1;
		}//ipv4 address
		else if (IN6_IS_ADDR_V4MAPPED(&gw_info->addr)) {
		    is_ipv4 = 1;
		}//ipv6 address
		else {
		    is_ipv6 = 1;
		}

		if (is_hostname) {
		    ret = resolve_dht_gateway_info(tmp_host_name,
					&opendht_serving_gateway,
					tmp_port, AF_INET);
		} else if (is_ipv4) {
		    IPV6_TO_IPV4_MAP(&gw_info->addr, &tmp_v4);
		    pret = inet_ntop(AF_INET, &tmp_v4, tmp_ip_str, 20);
		    HIP_DEBUG("Got address %s, port %d, TTL %d from hipconf\n",
					  tmp_ip_str, htons(gw_info->port), gw_info->ttl);
		    ret = resolve_dht_gateway_info(tmp_ip_str,
						   &opendht_serving_gateway,
						   tmp_port, AF_INET);
		} else if (is_ipv6) {
		    pret = inet_ntop(AF_INET6, &gw_info->addr, tmp_ip_str6, 39);
		    HIP_DEBUG("Got address %s, port %d, TTL %d from hipconf\n",
					  tmp_ip_str6, htons(gw_info->port), gw_info->ttl);
		    ret = resolve_dht_gateway_info(tmp_ip_str6,
						   &opendht_serving_gateway,
						   tmp_port, AF_INET6);
		}


		if (ret == 0) {
		    HIP_DEBUG("Serving gateway changed\n");
		    opendht_serving_gateway_ttl = tmp_ttl;
		    opendht_serving_gateway_port = tmp_port;
		    if (strlen(tmp_host_name) > 0) {
				memset(opendht_host_name, '\0', sizeof(opendht_host_name));
				memcpy(opendht_host_name, tmp_host_name, strlen(tmp_host_name));
		    }
		    hip_opendht_error_count = 0;
		    if (hip_opendht_sock_fqdn > 0) {
			close(hip_opendht_sock_fqdn);
			hip_opendht_sock_fqdn = init_dht_gateway_socket_gw(hip_opendht_sock_fqdn, opendht_serving_gateway);
				hip_opendht_fqdn_sent = STATE_OPENDHT_IDLE;
		    }
		    if (hip_opendht_sock_hit > 0) {
			close(hip_opendht_sock_hit);
			hip_opendht_sock_hit = init_dht_gateway_socket_gw(hip_opendht_sock_hit, opendht_serving_gateway);
			hip_opendht_hit_sent = STATE_OPENDHT_IDLE;
		    }
		    init_dht_sockets(&hip_opendht_sock_fqdn, &hip_opendht_fqdn_sent);
		    init_dht_sockets(&hip_opendht_sock_hit, &hip_opendht_hit_sent);
		}
		else{
		    HIP_DEBUG("Error in changing the serving gateway!");
		}
	}
	break;
        case SO_HIP_DHT_SERVING_GW:
        {
		int err_value = 0;
		if(hip_opendht_inuse != SO_HIP_DHT_ON){
			err_value = 5;
			hip_build_param_contents(msg, &err_value,
					 HIP_PARAM_INT, sizeof(int));
		}else if((opendht_serving_gateway == NULL) ||
			 (opendht_serving_gateway->ai_addr == NULL)){
			err_value = 4;
			hip_build_param_contents(msg, &err_value,
					 HIP_PARAM_INT, sizeof(int));
		}else{
			err = hip_get_dht_mapping_for_HIT_msg(msg);
		}
	}
        break;
        case SO_HIP_DHT_SET:
	{
                extern char opendht_name_mapping;
                err = 0;
                struct hip_opendht_set *name_info;
                HIP_IFEL(!(name_info = hip_get_param(msg, HIP_PARAM_OPENDHT_SET)), -1,
                         "no name struct found\n");
                _HIP_DEBUG("Name in name_info %s\n" , name_info->name);
                memcpy(&opendht_name_mapping, &name_info->name, HIP_HOST_ID_HOSTNAME_LEN_MAX);
                HIP_DEBUG("Name received from hipconf %s\n", &opendht_name_mapping);
	}
	break;
#endif	/* CONFIG_HIP_OPENDHT */
        case SO_HIP_CERT_SPKI_VERIFY:
                {
                        HIP_DEBUG("Got an request to verify SPKI cert\n");
                        reti = hip_cert_spki_verify(msg);
                        HIP_IFEL(reti, -1, "Verifying SPKI cert returned an error\n");
                        HIP_DEBUG("SPKI cert verified sending it back to requester\n");
                }
                break;
        case SO_HIP_CERT_SPKI_SIGN:
                {
                        HIP_DEBUG("Got an request to sign SPKI cert sequence\n");
                        reti = hip_cert_spki_sign(msg, hip_local_hostid_db);
                        HIP_IFEL(reti, -1, "Signing SPKI cert returned an error\n");
                        HIP_DEBUG("SPKI cert signed sending it back to requester\n");
                }
                break;
        case SO_HIP_CERT_X509V3_SIGN:
                {
                        HIP_DEBUG("Got an request to sign X509v3 cert\n");
                        reti = hip_cert_x509v3_handle_request_to_sign(msg,
                                                                      hip_local_hostid_db);
                        HIP_IFEL(reti, -1, "Signing of x509v3 cert returned an error\n");
                        HIP_DEBUG("X509v3 cert signed sending it back to requester\n");
                }
                break;
        case SO_HIP_CERT_X509V3_VERIFY:
                {
                        HIP_DEBUG("Got an request to verify X509v3 cert\n");
                        reti = hip_cert_x509v3_handle_request_to_verify(msg);
                        HIP_IFEL(reti, -1, "Verification of x509v3 cert "
                                 "returned an error\n");
                        HIP_DEBUG("X509v3 verification ended "
                                  "sending it back to requester\n");
                }
                break;
        case SO_HIP_TRANSFORM_ORDER:
	{
                extern int hip_transform_order;
                err = 0;
                struct hip_transformation_order *transorder;
                HIP_IFEL(!(transorder = hip_get_param(msg, HIP_PARAM_TRANSFORM_ORDER)), -1,
                         "no transform order struct found (should contain transform order)\n");
                HIP_DEBUG("Transform order received from hipconf: %d\n" ,transorder->transorder);
                hip_transform_order = transorder->transorder;
                hip_recreate_all_precreated_r1_packets();
	}
	break;
#ifdef CONFIG_HIP_OPENDHT
        case SO_HIP_DHT_ON:
        	{
                HIP_DEBUG("Setting DHT ON\n");
                hip_opendht_inuse = SO_HIP_DHT_ON;
                HIP_DEBUG("hip_opendht_inuse =  %d (should be %d)\n",
                          hip_opendht_inuse, SO_HIP_DHT_ON);
        	}

                dhterr = 0;
                dhterr = hip_init_dht();
                if (dhterr < 0) HIP_DEBUG("Initializing DHT returned error\n");

            break;
        case SO_HIP_DHT_OFF:
        	{
                HIP_DEBUG("Setting DHT OFF\n");
                hip_opendht_inuse = SO_HIP_DHT_OFF;
                HIP_DEBUG("hip_opendht_inuse =  %d (should be %d)\n",
                          hip_opendht_inuse, SO_HIP_DHT_OFF);
        	}
            break;
#endif	/* CONFIG_HIP_OPENDHT */

        case SO_HIP_SET_HIPPROXY_ON:
        	{
        		int n, err;
			//send_response = 0;

        		//firewall socket address
        		struct sockaddr_in6 sock_addr;
        		bzero(&sock_addr, sizeof(sock_addr));
        		sock_addr.sin6_family = AF_INET6;
        		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
        		sock_addr.sin6_addr = in6addr_loopback;

        		HIP_DEBUG("Setting HIP PROXY ON\n");
        		hip_set_hip_proxy_on();
      			hip_build_user_hdr(msg, SO_HIP_SET_HIPPROXY_ON, 0);
        	}
        	break;

        case SO_HIP_SET_HIPPROXY_OFF:
        	{
        		int n, err;
			//send_response = 0;

        		//firewall socket address
        		struct sockaddr_in6 sock_addr;
        		bzero(&sock_addr, sizeof(sock_addr));
        		sock_addr.sin6_family = AF_INET6;
        		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
        		sock_addr.sin6_addr = in6addr_loopback;

        		HIP_DEBUG("Setting HIP PROXY OFF\n");
        		hip_set_hip_proxy_off();
      			hip_build_user_hdr(msg, SO_HIP_SET_HIPPROXY_OFF, 0);

        	}
        	break;

        case SO_HIP_HIPPROXY_STATUS_REQUEST:
        	{
        		int n, err;

        		//firewall socket address
        		struct sockaddr_in6 sock_addr;
        		bzero(&sock_addr, sizeof(sock_addr));
        		sock_addr.sin6_family = AF_INET6;
        		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
        		sock_addr.sin6_addr = in6addr_loopback;

        		HIP_DEBUG("Received HIPPROXY Status Request from firewall\n");

        		memset(msg, 0, sizeof(struct hip_common));

        		if(hip_get_hip_proxy_status() == 0)
        			hip_build_user_hdr(msg, SO_HIP_SET_HIPPROXY_OFF, 0);

        		if(hip_get_hip_proxy_status() == 1)
        			hip_build_user_hdr(msg, SO_HIP_SET_HIPPROXY_ON, 0);

        	}
        	break;
	case SO_HIP_SAVAH_CLIENT_STATUS_REQUEST:
	        {
        		int n, err;

        		//firewall socket address
        		struct sockaddr_in6 sock_addr;
        		bzero(&sock_addr, sizeof(sock_addr));
        		sock_addr.sin6_family = AF_INET6;
        		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
        		sock_addr.sin6_addr = in6addr_loopback;

        		HIP_DEBUG("Received HIPPROXY Status Request from firewall\n");

        		memset(msg, 0, sizeof(struct hip_common));

        		if(hip_get_sava_client_status() == 0)
        			hip_build_user_hdr(msg, SO_HIP_SET_SAVAH_CLIENT_OFF, 0);

        		if(hip_get_sava_client_status() == 1)
 			        hip_build_user_hdr(msg, SO_HIP_SET_SAVAH_CLIENT_ON, 0);

        	}
 	        break;
        case SO_HIP_SAVAH_SERVER_STATUS_REQUEST:
	        {
        		int n, err;
        		struct sockaddr_in6 sock_addr;
        		bzero(&sock_addr, sizeof(sock_addr));
        		sock_addr.sin6_family = AF_INET6;
        		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
        		sock_addr.sin6_addr = in6addr_loopback;

        		HIP_DEBUG("Received SAVAH SERVER Status Request from firewall\n");

        		memset(msg, 0, sizeof(struct hip_common));

        		if(hip_get_sava_server_status() == 0)
        			hip_build_user_hdr(msg, SO_HIP_SET_SAVAH_SERVER_OFF, 0);

        		if(hip_get_sava_server_status() == 1)
 			        hip_build_user_hdr(msg, SO_HIP_SET_SAVAH_SERVER_ON, 0);

        	}
	        break;
#ifdef CONFIG_HIP_ESCROW
	case SO_HIP_OFFER_ESCROW:
		HIP_DEBUG("Handling add escrow service -user message.\n");

		HIP_IFEL(hip_services_add(HIP_SERVICE_ESCROW), -1,
			 "Error while adding service\n");

		hip_set_srv_status(HIP_SERVICE_ESCROW, HIP_SERVICE_ON);

		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1,
			 "Failed to recreate R1-packets\n");

		if (hip_firewall_is_alive()) {
			HIP_IFEL(hip_firewall_set_escrow_active(1), -1,
				 "Failed to deliver activation message to "\
				 "firewall\n");
		}

		break;

	case SO_HIP_CANCEL_ESCROW:
		HIP_DEBUG("Handling del escrow service -user message.\n");
		if (hip_firewall_is_alive()) {
			HIP_IFEL(hip_firewall_set_escrow_active(0), -1,
				 "Failed to deliver cancellation message to "\
				 "firewall\n");
		}

		hip_set_srv_status(HIP_SERVICE_ESCROW, HIP_SERVICE_OFF);

		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1,
			 "Failed to recreate R1-packets\n");

		break;
#endif /* CONFIG_HIP_ESCROW */
#if 0
	case SO_HIP_REGISTER_SAVAHR:
	  {
	  dst_hit = hip_get_param_contents(msg,HIP_PARAM_HIT);
	  dst_ip  = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
	  HIP_DEBUG("WE HAVE GOT SAVAH REGISTER MESSAGE \n");
	  if (dst_hit == NULL && dst_ip == NULL) { //HIT and IP are missing worst case opportunistic mode to register with the SAVAH router

	  } else if (dst_hit == NULL && dst_ip != NULL) { //we have at least SAVAH router IP

	  } else { // Both HIT and IP are present that is the simplest case we can register with the router directly
	    /* Add HIT to IP address mapping of the server to haDB. */
	    HIP_IFEL(hip_add_peer_map(msg), -1, "Error on registering sava router " \
		     "HIT to IP address mapping to the haDB.\n");
	    		/* Fetch the haDB entry just created. */
	    entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);

	    if(entry == NULL) {
	      HIP_ERROR("Error on fetching routers HIT to IP address "	\
			"mapping from the haDB.\n");
	      err = -1;
	      goto out_err;
	    }

	    if (!sava_serving_gateway) {
	      sava_serving_gateway =
		(struct in6_addr *)malloc(sizeof(struct in6_addr));
	      memset(sava_serving_gateway, 0, sizeof(struct in6_addr));
	    }

	    memcpy(sava_serving_gateway, dst_hit, sizeof(struct in6_addr));

	    HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry), -1,
		   "Error on sending I1 packet to the server.\n");
	    }
	  }
#endif
	  break;
	case SO_HIP_GET_SAVAHR_IN_KEYS:
	  {
	    dst_hit = hip_get_param_contents(msg,HIP_PARAM_HIT);
	    HIP_DEBUG("WE HAVE GOT SAVAH KEYS REQUEST MESSAGE \n");
	    entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);

	    if (entry == NULL) {

	    } else {
	      	HIP_DEBUG_HIT("Destination HIT: ", dst_hit);
		HIP_IFEL(hip_build_param_contents(msg, (void *)dst_hit, HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
					  "build param contents failed\n");
		HIP_HEXDUMP("crypto key :", &entry->auth_in, sizeof(struct hip_crypto_key));
		HIP_IFEL(hip_build_param_contents(msg,
						  (struct hip_crypto_key *) &entry->auth_in, //HMAC key for incomming direction
						  HIP_PARAM_KEYS,
						  sizeof(struct hip_crypto_key)), -1,
			 "build param contents failed\n");
		HIP_DEBUG("ealg value is %d \n", entry->esp_transform);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->esp_transform, HIP_PARAM_INT,
						  sizeof(int)), -1,
			 "build param contents failed\n");

	    }
	  }
	  break;
	 case SO_HIP_GET_SAVAHR_OUT_KEYS:
	  {
	    dst_hit = hip_get_param_contents(msg,HIP_PARAM_HIT);
	    HIP_DEBUG("WE HAVE GOT SAVAH KEYS REQUEST MESSAGE \n");
	    entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);

	    if (entry == NULL) {

	    } else {
	      	HIP_DEBUG_HIT("Destination HIT: ", dst_hit);
		HIP_IFEL(hip_build_param_contents(msg, (void *)dst_hit, HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
					  "build param contents failed\n");
		HIP_HEXDUMP("crypto key :", &entry->auth_out, sizeof(struct hip_crypto_key));
		HIP_IFEL(hip_build_param_contents(msg,
						  (struct hip_crypto_key *) &entry->auth_out, //HMAC key for incomming direction
						  HIP_PARAM_KEYS,
						  sizeof(struct hip_crypto_key)), -1,
			 "build param contents failed\n");
		HIP_DEBUG("ealg value is %d \n", entry->esp_transform);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->esp_transform, HIP_PARAM_INT,
						  sizeof(int)), -1,
			 "build param contents failed\n");

	    }
	  }
	  break;
	case SO_HIP_GET_SAVAHR_HIT:
	  {
	    HIP_DEBUG("WE HAVE GOT SAVAH HIT REQUEST MESSAGE \n");
	    //entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);
	    if (sava_serving_gateway) {
	      HIP_DEBUG_HIT("SAVAH HIT: ", sava_serving_gateway);
	      HIP_IFEL(hip_build_param_contents(msg, (void *)sava_serving_gateway,
						HIP_PARAM_HIT,
						sizeof(struct in6_addr)), -1,
						"build param contents failed\n");
	    }
	  }
	  break;
#ifdef CONFIG_HIP_RVS
	case SO_HIP_ADD_DEL_SERVER:
	{
		/* RFC 5203 service registration. The requester, i.e. the client
		   of the server handles this message. Message indicates that
		   the hip daemon wants either to register to a server for
		   additional services or it wants to cancel a registration.
		   Cancellation is identified with a zero lifetime. */
		struct hip_reg_request *reg_req = NULL;
		hip_pending_request_t *pending_req = NULL;
		struct in6_addr * hit_local;
		uint8_t *reg_types = NULL;
		int i = 0, type_count = 0;
		int opp_mode = 0;
		int add_to_global = 0;
		struct sockaddr_in6 sock_addr6;
		struct sockaddr_in sock_addr;
		struct in6_addr server_addr, hitr;

		_HIP_DEBUG("Handling ADD DEL SERVER user message.\n");

		/* Get RVS IP address, HIT and requested lifetime given as
		   commandline parameters to hipconf. */

		dst_hit = hip_get_param_contents(msg,HIP_PARAM_HIT);
		dst_ip  = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
		reg_req = hip_get_param(msg, HIP_PARAM_REG_REQUEST);

		/* Register to an LSI, no IP address */
		if (dst_ip && !dst_hit && !ipv6_addr_is_hit(dst_ip)) {
			struct in_addr lsi;

			IPV6_TO_IPV4_MAP(dst_ip, &lsi);
			memset(&hitr, 0, sizeof(hitr));
			memset(&server_addr, 0, sizeof(server_addr));

			if (IS_LSI32(lsi.s_addr) &&
			    !hip_map_id_to_addr(&hitr, &lsi, &server_addr)) {
				dst_ip = &server_addr;
				/* Note: next map_id below fills the HIT */
			}
		}

		/* Register to a HIT without IP address */
		if (dst_ip && !dst_hit && ipv6_addr_is_hit(dst_ip)) {
			struct in_addr bcast = { INADDR_BROADCAST };
			if (hip_map_id_to_addr(dst_ip, NULL,
					       &server_addr))
				IPV4_TO_IPV6_MAP(&bcast, &server_addr);
			dst_hit = dst_ip;
			dst_ip = &server_addr;
		}

		if(dst_hit == NULL) {
#if 0
			HIP_ERROR("No HIT parameter found from the user "\
				  "message.\n");
			err = -1;
			goto out_err;
#endif
			HIP_DEBUG("No HIT parameter found from the user " \
				  "message. Trying opportunistic mode \n");
			opp_mode = 1;
		}else if(dst_ip == NULL) {
			HIP_ERROR("No IPV6 parameter found from the user "\
				  "message.\n");
			err = -1;
			goto out_err;
		}else if(reg_req == NULL) {
			HIP_ERROR("No REG_REQUEST parameter found from the "\
				  "user message.\n");
			err = -1;
			goto out_err;
		}

		if (!opp_mode) {
			HIP_IFEL(hip_hadb_add_peer_info(dst_hit, dst_ip,
							NULL, NULL),
				 -1, "Error on adding server "	\
				 "HIT to IP address mapping to the hadb.\n");

		  /* Fetch the hadb entry just created. */
		  entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);

		  if(entry == NULL) {
		    HIP_ERROR("Error on fetching server HIT to IP address " \
			      "mapping from the haDB.\n");
		    err = -1;
		    goto out_err;
		  }
		} else {
		  hit_local = (struct in6_addr *)malloc(sizeof(struct in6_addr));
		  HIP_IFEL(hip_get_default_hit(hit_local), -1,
			   "Error retrieving default HIT \n");
		  entry = hip_opp_add_map(dst_ip, hit_local);
		}

		reg_types  = reg_req->reg_type;
		type_count = hip_get_param_contents_len(reg_req) -
			sizeof(reg_req->lifetime);

		for(;i < type_count; i++) {
			pending_req = (hip_pending_request_t *)
				malloc(sizeof(hip_pending_request_t));
			if(pending_req == NULL) {
				HIP_ERROR("Error on allocating memory for a "\
					  "pending registration request.\n");
				err = -1;
				goto out_err;
			}

			pending_req->entry    = entry;
			pending_req->reg_type = reg_types[i];
			pending_req->lifetime = reg_req->lifetime;
			pending_req->created  = time(NULL);

			HIP_DEBUG("Adding pending service request for service %u.\n",
				  reg_types[i]);
			hip_add_pending_request(pending_req);

			/* Set the request flag. */
			switch(reg_types[i]){
			case HIP_SERVICE_RENDEZVOUS:
				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_RVS);
				add_to_global = 1;
				break;
			case HIP_SERVICE_RELAY:
				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_RELAY);
				/* Don't ask for ICE from relay */
				entry->nat_mode = 1;
				add_to_global = 1;
				break;
			case HIP_SERVICE_SAVAH:
			        HIP_DEBUG("HIP_SERVICE_SAVAH \n");
			        if (!sava_serving_gateway) {
				  sava_serving_gateway =
				    (struct in6_addr *)malloc(sizeof(struct in6_addr));
				  memset(sava_serving_gateway, 0, sizeof(struct in6_addr));
				}
				if (!opp_mode)
				  memcpy(sava_serving_gateway, dst_hit, sizeof(struct in6_addr));

				hip_set_sava_client_off();

				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_SAVAH);
			        break;
#ifdef CONFIG_HIP_ESCROW
			case HIP_SERVICE_ESCROW:
				HIP_KEA * kea = NULL;

				/* Set a escrow request flag. Should this be
				   done for every entry? */
				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_ESCROW);
				/* Cancel registration to the escrow service. */
				if(reg_req->lifetime == 0) {
					HIP_IFEL((kea =
						  hip_kea_find(&entry->hit_our))
						 == NULL, -1,
						 "Could not find kea base entry.\n");

					if (ipv6_addr_cmp(dst_hit, &kea->server_hit) == 0) {
						HIP_IFEL(hip_for_each_hi(
								 hip_launch_cancel_escrow_registration,
								 dst_hit), 0,
							 "Error when doing "\
							 "hip_launch_cancel_escrow_registration() "\
							 "for each HI.\n");
						HIP_IFEL(hip_for_each_ha(
								 hip_remove_escrow_data,
								 dst_hit), 0,
							 "Error when doing "\
							 "hip_remove_escrow_data() "\
							 "for each HI.\n");
						HIP_IFEL(hip_kea_remove_base_entries(),
							 0, "Could not remove "\
							 "KEA base entries.\n");
					}
				}
				/* Register to the escrow service. */
				else {
					/* Create a KEA base entry. */
					HIP_IFEL(hip_for_each_hi(
							 hip_kea_create_base_entry,
							 dst_hit), 0,
						 "Error when doing "\
						 "hip_kea_create_base_entry() "\
						 "for each HI.\n");

					HIP_IFEL(hip_for_each_hi(
							 hip_launch_escrow_registration,
							 dst_hit), 0,
						 "Error when doing "\
						 "hip_launch_escrow_registration() "\
						 "for each HI.\n");
				}

				break;
#endif /* CONFIG_HIP_ESCROW */
			default:
				HIP_INFO("Undefined service type (%u) "\
					 "requested in the service "\
					 "request.\n", reg_types[i]);
				/* For testing purposes we allow the user to
				   request services that HIPL does not support.
				*/
				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_UNSUP);
				/*
				  HIP_DEBUG("Deleting pending service request "\
				  "for service %u.\n", reg_types[i]);
				  hip_del_pending_request_by_type(entry,
				  reg_types[i]);
				*/
				break;
			}
		}

		if (add_to_global)  
		{
			if (IN6_IS_ADDR_V4MAPPED(dst_ip))
			{
				memset(&sock_addr, 0, sizeof(sock_addr));
				IPV6_TO_IPV4_MAP(dst_ip, &sock_addr.sin_addr);
				sock_addr.sin_family = AF_INET;
				add_address_to_list(&sock_addr, 0, HIP_FLAG_CONTROL_TRAFFIC_ONLY); //< The server address is added with 0 interface index			
			}
			else
			{
				memset(&sock_addr6, 0, sizeof(sock_addr6));
				sock_addr6.sin6_family = AF_INET6;
				sock_addr6.sin6_addr = *dst_ip;
				add_address_to_list(&sock_addr6, 0, HIP_FLAG_CONTROL_TRAFFIC_ONLY); //< The server address is added with 0 interface index
			}
			
			// Refresh locators stored in DHT 
			if (hip_opendht_inuse == SO_HIP_DHT_ON) {
				/* First remove the old one -samu */				
				opendht_remove_current_hdrr();
				register_to_dht();
			}
		}
		
		/* Send a I1 packet to the server (registrar). */
		/** @todo When registering to a service or cancelling a service,
		    we should first check the state of the host association that
		    is registering. When it is ESTABLISHED or R2-SENT, we have
		    already successfully carried out a base exchange and we
		    must use an UPDATE packet to carry a REG_REQUEST parameter.
		    When the state is not ESTABLISHED or R2-SENT, we launch a
		    base exchange using an I1 packet. */
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry), -1,
			 "Error on sending I1 packet to the server.\n");
		break;
	}
	case SO_HIP_OFFER_RVS:
		/* draft-ietf-hip-registration-02 RVS registration. Rendezvous
		   server handles this message. Message indicates that the
		   current machine is willing to offer rendezvous service. This
		   message is received from hipconf. */
		HIP_DEBUG("Handling OFFER RENDEZVOUS user message.\n");

		hip_set_srv_status(HIP_SERVICE_RENDEZVOUS, HIP_SERVICE_ON);
		hip_relay_set_status(HIP_RELAY_ON);

		err = hip_recreate_all_precreated_r1_packets();
		break;
	case SO_HIP_OFFER_SAVAH:
	        hip_set_srv_status(HIP_SERVICE_SAVAH, HIP_SERVICE_ON);
	        hip_set_sava_server_on();
		//we need to add new REG_INFO parameters
		err = hip_recreate_all_precreated_r1_packets();
	        HIP_DEBUG("Handling SO_HIP_OFFER_SAVAH: STATUS ON\n");
	        break;
	case SO_HIP_OFFER_HIPRELAY:
		/* draft-ietf-hip-registration-02 HIPRELAY registration. Relay
		   server handles this message. Message indicates that the
		   current machine is willing to offer relay service. This
		   message is received from hipconf. */
		HIP_DEBUG("Handling OFFER HIPRELAY user message.\n");

		hip_set_srv_status(HIP_SERVICE_RELAY, HIP_SERVICE_ON);
		hip_relay_set_status(HIP_RELAY_ON);

		err = hip_recreate_all_precreated_r1_packets();
		break;

	case SO_HIP_REINIT_RVS:
	case SO_HIP_REINIT_RELAY:
		HIP_DEBUG("Handling REINIT RELAY or REINIT RVS user message.\n");
		HIP_IFEL(hip_relay_reinit(), -1, "Unable to reinitialize "\
			 "the HIP relay / RVS service.\n");

		break;

	case SO_HIP_CANCEL_SAVAH:
	        hip_set_srv_status(HIP_SERVICE_SAVAH, HIP_SERVICE_OFF);
 	        hip_set_sava_server_off();
		HIP_DEBUG("Handling CANCEL SAVAH user message.\n");
		break;
	case SO_HIP_CANCEL_RVS:
		HIP_DEBUG("Handling CANCEL RVS user message.\n");

		hip_set_srv_status(HIP_SERVICE_RENDEZVOUS, HIP_SERVICE_OFF);

		hip_relht_free_all_of_type(HIP_RVSRELAY);
		/* If all off the relay records were freed we can set the relay
		   status "off". */
		if(hip_relht_size() == 0) {
			hip_relay_set_status(HIP_RELAY_OFF);
		}

		/* We have to recreate the R1 packets so that they do not
		   advertise the RVS service anymore. I.e. we're removing
		   the REG_INFO parameters here. */
		err = hip_recreate_all_precreated_r1_packets();
		break;

	case SO_HIP_CANCEL_HIPRELAY:
		HIP_DEBUG("Handling CANCEL RELAY user message.\n");

		hip_set_srv_status(HIP_SERVICE_RELAY, HIP_SERVICE_OFF);

		hip_relht_free_all_of_type(HIP_FULLRELAY);
		/* If all off the relay records were freed we can set the relay
		   status "off". */
		if(hip_relht_size() == 0) {
			hip_relay_set_status(HIP_RELAY_OFF);
		}

		/* We have to recreate the R1 packets so that they do not
		   advertise the RVS service anymore. I.e. we're removing
		   the REG_INFO parameters here. */
		err = hip_recreate_all_precreated_r1_packets();
		break;
#endif /* CONFIG_HIP_RVS */
	case SO_HIP_GET_HITS:
		hip_msg_init(msg);
		hip_build_user_hdr(msg, SO_HIP_GET_HITS, 0);
		err = hip_for_each_hi(hip_host_id_entry_to_endpoint, msg);
		break;
	case SO_HIP_GET_HA_INFO:
		hip_msg_init(msg);
		hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0);
		err = hip_for_each_ha(hip_handle_get_ha_info, msg);
		break;
	case SO_HIP_DEFAULT_HIT:
		//hip_msg_init(msg);
		err =  hip_get_default_hit_msg(msg);
		break;
	case SO_HIP_HANDOFF_ACTIVE:
		//hip_msg_init(msg);
		is_active_handover=1;
		//hip_build_user_hdr(msg, SO_HIP_HANDOFF_ACTIVE, 0);
		break;

	case SO_HIP_HANDOFF_LAZY:
		//hip_msg_init(msg);
		is_active_handover=0;
		//hip_build_user_hdr(msg,SO_HIP_HANDOFF_LAZY, 0);
		break;

	case SO_HIP_RESTART:
		HIP_DEBUG("Restart message received, restarting HIP daemon now!!!\n");
		hipd_set_flag(HIPD_FLAG_RESTART);
		hip_close(SIGINT);
		break;
	case SO_HIP_OPPTCP_UNBLOCK_AND_BLACKLIST:
		hip_opptcp_unblock_and_blacklist(msg, src);
		break;
	case SO_HIP_OPPTCP_SEND_TCP_PACKET:
		hip_opptcp_send_tcp_packet(msg, src);

		break;
	case SO_HIP_GET_PROXY_LOCAL_ADDRESS:
	{
		//firewall socket address
		struct sockaddr_in6 sock_addr;
		bzero(&sock_addr, sizeof(sock_addr));
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
		sock_addr.sin6_addr = in6addr_loopback;
		HIP_DEBUG("GET HIP PROXY LOCAL ADDRESS\n");
		hip_get_local_addr(msg);
	}
	case SO_HIP_TRIGGER_BEX:
		HIP_DEBUG("SO_HIP_TRIGGER_BEX\n");
		hip_firewall_status = 1;
		err = hip_netdev_trigger_bex_msg(msg);
		goto out_err;
		break;
	case SO_HIP_VERIFY_DHT_HDRR_RESP: // Added by Pardeep to verify signature and host id
        	/* This case verifies host id in the value (HDRR) against HIT used as a key for DHT
	        * And it also verifies the signature in HDRR
        	* This works on the hip common message sent to the daemon
        	* */
       		verify_hdrr (msg,NULL);
        	break;
	case SO_HIP_USERSPACE_IPSEC:
		HIP_DUMP_MSG(msg);
		//send_response = 0;
		err = hip_userspace_ipsec_activate(msg);
		break;
	case SO_HIP_RESTART_DUMMY_INTERFACE:
		set_up_device(HIP_HIT_DEV, 0);
		err = set_up_device(HIP_HIT_DEV, 1);
		break;
	case SO_HIP_ESP_PROT_TFM:
		HIP_DUMP_MSG(msg);
		err = esp_prot_set_preferred_transforms(msg);
		break;
	case SO_HIP_BEX_STORE_UPDATE:
		HIP_DUMP_MSG(msg);
		err = anchor_db_update(msg);
		break;
	case SO_HIP_TRIGGER_UPDATE:
		HIP_DUMP_MSG(msg);
		err = esp_prot_handle_trigger_update_msg(msg);
		break;
	case SO_HIP_ANCHOR_CHANGE:
		HIP_DUMP_MSG(msg);
		err = esp_prot_handle_anchor_change_msg(msg);
		break;
	case SO_HIP_GET_LSI_PEER:
		while((param = hip_get_next_param(msg, param))) {
			if (hip_get_param_type(param) == HIP_PARAM_HIT){
				if (!dst_hit) {
		      			dst_hit = (struct in6_addr *)hip_get_param_contents_direct(param);
					HIP_DEBUG_HIT("dst_hit", dst_hit);
		    		} else {
		      			src_hit = (struct in6_addr *)hip_get_param_contents_direct(param);
					HIP_DEBUG_HIT("src_hit", src_hit);
				}
		  	}
	  	}
		if (src_hit && dst_hit)
		        entry = hip_hadb_find_byhits(src_hit, dst_hit);
		else if (dst_hit)
			entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);
		if (entry && IS_LSI32(entry->lsi_peer.s_addr)) {
			HIP_IFE(hip_build_param_contents(msg, &entry->lsi_peer,
							 HIP_PARAM_LSI, sizeof(hip_lsi_t)), -1);
			HIP_IFE(hip_build_param_contents(msg, &entry->lsi_our,
							 HIP_PARAM_LSI, sizeof(hip_lsi_t)), -1);
		} else if (dst_hit) { /* Assign a new LSI */
			struct hip_common msg_tmp;
			hip_lsi_t lsi;

			memset(&msg_tmp, 0, sizeof(msg_tmp));
			hip_generate_peer_lsi(&lsi);
			HIP_IFE(hip_build_param_contents(&msg_tmp, dst_hit,
						HIP_PARAM_HIT, sizeof(hip_hit_t)), -1);
			HIP_IFE(hip_build_param_contents(&msg_tmp, &lsi,
						HIP_PARAM_LSI, sizeof(hip_lsi_t)), -1);
			hip_add_peer_map(&msg_tmp);
			HIP_IFE(hip_build_param_contents(msg, &lsi,
						HIP_PARAM_LSI, sizeof(hip_lsi_t)), -1);
		}
	        break;
	case SO_HIP_BUDDIES_ON:
		HIP_DEBUG("Setting BUDDIES ON\n");
		hip_buddies_inuse = SO_HIP_BUDDIES_ON;
		HIP_DEBUG("hip_buddies_inuse =  %d (should be %d)\n",
		hip_buddies_inuse, SO_HIP_BUDDIES_ON);
		break;

	case SO_HIP_BUDDIES_OFF:
		HIP_DEBUG("Setting BUDDIES OFF\n");
		hip_buddies_inuse = SO_HIP_BUDDIES_OFF;
		HIP_DEBUG("hip_buddies_inuse =  %d (should be %d)\n",
			hip_buddies_inuse, SO_HIP_BUDDIES_OFF);
		break;
	case SO_HIP_SET_NAT_PORT:
	{
		struct hip_port_info *nat_port;

		nat_port = hip_get_param(msg, HIP_PARAM_LOCAL_NAT_PORT);
		if (nat_port)
		{
			HIP_DEBUG("Setting local NAT port\n");	  
			hip_set_local_nat_udp_port(nat_port->port);	
			// We need to recreate the NAT UDP sockets to bind to the new port.
			hip_create_nat_sock_udp(&hip_nat_sock_output_udp, 1);
			hip_create_nat_sock_udp(&hip_nat_sock_input_udp, 1);
		}
		else
		{
			HIP_DEBUG("Setting peer NAT port\n");	  
			HIP_IFEL(!(nat_port = hip_get_param(msg, HIP_PARAM_PEER_NAT_PORT)),
					-1, "No nat port param found\n");
			hip_set_peer_nat_udp_port(nat_port->port);
		}
			
		break;
	}
	case SO_HIP_NSUPDATE_OFF:
	case SO_HIP_NSUPDATE_ON:
		hip_set_nsupdate_status((msg_type == SO_HIP_NSUPDATE_OFF) ? 0 : 1);
		if (msg_type == SO_HIP_NSUPDATE_ON)
			nsupdate(1);
		break;

        case SO_HIP_HIT_TO_IP_OFF:
        case SO_HIP_HIT_TO_IP_ON:
		hip_set_hit_to_ip_status ((msg_type == SO_HIP_NSUPDATE_OFF) ? 0 : 1);
	        break;

        case SO_HIP_HIT_TO_IP_SET:
	{
                err = 0;
                struct hip_hit_to_ip_set *name_info;
                HIP_IFEL(!(name_info = hip_get_param(msg, HIP_PARAM_HIT_TO_IP_SET)), -1,
                         "no name struct found\n");
                HIP_DEBUG("Name in name_info %s\n" , name_info->name);
		int name_len = strlen(name_info->name);
		if (name_len>=1)
			if (name_info->name[name_len-1]!='.') {
				HIP_DEBUG("final dot is missing");
				if (name_len < HIT_TO_IP_ZONE_MAX_LEN-2) {
					HIP_DEBUG("adding final dot");
					name_info->name[name_len]='.';
					name_info->name[name_len+1]=0;
					HIP_DEBUG("new name %s\n" , name_info->name);
				}
			}
                hip_hit_to_ip_set(name_info->name);
	}
	break;
	case SO_HIP_SHOTGUN_ON:
		HIP_DEBUG("Setting SHOTGUN ON\n");
		hip_shotgun_status = SO_HIP_SHOTGUN_ON;
		HIP_DEBUG("hip_shotgun_status =  %d (should be %d)\n",
                    hip_shotgun_status, SO_HIP_SHOTGUN_ON);
		break;

	case SO_HIP_SHOTGUN_OFF:
		HIP_DEBUG("Setting SHOTGUN OFF\n");
		hip_shotgun_status = SO_HIP_SHOTGUN_OFF;
		HIP_DEBUG("hip_shotgun_status =  %d (should be %d)\n",
			hip_shotgun_status, SO_HIP_SHOTGUN_OFF);
                break;
	case SO_HIP_MAP_ID_TO_ADDR:
	{
		struct in6_addr *id = NULL;
		hip_hit_t *hit = NULL;
		hip_lsi_t lsi;
		struct in6_addr addr;
		void * param = NULL;

		HIP_IFE(!(param = hip_get_param(msg, HIP_PARAM_IPV6_ADDR)),-1);
		HIP_IFE(!(id = hip_get_param_contents_direct(param)), -1);

		if (IN6_IS_ADDR_V4MAPPED(id)) {
			IPV6_TO_IPV4_MAP(id, &lsi);
		} else {
			hit = id;
		}

		memset (&addr, 0, sizeof(addr));
		HIP_IFEL(hip_map_id_to_addr(hit, &lsi, &addr), -1,
					"Couldn't determine address\n");
		hip_msg_init(msg);
		HIP_IFEL(hip_build_param_contents(msg, &addr,
				HIP_PARAM_IPV6_ADDR, sizeof(addr)),
				-1, "Build param failed\n");
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_MAP_ID_TO_ADDR, 0), -1,
						"Build header failed\n");
		break;
	}
	case SO_HIP_LSI_TO_HIT:
	{
		hip_lsi_t *lsi;
		struct hip_tlv_common *param;
		hip_ha_t *ha;

		HIP_IFE(!(param = hip_get_param(msg, HIP_PARAM_LSI)), -1);
		HIP_IFE(!(lsi =  hip_get_param_contents_direct(param)), -1);
		if (!(ha = hip_hadb_try_to_find_by_peer_lsi(lsi))) {
			HIP_DEBUG("No HA found\n");
			goto out_err;
		}
		hip_msg_init(msg);
		HIP_IFEL(hip_build_param_contents(msg, &ha->hit_peer,
				HIP_PARAM_IPV6_ADDR, sizeof(struct in6_addr)),
						-1, "Build param failed\n");
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_LSI_TO_HIT, 0), -1,
						"Build header failed\n");
		break;
	}
        default:
		HIP_ERROR("Unknown socket option (%d)\n", msg_type);
		err = -ESOCKTNOSUPPORT;
	}

 out_err:

	if (send_response) {
	        HIP_DEBUG("Send response\n");
		if (err)
		        hip_set_msg_err(msg, 1);
		len = hip_get_msg_total_len(msg);
		HIP_DEBUG("Sending message (type=%d) response to port %d \n",
			  hip_get_msg_type(msg), ntohs(src->sin6_port));
		HIP_DEBUG_HIT("To address", src);
		n = hip_sendto_user(msg, (struct sockaddr *)  src);
		if(n != len)
			err = -1;
		else
			HIP_DEBUG("Response sent ok\n");
	} else
		HIP_DEBUG("No response sent\n");

	return err;
}
