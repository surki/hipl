/*
 * Firewall control
 *
 */

#include "firewall_control.h"

int control_thread_started = 0;
//GThread * control_thread = NULL;

extern int system_based_opp_mode;

//Prabhu datapacket mode

extern int hip_datapacket_mode;

int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr)
{
	/* Variables. */
	struct hip_tlv_common *param = NULL;
	socklen_t alen;
	int type, err = 0, param_type;
	struct hip_keys *keys = NULL;
	struct in6_addr *hit_s = NULL, *hit_r = NULL;
	extern int hip_lsi_support;

	HIP_DEBUG("Handling message from hipd\n");

	type = hip_get_msg_type(msg);

	switch(type) {
	case SO_HIP_FW_I2_DONE:
		if (hip_sava_router || hip_sava_client)
			handle_sava_i2_state_update(msg);
		break;
	case SO_HIP_FW_BEX_DONE:
	case SO_HIP_FW_UPDATE_DB:
	        if(hip_lsi_support)
	          handle_bex_state_update(msg);
		break;
	case SO_HIP_IPSEC_ADD_SA:
		HIP_DEBUG("Received add sa request from hipd\n");
		HIP_IFEL(handle_sa_add_request(msg), -1,
				"hip userspace sadb add did NOT succeed\n");
		break;
	case SO_HIP_IPSEC_DELETE_SA:
		HIP_DEBUG("Received delete sa request from hipd\n");
		HIP_IFEL(handle_sa_delete_request(msg), -1,
				"hip userspace sadb delete did NOT succeed\n");
		break;
	case SO_HIP_IPSEC_FLUSH_ALL_SA:
		HIP_DEBUG("Received flush all sa request from hipd\n");
		HIP_IFEL(handle_sa_flush_all_request(msg), -1,
				"hip userspace sadb flush all did NOT succeed\n");
		break;
	case SO_HIP_ADD_ESCROW_DATA:
		while((param = hip_get_next_param(msg, param)))
		{
			if (hip_get_param_type(param) == HIP_PARAM_HIT)
			{
				_HIP_DEBUG("Handling HIP_PARAM_HIT\n");
				if (!hit_s)
					hit_s = hip_get_param_contents_direct(param);
				else
					hit_r =hip_get_param_contents_direct(param);
			}
			if (hip_get_param_type(param) == HIP_PARAM_KEYS)
			{
				_HIP_DEBUG("Handling HIP_PARAM_KEYS\n");
				int alg;
				int auth_len;
				int key_len;
				int spi;

				keys = (struct hip_keys *)param;

				// TODO: Check values!!
				auth_len = 0;
				//op = ntohs(keys->operation);
		 		//spi = ntohl(keys->spi);
		 		spi = ntohl(keys->spi);
		 		//spi_old = ntohl(keys->spi_old);
		 		key_len = ntohs(keys->key_len);
		 		alg = ntohs(keys->alg_id);

				if (alg == HIP_ESP_3DES_SHA1)
					auth_len = 24;
				else if (alg == HIP_ESP_AES_SHA1)
					auth_len = 32;
				else if (alg == HIP_ESP_NULL_SHA1)
					auth_len = 32;
				else
					HIP_DEBUG("Authentication algorithm unsupported\n");
				err = add_esp_decryption_data(hit_s, hit_r, (struct in6_addr *)&keys->address,
		     					      spi, alg, auth_len, key_len, &keys->enc);

				HIP_IFEL(err < 0, -1,"Adding esp decryption data failed");
				_HIP_DEBUG("Successfully added esp decryption data\n");
			}
		}
	case SO_HIP_DELETE_ESCROW_DATA:
	{
                struct in6_addr * addr = NULL;
                uint32_t * spi = NULL;

                HIP_DEBUG("Received delete message from hipd\n\n");
                while((param = hip_get_next_param(msg, param)))
                {

                        if (hip_get_param_type(param) == HIP_PARAM_HIT)
                        {
                                HIP_DEBUG("Handling HIP_PARAM_HIT\n");
                                addr = hip_get_param_contents_direct(param);
                        }
                        if (hip_get_param_type(param) == HIP_PARAM_UINT)
                        {
                                HIP_DEBUG("Handling HIP_PARAM_UINT\n");
                                spi = hip_get_param_contents(msg, HIP_PARAM_UINT);
                        }
                }
                if ((addr != NULL) && (spi != NULL)) {
                        HIP_IFEL(remove_esp_decryption_data(addr, *spi), -1,
				 "Error while removing decryption data\n");
                }
		break;
	}
	case SO_HIP_SET_ESCROW_ACTIVE:
		HIP_DEBUG("Received activate escrow message from hipd\n");
		set_escrow_active(1);
		break;
	case SO_HIP_SET_ESCROW_INACTIVE:
		HIP_DEBUG("Received deactivate escrow message from hipd\n");
		set_escrow_active(0);
		break;
	case SO_HIP_SET_HIPPROXY_ON:
	        HIP_DEBUG("Received HIP PROXY STATUS: ON message from hipd\n");
	        HIP_DEBUG("Proxy is on\n");
		if (!hip_proxy_status)
			hip_fw_init_proxy();
		hip_proxy_status = 1;
		break;
	case SO_HIP_SET_HIPPROXY_OFF:
		HIP_DEBUG("Received HIP PROXY STATUS: OFF message from hipd\n");
		HIP_DEBUG("Proxy is off\n");
		if (hip_proxy_status)
			hip_fw_uninit_proxy();
		hip_proxy_status = 0;
		break;
	case SO_HIP_SET_SAVAH_CLIENT_ON:
	        HIP_DEBUG("Received HIP_SAVAH_CLIENT_STATUS: ON message from hipd \n");
		restore_filter_traffic = filter_traffic;
		filter_traffic = 0;
	        if (!hip_sava_client && !hip_sava_router) {
		  hip_sava_client = 1;
		  hip_fw_init_sava_client();
		} 
	        break;
	case SO_HIP_SET_SAVAH_CLIENT_OFF:
	        _HIP_DEBUG("Received HIP_SAVAH_CLIENT_STATUS: OFF message from hipd \n");
		filter_traffic = restore_filter_traffic;
                if (hip_sava_client) {
		  hip_sava_client = 0;
		  hip_fw_uninit_sava_client();
		} 
	        break;
	case SO_HIP_SET_SAVAH_SERVER_OFF:
	        _HIP_DEBUG("Received HIP_SAVAH_SERVER_STATUS: OFF message from hipd \n");
                if (!hip_sava_client && !hip_sava_router) {
		  hip_sava_router = 0;
		  // XX FIXME
		  accept_hip_esp_traffic_by_default = restore_accept_hip_esp_traffic;
		  hip_fw_uninit_sava_router();
		}
	        break;
        case SO_HIP_SET_SAVAH_SERVER_ON: 
	        HIP_DEBUG("Received HIP_SAVAH_SERVER_STATUS: ON message from hipd \n");
                if (!hip_sava_client && !hip_sava_router) {
		  hip_sava_router = 1;
		  restore_accept_hip_esp_traffic = accept_hip_esp_traffic_by_default;
		  accept_hip_esp_traffic_by_default = 0;
		  // XX FIXME
		  hip_fw_init_sava_router();
		}
	        break;
	/*   else if(type == HIP_HIPPROXY_LOCAL_ADDRESS){
	     HIP_DEBUG("Received HIP PROXY LOCAL ADDRESS message from hipd\n");
	     if (hip_get_param_type(param) == HIP_PARAM_IPV6_ADDR)
		{
		_HIP_DEBUG("Handling HIP_PARAM_IPV6_ADDR\n");
		hit_s = hip_get_param_contents_direct(param);
		}
		}
	*/
	case SO_HIP_SET_OPPTCP_ON:
		HIP_DEBUG("Opptcp on\n");
		if (!hip_opptcp)
			hip_fw_init_opptcp();
		hip_opptcp = 1;
		break;
	case SO_HIP_SET_OPPTCP_OFF:
		HIP_DEBUG("Opptcp on\n");
		if (hip_opptcp)
			hip_fw_uninit_opptcp();
		hip_opptcp = 0;
		break;
	case SO_HIP_GET_PEER_HIT:
		if (hip_proxy_status)
			err = hip_fw_proxy_set_peer_hit(msg);
		else if (system_based_opp_mode)
			err = hip_fw_sys_opp_set_peer_hit(msg);
		break;
	case SO_HIP_TURN_INFO:
		// struct hip_turn_info *turn = hip_get_param_contents(HIP_PARAM_TURN_INFO);
		// save to database
		break;
	case SO_HIP_RESET_FIREWALL_DB:
		hip_firewall_cache_delete_hldb();
		hip_firewall_delete_hldb();
		break;
       //Prabhu enable hip datapacket mode 
        case SO_HIP_SET_DATAPACKET_MODE_ON:
		HIP_DEBUG("Setting HIP DATA PACKET MODE ON \n "); 
		hip_datapacket_mode = 1;
                break;

       //Prabhu enable hip datapacket mode 
        case SO_HIP_SET_DATAPACKET_MODE_OFF:
		HIP_DEBUG("Setting HIP DATA PACKET MODE OFF \n "); 
		hip_datapacket_mode = 0;
                break;

	default:
		HIP_ERROR("Unhandled message type %d\n", type);
		err = -1;
		break;
	}
 out_err:

	return err;
}

inline u16 inchksum(const void *data, u32 length){
	long sum = 0;
    	const u16 *wrd =  (u16 *) data;
    	long slen = (long) length;

    	while (slen > 1) {
        	sum += *wrd++;
        	slen -= 2;
    	}

    	if (slen > 0)
        	sum += * ((u8 *)wrd);

    	while (sum >> 16)
        	sum = (sum & 0xffff) + (sum >> 16);

    	return (u16) sum;
}

u16 ipv4_checksum(u8 protocol, u8 src[], u8 dst[], u8 data[], u16 len)
{

	u16 word16;
	u32 sum;
	u16 i;

	//initialize sum to zero
	sum=0;

	// make 16 bit words out of every two adjacent 8 bit words and
	// calculate the sum of all 16 vit words
	for (i=0;i<len;i=i+2){
		word16 =((((u16)(data[i]<<8)))&0xFF00)+(((u16)data[i+1])&0xFF);
		sum = sum + (unsigned long)word16;
	}
	// add the TCP pseudo header which contains:
	// the IP source and destination addresses,
	for (i=0;i<4;i=i+2){
		word16 =((src[i]<<8)&0xFF00)+(src[i+1]&0xFF);
		sum=sum+word16;
	}
	for (i=0;i<4;i=i+2)
	{
		word16 =((dst[i]<<8)&0xFF00)+(dst[i+1]&0xFF);
		sum=sum+word16;
	}
	// the protocol number and the length of the TCP packet
	sum = sum + protocol + len;

	// keep only the last 16 bits of the 32 bit calculated sum and add the carries
	while (sum>>16)
		sum = (sum & 0xFFFF)+(sum >> 16);

	// Take the one's complement of sum
	sum = ~sum;
	return (htons((unsigned short) sum));
}

u16 ipv6_checksum(u8 protocol, struct in6_addr *src, struct in6_addr *dst, void *data, u16 len)
{
	u32 chksum = 0;
    	pseudo_v6 pseudo;
    	memset(&pseudo, 0, sizeof(pseudo_v6));

    	pseudo.src = *src;
    	pseudo.dst = *dst;
    	pseudo.length = htons(len);
    	pseudo.next = protocol;

    	chksum = inchksum(&pseudo, sizeof(pseudo_v6));
    	chksum += inchksum(data, len);

    	chksum = (chksum >> 16) + (chksum & 0xffff);
    	chksum += (chksum >> 16);

    	chksum = (u16)(~chksum);
    	if (chksum == 0)
    		chksum = 0xffff;

    	return chksum;
}

int request_savah_status(int mode)
{
        struct hip_common *msg = NULL;
        int err = 0;
        int n;
        socklen_t alen;
        HIP_DEBUG("Sending hipproxy msg to hipd.\n");
        HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
        hip_msg_init(msg);
	if (mode == SO_HIP_SAVAH_CLIENT_STATUS_REQUEST) {
	  HIP_DEBUG("SO_HIP_SAVAH_CLIENT_STATUS_REQUEST \n");
	  HIP_IFEL(hip_build_user_hdr(msg,
				      SO_HIP_SAVAH_CLIENT_STATUS_REQUEST, 0),
		   -1, "Build hdr failed\n");
	}
	else if (mode == SO_HIP_SAVAH_SERVER_STATUS_REQUEST) {
	  HIP_DEBUG("SO_HIP_SAVAH_SERVER_STATUS_REQUEST \n");
	  HIP_IFEL(hip_build_user_hdr(msg,
				      SO_HIP_SAVAH_SERVER_STATUS_REQUEST, 0),
		   -1, "Build hdr failed\n");
	}
	else {
	  HIP_ERROR("Unknown sava mode \n");
	  goto out_err;
	}

        HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
		 " Sendto HIPD failed.\n");
	HIP_DEBUG("Sendto hipd OK.\n");

out_err:
	if(msg)
		free(msg);
        return err;
}

#ifdef CONFIG_HIP_HIPPROXY
int request_hipproxy_status(void)
{
        struct hip_common *msg = NULL;
        int err = 0, n;
        socklen_t alen;
        HIP_DEBUG("Sending hipproxy msg to hipd.\n");
        HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg,
                SO_HIP_HIPPROXY_STATUS_REQUEST, 0),
                -1, "Build hdr failed\n");

        //n = hip_sendto(msg, &hip_firewall_addr);

        //n = sendto(hip_fw_sock, msg, hip_get_msg_total_len(msg),
        //		0,(struct sockaddr *)dst, sizeof(struct sockaddr_in6));

        HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
		 "HIP_HIPPROXY_STATUS_REQUEST: Sendto HIPD failed.\n");
	HIP_DEBUG("HIP_HIPPROXY_STATUS_REQUEST: Sendto hipd ok.\n");

out_err:
	if(msg)
		free(msg);
        return err;
}
#endif /* CONFIG_HIP_HIPPROXY */

int handle_bex_state_update(struct hip_common * msg)
{
	struct in6_addr *src_hit = NULL, *dst_hit = NULL;
	struct hip_tlv_common *param = NULL;
	int err = 0, msg_type = 0;

	msg_type = hip_get_msg_type(msg);

	/* src_hit */
        param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_HIT);
	src_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Source HIT: ", src_hit);

	/* dst_hit */
	param = hip_get_next_param(msg, param);
	dst_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Destination HIT: ", dst_hit);

	/* update bex_state in firewalldb */
	switch(msg_type)
	{
	        case SO_HIP_FW_BEX_DONE:
		        err = firewall_set_bex_state(src_hit,
						     dst_hit,
						     (dst_hit ? 1 : -1));
			break;
                case SO_HIP_FW_UPDATE_DB:
		        err = firewall_set_bex_state(src_hit, dst_hit, 0);
			break;
                default:
		        break;
	}
	return err;
}

int handle_sava_i2_state_update(struct hip_common * msg, int hip_lsi_support)
{
	struct in6_addr *src_ip = NULL, *src_hit = NULL;
	struct hip_tlv_common *param = NULL;
	int err = 0, msg_type = 0;

	msg_type = hip_get_msg_type(msg);

	/* src_hit */
        param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_HIT);
	src_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Source HIT: ", src_hit);

	param = hip_get_next_param(msg, param);
	src_ip = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Source IP: ", src_ip);

	/* update bex_state in firewalldb */
	switch(msg_type)
	{
	        case SO_HIP_FW_I2_DONE:
		        err = hip_sava_handle_bex_completed (src_ip, src_hit);
         	        break;
                default:
		        break;
	}
	return err;
}
