#include "fw_stun.h"
extern int hip_fw_async_sock;

// add a database here for TURN
// hashtable with key = SPI, value = hip_turn_info
// see libopphip/wrap_db.c

int hip_fw_handle_turn_esp_output(hip_fw_context_t* ctx){
	/* XX FIXME */
	/* Map SPI number to TURN information from TURN database */
	/* Allocate some memory for new packet and copy relevant fields */
	/* Rewrite source port and add extra field for TURN */
	/* Recalculate UDP checksum */
	/* Add length of TURN field to IP header and recalculate IP checksum */
	/* Reinject the new packet using a raw socket (with sendto(), see e.g. firewall_send_outgoing_pkt) */
 out_err:

	/* Deallocate memory for new packet */
	return DROP;
}

#if 0
int hip_fw_handle_stun_packet(hip_fw_context_t* ctx){
	int err= 0;
	int  udp_len, new_udp_len, new_ip_len, len, missing, total_sent;
	struct udphdr *new_udp_msg, *incoming_udp_msg;
	struct ip *new_ip_msg = NULL, *incoming_ip_msg;
	struct sockaddr_in dst,src; 
	struct hip_common *hip_msg = NULL;
	
	// verdict zero drops the original so that you can send a new one
	// alloc new memory, copy the packet and add some zeroes (and hip header?)
	// changed ip and udp lengths and checksums accordingly
	// check handle_proxy_inbound_traffic() for examples
	// use raw_sock_v4 to send the packets
	
	HIP_DEBUG("hip_fw_handle_stun_packet\n");
	
	memset(&dst, 0, sizeof(dst));
	memset(&src, 0, sizeof(src));

	IPV6_TO_IPV4_MAP(&ctx->dst, &dst.sin_addr);
	IPV6_TO_IPV4_MAP(&ctx->src, &src.sin_addr);
	src.sin_family = AF_INET;
	dst.sin_family = AF_INET;
	
	udp_len = ntohs(ctx->udp_encap_hdr->len);
	//ip_len = ctx->ip_hdr_len;
	
	
	incoming_ip_msg = ctx->ip_hdr.ipv4;
	incoming_udp_msg =  ctx->udp_encap_hdr;
	
	//HIP_IFEL(!(hip_msg = hip_msg_alloc()), -1, 0), -1, "hip msg alloc\n");
	HIP_IFEL(!(hip_msg = hip_msg_alloc()), -ENOMEM, "Allocation failed\n");
	
	HIP_DEBUG_HIT("default hit is : ",&default_hit );
	
	hip_build_network_hdr(hip_msg, HIP_UPDATE, 0, &default_hit, &default_hit);
	hip_build_param_contents(hip_msg,
				 incoming_udp_msg + 1,
				 HIP_PARAM_STUN,
				 udp_len - sizeof(struct udphdr));
	
	new_udp_len = udp_len + HIP_UDP_ZERO_BYTES_LEN + hip_get_msg_total_len(hip_msg);
	new_ip_len = sizeof(struct ip) + new_udp_len;
	
	
	HIP_IFEL(!(new_ip_msg = HIP_MALLOC(new_ip_len, 0)), -1, "malloc\n");

	
	new_udp_msg = (struct udphdr *)(new_ip_msg +1);
	
	memset(new_ip_msg, 0, new_ip_len);
	//copy the ip and udp header into the new msg
	memcpy(new_ip_msg, incoming_ip_msg, sizeof(struct ip) + sizeof(struct udphdr));
	// copy the stun into the end of the msg
	memcpy(((char *)new_ip_msg)+sizeof(struct ip) + sizeof(struct udphdr) 
			+ HIP_UDP_ZERO_BYTES_LEN,
			hip_msg, hip_get_msg_total_len(hip_msg));

	//memcpy(((char *)new_ip_msg)+sizeof(struct udphdr)+ sizeof(struct ip)
	//		+HIP_UDP_ZERO_BYTES_LEN + sizeof(struct hip_common), 
	//		incoming_udp_msg +1, udp_len-sizeof(struct udphdr));
	
	new_udp_msg->len = htons(new_udp_len);
	new_ip_msg->ip_len = htons(new_ip_len);
//udp:checksum
	new_udp_msg->check = checksum_udp(new_udp_msg,&ctx->src,&ctx->dst);
//ip: checksum
	new_ip_msg->ip_sum = checksum_ip(new_ip_msg,new_ip_msg->ip_hl);
//send:

	missing = new_ip_len;
	total_sent = 0;
	HIP_DEBUG("raw socket v4: %d\n",raw_sock_v4 );
	
	while(missing > 0) {
		len = sendto(raw_sock_v4, ((char *)new_ip_msg)+total_sent,
			     missing, 0, &dst,sizeof(dst));
		if (len < 0) {
			HIP_PERROR("sendto");
			err = -1;
			goto out_err;
		}
		missing -= len;
		total_sent += len;
		HIP_DEBUG("missing: %d total_send : %d  len: %d \n", missing, total_sent, len);
		
	}
	
	HIP_DEBUG("sock: %d\n", raw_sock_v4);
	HIP_DEBUG("send ip len: %d \n new_ip_len: %d \n incoming Ip len: %d\n "
			,len,new_ip_len, ntohs(incoming_ip_msg->ip_len));
	HIP_DEBUG("incoming udp len: %d \n new_udp_len: %d\n",udp_len,new_udp_len);
	//HIP_IFEL(( len != new_ip_len),-1,"send udp failed");
	HIP_DEBUG("hip_fw_handle_stun_packet end\n");
 out_err:

	HIP_DUMP_MSG(hip_msg);
	if(hip_msg)
		HIP_FREE(hip_msg);
	if(new_ip_msg)
		HIP_FREE(new_ip_msg);


	return err;
}
#endif

int hip_fw_handle_stun_packet(hip_fw_context_t* ctx) {
	struct hip_common *hip_msg = NULL;
	struct udphdr *incoming_udp_msg;
	struct ip *incoming_ip_msg;
	int err = 0;
	uint16_t udp_len;

	incoming_ip_msg = ctx->ip_hdr.ipv4;
	incoming_udp_msg = ctx->udp_encap_hdr;
	udp_len = ntohs(ctx->udp_encap_hdr->len);
	
	HIP_IFEL(!(hip_msg = hip_msg_alloc()), -ENOMEM, "Allocation failed\n");

	HIP_IFEL(hip_build_user_hdr(hip_msg, SO_HIP_STUN, 0), -1, "hdr\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  incoming_udp_msg + 1,
					  HIP_PARAM_STUN,
					  udp_len - sizeof(struct udphdr)),
		 -1, "build_param\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  &incoming_udp_msg->dest,
					  HIP_PARAM_LOCAL_NAT_PORT,
					  sizeof(incoming_udp_msg->dest)),
		 -1, "build param\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  &incoming_udp_msg->source,
					  HIP_PARAM_PEER_NAT_PORT,
					  sizeof(incoming_udp_msg->source)),
		 -1, "build param\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  &ctx->dst,
					  HIP_PARAM_IPV6_ADDR_LOCAL,
					  sizeof(ctx->dst)),
		 -1, "build param\n");

	HIP_IFEL(hip_build_param_contents(hip_msg,
					  &ctx->src,
					  HIP_PARAM_IPV6_ADDR_PEER,
					  sizeof(ctx->src)),
		 -1, "build param\n");

	HIP_IFEL(hip_send_recv_daemon_info(hip_msg, 1, hip_fw_async_sock), -1,
		 "send/recv daemon info\n");

	HIP_DEBUG("STUN message forwarded to hipd successfully\n");
					  
 out_err:
	if (hip_msg)
		free(hip_msg);
	return err;
}
