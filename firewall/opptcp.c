#include "opptcp.h"

extern int hip_fw_async_sock;

/* This file produces the following compiler warnings:
opptcp.c: In function 'tcp_packet_has_i1_option':
opptcp.c:186: warning: case label value exceeds maximum value for type
opptcp.c:187: warning: case label value exceeds maximum value for type
opptcp.c: In function 'hip_request_send_tcp_packet':
opptcp.c:357: warning: passing argument 1 of 'hip_build_param_contents' discards qualifiers from pointer target type
opptcp.c:362: warning: passing argument 1 of 'hip_build_param_contents' discards qualifiers from pointer target type
opptcp.c:367: warning: passing argument 1 of 'hip_build_param_contents' discards qualifiers from pointer target type
opptcp.c:372: warning: passing argument 1 of 'hip_build_param_contents' discards qualifiers from pointer target type
opptcp.c:377: warning: passing argument 1 of 'hip_build_param_contents' discards qualifiers from pointer target type
opptcp.c:383: warning: passing argument 1 of 'hip_build_user_hdr' discards qualifiers from pointer target type
opptcp.c:387: warning: passing argument 1 of 'hip_send_daemon_info' discards qualifiers from pointer target type
-Lauri 09.07.2008
*/

/**
 * Analyzes incoming TCP packets
 * 
 * @param *handle	the handle that has grabbed the packet, needed when allowing or dropping the packet.
 * @param hdr		pointer to the ip packet being examined.
 * @param ip_version	ipv4 or ipv6 type of traffic.
 * @return		nothing
 */
int hip_fw_examine_incoming_tcp_packet(void *hdr,
				       int ip_version,
				       int header_size) {
	int i, optLen, optionsLen, err = 0, state_ha;
	char 	       *hdrBytes = NULL;
	struct tcphdr  *tcphdr;
	struct ip      *iphdr;
	struct ip6_hdr *ip6_hdr;
	//fields for temporary values
	u_int16_t       portTemp;
	struct in_addr  addrTemp;
	struct in6_addr addr6Temp;
	/* the following vars are needed for
	 * sending the i1 - initiating the exchange
	 * in case we see that the peer supports hip*/
	struct in6_addr peer_ip, own_ip;
	struct in6_addr peer_hit;
	in_port_t        src_tcp_port;
	in_port_t        dst_tcp_port;
	/*this is needed for puting in default values
	  for the hits and lsi in the firewall entry*/
	struct in6_addr all_zero_default;
	firewall_hl_t *entry_peer = NULL;
	struct in6_addr src_lsi, dst_lsi;
	struct in6_addr src_hit, dst_hit;

	HIP_DEBUG("\n");

	if(ip_version == 4){
		iphdr = (struct ip *)hdr;
		//get the tcp header
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + header_size));
		hdrBytes = ((char *) iphdr) + header_size;
		HIP_DEBUG_INADDR("the destination", &iphdr->ip_src);
		//peer and local ip needed for sending the i1 through hipd
		IPV4_TO_IPV6_MAP(&iphdr->ip_src, &peer_ip);
		IPV4_TO_IPV6_MAP(&iphdr->ip_dst, &own_ip);
	}
	else if(ip_version == 6){
		ip6_hdr = (struct ip6_hdr *)hdr;
		//get the tcp header
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + header_size));
		hdrBytes = ((char *) ip6_hdr) + header_size;
		//peer and local ip needed for sending the i1 through hipd
		ipv6_addr_copy(&peer_ip, &ip6_hdr->ip6_src);
		ipv6_addr_copy(&own_ip, &ip6_hdr->ip6_dst);
	}

	/* this condition was originally only for SYN 0
	 * but below we added a condition for RST 1 and ACK 1
	 * So, in order for the RST ACK condition to be reachable,
	 * we added the condition for RST 0 here.
	 * The purpose is to process the packets as soon as possible.
	 * Many packets have SYN 0 and RST 0, so they get accepted quickly. 
	 */
	if((tcphdr->syn == 0) && (tcphdr->rst == 0) && (tcphdr->fin == 0)){
		return 1;
	}
	
	/* this shortcut check was removed
	 * because we need to analyze incoming
	 * TCP SYN_ACK, RST_ACK and FIN_ACK packets
	 * even when there are no options
	 * for updating the firewall entry
	 */
	/*//check that there are no options
	if(tcphdr->doff == 5){
		return 1;
	}*/

	if((tcphdr->syn == 1) && (tcphdr->ack == 0)){	//incoming, syn=1 and ack=0
		
		/* We need to create state in the firewall db
		 * if there is no entry for the peer yet. */
		entry_peer = (firewall_hl_t *)firewall_ip_db_match(&peer_ip);
		//if there is no entry in fw, add a default one
		if(!entry_peer){
			firewall_add_default_entry(&peer_ip);
			entry_peer = (firewall_hl_t *)firewall_ip_db_match(&peer_ip);
		}


		if(tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
			/*//swap the ports
			portTemp = tcphdr->source;
			tcphdr->source = tcphdr->dest;
			tcphdr->dest = portTemp;
			//swap the ip addresses
			if(ip_version == 4){
				addrTemp = iphdr->ip_src;
				iphdr->ip_src = iphdr->ip_dst;
				iphdr->ip_dst = addrTemp;
			}
			else if(ip_version == 6){
				addr6Temp = ip6_hdr->ip6_src;
				ip6_hdr->ip6_src = ip6_hdr->ip6_dst;
				ip6_hdr->ip6_dst = addr6Temp;
			}
			//set ack field
			tcphdr->ack_seq = tcphdr->seq + 1;
			//set seq field
			tcphdr->seq = htonl(0);
			//set flags
			tcphdr->syn = 1;
			tcphdr->ack = 1;

			// send packet out after adding HIT
			// the option is already there but
			// it has to be added again since
			// if only the HIT is added, it will
			// overwrite the i1 option that is
			// in the options of TCP
			hip_request_send_tcp_packet(hdr, hdr_size + 4*tcphdr->doff, ip_version, 1, 1);
			*/
			//drop original packet
			return 0;
		}
		else{
			/* A SYN packet without option indicates lack of peer
			 * HIP support. Updating the fw db to NOT_SUPPORTED. */
			state_ha = hip_get_bex_state_from_IPs(&own_ip, &peer_ip, &src_hit,
					     &dst_hit, &src_lsi, &dst_lsi);

			if(state_ha != HIP_STATE_ESTABLISHED)
				firewall_update_entry(NULL, NULL, NULL, &peer_ip,
					       FIREWALL_STATE_BEX_NOT_SUPPORTED);

			//allow packet
			return 1;
		}
	}
	else if( ((tcphdr->syn == 1) && (tcphdr->ack == 1)) ||	 //SYN_ACK
		 ((tcphdr->rst == 1) && (tcphdr->ack == 1)) ||   //RST_ACK
		 ((tcphdr->fin == 1) && (tcphdr->ack == 1))   ){ //FIN_ACK
		//with the new implementation, the i1 is sent out directly
		/*if(tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
			// tcp header pointer + 20(minimum header length)
			// + 4(i1 option length in the TCP options)
			memcpy(peer_hit, &hdrBytes[20 + 4], 16);
			hip_request_send_i1_to_hip_peer_from_hipd(
					peer_hit,
					peer_ip);
			//the packet is no more needed
			drop_packet(handle, packetId);
			return;
		}
		else{*/

			/* Signal for normal TCP not
			 * to be blocked with this peer.
			 * Blacklist peer in the hipd db*/
			hip_fw_unblock_and_blacklist(&peer_ip);


			/* updating the fw db if necessary*/
			entry_peer = (firewall_hl_t *)firewall_ip_db_match(&peer_ip);
			//if there is no entry in fw, add a default one
			if(!entry_peer){
				firewall_add_default_entry(&peer_ip);
				entry_peer = (firewall_hl_t *)firewall_ip_db_match(&peer_ip);
			}
			if(entry_peer->bex_state != FIREWALL_STATE_BEX_ESTABLISHED){
				//update the firewall db entry
				HIP_DEBUG("updating fw entry state to NOT_SUPPORTED\n");
				firewall_update_entry(NULL, NULL, NULL, &peer_ip,
					      FIREWALL_STATE_BEX_NOT_SUPPORTED);
			}


			//normal traffic connections should be allowed to be created
			return 1;
		/*}*/
	}

out_err:
	/* Allow rest */
	return 1;
}

/**
 * checks for the i1 option in a packet
 *
 * @param  tcphdrBytes	a pointer to the TCP header that is examined.
 * @param  hdrLen  	the length of the TCP header in bytes.
 * @return 		zero if i1 option not found in the options, or 1 if it is found.
 */
int tcp_packet_has_i1_option(void * tcphdrBytes, int hdrLen)
{
	char i = 20;//the initial obligatory part of the TCP header
	int foundHipOpp = 0, len = 0;
	char *bytes =(char*)tcphdrBytes;

	HIP_DEBUG("\n");

	while((i < hdrLen) && (foundHipOpp == 0))
	{
		switch (bytes[i])
		{
			//options with one-byte length
		case 0:
			break;
		//options with one-byte length
		case 1: i++; break;
		case 11: i++; break;
		case 12: i++; break;
		case 13: i++; break;
		case 16: i++; break;
		case 17: i++; break;
		case 20: i++; break;
		case 21: i++; break;
		case 22: i++; break;
		case 23: i++; break;
		case 24: i++; break;
		//case 25: i++; break;  //unassigned
		case 26: i++; break;
		case 2: len = bytes[i+1]; i += len; break;
		case 3: len = bytes[i+1]; i += len; break;
		case 4: len = bytes[i+1]; i += len; break;
		case 5: len = bytes[i+1]; i += len; break;
		case 6: len = bytes[i+1]; i += len; break;
		case 7: len = bytes[i+1]; i += len; break;
		case 8: len = bytes[i+1]; i += len; break;
		case 9: len = bytes[i+1]; i += len; break;
		case 10: len = bytes[i+1]; i += len; break;
		case 14: len = bytes[i+1]; i += len; break;
		case 15: len = bytes[i+1]; i += len; break;
		case 18: len = bytes[i+1]; i += len; break;
		case 19: len = bytes[i+1]; i += len; break;
		case 27: len = bytes[i+1]; i += len; break;
		case 253: len = bytes[i+1]; i += len; break;
		case 254: len = bytes[i+1]; i += len; break;
		case HIP_OPTION_KIND: return 1; break;
		default:  len = bytes[i+1]; i += len; break;
		}
	}
	return foundHipOpp;
}

/**
 * Send the ip of a peer to hipd, so that it can:
 * - unblock the packets that are sent to a particular peer.
 * - add it to the blacklist database.
 *
 * @param peer_ip	peer ip.
 * @return		nothing
 */
int hip_fw_unblock_and_blacklist(const struct in6_addr *peer_ip){
	struct hip_common *msg = NULL;
	int err = 0;

	HIP_DEBUG("\n");

	HIP_IFE(!(msg = hip_msg_alloc()), -1);

	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_ip),
					HIP_PARAM_IPV6_ADDR,
					sizeof(struct in6_addr)),
			-1, "build param HIP_PARAM_IPV6_ADDR failed\n");

	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OPPTCP_UNBLOCK_AND_BLACKLIST, 0),
		 -1, "build hdr failed\n");
	HIP_DUMP_MSG(msg);

	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_async_sock), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");
	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");

out_err:
	return err;
}


/**
 * Send the necessary data to hipd, so that a tcp packet is sent from there. This was done because it was not possible to send a packet directly from here.
 * 
 * @param *hdr		pointer to the packet that is to be sent.
 * @param packet_size	the size of the packet.
 * @param ip_version	ipv4 or ipv6.
 * @param addHit	whether the local HIT is to be added at the tcp options
 * @param addOption	whether the i1 option is to be added at the tcp options
 * @return		nothing
 */
/**
 * Send the necessary data to hipd, so that a tcp packet is sent from there. This was done because it was not possible to send a packet directly from here.
 * 
 * @param *hdr		pointer to the packet that is to be sent.
 * @param packet_size	the size of the packet.
 * @param ip_version	ipv4 or ipv6.
 * @param addHit	whether the local HIT is to be added at the tcp options
 * @param addOption	whether the i1 option is to be added at the tcp options
 * @return		nothing
 */
int hip_request_send_tcp_packet(void *hdr,
				int   packet_size,
				int   ip_version,
				int   addHit,
				int   addOption){
	const struct hip_common *msg = NULL;
	int err = 0;
	
	HIP_DEBUG("\n");

	HIP_IFE(!(msg = hip_msg_alloc()), -1);

	HIP_IFEL(hip_build_param_contents(msg, (void *)hdr,
					  HIP_PARAM_IP_HEADER,
					  packet_size),
		-1, "build param HIP_PARAM_IP_HEADER failed\n");
	
	HIP_IFEL(hip_build_param_contents(msg, (int *)(&packet_size),
					  HIP_PARAM_PACKET_SIZE,
					  sizeof(int)),
		-1, "build param HIP_PARAM_PACKET_SIZE failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (int *)(&ip_version),
					  HIP_PARAM_TRAFFIC_TYPE,
					  sizeof(int)),
		-1, "build param HIP_PARAM_TRAFFIC_TYPE failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (int *)(&addHit),
					  HIP_PARAM_ADD_HIT,
					  sizeof(int)),
		-1, "build param HIP_PARAM_ADD_HIT failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (int *)(&addOption),
					  HIP_PARAM_ADD_OPTION,
					  sizeof(int)),
		-1, "build param HIP_PARAM_ADD_OPTION failed\n");

	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OPPTCP_SEND_TCP_PACKET, 0),
		-1, "build hdr failed\n");
	HIP_DUMP_MSG(msg);
	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_async_sock), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");
	/* check error value */
	//HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");

 out_err:
	return err;
}

