/* @file
 * This file defines handling functions for outgoing packets for the Host
 * Identity Protocol (HIP).
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author  Samu Varjonen
 * @author	Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#include "output.h"

enum number_dh_keys_t number_dh_keys = TWO;

/* @todo: why the heck do we need this here on linux? */
struct in6_pktinfo
{
  struct in6_addr ipi6_addr;  /* src/dst IPv6 address */
  unsigned int ipi6_ifindex;  /* send/recv interface index */
};

/**
* Standard BSD internet checksum routine from nmap
* for calculating the checksum field of the TCP header
*/
unsigned short in_cksum(u16 *ptr,int nbytes){
	register u32 sum;
	u16 oddbyte;
	register u16 answer;

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */
	sum = 0;
	while (nbytes > 1){
		sum += *ptr++;
		nbytes -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;            /* make sure top half is zero */
		*((u_char *) &oddbyte) = *(u_char *)ptr;   /* one byte only */
		sum += oddbyte;
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */
	sum  = (sum >> 16) + (sum & 0xffff);    /* add high-16 to low-16 */
	sum += (sum >> 16);                     /* add carry */
	answer = ~sum;          /* ones-complement, then truncate to 16 bits */
	return(answer);
}

/**
 * @brief Sends a TCP packet through a raw socket.
 *
 * @param  hdr
 * @param  newSize
 * @param  trafficType 4 or 6 - standing for ipv4 and ipv6
 * @param  sockfd      a socket file descriptor
 * @param  addOption   adds the I1 option to a packet if required
 * @param  addHIT      adds the default HIT after the I1 option (if I1 option
 *                     should be added)
 * @return             ?
 */
int send_tcp_packet(void *hdr, int newSize, int trafficType, int sockfd,
		    int addOption, int addHIT)
{
	int on = 1, i = 0, j = 0, err = 0, off = 0, hdr_size = 0;
	int newHdr_size = 0, twoHdrsSize = 0;
	char *packet = NULL, *HITbytes = NULL;
	char *bytes = (char*)hdr;
	void  *pointer = NULL;
	struct tcphdr *tcphdr = NULL, *newTcphdr = NULL;
	struct ip *iphdr = NULL, *newIphdr = NULL;
	struct ip6_hdr *ip6_hdr = NULL, *newIp6_hdr = NULL;
	struct pseudo_hdr *pseudo = NULL;
	struct pseudo6_hdr *pseudo6 = NULL;
	struct sockaddr_in  sin_addr;
	struct sockaddr_in6 sin6_addr;
	struct in_addr  dstAddr;
	struct in6_addr dst6Addr;

	in6_addr_t *defaultHit = (in6_addr_t *)malloc(sizeof(char) * 16);
	char newHdr[newSize + 4*addOption + (sizeof(struct in6_addr))*addHIT];

	if(addOption)
		newSize = newSize + 4;
	if(addHIT)
		newSize = newSize + sizeof(struct in6_addr);

	//initializing the headers and setting socket settings
	if(trafficType == 4){
		//get the ip header
		iphdr = (struct ip *)hdr;
		//get the tcp header
		hdr_size = (iphdr->ip_hl * 4);
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));
		//socket settings
		sin_addr.sin_family = AF_INET;
		sin_addr.sin_port   = htons(tcphdr->dest);

		/* Is that right to copy address? */
		sin_addr.sin_addr   = iphdr->ip_dst;
	}
	else if(trafficType == 6){
		//get the ip header
		ip6_hdr = (struct ip6_hdr *)hdr;
		//get the tcp header
		hdr_size = sizeof(struct ip6_hdr);
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));
		//socket settings
		sin6_addr.sin6_family = AF_INET6;
		sin6_addr.sin6_port   = htons(tcphdr->dest);
		sin6_addr.sin6_addr   = ip6_hdr->ip6_dst;
	}

	//measuring the size of ip and tcp headers (no options)
	twoHdrsSize = hdr_size + 4*5;

	//copy the ip header and the tcp header without the options
	memcpy(&newHdr[0], &bytes[0], twoHdrsSize);

	//get the default hit
	if(addHIT){
		hip_get_default_hit(defaultHit);
		HITbytes = (char*)defaultHit;
	}

	//add the i1 option and copy the old options
	//add the HIT if required,
	if(tcphdr->doff == 5){//there are no previous options
		if(addOption){
			newHdr[twoHdrsSize]     = (char)HIP_OPTION_KIND;
			newHdr[twoHdrsSize + 1] = (char)2;
			newHdr[twoHdrsSize + 2] = (char)1;
			newHdr[twoHdrsSize + 3] = (char)1;
			if(addHIT){
				//put the default hit
				memcpy(&newHdr[twoHdrsSize + 4], &HITbytes[0], 16);
			}
		}
		else{
			if(addHIT){
				//put the default hit
				memcpy(&newHdr[twoHdrsSize], &HITbytes[0], 16);
			}
		}
	}
	else{//there are previous options
		if(addOption){
			newHdr[twoHdrsSize]     = (char)HIP_OPTION_KIND;
			newHdr[twoHdrsSize + 1] = (char)2;
			newHdr[twoHdrsSize + 2] = (char)1;
			newHdr[twoHdrsSize + 3] = (char)1;

			//if the HIT is to be sent, the
			//other options are not important
			if(addHIT){
				//put the default hit
				memcpy(&newHdr[twoHdrsSize + 4], &HITbytes[0], 16);
			}
			else
				memcpy(&newHdr[twoHdrsSize + 4], &bytes[twoHdrsSize], 4*(tcphdr->doff-5));
		}
		else
		{
			//if the HIT is to be sent, the
			//other options are not important
			if(addHIT){
				//put the default hit
				memcpy(&newHdr[twoHdrsSize], &HITbytes[0], 16);
			}
			else
				memcpy(&newHdr[twoHdrsSize], &bytes[twoHdrsSize], 4*(tcphdr->doff-5));
		}
	}

	pointer = &newHdr[0];
	//get pointers to the new packet
	if(trafficType == 4){
		//get the ip header
		newIphdr = (struct ip *)pointer;
		//get the tcp header
		newHdr_size = (iphdr->ip_hl * 4);
		newTcphdr = ((struct tcphdr *) (((char *) newIphdr) + newHdr_size));
	}
	else if(trafficType == 6){
		//get the ip header
		newIp6_hdr = (struct ip6_hdr *)pointer;
		//get the tcp header
		newHdr_size = (newIp6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		newTcphdr = ((struct tcphdr *) (((char *) newIp6_hdr) + newHdr_size));
	}

	//change the values of the checksum and the tcp header length(+1)
	newTcphdr->check = 0;
	if(addOption)
		newTcphdr->doff = newTcphdr->doff + 1;
	if(addHIT)
		newTcphdr->doff = newTcphdr->doff + 4;//16 bytes HIT - 4 more words

	//the checksum
	if(trafficType == 4){
		pseudo = (struct pseudo_hdr *) ((u8*)newTcphdr - sizeof(struct pseudo_hdr));

		pseudo->s_addr = newIphdr->ip_src.s_addr;
		pseudo->d_addr = newIphdr->ip_dst.s_addr;
		pseudo->zer0    = 0;
		pseudo->protocol = IPPROTO_TCP;
		pseudo->length  = htons(sizeof(struct tcphdr) + 4*(newTcphdr->doff-5) + 0);

		newTcphdr->check = in_cksum((unsigned short *)pseudo, sizeof(struct tcphdr) +
							4*(newTcphdr->doff-5) + sizeof(struct pseudo_hdr) + 0);
	}
	else if(trafficType == 6){
		pseudo6 = (struct pseudo6_hdr *) ((u8*)newTcphdr - sizeof(struct pseudo6_hdr));

		pseudo6->s_addr = newIp6_hdr->ip6_src;
		pseudo6->d_addr = newIp6_hdr->ip6_dst;
		pseudo6->zer0    = 0;
		pseudo6->protocol = IPPROTO_TCP;
		pseudo6->length  = htons(sizeof(struct tcphdr) + 4*(newTcphdr->doff-5) + 0);

		newTcphdr->check = in_cksum((unsigned short *)pseudo6, sizeof(struct tcphdr) +
							4*(newTcphdr->doff-5) + sizeof(struct pseudo6_hdr) + 0);
	}

	//replace the pseudo header bytes with the correct ones
	memcpy(&newHdr[0], &bytes[0], hdr_size);

	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) < 0 ){
		HIP_DEBUG("Error setting an option to raw socket\n");
		return;
	}

	//finally send through the socket
	err = sendto(sockfd, &newHdr[0], newSize, 0, (struct sockaddr *)&sin_addr, sizeof(sin_addr));

out_err:
	if(defaultHit)
		HIP_FREE(defaultHit);

	setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, (char *)&off, sizeof(off));

	return err;
}


/**
 * Builds the TCP SYN packet that will be send with the i1 option.
 *
 * Send an I1 packet to the responder if an IPv6 address for the peer
 * is known.
 *
 * @param entry   	a pointer to a host association database state reserved for
 *                	the peer. The src and dst ports are included in this parameter
 * @return        	nothing
 */
void hip_send_opp_tcp_i1(hip_ha_t *entry){
	int    ipType = ! IN6_IS_ADDR_V4MAPPED(&entry->peer_addr);
	struct ip * iphdr;
	struct ip6_hdr * ip6_hdr;
	struct tcphdr *tcphdr;
	int    i, hdr_size;
	char bytes [sizeof(struct ip)*(1 - ipType)   +   sizeof(struct ip6_hdr)*ipType   +   5*4];

	HIP_DEBUG("\n");

	if(ipType == 0)
		hdr_size = sizeof(struct ip);
	else if(ipType == 1)
		hdr_size = sizeof(struct ip6_hdr);

	//set all bytes of both headers to 0
	memset(&bytes[0], 0, 40);

	//fill in the ip header fields
	if(ipType == 0){//ipv4
		//get the ip header
		iphdr = (struct ip *)&bytes[0];
		//get the tcp header
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));

		iphdr->ip_v = 4;
		iphdr->ip_hl = 5;
		iphdr->ip_tos = 0;
		iphdr->ip_len = 44;//20+20+4 ?????
		iphdr->ip_id = 100;//random
		//iphdr->FLAGS
		iphdr->ip_off = 0;
		iphdr->ip_ttl = 64;
		iphdr->ip_p = 6;
		iphdr->ip_sum = in_cksum((unsigned short *)iphdr, sizeof(struct ip));
		IPV6_TO_IPV4_MAP(&entry->our_addr, &iphdr->ip_src);
		IPV6_TO_IPV4_MAP(&entry->peer_addr, &iphdr->ip_dst);
	}
	else if(ipType == 1){//ipv6
		//get the ip header
		ip6_hdr = (struct ip6_hdr *)&bytes[0];
		//get the tcp header
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));

		ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_flow = 1610612736;//01100000000000000000000000000000;
		ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen = 20;
		ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt = 6;
		ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;
		memcpy(&ip6_hdr->ip6_src, &entry->our_addr, sizeof(struct in6_addr));
		memcpy(&ip6_hdr->ip6_dst, &entry->peer_addr, sizeof(struct in6_addr));
	}

	//randomize the source port to one of 1024-65535
	//but different from entry->tcp_opptcp_src_port
	tcphdr->source = rand() % (65536-1024) + 1024;//entry->tcp_opptcp_src_port;
	while(tcphdr->source == entry->tcp_opptcp_src_port)
		tcphdr->source = rand() % (65536-1024) + 1024;

	tcphdr->dest   = entry->tcp_opptcp_dst_port;
	tcphdr->seq = 0;
	tcphdr->ack_seq = 0;//is not important in the SYN packet
	tcphdr->doff = 5;
	tcphdr->syn = 1;
	//tcphdr->rst = 1;
	tcphdr->window = 34;//random
	tcphdr->check = 0;//will be set right when sent, no need to calculate it here
	//tcphdr->urg_ptr = ???????? TO BE FIXED
	if(ipType == 0)
		send_tcp_packet(&bytes[0], hdr_size + 4*tcphdr->doff, 4, hip_raw_sock_output_v4, 1, 0);
	else if(ipType == 1)
		send_tcp_packet(&bytes[0], hdr_size + 4*tcphdr->doff, 6, hip_raw_sock_output_v6, 1, 0);
}

/**
 * Sends an I1 packet to the peer. Used internally by hip_send_i1
 * Check hip_send_i1 & hip_send_raw for the parameters.
 */
int hip_send_i1_pkt(struct hip_common *i1, hip_hit_t *dst_hit,
                    struct in6_addr *local_addr, struct in6_addr *peer_addr,
                    in_port_t src_port, in_port_t dst_port, struct hip_common* i1_blind,
                    hip_ha_t *entry, int retransmit)
{
        int err = 0;
        
#ifdef CONFIG_HIP_OPPORTUNISTIC
        // if hitr is hashed null hit, send it as null on the wire
        if  (hit_is_opportunistic_hashed_hit(&i1->hitr))
                ipv6_addr_copy(&i1->hitr, &in6addr_any);

        HIP_HEXDUMP("daddr", peer_addr, sizeof(struct in6_addr));
#endif // CONFIG_HIP_OPPORTUNISTIC


#ifdef CONFIG_HIP_BLIND
        // Send blinded i1
        if (hip_blind_get_status())
        {
            err = entry->hadb_xmit_func->hip_send_pkt(local_addr,
                                                    peer_addr,
                                                    (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                                                    hip_get_peer_nat_udp_port(),
                                                    i1_blind, entry, 1);
        }
#endif

        HIP_DEBUG_HIT("BEFORE sending\n", peer_addr);
        if (!hip_blind_get_status())
        {
                err = entry->hadb_xmit_func->
                        hip_send_pkt(local_addr, peer_addr,
                                     (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                                     hip_get_peer_nat_udp_port(),
                                     i1, entry, 1);
        }

        HIP_DEBUG("err after sending: %d.\n", err);

        if (!err)
        {
                HIP_LOCK_HA(entry);
                entry->state = HIP_STATE_I1_SENT;
                HIP_UNLOCK_HA(entry);
        }
        else if (err == 1)
        {
            err = 0;
        }

        /*send the TCP SYN_i1 packet*/
        if (hip_get_opportunistic_tcp_status() &&
            hit_is_opportunistic_hashed_hit(dst_hit)) {
                /* Ensure that I1 gets first to destination */
                usleep(50);
                hip_send_opp_tcp_i1(entry);
        }

out_err:
        return err;
}

/**
 * Sends an I1 packet to the peer.
 *
 * Send an I1 packet to the responder if an IPv6 address for the peer
 * is known.
 *
 * @param src_hit a pointer to source host identity tag.
 * @param dst_hit a pointer to destination host identity tag.
 * @param entry   a pointer to a host association database state reserved for
 *                the peer.
 * @return        zero on success, or negative error value on error.
 */
int hip_send_i1(hip_hit_t *src_hit, hip_hit_t *dst_hit, hip_ha_t *entry)
{
	struct hip_common *i1 = 0;
	uint16_t mask = 0;
	int err = 0, n = 0;
       	hip_list_t *item = NULL, *tmp = NULL;
	struct hip_peer_addr_list_item *addr;
	struct hip_common *i1_blind = NULL;
	int i = 0;
        struct in6_addr *local_addr = NULL;
        struct in6_addr peer_addr;

	HIP_IFEL((entry->state == HIP_STATE_ESTABLISHED), 0,
		 "State established, not triggering bex\n");

	/* Assign a local private key, public key and HIT to HA */
	HIP_DEBUG_HIT("src_hit", src_hit);
	HIP_DEBUG_HIT("entry->src_hit", &entry->hit_our);
	HIP_IFEL(hip_init_us(entry, src_hit), -EINVAL,
		 "Could not assign a local host id\n");
	//hip_for_each_ha(hip_print_info_hadb, &n);
	HIP_DEBUG_HIT("entry->src_hit", &entry->hit_our);

#ifdef CONFIG_HIP_BLIND

	if (hip_blind_get_status()) {
		HIP_DEBUG("Blind is activated, building blinded I1 packet.\n");

		if((i1_blind = hip_blind_build_i1(entry, &mask)) == NULL) {
			err = -1;
			HIP_ERROR("hip_blind_build_i1() failed.\n");
			goto out_err;
		}
	}
#endif

	/* We don't need to use hip_msg_alloc(), since the I1
	   packet is just the size of struct hip_common. */

	/* ..except that when calculating the msg size, we need to have more
	   than just hip_common */

	/* So why don't we just have a hip_max_t struct to allow allocation of
	   maximum sized HIP packets from the stack? Not that it would make any
	   difference here, but playing with mallocs has always the chance of
	   leaks... */

	i1 = hip_msg_alloc();

	if (!hip_blind_get_status()) {
		entry->hadb_misc_func->
			hip_build_network_hdr(i1, HIP_I1,
					      mask, &entry->hit_our, dst_hit);
	}

	/* Calculate the HIP header length */
	hip_calc_hdr_len(i1);

	HIP_DEBUG_HIT("HIT source", &i1->hits);
	HIP_DEBUG_HIT("HIT dest", &i1->hitr);

        HIP_DEBUG("Sending I1 to the following addresses:\n");
        hip_print_peer_addresses_to_be_added(entry);

        if (hip_shotgun_status == SO_HIP_SHOTGUN_OFF ||
	    (entry->peer_addr_list_to_be_added == NULL))
        {
                HIP_IFEL(hip_hadb_get_peer_addr(entry, &peer_addr), -1,
                        "No preferred IP address for the peer.\n");
         
                local_addr = &entry->our_addr;
                err = hip_send_i1_pkt(i1, dst_hit,
                                      local_addr, &peer_addr,
                                      (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
                                      (entry->nat_mode ? hip_get_peer_nat_udp_port() : 0),
                                      i1_blind, entry, 1);
        }
        else
        {
	    HIP_DEBUG("Number of items in the peer addr list: %d ", entry->peer_addr_list_to_be_added->num_items);
            list_for_each_safe(item, tmp, entry->peer_addr_list_to_be_added, i)
            {
                    addr = list_entry(item);
                    peer_addr = addr->address;
                 
                    err = hip_send_i1_pkt(i1, dst_hit,
                                        local_addr, &peer_addr,
                                        (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
					  (entry->nat_mode ? hip_get_peer_nat_udp_port() : 0),
                                        i1_blind, entry, 1);
                
		    /* Do not bail out on error with shotgun. Some
		       address pairs just might fail. */
            }
        }


out_err:
	if (i1 != NULL) {
		free(i1);
	}
#ifdef CONFIG_HIP_BLIND
	if (i1_blind != NULL) {
		free(i1_blind);
	}
#endif
	return err;
}

/**
 * Constructs a new R1 packet payload.
 *
 * @param src_hit      a pointer to the source host identity tag used in the
 *                     packet.
 * @param sign         a funtion pointer to a signature funtion.
 * @param private_key  a pointer to ...
 * @param host_id_pub  a pointer to ...
 * @param cookie       a pointer to ...
 * @return             zero on success, or negative error value on error.
 */
struct hip_common *hip_create_r1(const struct in6_addr *src_hit,
				 int (*sign)(struct hip_host_id *p, struct hip_common *m),
				 void *private_key,
				 const struct hip_host_id *host_id_pub,
				 int cookie_k)
{
	struct hip_locator_info_addr_item *addr_list = NULL;
	struct hip_locator *locator = NULL;
 	struct hip_locator_info_addr_item *locators = NULL;
	struct netdev_address *n = NULL;
 	hip_ha_t *entry = NULL;
	hip_common_t *msg = NULL;
 	hip_list_t *item = NULL, *tmp = NULL;
	hip_srv_t service_list[HIP_TOTAL_EXISTING_SERVICES];
	u8 *dh_data1 = NULL, *dh_data2 = NULL;
	uint32_t spi = 0;
	char order[] = "000";
	int err = 0, dh_size1 = 0, dh_size2 = 0, written1 = 0, written2 = 0;
	int mask = 0, l = 0, is_add = 0, i = 0, ii = 0, *list = NULL;
	unsigned int service_count = 0;
	int ordint = 0;

	/* Supported HIP and ESP transforms. */
	hip_transform_suite_t transform_hip_suite[] = {
                HIP_HIP_AES_SHA1,
                HIP_HIP_3DES_SHA1,
                HIP_HIP_NULL_SHA1	};
        hip_transform_suite_t transform_esp_suite[] = {
		HIP_ESP_AES_SHA1,
		HIP_ESP_3DES_SHA1,
		HIP_ESP_NULL_SHA1	};
	hip_transform_suite_t transform_nat_suite[] = {
		HIP_NAT_MODE_ICE_UDP,
                HIP_NAT_MODE_PLAIN_UDP,
	};

        /* change order if necessary */
	sprintf(order, "%d", hip_transform_order);
	for ( i = 0; i < 3; i++) {
		switch (order[i]) {
		case '1':
			transform_hip_suite[i] = HIP_HIP_AES_SHA1;
			transform_esp_suite[i] = HIP_ESP_AES_SHA1;
			HIP_DEBUG("Transform order index %d is AES\n", i);
			break;
		case '2':
			transform_hip_suite[i] = HIP_HIP_3DES_SHA1;
			transform_esp_suite[i] = HIP_ESP_3DES_SHA1;
			HIP_DEBUG("Transform order index %d is 3DES\n", i);
			break;
		case '3':
 			transform_hip_suite[i] = HIP_HIP_NULL_SHA1;
			transform_esp_suite[i] = HIP_ESP_NULL_SHA1;
			HIP_DEBUG("Transform order index %d is NULL_SHA1\n", i);
			break;
		}
	}

 	_HIP_DEBUG("hip_create_r1() invoked.\n");
	HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "Out of memory\n");

 	/* Allocate memory for writing the first Diffie-Hellman shared secret */
	HIP_IFEL((dh_size1 = hip_get_dh_size(HIP_FIRST_DH_GROUP_ID)) == 0,
		 -1, "Could not get dh_size1\n");
	HIP_IFEL(!(dh_data1 = HIP_MALLOC(dh_size1, GFP_ATOMIC)),
		 -1, "Failed to alloc memory for dh_data1\n");
	memset(dh_data1, 0, dh_size1);

	_HIP_DEBUG("dh_size=%d\n", dh_size1);

 	/* Allocate memory for writing the second Diffie-Hellman shared secret */
	HIP_IFEL((dh_size2 = hip_get_dh_size(HIP_SECOND_DH_GROUP_ID)) == 0,
		 -1, "Could not get dh_size2\n");
	HIP_IFEL(!(dh_data2 = HIP_MALLOC(dh_size2, GFP_ATOMIC)),
		 -1, "Failed to alloc memory for dh_data2\n");
	memset(dh_data2, 0, dh_size2);

	/* Ready to begin building of the R1 packet */

	/** @todo TH: hip_build_network_hdr has to be replaced with an
	    appropriate function pointer */
	HIP_DEBUG_HIT("src_hit used to build r1 network header", src_hit);
 	hip_build_network_hdr(msg, HIP_R1, mask, src_hit, NULL);

	/********** R1_COUNTER (OPTIONAL) *********/

	/********* LOCATOR PARAMETER ************/
        /** Type 193 **/
        if (hip_locator_status == SO_HIP_SET_LOCATOR_ON &&
	    hip_nat_get_control(NULL) != HIP_NAT_MODE_ICE_UDP) {
            HIP_DEBUG("Building LOCATOR parameter\n");
            if ((err = hip_build_locators(msg, 0, hip_nat_get_control(NULL))) < 0)
                HIP_DEBUG("LOCATOR parameter building failed\n");
            _HIP_DUMP_MSG(msg);
        }


 	/********** PUZZLE ************/
	HIP_IFEL(hip_build_param_puzzle(msg, cookie_k,
					42 /* 2^(42-32) sec lifetime */,
					0, 0),  -1,
		 "Cookies were burned. Bummer!\n");

 	/* Parameter Diffie-Hellman */
	HIP_IFEL((written1 = hip_insert_dh(dh_data1, dh_size1,
					  HIP_FIRST_DH_GROUP_ID)) < 0,
		 -1, "Could not extract the first DH public key\n");

	if (number_dh_keys == TWO){
	         HIP_IFEL((written2 = hip_insert_dh(dh_data2, dh_size2,
		       HIP_SECOND_DH_GROUP_ID)) < 0,
		       -1, "Could not extract the second DH public key\n");

	         HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
		       HIP_FIRST_DH_GROUP_ID, dh_data1, written1,
		       HIP_SECOND_DH_GROUP_ID, dh_data2, written2), -1,
		       "Building of DH failed.\n");
	}else
	         HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
		       HIP_FIRST_DH_GROUP_ID, dh_data1, written1,
		       HIP_MAX_DH_GROUP_ID, dh_data2, 0), -1,
		       "Building of DH failed.\n");

 	/* Parameter HIP transform. */
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_HIP_TRANSFORM,
					   transform_hip_suite,
					   sizeof(transform_hip_suite) /
					   sizeof(hip_transform_suite_t)), -1,
		 "Building of HIP transform failed\n");
 	
#ifdef HIP_USE_ICE
	if (hip_nat_get_control(NULL) == HIP_NAT_MODE_ICE_UDP) {
		hip_build_param_nat_transform(msg, transform_nat_suite,
					      sizeof(transform_nat_suite) / sizeof(hip_transform_suite_t));
		hip_build_param_nat_pacing(msg, HIP_NAT_PACING_DEFAULT);
	} else {
		hip_transform_suite_t plain_udp_suite =
			HIP_NAT_MODE_PLAIN_UDP;
		
		hip_build_param_nat_transform(msg, &plain_udp_suite, 1);
	}
#endif

	/* Parameter HOST_ID */
	_HIP_DEBUG("This HOST ID belongs to: %s\n",
		   hip_get_param_host_id_hostname(host_id_pub));
	HIP_IFEL(hip_build_param(msg, host_id_pub), -1,
		 "Building of host id failed\n");

	/* Parameter REG_INFO */
	hip_get_active_services(service_list, &service_count);
	HIP_DEBUG("Found %d active service(s) \n", service_count);
	hip_build_param_reg_info(msg, service_list, service_count);

 	/* Parameter ESP-ENC transform. */
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_ESP_TRANSFORM,
					   transform_esp_suite,
					   sizeof(transform_esp_suite) /
					   sizeof(hip_transform_suite_t)), -1,
		 "Building of ESP transform failed\n");

 	/********** ESP-PROT transform (OPTIONAL) **********/

 	HIP_IFEL(esp_prot_r1_add_transforms(msg), -1,
 			"failed to add optional esp transform parameter\n");

	/********** ECHO_REQUEST_SIGN (OPTIONAL) *********/

	//HIP_HEXDUMP("Pubkey:", host_id_pub, hip_get_param_total_len(host_id_pub));

 	/* Parameter Signature 2 */

	HIP_IFEL(sign(private_key, msg), -1, "Signing of R1 failed.\n");

	_HIP_HEXDUMP("R1", msg, hip_get_msg_total_len(msg));

	/* Parameter ECHO_REQUEST (OPTIONAL) */

	/* Fill puzzle parameters */
	{
		struct hip_puzzle *pz;
		uint64_t random_i;

		HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)), -1,
			 "Internal error\n");

		// FIX ME: this does not always work:
		//get_random_bytes(pz->opaque, HIP_PUZZLE_OPAQUE_LEN);

		/* hardcode kludge */
		pz->opaque[0] = 'H';
		pz->opaque[1] = 'I';
		//pz->opaque[2] = 'P';
		/** @todo Remove random_i variable. */
		get_random_bytes(&random_i,sizeof(random_i));
		pz->I = random_i;
	}

 	/* Packet ready */

        // 	if (host_id_pub)
	//		HIP_FREE(host_id_pub);
 	if (dh_data1)
 		HIP_FREE(dh_data1);
 	if (dh_data2)
 		HIP_FREE(dh_data2);

	//HIP_HEXDUMP("r1", msg, hip_get_msg_total_len(msg));

	return msg;

  out_err:
	//	if (host_id_pub)
	//	HIP_FREE(host_id_pub);
 	if (msg)
 		HIP_FREE(msg);
 	if (dh_data1)
 		HIP_FREE(dh_data1);
 	if (dh_data2)
 		HIP_FREE(dh_data2);

  	return NULL;
}

/**
 * Builds HOST ID and signature and append it to msg after locator
 *
 * @param msg          a pointer to hip_common to append the HOST_ID param and sig param
 * @param key          a pointer to HIT used as a key for hash table to retrieve host id
 * @return             zero on success, or negative error value on error
 */
int hip_build_host_id_and_signature(struct hip_common *msg,  unsigned char * key)
{
	struct in6_addr addrkey;
	struct hip_host_id *hi_public = NULL;
	int err = 0;
	int alg = -1;
	void *private_key;

	if (inet_pton(AF_INET6, (char *)key, &addrkey.s6_addr) == 0)
    {
    	_HIP_DEBUG("Lookup for HOST ID structure from HI DB failed as key provided is not a HIT ");
    	goto out_err;
    }
    else
    {
    	/*
    	 * Setting two message parameters as stated in RFC for HDRR
    	 * First one is sender's HIT
    	 * Second one is message type, which is draft is assumed to be 20 but it is already used so using 22
    	 */
    	msg->hits = addrkey;
    	hip_set_msg_type(msg,HIP_HDRR);

    	/*
    	 * Below is the code for getting host id and appending it to the message (after removing private
    	 * key from it hi_public
    	 * Where as hi_private is used to create signature on message
    	 * Both of these are appended to the message sequally
    	 */

    	if (err = hip_get_host_id_and_priv_key(HIP_DB_LOCAL_HID, &addrkey,
					HIP_ANY_ALGO, &hi_public, &private_key))
    	{
    		HIP_ERROR("Unable to locate HI from HID with HIT as key");
    		goto out_err;
    	}

    	err = hip_build_param(msg, hi_public);
    	_HIP_DUMP_MSG(msg);
    	if (err != 0)
    	{
    		goto out_err;
    	}

    	alg = hip_get_host_id_algo(hi_public);
  		switch (alg) {
			case HIP_HI_RSA:
				hip_rsa_sign(private_key, msg);
				break;
			case HIP_HI_DSA:
				hip_dsa_sign(private_key, msg);
				break;
			default:
				HIP_ERROR("Unsupported HI algorithm (%d)\n", alg);
				break;
		}
		_HIP_DUMP_MSG(msg);
    }
    out_err:
     free (hi_public);
     return err;
}

/**
 * Transmits an R1 packet to the network.
 *
 * Sends an R1 packet to the peer and stores the cookie information that was
 * sent. The packet is sent either to @c i1_saddr or  @c dst_ip depending on the
 * value of @c dst_ip. If @c dst_ip is all zeroes (::/128) or NULL, R1 is sent
 * to @c i1_saddr; otherwise it is sent to @c dst_ip. In case the incoming I1
 * was relayed through a middlebox (e.g. rendezvous server) @c i1_saddr should
 * have the address of that middlebox.
 *
 * @param i1_saddr      a pointer to the source address from where the I1 packet
 *                      was received.
 * @param i1_daddr      a pointer to the destination address where to the I1
 *                      packet was sent to (own address).
 * @param src_hit       a pointer to the source HIT i.e. responder HIT
 *                      (own HIT).
 * @param dst_ip        a pointer to the destination IPv6 address where the R1
 *                      should be sent (peer ip).
 * @param dst_hit       a pointer to the destination HIT i.e. initiator HIT
 *                      (peer HIT).
 * @param i1_info       a pointer to the source and destination ports
 *                      (when NAT is in use).
 * @param traversed_rvs a pointer to the rvs addresses to be inserted into the
 *                      @c VIA_RVS parameter.
 * @param rvs_count     number of addresses in @c traversed_rvs.
 * @return              zero on success, or negative error value on error.
 */
int hip_xmit_r1(hip_common_t *i1, in6_addr_t *i1_saddr, in6_addr_t *i1_daddr,
                in6_addr_t *dst_ip, const in_port_t dst_port,
                hip_portpair_t *i1_info, uint16_t relay_para_type)
{
	hip_common_t *r1pkt = NULL;
	in6_addr_t *r1_dst_addr = NULL, *local_plain_hit = NULL,
		*r1_src_addr = i1_daddr;
	in_port_t r1_dst_port = 0;
	int err = 0;

	_HIP_DEBUG("hip_xmit_r1() invoked.\n");

	HIP_DEBUG_IN6ADDR("i1_saddr", i1_saddr);
	HIP_DEBUG_IN6ADDR("i1_daddr", i1_daddr);
	HIP_DEBUG_IN6ADDR("dst_ip", dst_ip);

	/* Get the final destination address and port for the outgoing R1.
	   dst_ip and dst_port have values only if the incoming I1 had
	   FROM/FROM_NAT parameter. */
	if(!ipv6_addr_any(dst_ip) && relay_para_type){
		//from RVS or relay
		if(relay_para_type == HIP_PARAM_RELAY_FROM){
			HIP_DEBUG("Param relay from\n");
			//from relay
			r1_dst_addr = i1_saddr;
			r1_dst_port = i1_info->src_port;
			// I---> NAT--> RVS-->R is not supported yet
			/*
			r1_dst_addr =  dst_ip;
			r1_dst_port = dst_port;
			*/
		}
		else if(relay_para_type == HIP_PARAM_FROM){
			HIP_DEBUG("Param from\n");
			//from RVS, answer to I
			r1_dst_addr =  dst_ip;
			if(i1_info->src_port)
				// R and RVS is in the UDP mode or I send UDP to RVS with incoming port hip_get_peer_nat_udp_port()
				r1_dst_port =  hip_get_peer_nat_udp_port();
			else
				// connection between R & RVS is in hip raw mode
				r1_dst_port =  0;
		}
	} else {
		HIP_DEBUG("No RVS or relay\n");
		/* no RVS or RELAY found;  direct connection */
		r1_dst_addr = i1_saddr;
		r1_dst_port = i1_info->src_port;
	}

/* removed by santtu because relay supported
	r1_dst_addr = (ipv6_addr_any(dst_ip) ? i1_saddr : dst_ip);
	r1_dst_port = (dst_port == 0 ? i1_info->src_port : dst_port);
*/
#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* It should not be null hit, null hit has been replaced by real local
	   hit. */
	HIP_ASSERT(!hit_is_opportunistic_hashed_hit(&i1->hitr));
#endif

	/* Case: I ----->IPv4---> RVS ---IPv6---> R */
	if (IN6_IS_ADDR_V4MAPPED(r1_src_addr) !=
	    IN6_IS_ADDR_V4MAPPED(r1_dst_addr)) {
		HIP_DEBUG_IN6ADDR("r1_src_addr", r1_src_addr);
		HIP_DEBUG_IN6ADDR("r1_dst_addr", r1_dst_addr);
		HIP_DEBUG("Different relayed address families\n");
		HIP_IFEL(hip_select_source_address(r1_src_addr, r1_dst_addr),
			 -1, "Failed to find proper src addr for R1\n");
		if (!IN6_IS_ADDR_V4MAPPED(r1_dst_addr)) {
			HIP_DEBUG("Destination IPv6, disabling UDP encap\n");
			r1_dst_port = 0;
		}
	}

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
		/* Compiler error:
		   'nonce' undeclared (first use in this function)
		   introduced nonce here and initialized it zero.
		   -Lauri 22.07.2008.
		*/
		uint16_t nonce = 0;
		if((local_plain_hit =
		    (in6_addr_t *)malloc(sizeof(struct in6_addr))) == NULL) {
			err = -1;
			HIP_ERROR("Error when allocating memory to local "\
				  "plain HIT.\n");
			goto out_err;
		}
		HIP_IFEL(hip_plain_fingerprint(
				 &nonce, &i1->hitr, local_plain_hit), -1,
			 "hip_plain_fingerprints() failed.\n");
		
		if (r1_dst_addr)
			HIP_DEBUG_HIT("r1_dst_addr", r1_dst_addr);
		if (r1_src_addr)
			HIP_DEBUG_HIT("r1_src_addr", r1_src_addr);

		if((r1pkt = hip_get_r1(r1_dst_addr, r1_src_addr, local_plain_hit,
				       &i1->hits)) == NULL) {
			HIP_ERROR("Unable to get a precreated R1 packet.\n");
		}

		/* Replace the plain HIT with the blinded HIT. */
		ipv6_addr_copy(&r1pkt->hits, &i1->hitr);
	}
#endif
	if (!hip_blind_get_status()) {
	  HIP_IFEL(!(r1pkt = hip_get_r1(r1_dst_addr, i1_daddr,
					&i1->hitr, &i1->hits)),
		   -ENOENT, "No precreated R1\n");
	}

	if (&i1->hits)
		ipv6_addr_copy(&r1pkt->hitr, &i1->hits);
	else
		memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));

	HIP_DEBUG_HIT("hip_xmit_r1(): ripkt->hitr", &r1pkt->hitr);

#ifdef CONFIG_HIP_RVS
	/* Build VIA_RVS or RELAY_TO parameter if the I1 packet was relayed
	   through a rvs. */
	/** @todo Parameters must be in ascending order, should this
	    be checked here? Now we just assume that the VIA_RVS/RELAY_TO
	    parameter is the last parameter. */
	/* If I1 had a FROM/RELAY_FROM, then we must build a RELAY_TO/VIA_RVS
	   parameter. */
	if(!ipv6_addr_any(dst_ip) && relay_para_type)
	{    // dst_port has the value of RELAY_FROM port.
		//there is port no value for FROM parameter
		//here condition is not enough
		if(relay_para_type == HIP_PARAM_RELAY_FROM)
		{
			HIP_DEBUG("Build param relay from\n");
			hip_build_param_relay_to(
				r1pkt, dst_ip, dst_port);
		}
		else if(relay_para_type == HIP_PARAM_FROM)
		{
			HIP_DEBUG("Build param from\n");
			hip_build_param_via_rvs(r1pkt, i1_saddr);
		}
	}
#endif

	/* R1 is send on UDP if R1 destination port is hip_get_peer_nat_udp_port(). This is if:
	   a) the I1 was received on UDP.
	   b) the received I1 packet had a RELAY_FROM parameter. */
	if(r1_dst_port)
	{
		HIP_IFEL(hip_send_udp(r1_src_addr, r1_dst_addr, hip_get_local_nat_udp_port(),
				      r1_dst_port, r1pkt, NULL, 0),
			 -ECOMM, "Sending R1 packet on UDP failed.\n");
	}
	/* Else R1 is send on raw HIP. */
	else
	{
#ifdef CONFIG_HIP_I3
		if(i1_info->hi3_in_use){
			HIP_IFEL(hip_send_i3(r1_src_addr,
					     r1_dst_addr, 0, 0,
					     r1pkt, NULL, 0),
				 -ECOMM,
				 "Sending R1 packet through i3 failed.\n");
		}
		else
#endif
			HIP_IFEL(hip_send_raw(
					 r1_src_addr,
					 r1_dst_addr, 0, 0,
					 r1pkt, NULL, 0),
				 -ECOMM,
				 "Sending R1 packet on raw HIP failed.\n");

	}

 out_err:
	if (r1pkt)
		HIP_FREE(r1pkt);
	if (local_plain_hit)
	  HIP_FREE(local_plain_hit);
	return err;
}

/**
 * Sends a NOTIFY packet to peer.
 *
 * @param entry a pointer to the current host association database state.
 * @warning     includes hardcoded debug data inserted in the NOTIFICATION.
 */
void hip_send_notify(hip_ha_t *entry)
{
	int err = 0; /* actually not needed, because we can't do
		      * anything if packet sending fails */
	struct hip_common *notify_packet = NULL;
	struct in6_addr daddr;

	HIP_IFE(!(notify_packet = hip_msg_alloc()), -ENOMEM);
	entry->hadb_misc_func->
		hip_build_network_hdr(notify_packet, HIP_NOTIFY, 0,
				      &entry->hit_our, &entry->hit_peer);
	HIP_IFEL(hip_build_param_notification(notify_packet,
					      HIP_NTF_UNSUPPORTED_CRITICAL_PARAMETER_TYPE,
					      "ABCDEFGHIJ", 10), 0,
		 "Building of NOTIFY failed.\n");

        HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), 0);


	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(NULL, &daddr, (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			      entry->peer_udp_port, notify_packet,
			      entry, 0),
		 -ECOMM, "Sending NOTIFY packet failed.\n");

 out_err:
	if (notify_packet)
		HIP_FREE(notify_packet);
	return;
}

/** Temporary kludge for escrow service.
    @todo remove this kludge. */
struct hip_rea_kludge {
	hip_ha_t **array;
	int count;
	int length;
};

/**
 * ...
 *
 * @param entry a pointer to the current host association database state.
 * @param op    a pointer to...
 * @return      ...
 * @todo        Comment this function properly.
 */
static int hip_get_all_valid(hip_ha_t *entry, void *op)
{
	struct hip_rea_kludge *rk = op;

	if (rk->count >= rk->length)
		return -1;

	/* should we check the established status also? */
	if ((entry->hastate & HIP_HASTATE_VALID) == HIP_HASTATE_VALID) {
		rk->array[rk->count] = entry;
		hip_hold_ha(entry);
		rk->count++;
	}

	return 0;
}

/**
 * Sends a NOTIFY packet to all peer hosts.
 *
 */
void hip_send_notify_all(void)
{
        int err = 0, i;
        hip_ha_t *entries[HIP_MAX_HAS] = {0};
        struct hip_rea_kludge rk;

        rk.array = entries;
        rk.count = 0;
        rk.length = HIP_MAX_HAS;

        HIP_IFEL(hip_for_each_ha(hip_get_all_valid, &rk), 0,
		 "for_each_ha failed.\n");
        for (i = 0; i < rk.count; i++) {
                if (rk.array[i] != NULL) {
                        hip_send_notify(rk.array[i]);
                        hip_put_ha(rk.array[i]);
                }
        }

 out_err:
        return;
}

/**
 * ...
 *
 * @param src_addr  a pointer to the packet source address.
 * @param peer_addr a pointer to the packet destination address.
 * @param msg       a pointer to a HIP packet common header with source and
 *                  destination HITs.
 * @param entry     a pointer to the current host association database state.
 * @return          zero on success, or negative error value on error.
 */
int hip_queue_packet(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		     struct hip_common* msg, hip_ha_t *entry)
{
	int err = 0;
	int len = hip_get_msg_total_len(msg);

	_HIP_DEBUG("hip_queue_packet() invoked.\n");
	/* Not reusing the old entry as the new packet may have
	   different length */
	if (!entry)
		goto out_err;
	else if (entry->hip_msg_retrans.buf) {
            HIP_FREE(entry->hip_msg_retrans.buf);
            entry->hip_msg_retrans.buf= NULL;
	}

	HIP_IFE(!(entry->hip_msg_retrans.buf =
		  HIP_MALLOC(len + HIP_UDP_ZERO_BYTES_LEN, 0)), -ENOMEM);
	memcpy(entry->hip_msg_retrans.buf, msg, len);
	memcpy(&entry->hip_msg_retrans.saddr, src_addr,
	       sizeof(struct in6_addr));
	memcpy(&entry->hip_msg_retrans.daddr, peer_addr,
	       sizeof(struct in6_addr));
	entry->hip_msg_retrans.count = HIP_RETRANSMIT_MAX;
	time(&entry->hip_msg_retrans.last_transmit);
out_err:
	return err;
}

/**
 * Sends a HIP message using raw HIP from one source address. Don't use this
 * function directly. It's used by hip_send_raw internally.
 *
 * @see              hip_send_udp
 */
int hip_send_raw_from_one_src(struct in6_addr *local_addr, struct in6_addr *peer_addr,
		 in_port_t src_port, in_port_t dst_port,
		 struct hip_common *msg, hip_ha_t *entry, int retransmit)
{
	int err = 0, sa_size, sent, len, dupl, try_again;
	struct sockaddr_storage src, dst;
	int src_is_ipv4, dst_is_ipv4;
	struct sockaddr_in6 *src6, *dst6;
	struct sockaddr_in *src4, *dst4;
	struct in6_addr my_addr;
	/* Points either to v4 or v6 raw sock */
	int hip_raw_sock_output = 0;

	_HIP_DEBUG("hip_send_raw() invoked.\n");

	/* Verify the existence of obligatory parameters. */
	HIP_ASSERT(peer_addr != NULL && msg != NULL);

	HIP_DEBUG("Sending %s packet on raw HIP.\n",
		  hip_message_type_name(hip_get_msg_type(msg)));
	HIP_DEBUG_IN6ADDR("hip_send_raw(): local_addr", local_addr);
	HIP_DEBUG_IN6ADDR("hip_send_raw(): peer_addr", peer_addr);
	HIP_DEBUG("Source port=%d, destination port=%d\n", src_port, dst_port);
	HIP_DUMP_MSG(msg);

	//check msg length
	if (!hip_check_network_msg_len(msg)) {
		err = -EMSGSIZE;
		HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
		goto out_err;
	}

	dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);
	len = hip_get_msg_total_len(msg);

	/* Some convinient short-hands to avoid too much casting (could be
	   an union as well) */
	src6 = (struct sockaddr_in6 *) &src;
	dst6 = (struct sockaddr_in6 *) &dst;
	src4 = (struct sockaddr_in *)  &src;
	dst4 = (struct sockaddr_in *)  &dst;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	if (dst_is_ipv4) {
	        HIP_DEBUG("Using IPv4 raw socket\n");
		hip_raw_sock_output = hip_raw_sock_output_v4;
		sa_size = sizeof(struct sockaddr_in);
	} else {
		HIP_DEBUG("Using IPv6 raw socket\n");
		hip_raw_sock_output = hip_raw_sock_output_v6;
		sa_size = sizeof(struct sockaddr_in6);
	}

	if (local_addr) {
		HIP_DEBUG("local address given\n");
		memcpy(&my_addr, local_addr, sizeof(struct in6_addr));
	} else {
		HIP_DEBUG("no local address, selecting one\n");
		HIP_IFEL(hip_select_source_address(&my_addr,
						   peer_addr), -1,
			 "Cannot find source address\n");
	}

	src_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&my_addr);

	if (src_is_ipv4) {
		IPV6_TO_IPV4_MAP(&my_addr, &src4->sin_addr);
		src4->sin_family = AF_INET;
		HIP_DEBUG_INADDR("src4", &src4->sin_addr);
	} else {
		memcpy(&src6->sin6_addr, &my_addr,
		       sizeof(struct in6_addr));
		src6->sin6_family = AF_INET6;
		HIP_DEBUG_IN6ADDR("src6", &src6->sin6_addr);
	}

	if (dst_is_ipv4) {
		IPV6_TO_IPV4_MAP(peer_addr, &dst4->sin_addr);
		dst4->sin_family = AF_INET;

		HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
	} else {
		memcpy(&dst6->sin6_addr, peer_addr, sizeof(struct in6_addr));
		dst6->sin6_family = AF_INET6;
		HIP_DEBUG_IN6ADDR("dst6", &dst6->sin6_addr);
	}

	if (src6->sin6_family != dst6->sin6_family) {
	  /* @todo: Check if this may cause any trouble.
	     It happens every time we send update packet that contains few locators in msg, one is
	     the IPv4 address of the source, another is IPv6 address of the source. But even if one of
	     them is ok to send raw IPvX to IPvX raw packet, another one cause the trouble, and all
	     updates are dropped.  by Andrey "laser".

	   */
		err = -1;
		HIP_ERROR("Source and destination address families differ\n");
		goto out_err;
	}

	hip_zero_msg_checksum(msg);
	msg->checksum = hip_checksum_packet((char*)msg,
					    (struct sockaddr *) &src,
					    (struct sockaddr *) &dst);

	/* Note that we need the original (possibly mapped addresses here.
	   Also, we need to do queuing before the bind because the bind
	   can fail the first time during mobility events (duplicate address
	   detection). */
	if (retransmit)
		HIP_IFEL(hip_queue_packet(&my_addr, peer_addr, msg, entry), -1,
			 "Queueing failed.\n");

	/* Handover may cause e.g. on-link duplicate address detection
	   which may cause bind to fail. */

	HIP_IFEL(bind(hip_raw_sock_output, (struct sockaddr *) &src, sa_size),
		 -1, "Binding to raw sock failed\n");

	if (HIP_SIMULATE_PACKET_LOSS && HIP_SIMULATE_PACKET_IS_LOST()) {
		HIP_DEBUG("Packet loss probability: %f\n", ((uint64_t) HIP_SIMULATE_PACKET_LOSS_PROBABILITY * RAND_MAX) / 100.f);
		HIP_DEBUG("Packet was lost (simulation)\n");
		goto out_err;
	}

	/* For some reason, neither sendmsg or send (with bind+connect)
	   do not seem to work properly. Thus, we use just sendto() */

	len = hip_get_msg_total_len(msg);
	_HIP_HEXDUMP("Dumping packet ", msg, len);

	for (dupl = 0; dupl < HIP_PACKET_DUPLICATES; dupl++) {
		for (try_again = 0; try_again < 2; try_again++) {
			sent = sendto(hip_raw_sock_output, msg, len, 0,
				      (struct sockaddr *) &dst, sa_size);
			if (sent != len) {
				HIP_ERROR("Could not send the all requested"\
					  " data (%d/%d)\n", sent, len);
				HIP_DEBUG("strerror %s\n",strerror(errno));
				sleep(2);
			} else {
				HIP_DEBUG("sent=%d/%d ipv4=%d\n",
					  sent, len, dst_is_ipv4);
				HIP_DEBUG("Packet sent ok\n");
				break;
			}
		}
	}
 out_err:

	/* Reset the interface to wildcard or otherwise receiving
	   broadcast messages fails from the raw sockets. A better
	   solution would be to have separate sockets for sending
	   and receiving because we cannot receive a broadcast while
	   sending */
	if (dst_is_ipv4) {
		src4->sin_addr.s_addr = INADDR_ANY;
		src4->sin_family = AF_INET;
		sa_size = sizeof(struct sockaddr_in);
	} else {
		struct in6_addr any = IN6ADDR_ANY_INIT;
		src6->sin6_family = AF_INET6;
		ipv6_addr_copy(&src6->sin6_addr, &any);
		sa_size = sizeof(struct sockaddr_in6);
	}
	bind(hip_raw_sock_output, (struct sockaddr *) &src, sa_size);

	if (err)
		HIP_ERROR("strerror: %s\n", strerror(errno));

	return err;
}

/* Checks if source and destination IP addresses are compatible for sending
 *  packets between them
 *
 * @param src_addr  Source address
 * @param dst_addr  Destination address
 * 
 * @return          non-zero on success, zero on failure
 */
int are_addresses_compatible(struct in6_addr *src_addr, struct in6_addr *dst_addr)
{
    if (!IN6_IS_ADDR_V4MAPPED(src_addr) && IN6_IS_ADDR_V4MAPPED(dst_addr))
        return 0;

    if (IN6_IS_ADDR_V4MAPPED(src_addr) && !IN6_IS_ADDR_V4MAPPED(dst_addr))
        return 0;

    if (!IN6_IS_ADDR_LINKLOCAL(src_addr) && IN6_IS_ADDR_LINKLOCAL(dst_addr))
        return 0;

    if (IN6_IS_ADDR_LINKLOCAL(src_addr) && !IN6_IS_ADDR_LINKLOCAL(dst_addr))
        return 0;

    return 1;
};

/**
 * Sends a HIP message using raw HIP.
 *
 * Sends a HIP message to the peer on HIP/IP. This function calculates the
 * HIP packet checksum.
 *
 * Used protocol suite is <code>IPv4(HIP)</code> or <code>IPv6(HIP)</code>.
 *
 * @param local_addr a pointer to our IPv6 or IPv4-in-IPv6 format IPv4 address.
 *                   If local_addr is NULL, the packet is sent from all addresses.
 * @param peer_addr  a pointer to peer IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param src_port   not used.
 * @param dst_port   not used.
 * @param msg        a pointer to a HIP packet common header with source and
 *                   destination HITs.
 * @param entry      a pointer to the current host association database state.
 * @param retransmit a boolean value indicating if this is a retransmission
 *                   (@b zero if this is @b not a retransmission).
 * @return           zero on success, or negative error value on error.
 * @note             This function should never be used directly. Use
 *                   hip_send_pkt_stateless() or the host association send
 *                   function pointed by the function pointer
 *                   hadb_xmit_func->send_pkt instead.
 * @note             If retransmit is set other than zero, make sure that the
 *                   entry is not NULL.
 * @todo             remove the sleep code (queuing is enough?)
 * @see              hip_send_udp
 */
int hip_send_raw(struct in6_addr *local_addr, struct in6_addr *peer_addr,
		 in_port_t src_port, in_port_t dst_port,
		 struct hip_common *msg, hip_ha_t *entry, int retransmit)
{
    int err = 0;

    struct netdev_address *netdev_src_addr = NULL;
    struct in6_addr *src_addr = NULL;
    hip_list_t *item = NULL, *tmp = NULL;
    int i = 0;

    HIP_DEBUG_IN6ADDR("Destination address:", peer_addr);

    if (local_addr)
    {
        return hip_send_raw_from_one_src(local_addr, peer_addr, src_port,
                dst_port, msg, entry, retransmit);
    }

    HIP_IFEL(hip_shotgun_status != SO_HIP_SHOTGUN_ON, -1,
            "Local address is set to NULL even though the shotgun is off\n");

    list_for_each_safe(item, tmp, addresses, i)
    {
	netdev_src_addr = list_entry(item);
        src_addr = hip_cast_sa_addr(&netdev_src_addr->addr);

        _HIP_DEBUG_IN6ADDR("Source address:", src_addr);

        if (!are_addresses_compatible(src_addr, peer_addr))
            continue;
            
	/* Notice: errors from sending are suppressed intentiously because they occur often */
        hip_send_raw_from_one_src(src_addr, peer_addr, src_port, dst_port,
            msg, entry, retransmit);
    }

out_err:
    return err;
};

/**
 * Sends a HIP message using User Datagram Protocol (UDP). From one address.
 * Don't use this function directly, instead use hip_send_udp()
 *
 * Sends a HIP message to the peer on UDP/IPv4. IPv6 is not supported, because
 * there are no IPv6 NATs deployed in the Internet yet. If either @c local_addr
 * or @c peer_addr is pure (not a IPv4-in-IPv6 format IPv4 address) IPv6
 * address, no message is send. IPv4-in-IPv6 format IPv4 addresses are mapped to
 * pure IPv4 addresses. In case of transmission error, this function tries to
 * retransmit the packet @c HIP_NAT_NUM_RETRANSMISSION times. The HIP packet
 * checksum is set to zero.
 *
 * Used protocol suite is <code>IPv4(UDP(HIP))</code>.
 *
 * @param local_addr a pointer to our IPv4-in-IPv6 format IPv4 address.
 * @param peer_addr  a pointer to peer IPv4-in-IPv6 format IPv4 address.
 * @param src_port   source port number to be used in the UDP packet header
 *                   (host byte order)
 * @param dst_port   destination port number to be used in the UDP packet header.
 *                   (host byte order).
 * @param msg        a pointer to a HIP packet common header with source and
 *                   destination HITs.
 * @param entry      a pointer to the current host association database state.
 * @param retransmit a boolean value indicating if this is a retransmission
 *                   (@b zero if this is @b not a retransmission).
 * @return           zero on success, or negative error value on error.
 * @note             This function should never be used directly. Use
 *                   hip_send_pkt_stateless() or the host association send
 *                   function pointed by the function pointer
 *                   hadb_xmit_func->send_pkt instead.
 * @note             If retransmit is set other than zero, make sure that the
 *                   entry is not NULL.
 * @todo             remove the sleep code (queuing is enough?)
 * @todo             Add support to IPv6 address family.
 * @see              hip_send_raw
 */
int hip_send_udp_from_one_src(struct in6_addr *local_addr,
			      struct in6_addr *peer_addr,
			      in_port_t src_port, in_port_t dst_port,
			      struct hip_common* msg, hip_ha_t *entry,
			      int retransmit)
{
	int sockfd = 0, err = 0, xmit_count = 0;
	struct sockaddr_in src4, dst4;
	uint16_t packet_length = 0;
	ssize_t chars_sent = 0;
	/* If local address is not given, we fetch one in my_addr. my_addr_ptr
	   points to the final source address (my_addr or local_addr). */
	struct in6_addr my_addr, *my_addr_ptr = NULL;
	int memmoved = 0;
	/* sendmsg() crud */
	struct msghdr hdr;
	struct iovec iov;
	unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct cmsghdr *cmsg;
	struct in_pktinfo *pkt_info;

	HIP_DEBUG("hip_send_udp() invoked.\n");

	/* There are four zeroed bytes between UDP and HIP headers. We
	   use shifting later in this function */
	HIP_ASSERT(hip_get_msg_total_len(msg) <=
		   HIP_MAX_NETWORK_PACKET - HIP_UDP_ZERO_BYTES_LEN);

	/* Verify the existence of obligatory parameters. */
	HIP_ASSERT(peer_addr != NULL && msg != NULL);
	HIP_DEBUG("Sending %s packet on UDP.\n",
		  hip_message_type_name(hip_get_msg_type(msg)));
	HIP_DEBUG_IN6ADDR("hip_send_udp(): local_addr", local_addr);
	HIP_DEBUG_IN6ADDR("hip_send_udp(): peer_addr", peer_addr);
	HIP_DEBUG("Source port: %d, destination port: %d.\n",
		  src_port, dst_port);
	HIP_DUMP_MSG(msg);

	/* Currently only IPv4 is supported, so we set internet address family
	   accordingly and map IPv6 addresses to IPv4 addresses. */
	src4.sin_family = dst4.sin_family = AF_INET;

        /* Source address. */
        if (local_addr != NULL) {
		HIP_DEBUG_IN6ADDR("Local address is given", local_addr);
		HIP_IFEL(!IN6_IS_ADDR_V4MAPPED(local_addr), -EPFNOSUPPORT,
			 "Local address is a native IPv6 address, IPv6 address"\
			 "family is currently not supported on UDP/HIP.\n");
		my_addr_ptr = local_addr;
		IPV6_TO_IPV4_MAP(local_addr, &src4.sin_addr);
		//src4.sin_addr.s_addr = htonl(src4.sin_addr.s_addr);
		HIP_DEBUG_INADDR("src4", &src4.sin_addr);
	} else {
		HIP_DEBUG("Local address is NOT given, selecting one.\n");
		HIP_IFEL(hip_select_source_address(&my_addr, peer_addr),
			 -EADDRNOTAVAIL,
			 "Cannot find local address.\n");
		my_addr_ptr = &my_addr;
		IPV6_TO_IPV4_MAP(&my_addr, &src4.sin_addr);
	}

        src4.sin_port = htons(src_port); //< src4.sin_port is not used     
#if 0
        if (src_port != hip_get_local_nat_udp_port())
        	hip_set_local_nat_udp_port(src_port);
#endif

        /* Destination address. */
	HIP_IFEL(!IN6_IS_ADDR_V4MAPPED(peer_addr), -EPFNOSUPPORT,
		 "Peer address is pure IPv6 address, IPv6 address family is "\
		 "currently not supported on UDP/HIP.\n");
	IPV6_TO_IPV4_MAP(peer_addr, &dst4.sin_addr);
	HIP_DEBUG_INADDR("dst4", &dst4.sin_addr);

	if(dst_port != 0) {
		dst4.sin_port = htons(dst_port);
	} else {
		dst4.sin_port = htons(hip_get_peer_nat_udp_port());
	}

	hip_zero_msg_checksum(msg);
	packet_length = hip_get_msg_total_len(msg);

	HIP_DEBUG("Trying to send %u bytes on UDP with source port: %u and "\
		  "destination port: %u.\n",
		  packet_length, ntohs(src4.sin_port), ntohs(dst4.sin_port));

	if (retransmit) {
		HIP_IFEL(hip_queue_packet(my_addr_ptr, peer_addr, msg,
					  entry), -1, "Queueing failed.\n");
	}

	/* Insert 32 bits of zero bytes between UDP and HIP */
	memmove(((char *)msg) + HIP_UDP_ZERO_BYTES_LEN, msg, packet_length);
	memset(msg, 0, HIP_UDP_ZERO_BYTES_LEN);
	packet_length += HIP_UDP_ZERO_BYTES_LEN;
	memmoved = 1;

	/* Pass the correct source address to sendmsg() as ancillary data */
	cmsg = (struct cmsghdr *) &cmsgbuf;
	memset(cmsg, 0, sizeof(cmsgbuf));
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	pkt_info = (struct in_pktinfo *) CMSG_DATA(cmsg);
	pkt_info->ipi_addr.s_addr = src4.sin_addr.s_addr;
	
	memset(&hdr, 0, sizeof(hdr)); /* fixes bug id 621 */

	hdr.msg_name = &dst4;
	hdr.msg_namelen = sizeof(dst4);
	iov.iov_base = msg;
	iov.iov_len = packet_length;
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = &cmsgbuf;
	hdr.msg_controllen = sizeof(cmsgbuf);

	/* Try to send the data. */
	do {
		chars_sent = sendmsg(hip_nat_sock_output_udp, &hdr, 0);
		if(chars_sent < 0) {
			HIP_DEBUG("Problem in sending UDP packet. Sleeping "\
				  "for %d seconds and trying again.\n",
				  HIP_NAT_SLEEP_TIME);
			sleep(HIP_NAT_SLEEP_TIME);
		} else {
			break;
		}
		xmit_count++;
	} while(xmit_count < HIP_NAT_NUM_RETRANSMISSION);

	/* Verify that the message was sent completely. */
	HIP_IFEL((chars_sent != packet_length), -ECOMM,
		 "Error while sending data on UDP: %d bytes of %d sent.)\n",
		 chars_sent, packet_length);

	HIP_DEBUG("Packet sent successfully over UDP, characters sent: %u, "\
		  "packet length: %u.\n", chars_sent, packet_length);

 out_err:

	/* Reset the interface to wildcard or otherwise receiving
	   broadcast messages fails from the raw sockets. A better
	   solution would be to have separate sockets for sending
	   and receiving because we cannot receive a broadcast while
	   sending */

	/* currently disabled because I could not make this work -miika
	   src4.sin_addr.s_addr = INADDR_ANY;
	   src4.sin_family = AF_INET;
	   bind(hip_nat_sock_udp, (struct sockaddr *) &src4, sizeof(struct sockaddr_in));
	*/

	if (sockfd)
		close(sockfd);

	if (memmoved) {
		/* Remove 32 bits of zero bytes between UDP and HIP */
		packet_length -= HIP_UDP_ZERO_BYTES_LEN;
		memmove(msg, ((char *)msg) + HIP_UDP_ZERO_BYTES_LEN,
			packet_length);
		memset(((char *)msg) + packet_length, 0,
		       HIP_UDP_ZERO_BYTES_LEN);
	}

	return err;
}

int hip_send_udp(struct in6_addr *local_addr, struct in6_addr *peer_addr,
		 in_port_t src_port, in_port_t dst_port,
		 struct hip_common *msg, hip_ha_t *entry, int retransmit)
{
    int err = 0;

    struct netdev_address *netdev_src_addr = NULL;
    struct in6_addr *src_addr = NULL;
    hip_list_t *item = NULL, *tmp = NULL;
    int i = 0;

    HIP_DEBUG_IN6ADDR("Destination address:", peer_addr);

    if (local_addr)
    {
	if (IN6_IS_ADDR_V4MAPPED(peer_addr))
	    return hip_send_udp_from_one_src(local_addr, peer_addr, src_port,
					 dst_port, msg, entry, retransmit);
	else
		hip_send_raw_from_one_src(src_addr, peer_addr, src_port, dst_port,
					  msg, entry, retransmit);
    }

    HIP_IFEL(hip_shotgun_status != SO_HIP_SHOTGUN_ON, -1,
            "Local address is set to NULL even though the shotgun is off\n");

    list_for_each_safe(item, tmp, addresses, i)
    {
	netdev_src_addr = list_entry(item);
        src_addr = hip_cast_sa_addr(&netdev_src_addr->addr);

        _HIP_DEBUG_IN6ADDR("Source address:", src_addr);

        if (!are_addresses_compatible(src_addr, peer_addr))
            continue;
            
	/* Notice: errors from sending are suppressed intentiously because they occur often */
	if (IN6_IS_ADDR_V4MAPPED(peer_addr))
		hip_send_udp_from_one_src(src_addr, peer_addr, src_port, dst_port,
					  msg, entry, retransmit);
	else
		hip_send_raw_from_one_src(src_addr, peer_addr, src_port, dst_port,
					  msg, entry, retransmit);
    }

out_err:
    return err;
};


/**
 * This function sends ICMPv6 echo with timestamp to dsthit
 *
 * @param socket to send with
 * @param srchit HIT to send from
 * @param dsthit HIT to send to
 *
 * @return 0 on success negative on error
 */
int hip_send_icmp(int sockfd, hip_ha_t *entry) {
	int err = 0, i = 0, identifier = 0;
#ifdef ANDROID_CHANGES
	struct icmp6_hdr * icmph = NULL;
#else
	struct icmp6hdr * icmph = NULL;
#endif
	struct sockaddr_in6 dst6;
	u_char cmsgbuf[CMSG_SPACE(sizeof (struct in6_pktinfo))];
	u_char * icmp_pkt = NULL;
	struct msghdr mhdr;
	struct iovec iov[1];
	struct cmsghdr * chdr;
        struct in6_pktinfo * pkti;
	struct timeval tval;

	_HIP_DEBUG("Starting to send ICMPv6 heartbeat\n");

	/* memset and malloc everything you need */
	memset(&mhdr, 0, sizeof(struct msghdr));
	memset(&tval, 0, sizeof(struct timeval));
	memset(cmsgbuf, 0, sizeof(cmsgbuf));
	memset(iov, 0, sizeof(struct iovec));
	memset(&dst6, 0, sizeof(dst6));

	icmp_pkt = malloc(HIP_MAX_ICMP_PACKET);
        HIP_IFEL((!icmp_pkt), -1, "Malloc for icmp_pkt failed\n");
	memset(icmp_pkt, 0, sizeof(HIP_MAX_ICMP_PACKET));

        chdr = (struct cmsghdr *)cmsgbuf;
	pkti = (struct in6_pktinfo *)(CMSG_DATA(chdr));

	identifier = getpid() & 0xFFFF;

	/* Build ancillary data */
	chdr->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_PKTINFO;
	memcpy(&pkti->ipi6_addr, &entry->hit_our, sizeof(struct in6_addr));

	/* get the destination */
	memcpy(&dst6.sin6_addr, &entry->hit_peer, sizeof(struct in6_addr));
	dst6.sin6_family = AF_INET6;
	dst6.sin6_flowinfo = 0;

	/* build icmp header */
#ifdef ANDROID_CHANGES
	icmph = (struct icmp6_hdr *)icmp_pkt;
	icmph->icmp6_type = ICMP6_ECHO_REQUEST;
#else
	icmph = (struct icmp6hdr *)icmp_pkt;
	icmph->icmp6_type = ICMPV6_ECHO_REQUEST;
#endif
	icmph->icmp6_code = 0;
	entry->heartbeats_sent++;

#ifdef ANDROID_CHANGES
	icmph->icmp6_seq = htons(entry->heartbeats_sent);
	icmph->icmp6_id = identifier;
#else
	icmph->icmp6_sequence = htons(entry->heartbeats_sent);
	icmph->icmp6_identifier = identifier;
#endif

	gettimeofday(&tval, NULL);

	memset(&icmp_pkt[8], 0xa5, HIP_MAX_ICMP_PACKET - 8);
 	/* put timeval into the packet */
	memcpy(&icmp_pkt[8], &tval, sizeof(struct timeval));

	/* put the icmp packet to the io vector struct for the msghdr */
	iov[0].iov_base = icmp_pkt;
#ifdef ANDROID_CHANGES
	iov[0].iov_len  = sizeof(struct icmp6_hdr) + sizeof(struct timeval);
#else
	iov[0].iov_len  = sizeof(struct icmp6hdr) + sizeof(struct timeval);
#endif
	/* build the msghdr for the sendmsg, put ancillary data also*/
	mhdr.msg_name = &dst6;
	mhdr.msg_namelen = sizeof(struct sockaddr_in6);
	mhdr.msg_iov = iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = &cmsgbuf;
	mhdr.msg_controllen = sizeof(cmsgbuf);

	i = sendmsg(sockfd, &mhdr, 0);
	if (i <= 0)
		HIP_PERROR("sendmsg");

	/* Debug information*/
	_HIP_DEBUG_HIT("src hit", &entry->hit_our);
	_HIP_DEBUG_HIT("dst hit", &entry->hit_peer);
	_HIP_DEBUG("i == %d socket = %d\n", i, sockfd);
	HIP_PERROR("SENDMSG ");

	HIP_IFEL((i < 0), -1, "Failed to send ICMP into ESP tunnel\n");
	HIP_DEBUG_HIT("Succesfully sent heartbeat to", &entry->hit_peer);

out_err:
	if (icmp_pkt)
		free(icmp_pkt);
	return err;
}


#ifdef CONFIG_HIP_I3
/**
 * Hi3 outbound traffic processing.
 *
 * @param src_addr  a pointer to our IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param peer_addr a pointer to peer IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param not_used  source port number. Not in use.
 * @param not_used2 destination port number. Not in use.
 * @param msg       a pointer to a HIP packet common header with source and
 *                  destination HITs.
 * @param not_used3 a pointer to the current host association database state.
 *                  Not in use.
 * @param not_used4 a boolean value indicating if this is a retransmission
 *                  (@b zero if this is @b not a retransmission). Not in use.
 * @note            There are four parameters not used anywhere. However, these
 *                  parameters must exist in the function parameter list
 *                  because all the send-functions must have a uniform parameter
 *                  list as dictated by @c hip_hadb_xmit_func_set.
 * @todo            For now this supports only serialiazation of IPv6 addresses
 *                  to Hi3 header.
 * @todo            This function is outdated. Does not support in6 mapped
 *                  addresses and retransmission queues -mk
 * @todo            Does this support NAT travelsal? Or is it even supposed to
 *                  support it?
 *
 */
int hip_send_i3(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		in_port_t not_used, in_port_t not_used2, struct hip_common *msg,
		hip_ha_t *not_used3, int not_used4)
{
	ID id;
	cl_buf *clb;
  	u16 csum;
	int err = 0, msg_len;
	char *buf;

	//check msg length
	if (!hip_check_network_msg_len(msg)) {
		err = -EMSGSIZE;
		HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
		goto out_err;
	}

	msg_len = hip_get_msg_total_len(msg);

	clb = cl_alloc_buf(msg_len);
	if (!clb) {
		HIP_ERROR("Out of memory\n.");
		return -1;
	}

	buf = clb->data;

	hip_zero_msg_checksum(msg);
//	msg->checksum = hip_checksum_packet((char *)msg,
//					    (struct sockaddr *)&src,
//					    (struct sockaddr *)&dst);

	clb->data_len = msg_len;

	memcpy(buf, msg, msg_len);

	/* Send over i3 */
	bzero(&id, ID_LEN);
	memcpy(&id, &msg->hitr, sizeof(struct in6_addr));
	cl_set_private_id(&id);

	/* exception when matching trigger not found */
	cl_send(&id, clb, 0);
	cl_free_buf(clb);

 out_err:
	return err;
}
#endif

/**
 * Sends a HIP message using User Datagram Protocol (UDP).
 *
 * Sends a HIP message to the peer on UDP/IPv4. IPv6 is not supported, because
 * there are no IPv6 NATs deployed in the Internet yet. If either @c local_addr
 * or @c peer_addr is pure (not a IPv4-in-IPv6 format IPv4 address) IPv6
 * address, no message is send. IPv4-in-IPv6 format IPv4 addresses are mapped to
 * pure IPv4 addresses. In case of transmission error, this function tries to
 * retransmit the packet @c HIP_NAT_NUM_RETRANSMISSION times. The HIP packet
 * checksum is set to zero.
 *
 * Used protocol suite is <code>IPv4(UDP(HIP))</code>.
 *
 * @param local_addr a pointer to our IPv4-in-IPv6 format IPv4 address.
 * @param peer_addr  a pointer to peer IPv4-in-IPv6 format IPv4 address.
 * @param src_port   source port number to be used in the UDP packet header
 *                   (host byte order)
 * @param dst_port   destination port number to be used in the UDP packet header.
 *                   (host byte order).
 * @param msg        a pointer to a HIP packet common header with source and
 *                   destination HITs.
 * @param entry      a pointer to the current host association database state.
 * @param retransmit a boolean value indicating if this is a retransmission
 *                   (@b zero if this is @b not a retransmission).
 * @return           zero on success, or negative error value on error.
 * @note             This function should never be used directly. Use
 *                   hip_send_pkt_stateless() or the host association send
 *                   function pointed by the function pointer
 *                   hadb_xmit_func->send_pkt instead.
 * @note             If retransmit is set other than zero, make sure that the
 *                   entry is not NULL.
 * @todo             remove the sleep code (queuing is enough?)
 * @todo             Add support to IPv6 address family.
 * @see              hip_send_raw
 */
int hip_send_udp_stun(struct in6_addr *local_addr, struct in6_addr *peer_addr,
		 in_port_t src_port, in_port_t dst_port,
		 void* msg , int length)
{
	int sockfd = 0, err = 0, xmit_count = 0;
	/* IPv4 Internet socket addresses. */
	struct sockaddr_in src4, dst4;
	/* Length of the HIP message. */
	uint16_t packet_length = 0;
	/* Number of characters sent. */
	ssize_t chars_sent = 0;
	/* If local address is not given, we fetch one in my_addr. my_addr_ptr
	   points to the final source address (my_addr or local_addr). */
	struct in6_addr my_addr, *my_addr_ptr = NULL;
	int memmoved = 0;

	struct msghdr hdr;
	struct iovec iov;
	unsigned char cmsgbuf[CMSG_SPACE(sizeof(struct in_pktinfo))];
	struct cmsghdr *cmsg;
	struct in_pktinfo *pkt_info;

	_HIP_DEBUG("hip_send_udp() invoked.\n");


	/* Verify the existence of obligatory parameters. */
	HIP_ASSERT(peer_addr != NULL && msg != NULL);

	HIP_DEBUG_IN6ADDR("hip_send_udp_stun(): local_addr", local_addr);
	HIP_DEBUG_IN6ADDR("hip_send_udp_stun(): peer_addr", peer_addr);
	HIP_DEBUG("Source port: %d, destination port: %d.\n",
		  src_port, dst_port);
//	HIP_DUMP_MSG(msg);

	/* Currently only IPv4 is supported, so we set internet address family
	   accordingly and map IPv6 addresses to IPv4 addresses. */
	src4.sin_family = dst4.sin_family = AF_INET;

        /* Source address. */
        if (local_addr != NULL) {
		HIP_DEBUG_IN6ADDR("Local address is given", local_addr);
		HIP_IFEL(!IN6_IS_ADDR_V4MAPPED(local_addr), -EPFNOSUPPORT,
			 "Local address is a native IPv6 address, IPv6 address"\
			 "family is currently not supported on UDP/HIP.\n");
		my_addr_ptr = local_addr;
		IPV6_TO_IPV4_MAP(local_addr, &src4.sin_addr);
		//src4.sin_addr.s_addr = htonl(src4.sin_addr.s_addr);
		HIP_DEBUG_INADDR("src4", &src4.sin_addr);
	} else {
		HIP_DEBUG("Local address is NOT given, selecting one.\n");
		HIP_IFEL(hip_select_source_address(&my_addr, peer_addr),
			 -EADDRNOTAVAIL,
			 "Cannot find local address.\n");
		my_addr_ptr = &my_addr;
		IPV6_TO_IPV4_MAP(&my_addr, &src4.sin_addr);
	}

        /* Destination address. */
	HIP_IFEL(!IN6_IS_ADDR_V4MAPPED(peer_addr), -EPFNOSUPPORT,
		 "Peer address is pure IPv6 address, IPv6 address family is "\
		 "currently not supported on UDP/HIP.\n");
	IPV6_TO_IPV4_MAP(peer_addr, &dst4.sin_addr);
	HIP_DEBUG_INADDR("dst4", &dst4.sin_addr);

        /* Source port */
	if(src_port != 0) {
		src4.sin_port = htons(src_port);
	}
	else {
		src4.sin_port = 0;
	}

	/* Destination port. */
	if(dst_port != 0) {
		dst4.sin_port = htons(dst_port);
	}
	else {
		dst4.sin_port = htons(hip_get_peer_nat_udp_port());
	}

	/* Zero message HIP checksum. */
	//hip_zero_msg_checksum(msg);

	/* Get the packet total length for sendto(). */
	packet_length = length;

	HIP_DEBUG("Trying to send %u bytes stun on UDP with source port: %u and "\
		  "destination port: %u.\n",
		  packet_length, ntohs(src4.sin_port), ntohs(dst4.sin_port));



	/* Insert 32 bits of zero bytes between UDP and HIP */
	/*
	memmove(((char *)msg) + HIP_UDP_ZERO_BYTES_LEN, msg, packet_length);
	memset(msg, 0, HIP_UDP_ZERO_BYTES_LEN);
	packet_length += HIP_UDP_ZERO_BYTES_LEN;
	memmoved = 1;
*/
	/*
	  Currently disabled because I could not make this work -miika
	HIP_IFEL(bind(hip_nat_sock_udp, (struct sockaddr *) &src4, sizeof(src4)),
		 -1, "Binding to udp sock failed\n");

	*/

	/* Pass the correct source address to sendmsg() as ancillary data */
	cmsg = (struct cmsghdr *) &cmsgbuf;
	memset(cmsg, 0, sizeof(cmsgbuf));
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_PKTINFO;
	pkt_info = CMSG_DATA(cmsg);
	pkt_info->ipi_addr.s_addr = src4.sin_addr.s_addr;

	hdr.msg_name = &dst4;
	hdr.msg_namelen = sizeof(dst4);
	iov.iov_base = msg;
	iov.iov_len = packet_length;
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = &cmsgbuf;
	hdr.msg_controllen = sizeof(cmsgbuf);

	/* Try to send the data. */
	do {
		//chars_sent = sendto(hip_nat_sock_udp, msg, packet_length, 0,
				    //(struct sockaddr *) &dst4, sizeof(dst4));
		chars_sent = sendmsg(hip_nat_sock_output_udp, &hdr, 0);
		if(chars_sent < 0)
		{
			/* Failure. */
			HIP_DEBUG("Problem in sending UDP packet. Sleeping "\
				  "for %d seconds and trying again.\n",
				  HIP_NAT_SLEEP_TIME);
			sleep(HIP_NAT_SLEEP_TIME);
		}
		else
		{
			/* Success. */
			break;
		}
		xmit_count++;
	} while(xmit_count < HIP_NAT_NUM_RETRANSMISSION);

	/* Verify that the message was sent completely. */
	HIP_IFEL((chars_sent != packet_length), -ECOMM,
		 "Error while sending data on UDP_STUN: %d bytes of %d sent.)\n",
		 chars_sent, packet_length);

	HIP_DEBUG("Packet sent successfully over UDP_STUN, characters sent: %u, "\
		  "packet length: %u.\n", chars_sent, packet_length);

 out_err:

	/* Reset the interface to wildcard or otherwise receiving
	   broadcast messages fails from the raw sockets. A better
	   solution would be to have separate sockets for sending
	   and receiving because we cannot receive a broadcast while
	   sending */

	/* currently disabled because I could not make this work -miika
	   src4.sin_addr.s_addr = INADDR_ANY;
	   src4.sin_family = AF_INET;
	   bind(hip_nat_sock_udp, (struct sockaddr *) &src4, sizeof(struct sockaddr_in));
	*/

	if (sockfd)
		close(sockfd);
#if 0
	if (memmoved) {
		/* Remove 32 bits of zero bytes between UDP and HIP */
		packet_length -= HIP_UDP_ZERO_BYTES_LEN;
		memmove(msg, ((char *)msg) + HIP_UDP_ZERO_BYTES_LEN,
			packet_length);
		memset(((char *)msg) + packet_length, 0,
		       HIP_UDP_ZERO_BYTES_LEN);
	}
#endif
	return err;
}

