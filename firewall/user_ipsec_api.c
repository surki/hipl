/**
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "user_ipsec_api.h"

/* this is the ESP packet we are about to build */
unsigned char *esp_packet = NULL;
/* the original packet before ESP decryption */
unsigned char *decrypted_packet = NULL;

/* sockets needed in order to reinject the ESP packet into the network stack */
int raw_sock_v4 = 0, raw_sock_v6 = 0;
/* allows us to make sure that we only init ones */
int is_init = 0;
int init_hipd = 0; /* 0 = hipd does not know that userspace ipsec on */
extern int hip_datapacket_mode; 

int hip_fw_userspace_ipsec_init_hipd(int activate) {
	int err = 0;
	// TODO add (small, ring-) buffer here                                                                                                                                                                       
	HIP_IFE(init_hipd, 0);

	HIP_IFEL(send_userspace_ipsec_to_hipd(1), -1,
		 "hipd is not responding\n");

	HIP_DEBUG("hipd userspace ipsec activated\n");
	init_hipd = 1;

out_err:

	return err;
}

int init_raw_sockets() {
	int err = 0, on = 1;

	// open IPv4 raw socket
	raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (raw_sock_v4 < 0)
	{
		HIP_DEBUG("*** ipv4_raw_socket socket() error for raw socket\n");

		err = -1;
		goto out_err;
	}
	// this option allows us to add the IP header ourselves
	if (setsockopt(raw_sock_v4, IPPROTO_IP, IP_HDRINCL, (char *)&on,
		       sizeof(on)) < 0)
	{
		HIP_DEBUG("*** setsockopt() error for IPv4 raw socket\n");

		err = 1;
		goto out_err;
	}

	// open IPv6 raw socket, no options needed here
	raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (raw_sock_v6 < 0) {
		HIP_DEBUG("*** ipv6_raw_socket socket() error for raw socket\n");

		err = 1;
		goto out_err;
	}
	// this option allows us to add the IP header ourselves
	if (setsockopt(raw_sock_v6, IPPROTO_IPV6, IP_HDRINCL, (char *)&on,
		       sizeof(on)) < 0)
	{
		HIP_DEBUG("*** setsockopt() error for IPv6 raw socket\n");

		err = 1;
		goto out_err;
	}

 out_err:
	return err;
}

int userspace_ipsec_init()
{
	int err = 0;
	int activate = 1;

	HIP_DEBUG("\n");

	if (!is_init)
	{
		// init sadb
		HIP_IFEL(hip_sadb_init(), -1, "failed to init sadb\n");

		HIP_DEBUG("ESP_PACKET_SIZE is %i\n", ESP_PACKET_SIZE);
		// allocate memory for the packet buffers
		HIP_IFE(!(esp_packet = (unsigned char *)malloc(ESP_PACKET_SIZE)), -1);
		HIP_IFE(!(decrypted_packet = (unsigned char *)malloc(ESP_PACKET_SIZE)), -1);

		// activate userspace ipsec in hipd
		HIP_DEBUG("switching hipd to userspace ipsec...\n");
		hip_fw_userspace_ipsec_init_hipd(activate);

		is_init = 1;

		HIP_DEBUG("userspace IPsec successfully initialised\n");
	}

  out_err:
  	return err;
}

int userspace_ipsec_uninit()
{
	int activate = 0;
	int err = 0;

	// deactivate userspace ipsec in hipd
	HIP_DEBUG("switching hipd to kernel-mode ipsec...\n");
	err = send_userspace_ipsec_to_hipd(activate);
	if (err)
		HIP_ERROR("failed to notify hipd about userspace ipsec deactivation\n");

	// uninit sadb
	HIP_IFEL(hip_sadb_uninit(), -1, "failed to uninit sadb\n");

	// close sockets used for reinjection
	if (raw_sock_v4)
		close(raw_sock_v4);
	if (raw_sock_v6)
		close(raw_sock_v6);

	// free the members
	if (esp_packet)
		free(esp_packet);
	if (decrypted_packet)
		free(decrypted_packet);

  out_err:
	return err;
}


int hip_fw_userspace_ipsec_output(hip_fw_context_t *ctx)
{
	// entry matching the peer HIT
	hip_sa_entry_t *entry = NULL;
	// the routable addresses as used in HIPL
	struct in6_addr preferred_local_addr;
	struct in6_addr preferred_peer_addr;
	struct sockaddr_storage preferred_peer_sockaddr;
	struct timeval now;
	uint16_t esp_packet_len = 0;
	int out_ip_version = 0;
	int err = 0;
	struct ip6_hdr *ip6_hdr;
	uint16_t data_packet_len = 0;
	unsigned char *hip_data_packet_output = NULL;

#if 0	
	// this should already be done in userspace_ipsec_init()
        HIP_IFEL(hip_fw_userspace_ipsec_init_hipd(1), 1,
		 "Drop ESP packet until hipd is available\n");
#endif

	/* we should only get HIT addresses here
	 * LSI have been handled by LSI module before and converted to HITs */
	HIP_ASSERT(ipv6_addr_is_hit(&ctx->src) && ipv6_addr_is_hit(&ctx->dst));

       /* TODO check buffer for packets and do the following processing on them as well                                                                                                                       
        * NOTE ensure that you do NOT trigger the BEX with buffered packets, although                                                                                                                         
        *      hipd should handle duplicate BEX initiations well                                                                                                                                              
        */    

	HIP_DEBUG("original packet length: %u \n", ctx->ipq_packet->data_len);
	_HIP_HEXDUMP("original packet :", ctx->ipq_packet->payload, ctx->ipq_packet->data_len);

	ip6_hdr = (struct ip6_hdr *)ctx->ipq_packet->payload;

	HIP_DEBUG("ip6_hdr->ip6_vfc: 0x%x \n", ip6_hdr->ip6_vfc);
	HIP_DEBUG("ip6_hdr->ip6_plen: %u \n", ntohs(ip6_hdr->ip6_plen));
	HIP_DEBUG("ip6_hdr->ip6_nxt: %u \n", ip6_hdr->ip6_nxt);
	HIP_DEBUG("ip6_hdr->ip6_hlim: %u \n", ip6_hdr->ip6_hlim);

	HIP_DEBUG_HIT("src_hit", &ctx->src);
	HIP_DEBUG_HIT("dst_hit", &ctx->dst);

	gettimeofday(&now, NULL);

	// SAs directing outwards are indexed with local and peer HIT

	entry = hip_sa_entry_find_outbound(&ctx->src, &ctx->dst);
        
       /* If there is no Entry, meaning we are trying for new connection. Then only use DATA Packet mode */
 
	// create new SA entry, if none exists yet
	if (entry == NULL) {
		HIP_DEBUG("triggering BEX...\n");

		/* no SADB entry -> trigger base exchange providing src and dst hit as
		 * used by the application */

		HIP_IFEL(hip_trigger_bex(&ctx->src, &ctx->dst, NULL, NULL, NULL, NULL), -1,
			 "trigger bex\n");
               
		/* Modified by Prabhu to support DATA Packet Mode.
		   Hip Daemon doesnt send the i1 packet , if data packet mode is on. 
		   It just updates the preferred address in HADB and returns */
			
		if (hip_datapacket_mode ){
			if(firewall_cache_db_match(&ctx->src, &ctx->dst, NULL, NULL,
						   &preferred_local_addr, &preferred_peer_addr, NULL))
				HIP_DEBUG("HIP_DATAPACKET MODE is Already Set so using DATA PACKET MODE for new connections\n");
			goto process_next;
		}
                        
		// as we don't buffer the packet right now, we have to drop it
		// due to not routable addresses
		err = 1;
		// don't process this message any further
		goto out_err;
	}

	HIP_DEBUG("matching SA entry found\n");

	/* get preferred routable addresses */
	// XX TODO add multihoming support -> look up preferred address here
	memcpy(&preferred_local_addr, entry->src_addr, sizeof(struct in6_addr));
	memcpy(&preferred_peer_addr, entry->dst_addr, sizeof(struct in6_addr));


process_next:

	HIP_DEBUG_HIT("preferred_local_addr", &preferred_local_addr);
	HIP_DEBUG_HIT("preferred_peer_addr", &preferred_peer_addr);

	// check preferred addresses for the address type of the output
	if (IN6_IS_ADDR_V4MAPPED(&preferred_local_addr)
			&& IN6_IS_ADDR_V4MAPPED(&preferred_peer_addr))
	{
		HIP_DEBUG("out_ip_version is IPv4\n");
		out_ip_version = 4;
	} else if (!IN6_IS_ADDR_V4MAPPED(&preferred_local_addr)
			&& !IN6_IS_ADDR_V4MAPPED(&preferred_peer_addr))
	{
		HIP_DEBUG("out_ip_version is IPv6\n");
		out_ip_version = 6;
	} else
	{
		HIP_ERROR("bad address combination\n");

		err = -1;
		goto out_err;
	}
       
        if (hip_datapacket_mode) {
        	HIP_DEBUG("ESP_PACKET_SIZE is %i\n", ESP_PACKET_SIZE);
		hip_data_packet_output = (char *)malloc(ESP_PACKET_SIZE);
		
		HIP_IFEL(hip_data_packet_mode_output(ctx, &preferred_local_addr, &preferred_peer_addr,
						     hip_data_packet_output, &data_packet_len), 1, "failed to create HIP_DATA_PACKET_MODE packet");
		
		
		HIP_DEBUG(hip_data_packet_output);
		
		// create sockaddr for sendto
		hip_addr_to_sockaddr(&preferred_peer_addr, &preferred_peer_sockaddr);
		
		// reinsert the esp packet into the network stack
		if (out_ip_version == 4)
			err = sendto(raw_sock_v4, hip_data_packet_output, data_packet_len, 0,
				     (struct sockaddr *)&preferred_peer_sockaddr,
				     hip_sockaddr_len(&preferred_peer_sockaddr));
		else
			err = sendto(raw_sock_v6, hip_data_packet_output, data_packet_len, 0,
				     (struct sockaddr *)&preferred_peer_sockaddr,
				     hip_sockaddr_len(&preferred_peer_sockaddr));

		if (err < data_packet_len) {
			HIP_DEBUG("sendto() failed  sent %d    received %d\n",data_packet_len,err);
			printf("sendto() failed\n");
			err = -1;
			goto out_err;
		} else {
			HIP_DEBUG("new packet SUCCESSFULLY re-inserted into network stack\n");
			HIP_DEBUG("dropping original packet...\n");
			// the original packet has to be dropped
			err = 1;
			goto out_err;

		}
	}

        // encrypt transport layer and create new packet
        HIP_IFEL(hip_beet_mode_output(ctx, entry, &preferred_local_addr, &preferred_peer_addr,
			esp_packet, &esp_packet_len), 1, "failed to create ESP packet");
	   // create sockaddr for sendto
        hip_addr_to_sockaddr(&preferred_peer_addr, &preferred_peer_sockaddr);

	// create sockaddr for sendto
	hip_addr_to_sockaddr(&preferred_peer_addr, &preferred_peer_sockaddr);

	// reinsert the esp packet into the network stack
	if (out_ip_version == 4)
		err = sendto(raw_sock_v4, esp_packet, esp_packet_len, 0,
				(struct sockaddr *)&preferred_peer_sockaddr,
				hip_sockaddr_len(&preferred_peer_sockaddr));
	else
		err = sendto(raw_sock_v6, esp_packet, esp_packet_len, 0,
						(struct sockaddr *)&preferred_peer_sockaddr,
						hip_sockaddr_len(&preferred_peer_sockaddr));

	if (err < esp_packet_len) {
		HIP_DEBUG("sendto() failed\n");
		//printf("sendto() failed\n");
		err = -1;
	} else
	{
		HIP_DEBUG("new packet SUCCESSFULLY re-inserted into network stack\n");
		HIP_DEBUG("dropping original packet...\n");

		// update SA statistics for replay protection etc
		pthread_mutex_lock(&entry->rw_lock);
		entry->bytes += err;
		entry->usetime.tv_sec = now.tv_sec;
		entry->usetime.tv_usec = now.tv_usec;
		entry->usetime_ka.tv_sec = now.tv_sec;
		entry->usetime_ka.tv_usec = now.tv_usec;
		pthread_mutex_unlock(&entry->rw_lock);

		// the original packet has to be dropped
		err = 1;
	}

	// now do some esp token maintenance operations
	HIP_IFEL(esp_prot_sadb_maintenance(entry), -1,
			"esp protection extension maintenance operations failed\n");

  out_err:
	if (hip_data_packet_output)
		free(hip_data_packet_output);

  	return err;
}

int hip_fw_userspace_ipsec_input(hip_fw_context_t *ctx)
{
	struct hip_esp *esp_hdr = NULL;
	struct hip_esp_ext *esp_exthdr = NULL;
	struct sockaddr_storage local_sockaddr;
	// entry matching the SPI
	hip_sa_entry_t *entry = NULL;
	// return entry
	hip_sa_entry_t *inverse_entry = NULL;
	struct in6_addr src_hit;
	struct in6_addr dst_hit;
	struct timeval now;
	uint16_t decrypted_packet_len = 0;
	uint32_t spi = 0;
	uint32_t seq_no = 0;
	uint32_t hash = 0;
	unsigned char *sent_hc_element = NULL;
	int err = 0;

// this should already be done in userspace_ipsec_init()
#if 0
	HIP_IFEL(hip_fw_userspace_ipsec_init_hipd(1), 1,
		 "Drop ESP packet until hipd is available\n");
#endif

	// we should only get ESP packets here
	HIP_ASSERT(ctx->packet_type == ESP_PACKET);

	gettimeofday(&now, NULL);

	/* get ESP header of input packet
	 * UDP encapsulation is handled in firewall already */
	esp_hdr = ctx->transport_hdr.esp;
	spi = ntohl(esp_hdr->esp_spi);
	seq_no = ntohl(esp_hdr->esp_seq);

	// lookup corresponding SA entry by dst_addr and SPI
	HIP_IFEL(!(entry = hip_sa_entry_find_inbound(&ctx->dst, spi)), -1,
			"no SA entry found for dst_addr and SPI\n");
	HIP_DEBUG("matching SA entry found\n");

	// do a partial consistency check of the entry
	HIP_ASSERT(entry->inner_src_addr && entry->inner_dst_addr);

	HIP_DEBUG_HIT("src hit: ", entry->inner_src_addr);
	HIP_DEBUG_HIT("dst hit: ", entry->inner_dst_addr);

	// XX TODO implement check with seq window
	// check for correct SEQ no.
	_HIP_DEBUG("SEQ no. of entry: %u \n", entry->sequence);
	_HIP_DEBUG("SEQ no. of incoming packet: %u \n", seq_no);
	//HIP_IFEL(entry->sequence != seq_no, -1, "ESP sequence numbers do not match\n");


// this is helpful for testing
#if 0
	// check if we have a SA entry to reply to
	HIP_DEBUG("checking for inverse entry\n");
	HIP_IFEL(!(inverse_entry = hip_sa_entry_find_outbound(entry->inner_dst_addr,
			entry->inner_src_addr)), -1,
			"corresponding sadb entry for outgoing packets not found\n");
#endif

	// decrypt the packet and create a new HIT-based one
	HIP_IFEL(hip_beet_mode_input(ctx, entry, decrypted_packet, &decrypted_packet_len), 1,
			"failed to recreate original packet\n");

	_HIP_HEXDUMP("restored original packet: ", decrypted_packet, decrypted_packet_len);
	struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)decrypted_packet;
	HIP_DEBUG("ip6_hdr->ip6_vfc: 0x%x \n", ip6_hdr->ip6_vfc);
	HIP_DEBUG("ip6_hdr->ip6_plen: %u \n", ip6_hdr->ip6_plen);
	HIP_DEBUG("ip6_hdr->ip6_nxt: %u \n", ip6_hdr->ip6_nxt);
	HIP_DEBUG("ip6_hdr->ip6_hlim: %u \n", ip6_hdr->ip6_hlim);

	// create sockaddr for sendto
	hip_addr_to_sockaddr(entry->inner_dst_addr, &local_sockaddr);

	// re-insert the original HIT-based (-> IPv6) packet into the network stack
	err = sendto(raw_sock_v6, decrypted_packet, decrypted_packet_len, 0,
					(struct sockaddr *)&local_sockaddr,
					hip_sockaddr_len(&local_sockaddr));
	if (err < decrypted_packet_len) {
		HIP_DEBUG("sendto() failed\n");
		//printf("sendto() failed\n");

		err = -1;
	} else
	{
		HIP_DEBUG("new packet SUCCESSFULLY re-inserted into network stack\n");
		HIP_DEBUG("dropping ESP packet...\n");

		pthread_mutex_lock(&entry->rw_lock);
		entry->bytes += err;
		entry->usetime.tv_sec = now.tv_sec;
		entry->usetime.tv_usec = now.tv_usec;
		entry->usetime_ka.tv_sec = now.tv_sec;
		entry->usetime_ka.tv_usec = now.tv_usec;
		pthread_mutex_unlock(&entry->rw_lock);

		// the original packet has to be dropped
		err = 1;
	}

  out_err:
	return err;
}
