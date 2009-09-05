#include "firewalldb.h"

int hip_firewall_sock = 0;
int firewall_raw_sock_tcp_v4 = 0;
int firewall_raw_sock_udp_v4 = 0;
int firewall_raw_sock_icmp_v4 = 0;
int firewall_raw_sock_tcp_v6 = 0;
int firewall_raw_sock_udp_v6 = 0;
int firewall_raw_sock_icmp_v6 = 0;
int firewall_raw_sock_icmp_outbound = 0;

HIP_HASHTABLE *firewall_hit_lsi_ip_db;

/**
 * firewall_ip_db_match:
 * Search in the database the given peer ip
 *
 * @param ip_peer: entrance that we are searching in the db
 * @return NULL if not found and otherwise the firewall_hl_t structure
 */
firewall_hl_t *firewall_ip_db_match(struct in6_addr *ip_peer){
  //hip_firewall_hldb_dump();
  return (firewall_hl_t *)hip_ht_find(firewall_hit_lsi_ip_db, (void *)ip_peer);
  
}


firewall_hl_t *hip_create_hl_entry(void){
	firewall_hl_t *entry = NULL;
	int err = 0;
	HIP_IFEL(!(entry = (firewall_hl_t *) HIP_MALLOC(sizeof(firewall_hl_t),0)),
		 -ENOMEM, "No memory available for firewall database entry\n");
  	memset(entry, 0, sizeof(*entry));
out_err:
	return entry;
}


void hip_firewall_hldb_dump(void){
	int i;
	firewall_hl_t *this;
	hip_list_t *item, *tmp;
	HIP_DEBUG("---------   Firewall db   ---------\n");
	HIP_LOCK_HT(&firewall_lsi_hit_db);

	list_for_each_safe(item, tmp, firewall_hit_lsi_ip_db, i){
		this = list_entry(item);
		HIP_DEBUG_HIT("hit_our", &this->hit_our);
		HIP_DEBUG_HIT("hit_peer", &this->hit_peer);
		HIP_DEBUG_LSI("lsi", &this->lsi);
		HIP_DEBUG_IN6ADDR("ip", &this->ip_peer);
		HIP_DEBUG("bex_state %d \n", this->bex_state);
	}
	HIP_UNLOCK_HT(&firewall_lsi_hit_db);
}


/**
 * Adds a default entry in the firewall db.
 * 
 * @param *ip	the only supplied field, the ip of the peer
 * 
 * @return	error if any
 */
int firewall_add_default_entry(struct in6_addr *ip){
	struct in6_addr all_zero_default_v6 = {0};
	struct in_addr  all_zero_default_v4 = {0};
	firewall_hl_t *new_entry  = NULL;
	firewall_hl_t *entry_peer = NULL;
	int err = 0;

	HIP_DEBUG("\n");

	HIP_ASSERT(ip != NULL);

	entry_peer = firewall_ip_db_match(ip);

	if(!entry_peer){
		HIP_DEBUG_IN6ADDR("ip ", ip);

		new_entry = hip_create_hl_entry();
		ipv6_addr_copy(&new_entry->hit_our,  &all_zero_default_v6);
		ipv6_addr_copy(&new_entry->hit_peer, &all_zero_default_v6);
		ipv4_addr_copy(&new_entry->lsi,      &all_zero_default_v4);
		ipv6_addr_copy(&new_entry->ip_peer,  ip);
		new_entry->bex_state = FIREWALL_STATE_BEX_DEFAULT;

		hip_ht_add(firewall_hit_lsi_ip_db, new_entry);
	}

out_err:
	return err;
}


/**
 * Updates an existing entry. The entry is found based on the peer ip.
 * If any one of the first three params is null,
 * the corresponding field in the db entry is not updated.
 * The ip field is required so as to find the entry.
 * 
 * @param *hit_our	our hit, optionally null
 * @param *hit_peer	peer hit, optionally null
 * @param *lsi		peer lsi, optionally null
 * @param *ip		peer ip, NOT null
 * @param state		state of entry, required
 * 
 * @return	error if any
 */
int firewall_update_entry(struct in6_addr *hit_our,
			  struct in6_addr *hit_peer,
			  hip_lsi_t       *lsi,
			  struct in6_addr *ip,
			  int              state){
	int err = 0;
	hip_lsi_t *lsi_peer = NULL;
	hip_list_t *item, *tmp;
	firewall_hl_t *this;
	firewall_hl_t *entry_update = NULL;

	HIP_DEBUG("\n");

	HIP_ASSERT(ip != NULL &&
		   (state == FIREWALL_STATE_BEX_DEFAULT        ||
		    state == FIREWALL_STATE_BEX_NOT_SUPPORTED  ||
		    state == FIREWALL_STATE_BEX_ESTABLISHED 	 ));

	if (ip)
		HIP_DEBUG_IN6ADDR("ip", ip);

	HIP_IFEL(!(entry_update = firewall_ip_db_match(ip)), -1,
		 "Did not find entry\n");

	//update the fields if new value value is not NULL
	if (hit_our)
		ipv6_addr_copy(&entry_update->hit_our, hit_our);
	if (hit_peer)
		ipv6_addr_copy(&entry_update->hit_peer, hit_peer);
	if (lsi)
		ipv4_addr_copy(&entry_update->lsi, lsi);
	entry_update->bex_state = state;

 out_err:
	return err;
}


/**
 * hip_firewall_hash_ip_peer:
 * Generates the hash information that is used to index the table
 *
 * @param ptr: pointer to the lsi used to make the hash
 *
 * @return hash information
 */
unsigned long hip_firewall_hash_ip_peer(const void *ptr){
        struct in6_addr *ip_peer = &((firewall_hl_t *)ptr)->ip_peer;
	uint8_t hash[HIP_AH_SHA_LEN];     
	     
	hip_build_digest(HIP_DIGEST_SHA1, ip_peer, sizeof(*ip_peer), hash);     
	return *((unsigned long *)hash);
}


/**
 * hip_firewall_match_ip_peer:
 * Compares two IPs
 *
 * @param ptr1: pointer to ip
 * @param ptr2: pointer to ip
 *
 * @return 0 if hashes identical, otherwise 1
 */
int hip_firewall_match_ip_peer(const void *ptr1, const void *ptr2){
	return (hip_firewall_hash_ip_peer(ptr1) != hip_firewall_hash_ip_peer(ptr2));
}

void firewall_init_hldb(void){
	firewall_hit_lsi_ip_db = hip_ht_init(hip_firewall_hash_ip_peer,
					     hip_firewall_match_ip_peer);
	firewall_init_raw_sockets();
}


int firewall_set_bex_state(struct in6_addr *hit_s,
			   struct in6_addr *hit_r,
			   int state){
	struct in6_addr ip_src, ip_dst;
	firewall_hl_t *entry_update = NULL;
	hip_lsi_t lsi_our, lsi_peer;
	int err = 0;

	HIP_IFEL(firewall_cache_db_match(hit_r, hit_s, &lsi_our, &lsi_peer,
				   &ip_src, &ip_dst, NULL),
		 -1, "Failed to query LSIs\n");
	HIP_IFEL(firewall_update_entry(NULL, NULL, NULL, &ip_dst, state), -1,
		 "Failed to update firewall entry\n");

 out_err:
	return err;
}

void hip_firewall_delete_hldb(void){
	int i;
	firewall_hl_t *this = NULL;
	hip_list_t *item, *tmp;
	
	HIP_DEBUG("Start hldb delete\n");
	HIP_LOCK_HT(&firewall_lsi_hit_db);

	list_for_each_safe(item, tmp, firewall_hit_lsi_ip_db, i)
	{
		this = list_entry(item);
		// delete this 
		hip_ht_delete(firewall_hit_lsi_ip_db, this);
		// free this
		free(this);
	}
	HIP_UNLOCK_HT(&firewall_lsi_hit_db);
	HIP_DEBUG("End hldbdb delete\n");
}


/*Init functions raw_sockets ipv4*/
int firewall_init_raw_sock_tcp_v4(int *firewall_raw_sock_v4){
	int on = 1, err = 0;
	int off = 0;

	*firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
	return err;
}


int firewall_init_raw_sock_udp_v4(int *firewall_raw_sock_v4){
	int on = 1, err = 0;
	int off = 0;

	*firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
	return err;
}

int firewall_init_raw_sock_icmp_v4(int *firewall_raw_sock_v4){
	int on = 1, err = 0;
	int off = 0;

	*firewall_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	HIP_IFEL(*firewall_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
	err = setsockopt(*firewall_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
	err = setsockopt(*firewall_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

out_err:
	return err;
}


/*Init functions for raw sockets ipv6*/
int firewall_init_raw_sock_tcp_v6(int *firewall_raw_sock_v6){
    	int on = 1, off = 0, err = 0;

    	*firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    	HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");
	
    	/* see bug id 212 why RECV_ERR is off */
    	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    	err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
	return err;
}


int firewall_init_raw_sock_udp_v6(int *firewall_raw_sock_v6){
	int on = 1, off = 0, err = 0;

	*firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
    	HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
	err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
	return err;
}


int firewall_init_raw_sock_icmp_v6(int *firewall_raw_sock_v6){
    	int on = 1, off = 0, err = 0;

    	*firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    	HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt recverr failed\n");
	err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
    	err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    	HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
	return err;
}


int firewall_init_raw_sock_icmp_outbound(int *firewall_raw_sock_v6){
    int on = 1, off = 0, err = 0;

    *firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMP);
    HIP_IFEL(*firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

    /* see bug id 212 why RECV_ERR is off */
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt recverr failed\n");
    err = setsockopt(*firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt pktinfo failiped\n");
    err = setsockopt(*firewall_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

out_err:
    return err;
}


void firewall_init_raw_sockets(void){
  //HIP_IFEL(initialise_firewall_socket(),-1,"Firewall socket creation failed\n");
	firewall_init_raw_sock_tcp_v4(&firewall_raw_sock_tcp_v4);
	firewall_init_raw_sock_udp_v4(&firewall_raw_sock_udp_v4);
	firewall_init_raw_sock_icmp_v4(&firewall_raw_sock_icmp_v4);
	firewall_init_raw_sock_icmp_outbound(&firewall_raw_sock_icmp_outbound);
	firewall_init_raw_sock_tcp_v6(&firewall_raw_sock_tcp_v6);
	firewall_init_raw_sock_udp_v6(&firewall_raw_sock_udp_v6);
	firewall_init_raw_sock_icmp_v6(&firewall_raw_sock_icmp_v6); 
}


int firewall_send_incoming_pkt(struct in6_addr *src_hit,
			       struct in6_addr *dst_hit,
			       u8 *msg, u16 len,
			       int proto,
			       int ttl){
        int err = 0, dupl, try_again, sent, sa_size;
	int firewall_raw_sock = 0, is_ipv6 = 0, on = 1;
	struct ip *iphdr = NULL;
	struct udphdr *udp = NULL;
	struct tcphdr *tcp = NULL;
	struct icmphdr *icmp = NULL;
	struct icmp6hdr *icmpv6 = NULL;
	struct sockaddr_storage src, dst;
	struct sockaddr_in6 *sock_src6, *sock_dst6;
	struct sockaddr_in *sock_src4, *sock_dst4;
	struct in_addr src_aux, dst_aux;
	struct in6_addr any = IN6ADDR_ANY_INIT;

	HIP_ASSERT(src_hit != NULL && dst_hit != NULL);
	sock_src4 = (struct sockaddr_in *) &src;
	sock_dst4 = (struct sockaddr_in *) &dst;
	sock_src6 = (struct sockaddr_in6 *) &src;
	sock_dst6 = (struct sockaddr_in6 *) &dst;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	if (IN6_IS_ADDR_V4MAPPED(src_hit)){
		sock_src4->sin_family = AF_INET;
		sock_dst4->sin_family = AF_INET;
		IPV6_TO_IPV4_MAP(src_hit,&(sock_src4->sin_addr));
		IPV6_TO_IPV4_MAP(dst_hit,&(sock_dst4->sin_addr));
		sa_size = sizeof(struct sockaddr_in);
		HIP_DEBUG_LSI("src4 addr ",&(sock_src4->sin_addr));
		HIP_DEBUG_LSI("dst4 addr ",&(sock_dst4->sin_addr));

	} else {
		sock_src6->sin6_family = AF_INET6;
		ipv6_addr_copy(&sock_src6->sin6_addr, src_hit);
		sock_dst6->sin6_family = AF_INET6;
		ipv6_addr_copy(&sock_dst6->sin6_addr, dst_hit);
		sa_size = sizeof(struct sockaddr_in6);
		is_ipv6 = 1;
	}

	switch(proto){
		case IPPROTO_UDP:
			_HIP_DEBUG("IPPROTO_UDP\n");
			if (is_ipv6){
				HIP_DEBUG(" IPPROTO_UDP v6\n");
			  	firewall_raw_sock = firewall_raw_sock_udp_v6;
			  	((struct udphdr*)msg)->check = ipv6_checksum(IPPROTO_UDP, &sock_src6->sin6_addr, 
								     	     &sock_dst6->sin6_addr, msg, len);
			}else{
				HIP_DEBUG(" IPPROTO_UDP v4\n");
			  	firewall_raw_sock = firewall_raw_sock_udp_v4;

			  	udp = (struct udphdr *)msg;

				sa_size = sizeof(struct sockaddr_in);

		   		udp->check = htons(0);
				udp->check = ipv4_checksum(IPPROTO_UDP, &(sock_src4->sin_addr), 
							   &(sock_dst4->sin_addr), udp, len);		
				memmove((msg+sizeof(struct ip)), (u8*)udp, len);
			}
			break;
		case IPPROTO_TCP:
		        _HIP_DEBUG("IPPROTO_TCP\n");
			tcp = (struct tcphdr *)msg;
		   	tcp->check = htons(0);

			if (is_ipv6){
				HIP_DEBUG(" IPPROTO_TCP v6\n");
			  	firewall_raw_sock = firewall_raw_sock_tcp_v6;
			  	tcp->check = ipv6_checksum(IPPROTO_TCP, &sock_src6->sin6_addr, 
							   &sock_dst6->sin6_addr, msg, len);
			}else{
				HIP_DEBUG(" IPPROTO_TCP v4\n");
			  	firewall_raw_sock = firewall_raw_sock_tcp_v4;
			  	
				tcp->check = ipv4_checksum(IPPROTO_TCP, &(sock_src4->sin_addr), 
							   &(sock_dst4->sin_addr), tcp, len);
				_HIP_DEBUG("checksum %x, len=%d\n", htons(tcp->check), len);
				_HIP_DEBUG_LSI("src", &(sock_src4->sin_addr));
				_HIP_DEBUG_LSI("dst", &(sock_dst4->sin_addr));
				
				memmove((msg+sizeof(struct ip)), (u8*)tcp, len);
			}	
			break;
		case IPPROTO_ICMP:
		        firewall_raw_sock = firewall_raw_sock_icmp_v4;
			icmp = (struct icmphdr *) msg;
			icmp->checksum = htons(0);
			icmp->checksum = inchksum(icmp, len);
			memmove((msg+sizeof(struct ip)), (u8*)icmp, len);
			_HIP_DEBUG("icmp->type = %d\n",icmp->type);
			_HIP_DEBUG("icmp->code = %d\n",icmp->code);
			break;
	        case IPPROTO_ICMPV6:
			goto not_sending;
			break;
		default:
		        HIP_ERROR("No protocol family found\n");
		        break;
	}

	if (!is_ipv6){
		iphdr = (struct ip *) msg;	
		iphdr->ip_v = 4;
		iphdr->ip_hl = sizeof(struct ip) >> 2;
		iphdr->ip_tos = 0;
		iphdr->ip_len = len + iphdr->ip_hl*4;
		iphdr->ip_id = htons(0);
		iphdr->ip_off = 0;
		iphdr->ip_ttl = ttl;
		iphdr->ip_p = proto;
		iphdr->ip_src = sock_src4->sin_addr;
		iphdr->ip_dst = sock_dst4->sin_addr;
		iphdr->ip_sum = htons(0);
			
		/* @todo: move the socket option to fw initialization */
		if (setsockopt(firewall_raw_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)))
		        HIP_IFEL(err, -1, "setsockopt IP_HDRINCL ERROR\n");  


		_HIP_HEXDUMP("hex", iphdr, (len + sizeof(struct ip)));
		sent = sendto(firewall_raw_sock, iphdr, 
			      iphdr->ip_len, 0,
			      (struct sockaddr *) &dst, sa_size);
		if (sent != (len + sizeof(struct ip))) {
			HIP_ERROR("Could not send the all requested" \
				  " data (%d/%d)\n", sent, 
				  iphdr->ip_len);
		} else {
			HIP_DEBUG("sent=%d/%d \n",
				  sent, (len + sizeof(struct ip)));
			HIP_DEBUG("Packet sent ok\n");
		}
	}//if !is_ipv6

 out_err:
	if(is_ipv6){
		ipv6_addr_copy(&sock_src6->sin6_addr, &any);
	}else{
		sock_src4->sin_addr.s_addr = INADDR_ANY;
		sock_src4->sin_family = AF_INET;
	}

	bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size);
 not_sending:
	if (err)
		HIP_DEBUG("sterror %s\n",strerror(errno));
	return err;
	
}


int firewall_send_outgoing_pkt(struct in6_addr *src_hit,
			       struct in6_addr *dst_hit,
			       u8 *msg, u16 len,
			       int proto){
        int err = 0, dupl, try_again, sent, sa_size;
	int firewall_raw_sock = 0, is_ipv6 = 0, on = 1;
	struct ip *iphdr = NULL;

	struct sockaddr_storage src, dst;
	struct sockaddr_in6 *sock_src6, *sock_dst6;
	struct icmp6hdr *icmpv6 = NULL;
	struct icmphdr *icmp = NULL;
	struct sockaddr_in *sock_src4, *sock_dst4;
	struct in6_addr any = IN6ADDR_ANY_INIT;

	HIP_ASSERT(src_hit != NULL && dst_hit != NULL);

	sock_src4 = (struct sockaddr_in *) &src;
	sock_dst4 = (struct sockaddr_in *) &dst;
	sock_src6 = (struct sockaddr_in6 *) &src;
	sock_dst6 = (struct sockaddr_in6 *) &dst;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));

	if (IN6_IS_ADDR_V4MAPPED(src_hit)){
		sock_src4->sin_family = AF_INET;
		IPV6_TO_IPV4_MAP(src_hit, &sock_src4->sin_addr);
		sock_dst4->sin_family = AF_INET;
		IPV6_TO_IPV4_MAP(dst_hit, &sock_dst4->sin_addr);
		sa_size = sizeof(struct sockaddr_in);
		HIP_DEBUG_LSI("src4 addr ", &(sock_src4->sin_addr));
		HIP_DEBUG_LSI("dst4 addr ", &(sock_dst4->sin_addr));
	}else{
		sock_src6->sin6_family = AF_INET6;
		ipv6_addr_copy(&sock_src6->sin6_addr, src_hit);
		sock_dst6->sin6_family = AF_INET6;
		ipv6_addr_copy(&sock_dst6->sin6_addr, dst_hit);
		sa_size = sizeof(struct sockaddr_in6);
		is_ipv6 = 1;
		HIP_DEBUG_HIT("src6 addr ",&(sock_src6->sin6_addr));
                HIP_DEBUG_HIT("dst6 addr ",&(sock_dst6->sin6_addr));
	}
	
	switch(proto){
		case IPPROTO_TCP:
  			_HIP_DEBUG("IPPROTO_TCP\n");
			((struct tcphdr*)msg)->check = htons(0);			
			if (is_ipv6){
				firewall_raw_sock = firewall_raw_sock_tcp_v6;
			  	((struct tcphdr*)msg)->check = ipv6_checksum(IPPROTO_TCP, &sock_src6->sin6_addr, 
								      	     &sock_dst6->sin6_addr, msg, len);
			}else{
			  	firewall_raw_sock = firewall_raw_sock_tcp_v4;
			  	((struct tcphdr*)msg)->check = ipv4_checksum(IPPROTO_TCP, &(sock_src4->sin_addr), 
								      	     &(sock_dst4->sin_addr), msg, len);
			}
    			break;
		case IPPROTO_UDP:
		        _HIP_DEBUG("IPPROTO_UDP\n");
			((struct udphdr*)msg)->check = htons(0);
			if (is_ipv6){
			  	firewall_raw_sock = firewall_raw_sock_udp_v6;
			  	((struct udphdr*)msg)->check = ipv6_checksum(IPPROTO_UDP, &sock_src6->sin6_addr, 
									     &sock_dst6->sin6_addr, msg, len);
				HIP_DEBUG("src_port is %d\n",ntohs(((struct udphdr*)msg)->source));
				HIP_DEBUG("dst_port is %d\n",ntohs(((struct udphdr*)msg)->dest));
				HIP_DEBUG("checksum is %x\n",ntohs(((struct udphdr*)msg)->check));
			}else{
			  	firewall_raw_sock = firewall_raw_sock_udp_v4;
				((struct udphdr*)msg)->check = ipv4_checksum(IPPROTO_TCP, &(sock_src4->sin_addr), 
								      	     &(sock_dst4->sin_addr), msg, len);
			}
			break;
		case IPPROTO_ICMP:
			((struct icmphdr*)msg)->checksum = htons(0);
			((struct icmphdr*)msg)->checksum = inchksum(msg, len);

		        if (is_ipv6)
			        firewall_raw_sock = firewall_raw_sock_icmp_outbound;
			else
			        firewall_raw_sock = firewall_raw_sock_icmp_v4;

			break;
	        case IPPROTO_ICMPV6:
		        firewall_raw_sock = firewall_raw_sock_icmp_v6;
			((struct icmp6hdr*)msg)->icmp6_cksum = htons(0);
			((struct icmp6hdr*)msg)->icmp6_cksum = ipv6_checksum(IPPROTO_ICMPV6, &sock_src6->sin6_addr, 
									     &sock_dst6->sin6_addr, msg, len);
	                break;
		default:
		        HIP_DEBUG("No protocol family found\n");
			break;
	}

	
	HIP_IFEL(bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size),
		 -1, "Binding to raw sock failed\n");
	sent = sendto(firewall_raw_sock, msg, len, 0,
		      (struct sockaddr *) &dst, sa_size);
	if (sent != len) {
		HIP_ERROR("Could not send the all requested"\
			  " data (%d/%d)\n", sent, len);
	} else {
		HIP_DEBUG("sent=%d/%d \n",
			  sent, len);
	}

 out_err:
	/* Reset the interface to wildcard*/
	if (is_ipv6)
		ipv6_addr_copy(&sock_src6->sin6_addr, &any);
	else{
		sock_src4->sin_addr.s_addr = INADDR_ANY;
		sock_src4->sin_family = AF_INET;
	}

	bind(firewall_raw_sock, (struct sockaddr *) &src, sa_size);
	if (err)
		HIP_DEBUG("sterror %s\n",strerror(errno));

	return err;
}
