#include "cache.h"

HIP_HASHTABLE *firewall_cache_db;

/**
 * firewall_cache_db_match:
 * Search in the cache database the given peers of hits, lsis or ips
 */
int firewall_cache_db_match(    struct in6_addr *hit_our,
				struct in6_addr *hit_peer,
				hip_lsi_t       *lsi_our,
				hip_lsi_t       *lsi_peer,
				struct in6_addr *ip_our,
				struct in6_addr *ip_peer,
				int *state){
	int i, err = 0, entry_in_cache = 0;
	firewall_cache_hl_t *this;
	hip_list_t *item, *tmp;
	struct in6_addr all_zero_v6 = {0};
	struct in_addr  all_zero_v4 = {0};
	struct hip_common *msg = NULL;
	firewall_cache_hl_t *ha_curr = NULL;
	firewall_cache_hl_t *ha_match = NULL;
	struct hip_tlv_common *current_param = NULL;

	HIP_ASSERT( (hit_our && hit_peer) ||
		    (lsi_our && lsi_peer)    );

	if(hit_peer){
		ha_match = (firewall_cache_hl_t *)hip_ht_find(
						firewall_cache_db,
						(void *)hit_peer);
		if(ha_match){
			HIP_DEBUG("Matched using hash\n");
			entry_in_cache = 1;
			goto out_err;
		}
	}

	HIP_DEBUG("Check firewall cache db\n");

	HIP_LOCK_HT(&firewall_cache_db);

	list_for_each_safe(item, tmp, firewall_cache_db, i){
		this = list_entry(item);

		if( lsi_our && lsi_peer) {
		  HIP_DEBUG_INADDR("this->our", &this->lsi_our.s_addr);
		  HIP_DEBUG_INADDR("this->peer", &this->lsi_peer.s_addr);
		  HIP_DEBUG_INADDR("our", lsi_our);
		  HIP_DEBUG_INADDR("peer", lsi_peer);
		}

		if( hit_our && hit_peer &&
		    (ipv6_addr_cmp(hit_peer, &this->hit_peer) == 0 ) &&
		    (ipv6_addr_cmp(hit_our,  &this->hit_our)  == 0 )    ){
			ha_match = this;
			break;
		}
		if( lsi_our && lsi_peer &&
		    lsi_peer->s_addr == this->lsi_peer.s_addr &&
		    lsi_our->s_addr  == this->lsi_our.s_addr     ){
			ha_match = this;
			break;
		}
		if( ip_our && ip_peer &&
		    ip_peer->s6_addr == this->ip_peer.s6_addr &&
		    ip_our->s6_addr  == this->ip_our.s6_addr     ) {
			ha_match = this;
			break;
		}
	}
	HIP_UNLOCK_HT(&firewall_cache_db);

	if(ha_match){
		entry_in_cache = 1;
		goto out_err;
	}

	HIP_DEBUG("No cache found, querying daemon\n");
  
	HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0),
				-1, "Building of daemon header failed\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1,
		 "send recv daemon info\n");

	while((current_param=hip_get_next_param(msg, current_param)) != NULL) {
		ha_curr = hip_get_param_contents_direct(current_param);

		HIP_DEBUG_HIT("our1", &ha_curr->hit_our);
		HIP_DEBUG_HIT("peer1", &ha_curr->hit_peer);
		if (hit_our)
			HIP_DEBUG_HIT("our2", hit_our);
		if (hit_peer)
			HIP_DEBUG_HIT("peer2", hit_peer);
		if( hit_our && hit_peer &&
		    (ipv6_addr_cmp(hit_peer, &ha_curr->hit_peer) == 0 ) &&
		    (ipv6_addr_cmp(hit_our,  &ha_curr->hit_our)  == 0 )    ){
			HIP_DEBUG("Matched HITs\n");
			ha_match = ha_curr;
			break;
		}
		if( lsi_our && lsi_peer &&
		    lsi_peer->s_addr == ha_curr->lsi_peer.s_addr &&
		    lsi_our->s_addr  == ha_curr->lsi_our.s_addr     ){
			HIP_DEBUG("Matched LSIs\n");
			ha_match = ha_curr;
			break;
		}
		if( ip_our && ip_peer &&
		    ip_peer->s6_addr == ha_curr->ip_peer.s6_addr &&
		    ip_our->s6_addr  == ha_curr->ip_our.s6_addr     ) {
			HIP_DEBUG("Matched IPs\n");
			ha_match = ha_curr;
			break;
		}
	}

out_err:
    if(ha_match){
	if(!entry_in_cache)
		firewall_add_new_entry(ha_match);

	if(hit_our)
		ipv6_addr_copy(hit_our, &ha_match->hit_our);

	if(hit_peer)
		ipv6_addr_copy(hit_peer, &ha_match->hit_peer);

	if(lsi_our)
	    ipv4_addr_copy(lsi_our, &ha_match->lsi_our);

	if(lsi_peer)
	    ipv4_addr_copy(lsi_peer, &ha_match->lsi_peer);

	if(ip_our)
	    ipv6_addr_copy(ip_our, &ha_match->ip_our);

	if(ip_peer) {
	    ipv6_addr_copy(ip_peer, &ha_match->ip_peer);
	    HIP_DEBUG_IN6ADDR("peer ip", ip_peer);
	}

        if(state)
	    *state = ha_match->state;
    } else {
      err = -1;
    }

    return err;
}


firewall_cache_hl_t *hip_cache_create_hl_entry(void){
	firewall_cache_hl_t *entry = NULL;
	int err = 0;
	HIP_IFEL(!(entry = (firewall_cache_hl_t *) HIP_MALLOC(sizeof(firewall_cache_hl_t),0)),
		-ENOMEM, "No memory available for firewall database entry\n");
  	memset(entry, 0, sizeof(*entry));
out_err:
	return entry;
}


/**
 * Adds a default entry in the firewall db.
 * 
 * @param *ip	the only supplied field, the ip of the peer
 * 
 * @return	error if any
 */
int firewall_add_new_entry(firewall_cache_hl_t *ha_entry){
	struct in6_addr all_zero_default_v6;
	struct in_addr  all_zero_default_v4;
	firewall_cache_hl_t *new_entry = NULL;
	int err = 0;

	HIP_DEBUG("\n");

	HIP_ASSERT(ha_entry != NULL);

	new_entry = hip_cache_create_hl_entry();
	ipv6_addr_copy(&new_entry->hit_our,  &ha_entry->hit_our);
	ipv6_addr_copy(&new_entry->hit_peer, &ha_entry->hit_peer);

	ipv4_addr_copy(&new_entry->lsi_our,  &ha_entry->lsi_our);
	ipv4_addr_copy(&new_entry->lsi_peer, &ha_entry->lsi_peer);

	ipv6_addr_copy(&new_entry->ip_our,  &ha_entry->ip_our);
	ipv6_addr_copy(&new_entry->ip_peer, &ha_entry->ip_peer);

	new_entry->state = ha_entry->state;

	hip_ht_add(firewall_cache_db, new_entry);

out_err:
	return err;
}


/**
 * hip_firewall_hash_hit_peer:
 * Generates the hash information that is used to index the table
 *
 * @param ptr: pointer to the hit used to make the hash
 *
 * @return hash information
 */
unsigned long hip_firewall_hash_hit_peer(const void *ptr){
        struct in6_addr *hit_peer = &((firewall_cache_hl_t *)ptr)->hit_peer;
	uint8_t hash[HIP_AH_SHA_LEN];     
	     
	hip_build_digest(HIP_DIGEST_SHA1, hit_peer, sizeof(*hit_peer), hash);     
	return *((unsigned long *)hash);
}


/**
 * hip_firewall_match_hit_peer:
 * Compares two HITs
 *
 * @param ptr1: pointer to hit
 * @param ptr2: pointer to hit
 *
 * @return 0 if hashes identical, otherwise 1
 */
int hip_firewall_match_hit_peer(const void *ptr1, const void *ptr2){
	return (hip_firewall_hash_hit_peer(ptr1) != hip_firewall_hash_hit_peer(ptr2));
}


void firewall_cache_init_hldb(void){
	firewall_cache_db = hip_ht_init(hip_firewall_hash_hit_peer,
					hip_firewall_match_hit_peer);
}


void hip_firewall_cache_delete_hldb(void){
	int i;
	firewall_cache_hl_t *this = NULL;
	hip_list_t *item, *tmp;
	
	HIP_DEBUG("Start hldb delete\n");
	HIP_LOCK_HT(&firewall_cache_db);

	list_for_each_safe(item, tmp, firewall_cache_db, i)
	{
		this = list_entry(item);
		// delete this 
		hip_ht_delete(firewall_cache_db, this);
		// free this
		free(this);
	}
	HIP_UNLOCK_HT(&firewall_cache_db);
	HIP_DEBUG("End hldbdb delete\n");
}


void hip_firewall_cache_hldb_dump(void){
	int i;
	firewall_cache_hl_t *this;
	hip_list_t *item, *tmp;
	HIP_DEBUG("---------   Firewall db   ---------\n");
	HIP_LOCK_HT(&firewall_cache_db);

	list_for_each_safe(item, tmp, firewall_cache_db, i){
		this = list_entry(item);
		HIP_DEBUG_HIT("hit_our",     &this->hit_our);
		HIP_DEBUG_HIT("hit_peer",    &this->hit_peer);
		HIP_DEBUG_LSI("lsi our",     &this->lsi_our);
		HIP_DEBUG_LSI("lsi peer",    &this->lsi_peer);
		HIP_DEBUG_IN6ADDR("ip our",  &this->ip_our);
		HIP_DEBUG_IN6ADDR("ip peer", &this->ip_peer);
		//HIP_DEBUG("bex_state %d \n", this->bex_state);
	}
	HIP_UNLOCK_HT(&firewall_cache_db);
}
