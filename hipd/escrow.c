/**
 * @file
 * This file defines key escrow functionality for HIP.
 * 
 * @author  Anu Markkola
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note    Since the creation of this file, implementations of both the
 *          registration extension and UPDATE packet support have changed quite
 *          a lot. This extension has not been tested since 2006 and therefore
 *          is most likely be defunct. -Lauri 01.07.2008
 */
#include "escrow.h"

HIP_HASHTABLE *kea_table;
HIP_HASHTABLE *kea_endpoints;

/** Minimum relay record life time as a 8-bit integer. */
uint8_t escrow_min_lifetime = HIP_ESCROW_MIN_LIFETIME;
/** Maximum relay record life time as a 8-bit integer. */
uint8_t escrow_max_lifetime = HIP_ESCROW_MAX_LIFETIME;

static void *hip_keadb_get_key(void *entry)
{
	return (void *)&(((HIP_KEA *)entry)->hit);
}

/** 
 * Initializes the database 
 */
void hip_init_keadb(void)
{
#if 0
	memset(&kea_table, 0, sizeof(kea_table));

	kea_table.head = keadb;
	kea_table.hashsize = HIP_KEA_SIZE;
	kea_table.offset = offsetof(HIP_KEA, list_hit);
	kea_table.hash = hip_hash_hit;
	kea_table.compare = hip_match_hit;
	kea_table.hold = hip_keadb_hold_entry;
	kea_table.put = hip_keadb_put_entry;
	kea_table.get_key = hip_keadb_get_key;

	strncpy(kea_table.name, "KEA TABLE", 15);
	kea_table.name[15] = 0;

	hip_ht_init(&kea_table);
#endif
	kea_table = hip_ht_init(hip_hash_hit, hip_match_hit);
}


void hip_keadb_hold_entry(void *entry) 
{
	HIP_KEA *kea = entry;

	HIP_ASSERT(entry);
	atomic_inc(&kea->refcnt);
	HIP_DEBUG("KEA: %p, refcnt incremented to: %d\n", kea, 
		atomic_read(&kea->refcnt));
}

void hip_keadb_put_entry(void *entry)
{
	HIP_KEA *kea = entry;

	HIP_ASSERT(entry);
	if (atomic_dec_and_test(&kea->refcnt)) {
    	HIP_DEBUG("KEA: %p, refcnt reached zero. Deleting...\n",kea);
		hip_keadb_delete_entry(kea);
	} else {
    	HIP_DEBUG("KEA: %p, refcnt decremented to: %d\n", kea, 
    		atomic_read(&kea->refcnt));
	}
}

void hip_uninit_keadb(void)
{
	HIP_DEBUG("Unitializing KEA TABLE\n");
	hip_ht_uninit(kea_table);
}

// hit_our is not really needed now
int hip_kea_create_base_entry(struct hip_host_id_entry *entry, 
	void *server_hit_void)
{
	int err = 0;
	HIP_KEA *kea;
	struct in6_addr *server_hit = server_hit_void; 	
	kea = hip_kea_create(&entry->lhi.hit);
	if (!kea) 
		return -1;	
	ipv6_addr_copy(&kea->server_hit, server_hit);	
	err = hip_keadb_add_entry(kea);
	hip_keadb_put_entry(kea);
	HIP_DEBUG_HIT("Created kea base entry with hit: ", &entry->lhi.hit);
	return err;
}

/**
 * Launches registration to escrow service 
 * op = 0/1 (zero for cancelling registration)
 */
int hip_launch_escrow_registration(struct hip_host_id_entry * id_entry, 
				   void * server_hit_void)
{
	int err = 0;
	hip_ha_t * entry = NULL;	
	struct in6_addr * server_hit = server_hit_void;
	HIP_KEA * kea = NULL;
	
	HIP_IFEL(!(entry = hip_hadb_find_byhits(&id_entry->lhi.hit, server_hit_void)),
		 -1, "Internal error: no haDB entry found.\n");
	HIP_IFEL(!(kea = hip_kea_find(&entry->hit_our)), -1, "No KEA base entry found\n");
	HIP_DEBUG_HIT("Registering to server from ", &entry->hit_our);
	
        kea->keastate = HIP_KEASTATE_REGISTERING;
        hip_keadb_put_entry(kea);
	
 out_err:
        if (entry != NULL) {
                hip_hadb_put_entry(entry);
	}

	return err;		
}

int hip_launch_cancel_escrow_registration(struct hip_host_id_entry * id_entry, 
					  void * server_hit_void)
{
        int err = 0;
        hip_ha_t * entry = NULL;        
        struct in6_addr * server_hit = server_hit_void;
        HIP_KEA * kea = NULL;
	in_port_t *peer_port;
        
        HIP_IFEL(!(entry = hip_hadb_find_byhits(&id_entry->lhi.hit, server_hit_void)),
		 -1, "Internal error: no haDB entry found\n");
        HIP_IFEL(!(kea = hip_kea_find(&entry->hit_our)), -1, "No KEA base entry found\n");
        HIP_DEBUG_HIT("Cancelling registration of ", &entry->hit_our);
        
        kea->keastate = HIP_KEASTATE_UNREGISTERING;
	
        hip_keadb_put_entry(kea);
	
 out_err:
        if (entry != NULL)
                hip_put_ha(entry);
	
        return err;             
}


int hip_remove_escrow_data(hip_ha_t * entry, void * data)
{
	int err = 0;
	entry->escrow_used = 0;
	
 out_err:	
	return err;
}

int hip_kea_remove(struct hip_host_id_entry *entry, 
	void *data) 
{
	int err = 0;
	HIP_KEA *kea;
	HIP_IFE(!(kea = hip_kea_find((struct in6_addr *)&entry->lhi.hit)), -1);
	HIP_DEBUG("Found kea base entry");
	hip_keadb_remove_entry(kea);
	hip_keadb_put_entry(kea); 
	//hip_keadb_delete_entry(kea);	

out_err:
	return err;	
}

// TODO: fix parameter to something meaningful
int hip_kea_remove_base_entries()
{
	int err = 0;
	HIP_DEBUG("Removing base entries");
	// Removing keas
	HIP_IFEL(hip_for_each_hi(hip_kea_remove, NULL), 0, "for_each error");
out_err:
	return err;	
}


HIP_KEA *hip_kea_allocate()
{
	HIP_KEA *kea;

	kea = HIP_MALLOC(sizeof(*kea), 0);
	
	if (!kea)
		return NULL;

	atomic_set(&kea->refcnt, 0);
	HIP_LOCK_INIT(kea);
	kea->keastate = HIP_KEASTATE_INVALID;

	return kea;
}



/**
 * Creates a new key escrow association with the given values.
 */
HIP_KEA *hip_kea_create(struct in6_addr *hit)
{
	HIP_KEA *kea;
	_HIP_DEBUG("Creating kea entry");
	kea = hip_kea_allocate();
	if (!kea)
		return NULL;
	
	hip_keadb_hold_entry(kea); // Add reference
	
	ipv6_addr_copy(&kea->hit, hit);
	kea->keastate = HIP_KEASTATE_VALID;
	kea->peer_end = NULL;
        kea->client_end = NULL;
      
	return kea;	
}


int hip_keadb_add_entry(HIP_KEA *kea)
{
	int err = 0;
	HIP_KEA * temp;

	_HIP_DEBUG("Adding kea entry");

	/* if assertation holds, then we don't need locking */
	HIP_ASSERT(atomic_read(&kea->refcnt) <= 1); 

	HIP_IFEL(ipv6_addr_any(&kea->hit), -EINVAL,
		 "Cannot insert KEA entry with NULL hit\n");
		 
	// Do we allow duplicates?	 
	temp = hip_ht_find(kea_table, &kea->hit); // Adds reference
	
	if (temp) {
		hip_keadb_put_entry(temp); // remove reference
		HIP_ERROR("Failed to add kea hash table entry\n");
	} else {
		hip_ht_add(kea_table, kea);
		kea->keastate |= HIP_KEASTATE_VALID;
	}
	
 out_err:
	return err;
}


void hip_keadb_remove_entry(HIP_KEA *kea)
{
	HIP_ASSERT(kea);

	HIP_LOCK_HA(kea); // refcnt should be more than 1
	if (!kea->keastate) {
		HIP_DEBUG("KEA not in kea hashtable\n");
		return;
	}
	
	hip_ht_delete(kea_table, kea); // refcnt decremented
	HIP_UNLOCK_HA(kea); 
}


void hip_keadb_delete_entry(HIP_KEA *kea)
{
	HIP_FREE(kea);
}

HIP_KEA *hip_kea_find(struct in6_addr *hit)
{
	return hip_ht_find(kea_table, hit);
}

void hip_kea_set_state_registering(HIP_KEA *kea)
{
	kea->keastate = HIP_KEASTATE_REGISTERING;

}

/**********************************************/



void hip_kea_hold_ep(void *entry) //TODO: remove?
{
	HIP_KEA_EP *kea_ep = entry;

	HIP_ASSERT(entry);
	atomic_inc(&kea_ep->refcnt);
	HIP_DEBUG("KEA EP: %p, refcnt incremented to: %d\n", kea_ep, 
		atomic_read(&kea_ep->refcnt));
}

void hip_kea_put_ep(void *entry) //TODO: remove?
{
	HIP_KEA_EP *kea_ep = entry;

	HIP_ASSERT(entry);
	if (atomic_dec_and_test(&kea_ep->refcnt)) {
    	HIP_DEBUG("KEA EP: %p, refcnt reached zero. Deleting...\n",kea_ep);
		hip_kea_delete_endpoint(kea_ep);
	} else {
    	HIP_DEBUG("KEA EP: %p, refcnt decremented to: %d\n", kea_ep, 
    		atomic_read(&kea_ep->refcnt));
	}
}


static void *hip_kea_endpoints_get_key(void *entry)
{
	return (void *)&(((HIP_KEA_EP *)entry)->ep_id);
}

void hip_init_kea_endpoints(void)
{
#if 0
	memset(&kea_endpoints, 0, sizeof(kea_endpoints));

	kea_endpoints.head = kea_endpointdb;
	kea_endpoints.hashsize = HIP_KEA_EP_SIZE;
	kea_endpoints.offset = offsetof(HIP_KEA_EP, list_hit);
	kea_endpoints.hash = hip_kea_ep_hash;
	kea_endpoints.compare = hip_kea_ep_match;
	kea_endpoints.hold = hip_kea_hold_ep;
	kea_endpoints.put = hip_kea_put_ep;
	kea_endpoints.get_key = hip_kea_endpoints_get_key;

	strncpy(kea_endpoints.name, "KEA ENDPOINTS", 15);
	kea_endpoints.name[15] = 0;

	hip_ht_init(&kea_endpoints);
#endif
	kea_endpoints = hip_ht_init(hip_kea_ep_hash, hip_kea_ep_match);
}


void hip_uninit_kea_endpoints(void)
{
	HIP_DEBUG("Unitializing KEA ENDPOINTS TABLE\n");
	hip_ht_uninit(kea_endpoints);
}

unsigned long hip_kea_ep_hash(const void * key)
{
	HIP_KEA_EP_ID * id = (HIP_KEA_EP_ID *) key; 
	// TODO: Is the key random enough?
	return (id->value[2] ^ id->value[3] ^ id->value[4]) % ULONG_MAX;
}


int hip_kea_ep_match(const void * ep1, const void * ep2)
{	
	return !memcmp((const void *) ep1, (const void *) ep2, 18);
}

HIP_KEA_EP *hip_kea_ep_allocate()
{
	HIP_KEA_EP *kea_ep;

	kea_ep = HIP_MALLOC(sizeof(*kea_ep), 0);
	
	if (!kea_ep)
		return NULL;

	atomic_set(&kea_ep->refcnt, 0);
	HIP_LOCK_INIT(kea_ep);

	return kea_ep;

}

HIP_KEA_EP *hip_kea_ep_create(struct in6_addr *hit, struct in6_addr *peer_hit, struct in6_addr *ip, 
							  int esp_transform, uint32_t spi, uint16_t key_len, 
							  struct hip_crypto_key * key)
{
	HIP_KEA_EP *kea_ep;
	kea_ep = hip_kea_ep_allocate();
	if (!kea_ep)
		return NULL;
	
	HIP_DEBUG("Creating kea endpoint");
	HIP_DEBUG_HIT("ep hit:", hit);
        HIP_DEBUG_HIT("ep peer_hit:", peer_hit);
	HIP_DEBUG("ep spi: %d", spi);
	//HIP_HEXDUMP("spi: ", spi, sizeof(uint32_t));
	
	hip_kea_hold_ep(kea_ep); // Add reference
	
	ipv6_addr_copy(&kea_ep->hit, hit);
        ipv6_addr_copy(&kea_ep->peer_hit, peer_hit);
	ipv6_addr_copy(&kea_ep->ip, ip);
	kea_ep->esp_transform = esp_transform;
	kea_ep->key_len = key_len;
	kea_ep->spi = spi;
	
	memcpy(&kea_ep->esp_key, key, sizeof(kea_ep->esp_key));

	return kea_ep;	
}

int hip_kea_add_endpoint(HIP_KEA *kea, HIP_KEA_EP *kea_ep)
{
	int err = 0;
	HIP_KEA_EP * temp;
	
	HIP_DEBUG("Adding kea endpoint");

	/* if assertation holds, then we don't need locking */
	HIP_ASSERT(atomic_read(&kea_ep->refcnt) <= 1); 

	HIP_IFEL(ipv6_addr_any(&kea_ep->hit), -EINVAL,
		 "Cannot insert KEA_EP entry with NULL hit\n");
		 
	// Create key
	memcpy(&kea_ep->ep_id.value, &kea_ep->hit.s6_addr32, 
		   sizeof(struct in6_addr));
	memcpy(&kea_ep->ep_id.value[4], &kea_ep->spi, sizeof(int));
	
	temp = hip_ht_find(kea_endpoints, &kea_ep->ep_id); // Adds reference
	
	if (temp) {
		hip_kea_put_ep(temp); // remove reference
		HIP_ERROR("Failed to add kea endpoint hash table entry\n");
	} else {
		hip_ht_add(kea_endpoints, kea_ep);
		// set state if needed
	}
	
        if (ipv6_addr_cmp(&kea->hit, &kea_ep->hit)) {
                HIP_DEBUG("This is client endpoint\n");
                kea->client_end = kea_ep;
        }
        else {
                HIP_DEBUG("This is peer endpoint\n");
                kea->peer_end = kea_ep;
        }
        
 out_err:
	return err;
}


void hip_kea_remove_endpoint(HIP_KEA_EP *kea_ep)
{
	HIP_DEBUG("Removing kea endpoint");
	
	HIP_ASSERT(kea_ep);

	HIP_LOCK_HA(kea_ep); // refcnt should be more than 1
	//if (!(kea_ep->keastate & HIP_EP_KEASTATE_VALID)) { //check state
	//	HIP_DEBUG("KEA not in kea hashtable or state corrupted\n");
	//	return;
	//}
	
	hip_ht_delete(kea_endpoints, kea_ep); // refcnt decremented
	HIP_UNLOCK_HA(kea_ep); 	
}

int hip_escrow_validate_lifetime(uint8_t requested_lifetime,
				uint8_t *granted_lifetime)
{
	if(requested_lifetime < escrow_min_lifetime){
		*granted_lifetime = escrow_min_lifetime;
		return -1;
	}else if(requested_lifetime > escrow_max_lifetime){
		*granted_lifetime = escrow_max_lifetime;
		return -1;
	}else{
		*granted_lifetime = requested_lifetime;
		return 0;
	}
}

void hip_kea_delete_endpoint(HIP_KEA_EP *kea_ep)
{
	HIP_FREE(kea_ep);
}


HIP_KEA_EP *hip_kea_ep_find(struct in6_addr *hit, uint32_t spi)
{
	HIP_KEA_EP_ID * key = NULL;
	
	key = HIP_MALLOC(sizeof(struct hip_kea_ep_id), GFP_KERNEL);
	
	memcpy(&key->value, &hit->s6_addr32, sizeof(struct in6_addr));
	memcpy(&key->value[4], &spi, sizeof(int));

	HIP_HEXDUMP("Searching KEA endpoint with key:", key, 18);
		
	return hip_ht_find(kea_endpoints, key);
}


/******************************/


/**
 * Send UPDATE to escrow server. Operation can be HIP_ESCROW_OPERATION_ADD, 
 * HIP_ESCROW_OPERATION_MODIFY or HIP_ESCROW_OPERATION_DELETE. 
 * Note: Modification and deletion are not tested properly.
 */
int hip_send_escrow_update(hip_ha_t *entry, int operation, 
	struct in6_addr *addr, struct in6_addr *hit, struct in6_addr *peer_hit, uint32_t spi, uint32_t old_spi,
	int ealg, uint16_t key_len, struct hip_crypto_key * enc)
{
	int err = 0;
	uint32_t update_id_out = 0;
	struct hip_common * update_packet = NULL;
	struct in6_addr saddr = { 0 }, daddr = { 0 };
	uint16_t mask = 0;
	struct hip_keys keys_tmp;
	struct hip_keys * keys = NULL;
	char * keys_enc = NULL;
	char * enc_in_msg = NULL;
	int keys_enc_len;
	unsigned char * iv = NULL;
	
	hip_hadb_get_peer_addr(entry, &daddr);
	
	/*** Start building UPDATE packet ***/
	
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Out of memory.\n");
	HIP_DEBUG_HIT("sending UPDATE to", &entry->hit_peer);
	HIP_DEBUG_HIT("... from", &entry->hit_our);

	_HIP_DEBUG_HIT("escrow data hit:", hit);
	_HIP_DEBUG("escrow data spi: %d", spi);
	_HIP_DEBUG("escrow data old spi: %d", old_spi);
	_HIP_DEBUG("escrow data ealg: %d", ealg);
	_HIP_DEBUG("escrow data key length: %d",key_len);

        //HIP_LOCK_HA(entry);

	entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
						     mask, &entry->hit_our,
						     &entry->hit_peer);
			
	entry->update_id_out++;
	update_id_out = entry->update_id_out;
	_HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	/* todo: handle this case */
	HIP_IFEL(!update_id_out, -EINVAL,
		 "Outgoing UPDATE ID overflowed back to 0, bug ?\n");
	HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1, 
		 "Building of SEQ param failed\n");

	
	/*** Add hip_keys-parameter encrypted ***/
	
	HIP_DEBUG("Creating hip_keys parameter (escrow data)");
	/* Build hip_keys parameter*/
	HIP_IFEL(hip_build_param_keys_hdr(&keys_tmp, (uint16_t)operation, 
		(uint16_t)ealg, addr, hit, peer_hit, spi, old_spi, key_len, enc), -1, 
		 "Building of hip_keys param (escrow data) failed\n");
	HIP_IFEL(!(keys = HIP_MALLOC(hip_get_param_total_len(&keys_tmp), 0)), -1, 
		"Memory allocation failed.\n");
	memcpy(keys, &keys_tmp, sizeof(keys_tmp));
	HIP_DEBUG("Built escrow data");
	
	/* Encrypt hip_keys */
	switch (entry->hip_transform) {
	case HIP_HIP_AES_SHA1:
		HIP_IFEL(hip_build_param_encrypted_aes_sha1(update_packet, (struct hip_tlv_common *)keys), 
			 -1, "Building of param encrypted failed.\n");
		enc_in_msg = hip_get_param(update_packet, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
		get_random_bytes(iv, 16);
 		keys_enc = enc_in_msg +
			sizeof(struct hip_encrypted_aes_sha1);
		break;
	case HIP_HIP_3DES_SHA1:
		HIP_IFEL(hip_build_param_encrypted_3des_sha1(update_packet, (struct hip_tlv_common *)keys), 
			 -1, "Building of param encrypted failed.\n");
		enc_in_msg = hip_get_param(update_packet, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = ((struct hip_encrypted_3des_sha1 *) enc_in_msg)->iv;
		get_random_bytes(iv, 8);
 		keys_enc = enc_in_msg +
 			sizeof(struct hip_encrypted_3des_sha1);
		break;
	case HIP_HIP_NULL_SHA1:
		HIP_IFEL(hip_build_param_encrypted_null_sha1(update_packet, (struct hip_tlv_common *)keys), 
			 -1, "Building of param encrypted failed.\n");
		enc_in_msg = hip_get_param(update_packet, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = NULL;
 		keys_enc = enc_in_msg +
 			sizeof(struct hip_encrypted_null_sha1);
		break;
	default:
 		HIP_IFEL(1, -ENOSYS, "HIP transform not supported (%d)\n",
			 entry->hip_transform);
	}

	HIP_HEXDUMP("enc(keys)", keys_enc,
		    hip_get_param_total_len(keys_enc));

	/* Calculate the length of the parameter inside the encrypted param */
	keys_enc_len = hip_get_param_total_len(keys_enc);

	/* Adjust the host id length for AES (block size 16).
	   build_param_encrypted_aes has already taken care that there is
	   enough padding */
	if (entry->hip_transform == HIP_HIP_AES_SHA1) {
		int remainder = keys_enc_len % 16;
		if (remainder) {
			HIP_DEBUG("Remainder %d (for AES)\n", remainder);
			keys_enc_len += remainder;
		}
	}

	_HIP_HEXDUMP("hostidinmsg", keys_enc,
		    hip_get_param_total_len(keys_enc));
	_HIP_HEXDUMP("encinmsg", enc_in_msg,
		    hip_get_param_total_len(enc_in_msg));
	HIP_HEXDUMP("enc key", &entry->hip_enc_out.key, HIP_MAX_KEY_LEN);
	_HIP_HEXDUMP("IV", iv, 16); // or 8

	HIP_IFEL(hip_crypto_encrypted(keys_enc, iv,
				      entry->hip_transform,
				      keys_enc_len,
				      &entry->hip_enc_out.key,
				      HIP_DIRECTION_ENCRYPT), -1, 
		 "Building of param encrypted failed\n");

	_HIP_HEXDUMP("encinmsg 2", enc_in_msg,
		     hip_get_param_total_len(enc_in_msg));
	
	/*** Add HMAC ***/
	HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					       &entry->hip_hmac_out), -1,
		 "Building of HMAC failed\n");

	/*** Add SIGNATURE ***/
	HIP_IFEL(entry->sign(entry->our_priv_key, update_packet), -EINVAL,
	 	 "Could not sign UPDATE. Failing\n");

	
	/*** Send UPDATE ***/

	memcpy(&saddr, &entry->our_addr, sizeof(saddr));

	/** @todo Functionality on UDP has not been tested. */
	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(&saddr, &daddr, (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			      entry->peer_udp_port, update_packet,
			      entry, 1),
		 -ECOMM, "Sending UPDATE packet failed.\n");
	
	goto out;

 out_err:
	entry->state = HIP_STATE_ESTABLISHED;
	HIP_DEBUG("fallbacked to state ESTABLISHED (ok ?)\n");
	
 out:
	//HIP_UNLOCK_HA(entry);
	if (update_packet)
		HIP_FREE(update_packet);
	return err;
}

/* Deliver SA data to escrow server */
int hip_deliver_escrow_data(struct in6_addr *saddr, struct in6_addr *daddr,
                            struct in6_addr *src_hit, struct in6_addr *dst_hit,
                            uint32_t *spi, int ealg, struct hip_crypto_key *enckey, 
                            int operation)
{
    int err = 0;
    HIP_KEA * kea = NULL;
    hip_ha_t * entry = NULL;
    hip_ha_t * server_entry = NULL;
    
    HIP_IFEL(!(entry = hip_hadb_find_byhits(src_hit, dst_hit)), -1, 
        "Could not find ha_state entry");   
    if (entry->escrow_used) {
        int enckey_len;     
        HIP_IFEL(!(kea = hip_kea_find(&entry->hit_our)), -1, "Could not find kea base entry");
        HIP_DEBUG_HIT("escrow_server_hit ", &entry->escrow_server_hit);
        HIP_DEBUG_HIT("kea base entry server_hit", &kea->server_hit);
        HIP_IFEL(!(server_entry = hip_hadb_try_to_find_by_peer_hit(&entry->escrow_server_hit)),
            -1, "No server entry found");
        
        if (kea->keastate == HIP_KEASTATE_VALID) {
            enckey_len = hip_enc_key_length(ealg);
            err = hip_send_escrow_update(server_entry, operation, 
                daddr, dst_hit, src_hit, *spi, *spi, ealg, (uint16_t)enckey_len, enckey);
        }
        else {
            HIP_DEBUG("keastate not valid (%d) - not sending update\n", kea->keastate);
        }
    }
    else {
        HIP_DEBUG("Escrow not in use\n");
    }

out_err:
    if (kea)
        hip_keadb_put_entry(kea);
    if (entry)
        hip_put_ha(entry);
    if (server_entry)
        hip_put_ha(server_entry);        
    return err;   
}


int hip_handle_escrow_registration(struct in6_addr *hit)
{
	int err = 0;
	HIP_KEA * kea = NULL;
	// TODO: check the authorization of the registration
		
	// If hit is authorized add escrow association to database
	HIP_IFE(!(kea = hip_kea_create(hit)), -1);
	HIP_HEXDUMP("Created kea entry with peer hit: ", hit, 16);
	kea->keastate = HIP_KEASTATE_VALID;
	HIP_IFEBL(hip_keadb_add_entry(kea), -1, hip_keadb_put_entry(kea), 
		"Error while inserting KEA to keatable");
	HIP_DEBUG("Added kea entry");
	return 1;

out_err:	
	return 0;
}


int hip_cancel_escrow_registration(struct in6_addr *hit)
{
        int err = 0;
        HIP_KEA * kea = NULL;
        HIP_KEA_EP *client_end = NULL;
        HIP_KEA_EP *peer_end = NULL;
        
        HIP_DEBUG("Cancelling escrow registration\n");
        HIP_IFEL(!(kea = hip_kea_find(hit)), -1, "Error while finding kea\n");

        client_end = kea->client_end;
        peer_end = kea->peer_end;
        
        if (client_end != NULL) {
                HIP_DEBUG("Client end\n");
                if (hip_firewall_is_alive()) {
                        HIP_DEBUG("Firewall alive!\n");
                        HIP_IFEL(hip_firewall_remove_escrow_data(&client_end->ip, client_end->spi), 
                                -1, "Could not send remove escrow data -msg to firewall\n");
                }
                hip_kea_remove_endpoint(client_end);
                kea->client_end = NULL;
        }
        if (peer_end != NULL) {
                HIP_DEBUG("Peer end\n");
                if (hip_firewall_is_alive()) {
                        HIP_DEBUG("Firewall alive!\n");
                        HIP_IFEL(hip_firewall_remove_escrow_data(&peer_end->ip, peer_end->spi), 
                                -1, "Could not send remove escrow data -msg to firewall\n");
                }
                hip_kea_remove_endpoint(peer_end);
                kea->peer_end = NULL;               
        }
        
        hip_keadb_remove_entry(kea);
        
out_err:
        if (kea)
                hip_keadb_put_entry(kea); 
        return err;
}


int hip_cancel_escrow_service(void)
{
	// - notify all registered clients with REG_RESPONSE
	// - free all kea and kea_ep data
	int err = 0;
	HIP_KEA *kea = NULL;
	hip_ha_t *entry = NULL;
	struct in6_addr saddr = { 0 }, daddr = { 0 };
	uint8_t services[1] = { HIP_SERVICE_ESCROW };
	int i = 0;
	hip_list_t *item, *tmp;

	list_for_each_safe(item, tmp, kea_table, i)
	{
		kea = list_entry(item);
		hip_keadb_hold_entry(kea);
		//HIP_DEBUG_HIT("Sending cancel to client\n", kea->hit);
		HIP_DEBUG("Sending cancel to client\n");
		HIP_IFEL(!(entry = hip_hadb_try_to_find_by_peer_hit(&kea->hit)), 
				-1, "Could not find client entry\n");
		HIP_IFEL(hip_hadb_get_peer_addr(entry, &daddr), -1, 
				"Failed to get peer address");
		memcpy(&saddr, &entry->our_addr, sizeof(saddr));
		
		/* Here we should send an UPDATE with REG_RESPONSE to current
		   peer. The sending of the UPDATE was removed when the update.c
		   was revised.
		   -Lauri 01.07.2008 */
		
		hip_keadb_put_entry(kea);
		HIP_IFEL(hip_cancel_escrow_registration(&entry->hit_peer), 
				-1, "Error cancelling registration\n");
	}
	
	hip_uninit_kea_endpoints();
	hip_uninit_keadb();

out_err:
	return err;
}
