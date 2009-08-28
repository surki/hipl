// FIXME: whenever something that is replicated in beet db is
// modified, the modifications must be written there too.
#include "hadb.h"

HIP_HASHTABLE *hadb_hit;
struct in_addr peer_lsi_index;

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_hash_ha, const hip_ha_t *)
/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_compare_ha, const hip_ha_t *)

/* default set of miscellaneous function pointers. This has to be in the global
   scope. */

/** A transmission function set for sending raw HIP packets. */
hip_xmit_func_set_t default_xmit_func_set;
/** A transmission function set for NAT traversal. */
hip_xmit_func_set_t nat_xmit_func_set;

/* added by Tao Wan, 24 Jan, 2008, For IPsec (user_space/kernel) */
hip_ipsec_func_set_t default_ipsec_func_set;

static hip_misc_func_set_t ahip_misc_func_set;
static hip_misc_func_set_t default_misc_func_set;
static hip_input_filter_func_set_t default_input_filter_func_set;
static hip_output_filter_func_set_t default_output_filter_func_set;
static hip_rcv_func_set_t default_rcv_func_set;
static hip_rcv_func_set_t ahip_rcv_func_set;
static hip_handle_func_set_t default_handle_func_set;
static hip_handle_func_set_t ahip_handle_func_set;
static hip_update_func_set_t default_update_func_set;
static hip_update_func_set_t ahip_update_func_set;

unsigned long hip_hash_peer_addr(const void *ptr)
{
	struct in6_addr *addr = &((struct hip_peer_addr_list_item *)ptr)->address;
        uint8_t hash[HIP_AH_SHA_LEN];

	hip_build_digest(HIP_DIGEST_SHA1, addr, sizeof(*addr), hash);

	return *((unsigned long *) hash);
}

int hip_match_peer_addr(const void *ptr1, const void *ptr2)
{
	return (hip_hash_peer_addr(ptr1) != hip_hash_peer_addr(ptr2));
}

void hip_hadb_hold_entry(void *entry)
{
	HIP_DB_HOLD_ENTRY(entry,hip_ha_t);
}

void hip_hadb_put_entry(void *entry)
{
	HIP_DB_PUT_ENTRY(entry, hip_ha_t, hip_hadb_delete_state);
}

static void *hip_hadb_get_key_spi_list(void *entry)
{
	return (void *)(&((struct hip_hit_spi *)entry)->spi);
}

static int hit_match(hip_ha_t *entry, void *our) {
	return ipv6_addr_cmp(our, &entry->hit_our) == 0;
}

//static hip_list_t hadb_byspi_list[HIP_HADB_SIZE];

/**
 * hip_hadb_rem_state_hit - Remove HA from HIT table
 * @param entry HA
 * HA must be locked.
 */
static inline void hip_hadb_rem_state_hit(void *entry)
{
	hip_ha_t *ha = (hip_ha_t *)entry;
	HIP_DEBUG("\n");
	ha->hastate &= ~HIP_HASTATE_HITOK;
        if (ha->locator)
		free(ha->locator);
	ha->locator = NULL;
	hip_ht_delete(hadb_hit, entry);
}

/**
 * hip_hadb_remove_state_hit - Remove HA from HIT hash table.
 * @param ha HA
 */
static void hip_hadb_remove_state_hit(hip_ha_t *ha)
{
	HIP_LOCK_HA(ha);
	if ((ha->hastate & HIP_HASTATE_HITOK) == HIP_HASTATE_HITOK) {
		hip_hadb_rem_state_hit(ha);
	}
	HIP_UNLOCK_HA(ha);
}

/*
  Support for multiple inbound IPsec SAs:

  We need a separate hashtable containing elements HIT and SPI, which
  tells which HIT has the inbound SPI. When an ESP packet is received,
  we first get the SPI from it and perform a lookup on the HIT-SPI
  hashtable to get the mapping. Then we perform another lookup from
  the HIT hashtable using the HIT we got from the previous
  lookup. This way we get the HA belonging to the connection.

  hs = HIT-SPI (struct hip_hit_spi)

  (functions hip_ .. _hs)
*/


/*
 *
 * All the primitive functions up to this point are static, to force
 * some information hiding. The construct functions can access these
 * functions directly.
 *
 *
 */


/* PRIMITIVES */

/**
 * This function searches for a hip_ha_t entry from the hip_hadb_hit
 * by a HIT pair (local,peer).
 */
hip_ha_t *hip_hadb_find_byhits(hip_hit_t *hit, hip_hit_t *hit2)
{
  //int n = 0;
	hip_ha_t ha, *ret;
	memcpy(&ha.hit_our, hit, sizeof(hip_hit_t));
	memcpy(&ha.hit_peer, hit2, sizeof(hip_hit_t));
	HIP_DEBUG_HIT("HIT1", hit);
	HIP_DEBUG_HIT("HIT2", hit2);

	//HIP_DEBUG("----------Checking database-----------------\n");
	//hip_for_each_ha(hip_print_info_hadb, &n);
	//HIP_DEBUG("----------End Checking database-----------------\n");
	ret = hip_ht_find(hadb_hit, &ha);
	if (!ret) {
	        memcpy(&ha.hit_peer, hit, sizeof(hip_hit_t));
		memcpy(&ha.hit_our, hit2, sizeof(hip_hit_t));
		ret = hip_ht_find(hadb_hit, &ha);
	}

	return ret;
}

/**
 * This function simply goes through all local HIs and tries
 * to find a HADB entry that matches the current HI and
 * the given peer hit. First matching HADB entry is then returned.
 *
 * @todo Find a better solution, see the text below:
 * This function is needed because we index the HADB now by
 * key values calculated from <peer_hit,local_hit> pairs. Unfortunately, in
 * some functions like the ipv6 stack hooks hip_get_saddr() and
 * hip_handle_output() we just can't know the local_hit so we have to
 * improvise and just try to find some HA entry.
 *
 * @note This way of finding HA entries doesn't work properly if we have
 * multiple entries with the same peer_hit.
 * @note Don't use this function because it does not deal properly
 * with multiple source hits. Prefer hip_hadb_find_byhits() function.
 */
hip_ha_t *hip_hadb_try_to_find_by_peer_hit(hip_hit_t *hit)
{
	hip_list_t *item, *tmp;
	struct hip_host_id_entry *e;
	hip_ha_t *entry = NULL;
	hip_hit_t our_hit;
	int i;

	memset(&our_hit, 0, sizeof(our_hit));

	/* Let's try with the default HIT first */
	hip_get_default_hit(&our_hit);

	if (entry = hip_hadb_find_byhits(hit, &our_hit)) {
		_HIP_DEBUG_HIT("Returning default HIT", our_hit);
		return entry;
	}

	/* and then with rest (actually default HIT is here redundantly) */
	list_for_each_safe(item, tmp, hip_local_hostid_db, i)
	{
		e = list_entry(item);
		ipv6_addr_copy(&our_hit, &e->lhi.hit);
		_HIP_DEBUG_HIT("try_to_find_by_peer_hit:", &our_hit);
		_HIP_DEBUG_HIT("hit:", hit);
		entry = hip_hadb_find_byhits(hit, &our_hit);
		if (!entry)
			continue;
		else
			return entry;
	}
	return NULL;
}

/**
 * @brief Inserts a HIP association to HIP association hash table.
 *
 * Inserts a HIP association to HIP association hash table @c hadb_hit and
 * updates the the hastate of the HIP association @c ha. This function can be
 * called even if the @c ha is in the hash table already. <b>The peer address of
 * the host association must be set (i.e. @c ha->hit_peer must not be
 * ipv6_addr_any). </b> When @c ha is NULL or if @c ha->hit_peer is
 * ipv6_addr_any this function will kill the HIP daemon.
 *
 * @return The state of the HIP association (hip_hastate_t).
 * @note   For multithreaded model: this function assumes that @c ha is locked.
 */
int hip_hadb_insert_state(hip_ha_t *ha)
{
	hip_hastate_t st = 0;
	hip_ha_t *tmp = NULL;

	HIP_DEBUG("hip_hadb_insert_state() invoked.\n");

	/* assume already locked ha */

	HIP_ASSERT(!(ipv6_addr_any(&ha->hit_peer)));

	st = ha->hastate;

	HIP_DEBUG("hip_hadb_insert_state() invoked. Inserting a new state to "\
		  "the HIP association hash table.\n");

	if(ha == NULL) {
		HIP_DIE("Trying to insert a NULL HIP association to the HIP "\
			"association hash table.\n");
	} else if (ipv6_addr_any(&ha->hit_peer)) {
		HIP_DIE("Trying to insert a HIP association with zero "\
			"(ipv6_addr_any) peer HIT to the HIP association hash "\
			"table.\n");
	}

	st = ha->hastate;

#ifdef CONFIG_HIP_DEBUG /* Debug block. */
	{
		char hito[INET6_ADDRSTRLEN], hitp[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ha->hit_our, hito, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &ha->hit_peer, hitp, INET6_ADDRSTRLEN);
		HIP_DEBUG("Trying to insert a new state to the HIP "\
			  "association database. Our HIT: %s,"\
			  "Peer HIT: %s, HIP association state: %d\n",
			  hito, hitp, ha->hastate);
	}
#endif

	/* We're using hastate here as if it was a binary mask. hastate,
	   however, is of signed type and all of the predefined values are not
	   in the power of two. -Lauri 07.08.2008 */
	if (!(st & HIP_HASTATE_HITOK)) {
		tmp = hip_ht_find(hadb_hit, ha);

		if (tmp == NULL) {
		        if ((ha->lsi_peer).s_addr == 0) {
		                hip_hadb_set_lsi_pair(ha);
			}
			hip_ht_add(hadb_hit, ha);
			st |= HIP_HASTATE_HITOK;
			HIP_DEBUG("HIP association was inserted "\
				  "successfully.\n");
		} else {
			hip_db_put_ha(tmp, hip_hadb_delete_state);
			HIP_DEBUG("HIP association was NOT inserted because "\
				  "a HIP association with matching HITs was "\
				  "already present in the database.\n");
		}
	} else {
		HIP_DEBUG("HIP association was NOT inserted because the "\
			  "HIP association state is not OK.\n");
	}

#ifdef CONFIG_HIP_ESCROW
	{
		HIP_KEA *kea;
		kea = hip_kea_find(&ha->hit_our);
		if (kea) {
			/** @todo Check conditions for escrow associations here
			    (for now, there are none). */
			HIP_DEBUG("Escrow used for this entry: Initializing "\
				  "ha_state escrow fields.\n");
			ha->escrow_used = 1;
			ipv6_addr_copy(&ha->escrow_server_hit, &kea->server_hit);
			HIP_DEBUG_HIT("server hit saved: ", &kea->server_hit);
			hip_keadb_put_entry(kea);
		}
		else {
			HIP_DEBUG("Escrow not in use.\n");
		}
	}
#endif //CONFIG_HIP_ESCROW

	ha->hastate = st;
	return st;
}

int hip_print_info_hadb(hip_ha_t *entry, void *cntr)
{
	HIP_DEBUG_HIT("Peer HIT ", &entry->hit_peer);
	HIP_DEBUG_HIT("Our HIT ", &entry->hit_our);
	HIP_DEBUG_LSI("Our LSI ", &entry->lsi_our);
	if (&entry->lsi_peer) HIP_DEBUG_LSI("Peer LSI ", &entry->lsi_peer);
	return 0;
}


void hip_print_debug_info(struct in6_addr *local_addr,
			  struct in6_addr *peer_addr,
			  hip_hit_t  *local_hit,
			  hip_hit_t  *peer_hit,
			  hip_lsi_t  *peer_lsi,
			  const char *peer_hostname,
			  in_port_t *local_nat_udp_port,
			  in_port_t *peer_nat_udp_port){
	if(local_addr)
		HIP_DEBUG_IN6ADDR("Our addr", local_addr);
	if(peer_addr)
		HIP_DEBUG_IN6ADDR("Peer addr", peer_addr);
	if(local_hit)
		HIP_DEBUG_HIT("Our HIT", local_hit);
	if(peer_hit)
		HIP_DEBUG_HIT("Peer HIT", peer_hit);
	if(peer_lsi)
		HIP_DEBUG_LSI("Peer LSI", peer_lsi);
	if(peer_hostname)
		HIP_DEBUG("Peer hostname: %s\n", peer_hostname);
	
	if (local_nat_udp_port)
		HIP_DEBUG("Local NAT traversal UDP port: %d\n", *local_nat_udp_port);
	
	if (peer_nat_udp_port)
		HIP_DEBUG("Peer NAT traversal UDP port: %d\n", *peer_nat_udp_port);
}


void hip_hadb_set_lsi_pair(hip_ha_t *entry)
{
        hip_lsi_t aux;
	//Assign value to lsi_our searching in hidb by the correspondent hit
	_HIP_DEBUG("hip_hadb_set_lsi_pair\n");
	if (entry){
		hip_hidb_get_lsi_by_hit(&entry->hit_our, &entry->lsi_our);
		//Assign lsi_peer
		if (hip_map_hit_to_lsi_from_hosts_files(&entry->hit_peer,&aux))
			hip_generate_peer_lsi(&aux);
		memcpy(&entry->lsi_peer, &aux, sizeof(hip_lsi_t));
		_HIP_DEBUG_LSI("entry->lsi_peer is ", &entry->lsi_peer);
	}
}


/**
 * Practically called only by when adding a HIT-IP mapping before base exchange.
 *
 * @param  local_hit  a pointer to...
 * @param  peer_hit   a pointer to...
 * @param  local_addr a pointer to...
 * @param  peer_addr  a pointer to...
 * @param  peer_lsi   a pointer to...
 * @return
 * @todo   Allow multiple mappings; base exchange should be initiated to allow
 *         of them in order to prevent local DoS.
 * @todo   Create a security policy for triggering base exchange.
 * @todo   Multiple identities support: alternative a) make generic HIT prefix
 *         based policy to work alternative b) add SP pair for all local HITs.
 */
int hip_hadb_add_peer_info_complete(hip_hit_t *local_hit,
				    hip_hit_t *peer_hit,
				    hip_lsi_t *peer_lsi,
				    struct in6_addr *local_addr,
				    struct in6_addr *peer_addr,
				    const char *peer_hostname)
{
	int err = 0, n=0;
	hip_ha_t *entry = NULL, *aux = NULL;
	hip_lsi_t local_lsi, lsi_aux;
	in_port_t nat_udp_port_local = hip_get_local_nat_udp_port();
	in_port_t nat_udp_port_peer = hip_get_peer_nat_udp_port();

	HIP_DEBUG_INADDR("Local IP address ", local_addr);

	hip_print_debug_info(local_addr, peer_addr,
			     local_hit,  peer_hit,
			     peer_lsi,   peer_hostname,
			     &nat_udp_port_local,
			     &nat_udp_port_peer);

	entry = hip_hadb_find_byhits(local_hit, peer_hit);

	if (entry) {
		hip_hadb_dump_spis_out(entry);
		HIP_DEBUG_LSI("    Peer lsi   ",&entry->lsi_peer);

#if 0 /* Required for OpenDHT code of Pardeep?  */
		/* Check if LSIs are different */
		if (peer_lsi) {
			HIP_IFEL(hip_lsi_are_equal(&entry->lsi_peer, peer_lsi) ||
				 peer_lsi->s_addr == 0 , 0,
				 "Ignoring new mapping, old one exists\n");
		}
#endif
	}

	if (!entry){
		HIP_DEBUG("hip_hadb_create_state\n");
		entry = hip_hadb_create_state(0);
		HIP_IFEL(!entry, -1, "Unable to create a new entry");
		_HIP_DEBUG("created a new sdb entry\n");

		entry->peer_addr_list_to_be_added =
	  		hip_ht_init(hip_hash_peer_addr, hip_match_peer_addr);
	}

	ipv6_addr_copy(&entry->hit_peer, peer_hit);
	ipv6_addr_copy(&entry->hit_our, local_hit);
	ipv6_addr_copy(&entry->our_addr, local_addr);
	HIP_IFEL(hip_hidb_get_lsi_by_hit(local_hit, &entry->lsi_our), -1,
		 "Unable to find local hit");

	/*Copying peer_lsi*/
	if (peer_lsi != NULL && peer_lsi->s_addr != 0){
		ipv4_addr_copy(&entry->lsi_peer, peer_lsi);
	}
	else{
	        //Check if exists an entry in the hadb with the peer_hit given
	        aux = hip_hadb_try_to_find_by_peer_hit(peer_hit);
		if (aux && &(aux->lsi_peer).s_addr != 0){
		        // Exists: Assign its lsi to the new entry created
		        ipv4_addr_copy(&entry->lsi_peer, &aux->lsi_peer);
		} else if (!hip_map_hit_to_lsi_from_hosts_files(peer_hit, &lsi_aux)) {
			ipv4_addr_copy(&entry->lsi_peer, &lsi_aux);
		} else {
		  	// No exists: Call to the automatic generation
		        hip_generate_peer_lsi(&lsi_aux);
			ipv4_addr_copy(&entry->lsi_peer, &lsi_aux);
		}
	}

	/* If global NAT status is on, that is if the current host is behind
	   NAT, the NAT status of the host association is set on and the send
	   function set is set to "nat_xmit_func_set". */
	if(hip_nat_status && IN6_IS_ADDR_V4MAPPED(peer_addr) &&
	   !ipv6_addr_is_teredo(peer_addr)) {
		entry->nat_mode = hip_nat_status;
		entry->peer_udp_port = hip_get_peer_nat_udp_port();
		entry->local_udp_port = hip_get_local_nat_udp_port();
		entry->hadb_xmit_func = &nat_xmit_func_set;
	}
	else {
		/* NAT mode is not reset here due to "shotgun" support.
		   Hipd may get multiple locator mappings of which some can be
		   IPv4 and others IPv6. If NAT mode is on and the last
		   added address is IPv6, we don't want to reset NAT mode.
		   Note that send_udp() function can shortcut to send_raw()
		   when it gets an IPv6 address. */
		entry->hadb_xmit_func = &default_xmit_func_set;
	}

#ifdef CONFIG_HIP_BLIND
	if(hip_blind_status)
		entry->blind = 1;
#endif
	if (hip_hidb_hit_is_our(peer_hit)) {
		HIP_DEBUG("Peer HIT is ours (loopback)\n");
		entry->is_loopback = 1;
	}

     	entry->hip_is_opptcp_on = hip_get_opportunistic_tcp_status();
#ifdef CONFIG_HIP_I3
	entry->hip_is_hi3_on =    hip_get_hi3_status();
#endif
#ifdef CONFIG_HIP_HIPPROXY
     	entry->hipproxy = hip_get_hip_proxy_status();
#endif

	HIP_DEBUG_LSI("entry->lsi_peer \n", &entry->lsi_peer);
	hip_hadb_insert_state(entry);

	/* Released at the end */
	hip_hold_ha(entry);

	/* Add initial HIT-IP mapping. */
	HIP_IFEL(hip_hadb_add_peer_addr(entry, peer_addr, 0, 0, PEER_ADDR_STATE_ACTIVE),
		 -2, "error while adding a new peer address\n");

	HIP_IFEL(default_ipsec_func_set.hip_setup_hit_sp_pair(peer_hit, local_hit,
							       local_addr, peer_addr, 0, 1, 0),
		 -1, "Error in setting the SPs\n");

	if (entry)
		hip_db_put_ha(entry, hip_hadb_delete_state);
        /*
	hip_for_each_ha(hip_print_info_hadb, &n);
        */
out_err:
	return err;
}


/**
 * .
 *
 * @param  entry         a pointer to...
 * @param  peer_map_void a pointer to...
 * @return               ...
 */
int hip_hadb_add_peer_info_wrapper(struct hip_host_id_entry *entry,
				   void *peer_map_void)
{
	struct hip_peer_map_info *peer_map = peer_map_void;
	int err = 0;

	HIP_DEBUG("hip_hadb_add_peer_info_wrapper() invoked.\n");
	HIP_IFEL(hip_hadb_add_peer_info_complete(&entry->lhi.hit,
						 &peer_map->peer_hit,
						 &peer_map->peer_lsi,
						 &peer_map->our_addr,
						 &peer_map->peer_addr,
						 &peer_map->peer_hostname), -1,
		 "Failed to add peer info\n");

 out_err:
	return err;
}

int hip_hadb_add_peer_info(hip_hit_t *peer_hit, struct in6_addr *peer_addr,
			   hip_lsi_t *peer_lsi, const char *peer_hostname)
{
	int err = 0;
	struct hip_peer_map_info peer_map;

	HIP_DEBUG("hip_hadb_add_peer_info() invoked.\n");

 	in_port_t nat_local_udp_port = hip_get_local_nat_udp_port();
	in_port_t nat_peer_udp_port = hip_get_peer_nat_udp_port();
 	hip_print_debug_info(NULL, peer_addr, NULL, peer_hit, peer_lsi, peer_hostname,
 			&nat_local_udp_port, &nat_peer_udp_port);

	HIP_IFEL(!ipv6_addr_is_hit(peer_hit), -1, "Not a HIT\n");

	memset(&peer_map, 0, sizeof(peer_map));

	memcpy(&peer_map.peer_hit, peer_hit, sizeof(hip_hit_t));
	if (peer_addr)
		memcpy(&peer_map.peer_addr, peer_addr, sizeof(struct in6_addr));
	memset(peer_map.peer_hostname, '\0', HIP_HOST_ID_HOSTNAME_LEN_MAX);

	if(peer_lsi)
	        memcpy(&peer_map.peer_lsi, peer_lsi, sizeof(struct in6_addr));

	if(peer_hostname)
	        memcpy(peer_map.peer_hostname, peer_hostname,
		       HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);

	HIP_IFEL(hip_select_source_address(
			 &peer_map.our_addr, &peer_map.peer_addr),
		 -1, "Cannot find source address\n");
	
	HIP_IFEL(hip_for_each_hi(hip_hadb_add_peer_info_wrapper, &peer_map), 0,
	         "for_each_hi err.\n");

 out_err:
	return err;
}

int hip_add_peer_map(const struct hip_common *input)
{
	struct in6_addr *hit = NULL , *ip = NULL;
	hip_lsi_t *lsi = NULL;
	char *peer_hostname = NULL;
	int err = 0;
	_HIP_HEXDUMP("packet", input,  hip_get_msg_total_len(input));

	hit = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_HIT);

	lsi = (hip_lsi_t *)
		hip_get_param_contents(input, HIP_PARAM_LSI);

	ip = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_IPV6_ADDR);

	peer_hostname = (char *)
		hip_get_param_contents(input, HIP_PARAM_HOSTNAME);

	if (!ip && (!lsi || !hit)){
		HIP_ERROR("handle async map: no ip and maybe no lsi or hit\n");
		err = -ENODATA;
		goto out_err;
	}

	if (lsi)
	  	HIP_DEBUG_LSI("lsi value is\n",lsi);

	if (peer_hostname)
	  	HIP_DEBUG("Peer hostname value is %s\n", peer_hostname);

	err = hip_hadb_add_peer_info(hit, ip, lsi, peer_hostname);

	_HIP_DEBUG_HIT("hip_add_map_info peer's real hit=", hit);
	_HIP_ASSERT(hit_is_opportunistic_hashed_hit(hit));

 	if (err) {
 		HIP_ERROR("Failed to insert peer map (%d)\n", err);
		goto out_err;
	}

 out_err:

	return err;

}

/**
 * Allocates and initializes a new HA structure.
 *
 * @param  gfpmask a mask passed directly to HIP_MALLOC().
 * @return NULL if memory allocation failed, otherwise the HA.
 */
hip_ha_t *hip_hadb_create_state(int gfpmask)
{
	hip_ha_t *entry = NULL;
	int err = 0;

	entry = (hip_ha_t *) malloc(sizeof(struct hip_hadb_state));
	if (entry == NULL) {
		return NULL;
	}

	memset(entry, 0, sizeof(struct hip_hadb_state));

#if 0
	INIT_LIST_HEAD(&entry->next_hit);
	INIT_LIST_HEAD(&entry->spis_in);
	INIT_LIST_HEAD(&entry->spis_out);
#endif

	entry->spis_in = hip_ht_init(hip_hash_spi, hip_match_spi);
	entry->spis_out = hip_ht_init(hip_hash_spi, hip_match_spi);

#ifdef CONFIG_HIP_HIPPROXY
	entry->hipproxy = 0;
#endif
	//HIP_LOCK_INIT(entry);
	//atomic_set(&entry->refcnt,0);

	entry->state = HIP_STATE_UNASSOCIATED;
	entry->hastate = HIP_HASTATE_INVALID;

	/* Function pointer sets which define HIP behavior in respect to the
	   hadb_entry. */
	HIP_IFEL(hip_hadb_set_rcv_function_set(entry, &default_rcv_func_set),
		 -1, "Can't set new function pointer set.\n");
	HIP_IFEL(hip_hadb_set_handle_function_set(entry,
						  &default_handle_func_set),
		 -1, "Can't set new function pointer set.\n");
	HIP_IFEL(hip_hadb_set_update_function_set(entry,
						  &default_update_func_set),
		 -1, "Can't set new function pointer set\n");

	HIP_IFEL(hip_hadb_set_misc_function_set(entry, &default_misc_func_set),
		 -1, "Can't set new function pointer set.\n");

	/* Set the xmit function set as function set for sending raw HIP. */
	HIP_IFEL(hip_hadb_set_xmit_function_set(entry, &default_xmit_func_set),
		 -1, "Can't set new function pointer set.\n");

	HIP_IFEL(hip_hadb_set_input_filter_function_set(
			 entry, &default_input_filter_func_set), -1,
		 "Can't set new input filter function pointer set.\n");
	HIP_IFEL(hip_hadb_set_output_filter_function_set(
			 entry, &default_output_filter_func_set), -1,
		 "Can't set new output filter function pointer set.\n");

	/* added by Tao Wan, on 24, Jan, 2008 */
	entry->hadb_ipsec_func = &default_ipsec_func_set;

	//initialize the peer hostname
	memset(entry->peer_hostname, '\0', HIP_HOST_ID_HOSTNAME_LEN_MAX);

 out_err:
	return entry;
}

/* END OF PRIMITIVE FUNCTIONS */

/**
 * Selects the preferred address within the addresses of the given SPI.
 * The selected address is copied to @c addr, it is is non-NULL.
 */
int hip_hadb_select_spi_addr(hip_ha_t *entry, struct hip_spi_out_item *spi_out, struct in6_addr *addr)
{
	int err = 0, i;
	struct hip_peer_addr_list_item *s, *candidate = NULL;
	struct timeval latest, dt;
	hip_list_t *item, *tmp;

	list_for_each_safe(item, tmp, spi_out->peer_addr_list, i)
	{
		s = list_entry(item);
		if (s->address_state != PEER_ADDR_STATE_ACTIVE)
		{
			_HIP_DEBUG("skipping non-active address %s\n",addrstr);
			continue;
		}

		if (candidate)
		{
			int this_is_later;
			this_is_later = hip_timeval_diff(&s->modified_time, &latest, &dt);
			_HIP_DEBUG("latest=%ld.%06ld\n", latest.tv_sec, latest.tv_usec);
			_HIP_DEBUG("dt=%ld.%06ld\n", dt.tv_sec, dt.tv_usec);
			if (this_is_later)
			{
				_HIP_DEBUG("is later, change\n");
				memcpy(&latest, &s->modified_time, sizeof(struct timeval));
				candidate = s;
			}
		}
		else
		{
			candidate = s;
			memcpy(&latest, &s->modified_time, sizeof(struct timeval));
		}
	}

	if (!candidate)
	{
		HIP_ERROR("did not find usable peer address\n");
		HIP_DEBUG("todo: select from other SPIs ?\n");
		/* todo: select other SPI as the default SPI out */
		err = -ENOMSG;
	}
	else ipv6_addr_copy(addr, &candidate->address);

	return err;
}

/**
 * Gets some of the peer's usable IPv6 address.
 * @param entry corresponding hadb entry of the peer
 * @param addr where the selected IPv6 address of the peer is copied to
 *
 * Current destination address selection algorithm:
 * 1. use preferred address of the HA, if any (should be set)
 *
 * tkoponen: these are useless: ?
 * 2. use preferred address of the default outbound SPI, if any
 * (should be set, suspect bug if we get this far)
 *
 * 3. select among the active addresses of the default outbound SPI
 * (select the address which was added/updated last)
 *
 * @return 0 if some of the addresses was copied successfully, else < 0.
 */
int hip_hadb_get_peer_addr(hip_ha_t *entry, struct in6_addr *addr)
{
	int err = 0;
	//	struct hip_spi_out_item *spi_out;

	/* assume already locked entry */

	HIP_DEBUG_HIT("entry def addr", &entry->peer_addr);
	ipv6_addr_copy(addr, &entry->peer_addr);
        return err;
}

/**
 * Gets lsi address.
 * @param entry corresponding hadb entry of the peer
 * @param lsi where the selected lsi address of the peer is copied to
 *
 * @return 0 if some of the addresses was copied successfully, else < 0.
 */
int hip_hadb_get_peer_lsi(hip_ha_t *entry, hip_lsi_t *lsi)
{
	int err = 0;
	/* assume already locked entry */

	HIP_DEBUG_HIT("entry def addr", &entry->lsi_peer);
	ipv4_addr_copy(lsi, &entry->lsi_peer);
        return err;
}



/**
 * Gets infomation on the given peer IPv6 address.
 *
 * @param entry         corresponding hadb entry of the peer.
 * @param addr          the IPv6 address for which the information is to be
 *                      retrieved.
 * @param spi           where the outbound SPI of @c addr is copied to.
 * @param lifetime      where the lifetime of @c addr is copied to.
 * @param modified_time where the time when @c addr was added or updated is
 *                      copied to.
 * @return              If @c entry has the address @c addr in its peer address
 *                      list parameters @c spi, @c lifetime, and
 *                      @c modified_time are assigned if they are non-NULL and 1
 *                      is returned, else @c interface_id and @c lifetime are
 *                      not assigned a value and 0 is returned.
 */
int hip_hadb_get_peer_addr_info(hip_ha_t *entry, struct in6_addr *addr,
				uint32_t *spi, uint32_t *lifetime,
				struct timeval *modified_time)
{
	struct hip_peer_addr_list_item *s;
	int i = 1, ii, iii;
	struct hip_spi_out_item *spi_out;
	hip_list_t *item, *tmp, *a_item, *a_tmp;

	/* assumes already locked entry */
	list_for_each_safe(item, tmp, entry->spis_out, ii)
	{
		spi_out = list_entry(item);
		list_for_each_safe(a_item, a_tmp, spi_out->peer_addr_list, iii)
		{
			s = list_entry(a_item);
			if (!ipv6_addr_cmp(&s->address, addr))
			{
				_HIP_DEBUG("found\n");
				if (lifetime)
					*lifetime = s->lifetime;
				if (modified_time)
				{
					modified_time->tv_sec = s->modified_time.tv_sec;
					modified_time->tv_usec = s->modified_time.tv_usec;
				}
				if (spi)
					*spi = spi_out->spi;
				return 1;
			}
			i++;
		}
	}

	_HIP_DEBUG("not found\n");
	return 0;
}

/**
 * Adds a new peer IPv6 address to the entry's list of peer addresses.
 * @param entry corresponding hadb entry of the peer
 * @param new_addr IPv6 address to be added
 * @param spi outbound SPI to which the @c new_addr is related to
 * @param lifetime address lifetime of the address
 * @param state address state
 *
 * @return if @c new_addr already exists, 0 is returned. If address was
 * added successfully 0 is returned, else < 0.
 */
int hip_hadb_add_peer_addr(hip_ha_t *entry, struct in6_addr *new_addr,
			   uint32_t spi, uint32_t lifetime, int state)
{
	return hip_hadb_add_peer_udp_addr(entry, new_addr, 0, spi, lifetime, state);
#if 0
	int err = 0;
	struct hip_peer_addr_list_item *a_item;
	char addrstr[INET6_ADDRSTRLEN];
	uint32_t prev_spi;
	struct hip_spi_out_item *spi_list;

	/* assumes already locked entry */

	/* check if we are adding the peer's address during the base
	 * exchange */
	if (spi == 0) {
		HIP_DEBUG("SPI is 0, set address as the bex address\n");
		if (!ipv6_addr_any(&entry->peer_addr)) {
			hip_in6_ntop(&entry->peer_addr, addrstr);
			HIP_DEBUG("warning, overwriting existing preferred address %s\n",
				  addrstr);
		}
		ipv6_addr_copy(&entry->peer_addr, new_addr);
		HIP_DEBUG_IN6ADDR("entry->peer_addr \n", &entry->peer_addr);
		goto out_err;
	}

	spi_list = hip_hadb_get_spi_list(entry, spi);

	if (!spi_list)
	{
		HIP_ERROR("did not find SPI list for SPI 0x%x\n", spi);
		err = -EEXIST;
		goto out_err;
	}

	err = hip_hadb_get_peer_addr_info(entry, new_addr, &prev_spi, NULL, NULL);
	if (err)
	{
		/** @todo validate previous vs. new interface id for
		    the new_addr ? */
		if (prev_spi != spi)
			HIP_DEBUG("todo: SPI changed: prev=%u new=%u\n", prev_spi,
				  spi);

		HIP_DEBUG("duplicate address not added (todo: update address lifetime ?)\n");
		/** @todo update address lifetime ? */
		err = 0;
		goto out_err;
	}

	a_item = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
	if (!a_item)
	{
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	a_item->lifetime = lifetime;
	ipv6_addr_copy(&a_item->address, new_addr);
	a_item->address_state = state;
	do_gettimeofday(&a_item->modified_time);

	list_add(a_item, spi_list->peer_addr_list);

out_err:
	return err;
#endif
}


int hip_hadb_add_peer_udp_addr(hip_ha_t *entry, struct in6_addr *new_addr,in_port_t port,
			   uint32_t spi, uint32_t lifetime, int state)
{
	int err = 0;
	struct hip_peer_addr_list_item *a_item;
	char addrstr[INET6_ADDRSTRLEN];
	uint32_t prev_spi;
	struct hip_spi_out_item *spi_list;

	/* assumes already locked entry */

	/* check if we are adding the peer's address during the base
	 * exchange */
	if (spi == 0) {
		HIP_DEBUG("SPI is 0, set address as the bex address\n");
		if (!ipv6_addr_any(&entry->peer_addr)) {
			hip_in6_ntop(&entry->peer_addr, addrstr);
			HIP_DEBUG("warning, overwriting existing preferred address %s\n",
				  addrstr);
		}
		ipv6_addr_copy(&entry->peer_addr, new_addr);
		HIP_DEBUG_IN6ADDR("entry->peer_address \n", &entry->peer_addr);

		if (entry->peer_addr_list_to_be_added) {
			/*Adding the peer address to the entry->peer_addr_list_to_be_added
			 * So that later aftre base exchange it can be transfered to 
			 * SPI OUT's peer address list*/
			a_item = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
			if (!a_item)
			{
				HIP_ERROR("item HIP_MALLOC failed\n");
				err = -ENOMEM;
				goto out_err;
			}
			a_item->lifetime = lifetime;
			ipv6_addr_copy(&a_item->address, new_addr);
			a_item->address_state = state;
			do_gettimeofday(&a_item->modified_time);

			list_add(a_item, entry->peer_addr_list_to_be_added);
		}
		goto out_err;
	}

	spi_list = hip_hadb_get_spi_list(entry, spi);

	if (!spi_list)
	{
		HIP_ERROR("did not find SPI list for SPI 0x%x\n", spi);
		err = -EEXIST;
		goto out_err;
	}

	err = hip_hadb_get_peer_addr_info(entry, new_addr, &prev_spi, NULL, NULL);
	if (err)
	{
		/** @todo validate previous vs. new interface id for
		    the new_addr ? */
		if (prev_spi != spi)
			HIP_DEBUG("todo: SPI changed: prev=%u new=%u\n", prev_spi,
				  spi);

		HIP_DEBUG("duplicate address not added (todo: update address lifetime ?)\n");
		/** @todo update address lifetime ? */
		err = 0;
		goto out_err;
	}

	a_item = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), GFP_KERNEL);
	if (!a_item)
	{
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	a_item->lifetime = lifetime;
	a_item->port = port;
	ipv6_addr_copy(&a_item->address, new_addr);
	a_item->address_state = state;
	do_gettimeofday(&a_item->modified_time);

	list_add(a_item, spi_list->peer_addr_list);

out_err:
	return err;
}

/**
 * Deletes IPv6 address from the entry's list of peer addresses
 *
 * @param entry corresponding hadb entry of the peer
 * @param addr IPv6 address to be deleted
 */
void hip_hadb_delete_peer_addrlist_one(hip_ha_t *entry, struct in6_addr *addr)
{
	struct hip_peer_addr_list_item *a_item;
	int i = 1, ii, iii;
	struct hip_spi_out_item *spi_out;
	hip_list_t *spi_item, *spi_tmp, *item, *tmp;

	/* possibly deprecated function .. */

	HIP_LOCK_HA(entry);

	list_for_each_safe(spi_item, spi_tmp, entry->spis_out, ii)
	{
		spi_out = list_entry(spi_item);
		list_for_each_safe(item, tmp, spi_out->peer_addr_list, iii)
		{
			a_item = list_entry(item);
			if (!ipv6_addr_cmp(&a_item->address, addr))
			{
				_HIP_DEBUG("deleting address\n");
				list_del(a_item, spi_out->peer_addr_list);
				HIP_FREE(a_item);
				/* if address is on more than one spi list then do not goto out */
				goto out;
			}
			i++;
		}
	}
 out:
	HIP_UNLOCK_HA(entry);
	return;
}

int hip_del_peer_info_entry(hip_ha_t *ha)
{
	hip_opp_block_t *opp_entry   = NULL;
	hip_oppip_t     *oppip_entry = NULL;

	hip_hadb_remove_state_hit(ha);
	/* by now, if everything is according to plans, the refcnt
	   should be 1 */
	HIP_DEBUG_HIT("our HIT", &ha->hit_our);
	HIP_DEBUG_HIT("peer HIT", &ha->hit_peer);
	hip_delete_hit_sp_pair(&ha->hit_peer, &ha->hit_our, IPPROTO_ESP, 1);
	/* Not going to "put" the entry because it has been removed
	   from the hashtable already (hip_exit won't find it
	   anymore). */
	hip_hadb_delete_state(ha);
	//hip_db_put_ha(ha, hip_hadb_delete_state);
	/* and now zero --> deleted*/

	//if the ha entry is there, the opp entry
	//has already been removed

	/*empty the two opp dbs*/

	//delete entry from oppdb
	opp_entry = hip_oppdb_find_by_ip(&ha->peer_addr);
	if(opp_entry)
		hip_oppdb_entry_clean_up(opp_entry);

#if 0 /* the oppipdb entry must not be deleted or otherwise fallback fails to\
	 work */
	//delete entry from oppipdb
	oppip_entry = hip_oppipdb_find_byip(&ha->peer_addr);
	if(oppip_entry)
		hip_oppipdb_del_entry_by_entry(oppip_entry);
#endif /* 0 */

	return 0;
}

/**
 * Currently deletes the whole entry...
 */
int hip_del_peer_info(hip_hit_t *our_hit, hip_hit_t *peer_hit)
{
	hip_ha_t *ha;

	ha = hip_hadb_find_byhits(our_hit, peer_hit);
	if (!ha) {
		return -ENOENT;
	}

	return hip_del_peer_info_entry(ha);
}

/* assume already locked entry */
// SYNC
int hip_hadb_add_inbound_spi(hip_ha_t *entry, struct hip_spi_in_item *data)
{
	int err = 0, i;
	struct hip_spi_in_item *spi_item;
	uint32_t spi_in;
	hip_list_t *item, *tmp;
	spi_in = data->spi;

	/* assumes locked entry */
	_HIP_DEBUG("SPI_in=0x%x\n", spi_in);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		if (spi_item->spi == spi_in)
		{
			HIP_DEBUG("not adding duplicate SPI 0x%x\n", spi_in);
			goto out;
		}
	}

	spi_item = (struct hip_spi_in_item *)HIP_MALLOC(sizeof(struct hip_spi_in_item), GFP_ATOMIC);
	if (!spi_item)
	{
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	memcpy(spi_item, data, sizeof(struct hip_spi_in_item));
	spi_item->timestamp = jiffies;
	list_add(spi_item, entry->spis_in);
	spi_item->addresses = NULL;
	spi_item->addresses_n = 0;
	HIP_DEBUG("added SPI 0x%x to the inbound SPI list\n", spi_in);
	// hip_hold_ha(entry); ?

	/*_HIP_DEBUG("inserting SPI to HIT-SPI hashtable\n");
	err = hip_hadb_insert_state_spi_list(&entry->hit_peer, &entry->hit_our, spi_in);
	if (err == -EEXIST) err = 0;*/

out_err:
out:
	return err;
}

/* assume already locked entry */
// SYNCH
int hip_hadb_add_outbound_spi(hip_ha_t *entry, struct hip_spi_out_item *data)
{
	int err = 0, i;
	struct hip_spi_out_item *spi_item;
	uint32_t spi_out;
	hip_list_t *item, *tmp;

	/* assumes locked entry ? */
	spi_out = data->spi;

	_HIP_DEBUG("SPI_out=0x%x\n", spi_out);
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_item = list_entry(item);
		if (spi_item->spi == spi_out)
		{
			HIP_DEBUG("not adding duplicate SPI 0x%x\n", spi_out);
			goto out;
		}
	}

	spi_item = (struct hip_spi_out_item *)HIP_MALLOC(sizeof(struct hip_spi_out_item), GFP_ATOMIC);
	if (!spi_item)
	{
		HIP_ERROR("item HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	memcpy(spi_item, data, sizeof(struct hip_spi_out_item));
// 	INIT_LIST_HEAD(&spi_item->peer_addr_list);
	spi_item->peer_addr_list = hip_ht_init(hip_hash_peer_addr, hip_match_peer_addr);
	ipv6_addr_copy(&spi_item->preferred_address, &in6addr_any);
	list_add(spi_item, entry->spis_out);
	HIP_DEBUG("added SPI 0x%x to the outbound SPI list\n", spi_out);

 out_err:
 out:
	return err;
}

/* assume already locked entry */
int hip_hadb_add_spi(hip_ha_t *entry, int direction, void *data)
{
	int err = -EINVAL;

	if (direction == HIP_SPI_DIRECTION_IN)
		err = hip_hadb_add_inbound_spi(entry, (struct hip_spi_in_item *) data);
	else if (direction == HIP_SPI_DIRECTION_OUT)
		err = hip_hadb_add_outbound_spi(entry, (struct hip_spi_out_item *) data);
	else
		HIP_ERROR("bug, invalid direction %d\n", direction);

	return err;
}


/* Set the ifindex of given SPI */
/* assumes locked HA */
void hip_hadb_set_spi_ifindex(hip_ha_t *entry, uint32_t spi, int ifindex)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes that inbound spi already exists in ha's spis_in */
	HIP_DEBUG("SPI=0x%x ifindex=%d\n", spi, ifindex);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", spi_item->ifindex, spi_item->spi);
		if (spi_item->spi == spi)
		{
			HIP_DEBUG("found updated spi-ifindex mapping\n");
			spi_item->ifindex = ifindex;
			return;
		}
	}
	HIP_DEBUG("SPI not found, returning\n");
}

/* Get the ifindex of given SPI, returns 0 if SPI was not found */
int hip_hadb_get_spi_ifindex(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", spi_item->ifindex, spi_item->spi);
		if (spi_item->spi == spi || spi_item->new_spi == spi)
		{
			_HIP_DEBUG("found\n");
			return spi_item->ifindex;
		}
	}
	HIP_DEBUG("ifindex not found for the SPI 0x%x\n", spi);
	return 0;
}

/* Get the SPI of given ifindex, returns 0 if ifindex was not found  */
uint32_t hip_hadb_get_spi(hip_ha_t *entry, int ifindex)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("ifindex=%d\n", ifindex);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", spi_item->ifindex, spi_item->spi);
		if (spi_item->ifindex == ifindex || ifindex == -1)
		{
			HIP_DEBUG("found SPI 0x%x\n", spi_item->spi);
			return spi_item->spi;
		}
	}

	HIP_DEBUG("SPI not found for the ifindex\n");
	return 0;
}

uint32_t hip_update_get_prev_spi_in(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
				spi_item->ifindex, spi_item->spi, spi_item->nes_spi_out, spi_item->seq_update_id);
		if (spi_item->seq_update_id == peer_update_id) {
			HIP_DEBUG("found SPI 0x%x\n", spi_item->spi);
			return spi_item->spi;
		}
	}
	HIP_DEBUG("SPI not found\n");
	return 0;
}

/* Get the SPI of the SA belonging to the interface through
   which we received the UPDATE */
/* also sets updating flag of SPI to 1 */
uint32_t hip_get_spi_to_update_in_established(hip_ha_t *entry, struct in6_addr *dev_addr)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;
	int ifindex;

	HIP_DEBUG_HIT("dst dev_addr", dev_addr);
	ifindex = hip_devaddr2ifindex(dev_addr);
	HIP_DEBUG("ifindex of dst dev=%d\n", ifindex);
	if (!ifindex)
		return 0;

	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x\n", spi_item->ifindex, spi_item->spi);
		if (spi_item->ifindex == ifindex)
		{
			spi_item->updating = 1;
			return spi_item->spi;
		}
	}

	HIP_DEBUG("SPI not found for ifindex\n");
	return 0;
}

void hip_set_spi_update_status(hip_ha_t *entry, uint32_t spi, int set)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("spi=0x%x set=%d\n", spi, set);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x updating=%d\n",
				spi_item->ifindex, spi_item->spi, spi_item->updating);
		if (spi_item->spi == spi)
		{
			HIP_DEBUG("setting updating status to %d\n", set);
			spi_item->updating = set;
			break;
		}
	}
}

void hip_update_clear_status(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x\n", spi_item->spi);
		if (spi_item->spi == spi)
		{
			_HIP_DEBUG("clearing SPI status\n");
			spi_item->update_state_flags = 0;
			memset(&spi_item->stored_received_esp_info, 0,
					sizeof(struct hip_esp_info));
			break;
		}
	}
}

/* spi_out is the SPI which was in the received NES Old SPI field */
void hip_update_set_new_spi_in(hip_ha_t *entry, uint32_t spi, uint32_t new_spi,
			       uint32_t spi_out /* test */)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x new_spi=0x%x spi_out=0x%x\n", spi, new_spi, spi_out);

	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
				spi_item->spi, spi_item->new_spi);
		if (spi_item->spi == spi)
		{
			HIP_DEBUG("setting new_spi\n");
			if (!spi_item->updating)
			{
				_HIP_ERROR("SA update not in progress, continuing anyway\n");
			}
			if ((spi_item->spi != spi_item->new_spi) && spi_item->new_spi)
			{
				HIP_ERROR("warning: previous new_spi is not zero: 0x%x\n",
						spi_item->new_spi);
			}
			spi_item->new_spi = new_spi;
			spi_item->esp_info_spi_out = spi_out; /* maybe useless */
			break;
		}
	}
}

/* just sets the new_spi field */
void hip_update_set_new_spi_out(hip_ha_t *entry, uint32_t spi, uint32_t new_spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x new_spi=0x%x\n", spi, new_spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
				spi_item->spi, spi_item->new_spi);
		if (spi_item->spi == spi)
		{
			_HIP_DEBUG("setting new_spi\n");
			if (spi_item->new_spi)
			{
				HIP_ERROR("previous new_spi is not zero: 0x%x\n", spi_item->new_spi);
				HIP_ERROR("todo: delete previous new_spi\n");
			}
			spi_item->new_spi = new_spi;
			break;
		}
	}
}


uint32_t hip_update_get_new_spi_in(hip_ha_t *entry, uint32_t peer_update_id)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x\n",
			  spi_item->spi, spi_item->new_spi);
		if (spi_item->seq_update_id == peer_update_id)
		{
			if (spi_item->new_spi)
				return spi_item->new_spi;
			return spi_item->spi;
		}
	}
	HIP_DEBUG("New SPI not found\n");
	return 0;
}

/* switch from Old SPI to New SPI (inbound SA) */
/* caller must delete the Old SPI */
void hip_update_switch_spi_in(hip_ha_t *entry, uint32_t old_spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("old_spi=0x%x\n", old_spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: ifindex=%d spi=0x%x new_spi=0x%x nes_spi_out=0x%x seq_id=%u\n",
			   spi_item->ifindex, item->spi, spi_item->new_spi,
			   spi_item->nes_spi_out, spi_item->seq_update_id);
		if (spi_item->spi == old_spi)
		{
			_HIP_DEBUG("switching\n");
			spi_item->spi = spi_item->new_spi;
			spi_item->new_spi = 0;
			spi_item->esp_info_spi_out = 0;
			break;
		}
	}
}

/* switch from Old SPI to New SPI (outbound SA) */
/* caller must delete the Old SPI */
void hip_update_switch_spi_out(hip_ha_t *entry, uint32_t old_spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("old_spi=0x%x\n", old_spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi=0x%x new_spi=0x%x seq_id=%u\n",
			   spi_item->spi, spi_item->new_spi, spi_item->seq_update_id);
		if (spi_item->spi == old_spi)
		{
			_HIP_DEBUG("switching\n");
			spi_item->spi = spi_item->new_spi;
			spi_item->new_spi = 0;
			break;
		}
	}
}


void hip_update_set_status(hip_ha_t *entry, uint32_t spi, int set_flags,
			   uint32_t update_id, int update_flags_or,
			   struct hip_esp_info *esp_info,
			   uint16_t keymat_index)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	_HIP_DEBUG("spi=0x%x update_id=%u update_flags_or=0x%x keymat_index=%u esp_info=0x%p\n",
		   spi, update_id, update_flags_or, keymat_index, esp_info);
	if (esp_info)
		_HIP_DEBUG("esp_info: old_spi=0x%x new_spi=0x%x keymat_index=%u\n",
			   ntohl(esp_info->old_spi), ntohl(esp_info->new_spi), ntohs(esp_info->keymat_index));

	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi_in=0x%x new_spi=0x%x\n", spi_item->spi, spi_item->new_spi);
		if (spi_item->spi == spi)
		{
			_HIP_DEBUG("setting new values\n");
			if (set_flags & 0x1) spi_item->seq_update_id = update_id;
			if (set_flags & 0x2) spi_item->update_state_flags |= update_flags_or;
			if (esp_info && (set_flags & 0x4))
			{
				spi_item->stored_received_esp_info.old_spi = esp_info->old_spi;
				spi_item->stored_received_esp_info.new_spi = esp_info->new_spi;
				spi_item->stored_received_esp_info.keymat_index = esp_info->keymat_index;
			}
			if (set_flags & 0x8) spi_item->keymat_index = keymat_index;

			return;
		}
	}
	HIP_ERROR("SPI not found\n");
}


/**
 * If @c test_new_spi is 1 then test new_spi instead of spi.
 * @return 1 if given SPI belongs to the SA having direction, else 0.
 */
int hip_update_exists_spi(hip_ha_t *entry, uint32_t spi,
			       int direction, int test_new_spi)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *spi_item;
	int i;

	/* assumes locked entry  */

	_HIP_DEBUG("spi=0x%x direction=%d test_new_spi=%d\n",
		  spi, direction, test_new_spi);

	if (direction == HIP_SPI_DIRECTION_IN)
	{
		list_for_each_safe(item, tmp, entry->spis_in, i)
		{
			spi_item = list_entry(item);
			_HIP_DEBUG("test item: spi_in=0x%x new_spi=0x%x\n",
				   spi_item->spi, spi_item->new_spi);
			if ( (spi_item->spi == spi && !test_new_spi) ||
			     (spi_item->new_spi == spi && test_new_spi) )
				return 1;
		}
	}
	else
	{
		list_for_each_safe(item, tmp, entry->spis_out, i)
		{
			spi_item = list_entry(item);
			_HIP_DEBUG("test item: spi_out=0x%x new_spi=0x%x\n",
				   spi_item->spi, spi_item->new_spi);
			if ( (spi_item->spi == spi && !test_new_spi) ||
			     (spi_item->new_spi == spi && test_new_spi) )
				return 1;
		}
	}
	HIP_DEBUG("not found\n");
	return 0;
}

/* Get an usable outbound SPI, SPI must contain ACTIVE addresses */
/* todo: return void instead of spi */

/* returns the new default outbound SPI is succesful, or 0 if no
 * usable address was found */
uint32_t hip_hadb_relookup_default_out(hip_ha_t *entry)
{
	uint32_t spi = 0;
	struct hip_spi_out_item *spi_out;
	hip_list_t *item, *tmp;
	int i;

	/* assumes locked entry  */

	HIP_DEBUG("\n");
	/* latest outbound SPIs are usually in the beginning of the list */
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_out = list_entry(item);

		int ret;
		struct in6_addr addr;

		_HIP_DEBUG("checking SPI 0x%x\n", spi_out->spi);
		ret = hip_hadb_select_spi_addr(entry, spi_out, &addr);
		if (ret == 0)
		{
			hip_hadb_set_default_out_addr(entry, spi_out, &addr);
			spi = spi_out->spi;
			goto out;
		}
	}

	if (spi)
		HIP_DEBUG("Set SPI 0x%x as the default outbound SPI\n", spi);
	else
		HIP_DEBUG("Did not find an usable outbound SPI\n");
 out:
	return spi;
}

/* if add is non-NULL, set addr as the default address for both
 * entry's default address and outbound SPI list's default address*/

/* if addr is null, select some address from the SPI list */
void hip_hadb_set_default_out_addr(hip_ha_t *entry, struct hip_spi_out_item *spi_out,
				   struct in6_addr *addr)
{
	HIP_DEBUG("\n");

	if (!spi_out)
	{
		HIP_ERROR("NULL spi_out\n");
		return;
	}

	if (addr)
	{
		HIP_DEBUG("testing, setting given address as default out addr\n");
		ipv6_addr_copy(&spi_out->preferred_address, addr);
		ipv6_addr_copy(&entry->peer_addr, addr);
	}
	else
	{
		/* useless ? */
		struct in6_addr a;
		int err = hip_hadb_select_spi_addr(entry, spi_out, &a);
		_HIP_DEBUG("setting address as default out addr\n");
		if (!err)
		{
			ipv6_addr_copy(&spi_out->preferred_address, &a);
			ipv6_addr_copy(&entry->peer_addr, &a);
			HIP_DEBUG("default out addr\n",
				  &entry->peer_addr);
		}
		else HIP_ERROR("couldn't select and set preferred address\n");
	}
	HIP_DEBUG("setting default SPI out to 0x%x\n", spi_out->spi);
	entry->default_spi_out = spi_out->spi;
}

/* have_esp_info is 1, if there is ESP_INFO in the same packet as the ACK was */
void hip_update_handle_ack(hip_ha_t *entry, struct hip_ack *ack, int have_esp_info)
{
	size_t n = 0, i = 0;
	uint32_t *peer_update_id = NULL;

	HIP_DEBUG("hip_update_handle_ack() invoked with have_esp_info = %d.\n",
		  have_esp_info);

	if (ack == NULL) {
		HIP_ERROR("Function parameter ack was NULL in "\
			  "hip_update_handle_ack().\n");
		goto out_err;
	}

	if (hip_get_param_contents_len(ack) % sizeof(uint32_t)) {
		HIP_ERROR("ACK parameter length is not divisible by 4 (%u).\n",
			  hip_get_param_contents_len(ack));
		goto out_err;
	}

	n = hip_get_param_contents_len(ack) / sizeof(uint32_t);

	HIP_DEBUG("Number of peer Update IDs in ACK parameter: %d.\n", n);

	peer_update_id =
		(uint32_t *) ((void *)ack + sizeof(struct hip_tlv_common));

	/* Loop through all peer Update IDs in the ACK parameter. */
	for (i = 0; i < n; i++, peer_update_id++) {
		hip_list_t *item, *tmp;
		struct hip_spi_in_item *in_item;
		uint32_t puid = ntohl(*peer_update_id);
		int i;

		_HIP_DEBUG("peer Update ID=%u\n", puid);

		/* See if your ESP_INFO is acked and maybe if corresponging
		   ESP_INFO was received */
		list_for_each_safe(item, tmp, entry->spis_in, i) {
			in_item = list_entry(item);
			_HIP_DEBUG("test item: spi_in=0x%x seq=%u\n",
				   in_item->spi, in_item->seq_update_id);
			if (in_item->seq_update_id == puid) {
				_HIP_DEBUG("SEQ and ACK match\n");
				/* Received ACK */
				in_item->update_state_flags |= 0x1;
				/* Received also ESP_INFO */
				if (have_esp_info) {
					in_item->update_state_flags |= 0x2;
				}
			}
		}

	}
 out_err:
	return;
}



void hip_update_handle_esp_info(hip_ha_t *entry, uint32_t peer_update_id)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *spi_item;
	int i;

	_HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi_in=0x%x seq=%u\n",
			   spi_item->spi, spi_item->seq_update_id);
		if (spi_item->seq_update_id == peer_update_id)
		{
			_HIP_DEBUG("received peer's ESP_INFO\n");
			spi_item->update_state_flags |= 0x2; /* recv'd ESP_INFO */
		}
	}
}

/* works if update contains only one ESP_INFO */
int hip_update_get_spi_keymat_index(hip_ha_t *entry, uint32_t peer_update_id)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *spi_item;
	int i;

	_HIP_DEBUG("peer_update_id=%u\n", peer_update_id);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("test item: spi_in=0x%x seq_update_id=%u keymat_index=%u\n",
			   spi_item->spi, item->seq_update_id, item->keymat_index);
		if (spi_item->seq_update_id == peer_update_id)
		{
			return spi_item->keymat_index;
		}
	}
	return 0;
}

int hip_update_send_echo(hip_ha_t *entry,
			 uint32_t spi_out,
			 struct hip_peer_addr_list_item *addr){

	int err = 0, i = 0;
	struct hip_common *update_packet = NULL;
        hip_list_t *item = NULL, *tmp = NULL;
        struct netdev_address *n;

	HIP_DEBUG_HIT("new addr to check", &addr->address);

	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Update_packet alloc failed\n");

	HIP_IFEL(hip_build_verification_pkt(entry, update_packet, addr,
					    &entry->hit_peer, &entry->hit_our),
		 -1, "Building Echo Packet failed\n");

        /* Have to take care of UPDATE echos to opposite family */
        if (IN6_IS_ADDR_V4MAPPED((struct in6_addr *)&addr->address)
            == IN6_IS_ADDR_V4MAPPED(&entry->our_addr)) {
            HIP_IFEL(entry->hadb_xmit_func->
                     hip_send_pkt(&entry->our_addr, &addr->address,
                                  (entry->nat_mode ? hip_get_local_nat_udp_port() : 0), entry->peer_udp_port,
                                  update_packet, entry, 1),
                     -ECOMM, "Sending UPDATE packet with echo data failed.\n");
	} else {
            /* UPDATE echo is meant for opposite family of local_address*/
            /* check if we have one, otherwise let fail */
            list_for_each_safe(item, tmp, addresses, i) {
                n = list_entry(item);
                if (hip_sockaddr_is_v6_mapped(&n->addr)
                    != IN6_IS_ADDR_V4MAPPED(&entry->our_addr)) {
                    HIP_IFEL(entry->hadb_xmit_func->
                             hip_send_pkt(hip_cast_sa_addr(&n->addr),
                                          (struct in6_addr*)&addr->address,
                                          (entry->nat_mode ? hip_get_local_nat_udp_port() : 0), entry->peer_udp_port,
                                          update_packet, entry, 1),
                             -ECOMM, "Sending UPDATE packet with echo data failed.\n");
                }
            }
        }

 out_err:
	return err;

}

/* todo: use jiffies instead of timestamp */
uint32_t hip_hadb_get_latest_inbound_spi(hip_ha_t *entry)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *spi_item;
	uint32_t spi = 0;
	unsigned int now = jiffies;
	unsigned long t = ULONG_MAX;
	int i;

	/* assumes already locked entry */

	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		HIP_DEBUG("spi_in in loop is 0x%x\n", spi_item->spi);
		if (now - spi_item->timestamp < t)
		{
			spi = spi_item->spi;
			t = now - spi_item->timestamp;
		}
	}

	_HIP_DEBUG("newest spi_in is 0x%x\n", spi);
	return spi;
}
//add by santtu
/* todo: use jiffies instead of timestamp */
uint32_t hip_hadb_get_outbound_spi(hip_ha_t *entry)
{
	hip_list_t *item, *tmp;
	struct hip_spi_out_item *spi_item;
	uint32_t spi = 0;
	unsigned int now = jiffies;
	unsigned long t = ULONG_MAX;
	int i;

	/* assumes already locked entry */

	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_item = list_entry(item);

		spi = spi_item->spi;

		break;

	}

	_HIP_DEBUG("newest spi_in out 0x%x\n", spi);
	return spi;
}
//end add
/* get pointer to the outbound SPI list or NULL if the outbound SPI
   list does not exist */
struct hip_spi_out_item *hip_hadb_get_spi_list(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_out_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes already locked entry */

	_HIP_DEBUG("Search spi list for SPI=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_item = list_entry(item);
		_HIP_DEBUG("search: 0x%x ?= 0x%x\n", spi_item->spi, spi);
		if (spi_item->spi == spi) return spi_item;
	}

	return NULL;
}

/* get pointer to the inbound SPI list or NULL if SPI list does not exist */
struct hip_spi_in_item *hip_hadb_get_spi_in_list(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes already locked entry */

	HIP_DEBUG("SPI=0x%x\n", spi);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		if (spi_item->spi == spi) return spi_item;
	}

	return NULL;
}

/* add an address belonging to the SPI list */
/* or update old values */
int hip_hadb_add_addr_to_spi(hip_ha_t *entry, uint32_t spi,
			     struct in6_addr *addr,
			     int is_bex_address, uint32_t lifetime,
			     int is_preferred_addr)
{


	HIP_DEBUG("old hip_hadb_add_udp_addr_to_spi\n");
	return  hip_hadb_add_udp_addr_to_spi(entry, spi, addr, is_bex_address,
			lifetime, is_preferred_addr, 0, HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI_PRIORITY,0);
	//remove by santtu
#if 0
	int err = 0, new = 1, i;
	struct hip_spi_out_item *spi_list;
	struct hip_peer_addr_list_item *new_addr = NULL;
	struct hip_peer_addr_list_item *a;
	hip_list_t *item, *tmp;
	struct in6_addr *preferred_address;
	/* Assumes already locked entry */
	HIP_DEBUG("spi=0x%x is_preferred_addr=%d\n", spi, is_preferred_addr);

	spi_list = hip_hadb_get_spi_list(entry, spi);
	if (!spi_list)
	{
		HIP_ERROR("SPI list for 0x%x not found\n", spi);
		err = -EEXIST;
		goto out_err;
	}

	/* Check if addr already exists. If yes, then just update values. */
	list_for_each_safe(item, tmp, spi_list->peer_addr_list, i)
	{
		a = list_entry(item);
		if (!ipv6_addr_cmp(&a->address, addr))
		{
			// Do we send a verification if state is unverified?
			// The address should be awaiting verifivation already
			new_addr = a;
			new = 0;
			break;
		}
	}

	if (new)
	{
		HIP_DEBUG("create new addr item to SPI list\n");
		/* SPI list does not contain the address, add the address to the SPI list */
		new_addr = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), 0);
		if (!new_addr)
		{
			HIP_ERROR("item HIP_MALLOC failed\n");
			err = -ENOMEM;
			goto out_err;
		}
	}
	else HIP_DEBUG("update old addr item\n");

	new_addr->lifetime = lifetime;
	if (new) ipv6_addr_copy(&new_addr->address, addr);

	/* If the address is already bound, its lifetime is updated.
	   If the status of the address is DEPRECATED, the status is
	   changed to UNVERIFIED.  If the address is not already bound,
	   the address is added, and its status is set to UNVERIFIED. */


	/* We switch off the part that make no answer with echo response message
	   to the initiator. The reason is that we need the whole update schema work
	   for the program to run corrctly. This purely optimization part can be changed
	   latter. - Andrey.
	*/
#if 0
	if (!new)
	{
		switch (new_addr->address_state)
		{
		case PEER_ADDR_STATE_DEPRECATED:
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			HIP_DEBUG("updated address state DEPRECATED->UNVERIFIED\n");
			break;
 		case PEER_ADDR_STATE_ACTIVE:
			HIP_DEBUG("address state stays in ACTIVE\n");
			break;
		default:
			// Does this mean that unverified cant be here? Why?
			HIP_ERROR("state is UNVERIFIED, shouldn't even be here ?\n");
			break;
		}
	}
	else
	{
#endif
             if (is_bex_address)
		{
			/* workaround for special case */
 			HIP_DEBUG("address is base exchange address, setting state to ACTIVE\n");
			new_addr->address_state = PEER_ADDR_STATE_ACTIVE;
			HIP_DEBUG("setting bex addr as preferred address\n");
			ipv6_addr_copy(&entry->peer_addr, addr);
			new_addr->seq_update_id = 0;
		} else {
			HIP_DEBUG("address's state is set in state UNVERIFIED\n");
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			err = entry->hadb_update_func->hip_update_send_echo(entry, spi, new_addr);

			/** @todo: check! If not acctually a problem (during Handover). Andrey. */
			if( err==-ECOMM ) err = 0;
		}
		//}

	do_gettimeofday(&new_addr->modified_time);
	new_addr->is_preferred = is_preferred_addr;
	if(is_preferred_addr){
            //HIP_DEBUG("Since the address is preferred, we set the entry preferred_address as such\n");
              ipv6_addr_copy(&entry->peer_addr, &new_addr->address);
	}
	if (new) {
		HIP_DEBUG("adding new addr to SPI list\n");
		list_add(new_addr, spi_list->peer_addr_list);
	}

 out_err:
	HIP_DEBUG("returning, err=%d\n", err);
	return err;
#endif
}

/**
 * hip_hadb_dump_hits - Dump the contents of the HIT hash table.
 *
 * Should be safe to call from any context. THIS IS FOR DEBUGGING ONLY.
 * DONT USE IT IF YOU DONT UNDERSTAND IT.
 */
void hip_hadb_dump_hits(void)
{
	int i;
	hip_ha_t *entry;
	char *string;
	int cnt, k;
	hip_list_t *item, *tmp;

	string = (char *)HIP_MALLOC(4096, GFP_ATOMIC);
	if (!string)
	{
		HIP_ERROR("Cannot dump HADB... out of memory\n");
		return;
	}

	HIP_LOCK_HT(&hadb_hit);

	cnt = 0;
	list_for_each_safe(item, tmp, hadb_hit, i)
	{
		entry = list_entry(item);

		hip_hold_ha(entry);
		if (cnt > 3900)
		{
			string[cnt] = '\0';
			HIP_ERROR("%s\n", string);
			cnt = 0;
		}

		k = hip_in6_ntop2(&entry->hit_peer, string + cnt);
		cnt += k;
		hip_db_put_ha(entry, hip_hadb_delete_state);
	}
	HIP_ERROR("%s\n", string);

	HIP_UNLOCK_HT(&hadb_hit);
}


void hip_hadb_dump_spis_in(hip_ha_t *entry)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("start\n");
	HIP_LOCK_HA(entry);
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
		HIP_DEBUG(" SPI=0x%x new_SPI=0x%x esp_info_SPI_out=0x%x ifindex=%d "
			  "ts=%lu updating=%d keymat_index=%u upd_flags=0x%x seq_update_id=%u ESP_INFO=old 0x%x,new 0x%x,km %u\n",
			  spi_item->spi, spi_item->new_spi, spi_item->esp_info_spi_out, spi_item->ifindex,
			  jiffies - spi_item->timestamp, spi_item->updating, spi_item->keymat_index,
			  spi_item->update_state_flags, spi_item->seq_update_id,
			  spi_item->stored_received_esp_info.old_spi,
			  spi_item->stored_received_esp_info.old_spi,
			  spi_item->stored_received_esp_info.keymat_index);
	}
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("end\n");
}

void hip_hadb_dump_spis_out(hip_ha_t *entry)
{
	struct hip_spi_out_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("start\n");
	HIP_LOCK_HA(entry);
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_item = list_entry(item);
		HIP_DEBUG(" SPI=0x%x new_SPI=0x%x seq_update_id=%u\n",
			  spi_item->spi, spi_item->new_spi, spi_item->seq_update_id);
	}
	HIP_UNLOCK_HA(entry);
	HIP_DEBUG("end\n");
}

/**
 * Stores the keys negotiated in base exchange.
 *
 * @param ctx          the context inside which the key data will copied around.
 * @param is_initiator true if the localhost is the initiator, or false if the
 *                     localhost is the Responder
 * @return             0 if everything was stored successfully, otherwise < 0.
 */
int hip_store_base_exchange_keys(struct hip_hadb_state *entry,
				  struct hip_context *ctx, int is_initiator)
{
	int err = 0;
	int hmac_key_len, enc_key_len, auth_key_len, hip_enc_key_len;

	hmac_key_len = hip_hmac_key_length(entry->esp_transform);
	enc_key_len = hip_enc_key_length(entry->esp_transform);
	auth_key_len = hip_auth_key_length_esp(entry->esp_transform);
	hip_enc_key_len = hip_transform_key_length(entry->hip_transform);

	memcpy(&entry->hip_hmac_out, &ctx->hip_hmac_out, hmac_key_len);
	memcpy(&entry->hip_hmac_in, &ctx->hip_hmac_in, hmac_key_len);

	memcpy(&entry->esp_in.key, &ctx->esp_in.key, enc_key_len);
	memcpy(&entry->auth_in.key, &ctx->auth_in.key, auth_key_len);

	memcpy(&entry->esp_out.key, &ctx->esp_out.key, enc_key_len);
	memcpy(&entry->auth_out.key, &ctx->auth_out.key, auth_key_len);

	memcpy(&entry->hip_enc_out.key, &ctx->hip_enc_out.key, hip_enc_key_len);
	memcpy(&entry->hip_enc_in.key, &ctx->hip_enc_in.key, hip_enc_key_len);

	hip_update_entry_keymat(entry, ctx->current_keymat_index,
				ctx->keymat_calc_index, ctx->esp_keymat_index,
				ctx->current_keymat_K);

	if (entry->dh_shared_key)
	{
		HIP_DEBUG("HIP_FREEing old dh_shared_key\n");
		HIP_FREE(entry->dh_shared_key);
		entry->dh_shared_key = NULL;
	}

	entry->dh_shared_key_len = 0;
	/** @todo reuse pointer, no HIP_MALLOC */
	entry->dh_shared_key = (char *)HIP_MALLOC(ctx->dh_shared_key_len, GFP_ATOMIC);
	if (!entry->dh_shared_key)
	{
		HIP_ERROR("entry dh_shared HIP_MALLOC failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	entry->dh_shared_key_len = ctx->dh_shared_key_len;
	memcpy(entry->dh_shared_key, ctx->dh_shared_key, entry->dh_shared_key_len);
	_HIP_HEXDUMP("Entry DH SHARED", entry->dh_shared_key, entry->dh_shared_key_len);
	_HIP_HEXDUMP("Entry Kn", entry->current_keymat_K, HIP_AH_SHA_LEN);
	return err;

out_err:
	if (entry->dh_shared_key) {
		HIP_FREE(entry->dh_shared_key);
		entry->dh_shared_key = NULL;
	}

	return err;
}

/**
 * .
 *
 * @param entry ...
 * @param msg for future purposes (KeyNote)
 * @param peer ...
 * @return     ...
 */
int hip_init_peer(hip_ha_t *entry, struct hip_common *msg,
		  struct hip_host_id *peer)
{
	int err = 0;
	int len = hip_get_param_total_len(peer);
	struct in6_addr hit;

	/* public key and verify function might be initialized already in the
	   case of loopback */

	if (entry->peer_pub)
	{
		HIP_DEBUG("Not initializing peer host id, old exists\n");
		goto out_err;
	}

	HIP_IFEL(hip_host_id_to_hit(peer, &hit, HIP_HIT_TYPE_HASH100) ||
		 ipv6_addr_cmp(&hit, &entry->hit_peer),
		 -1, "Unable to verify sender's HOST_ID\n");

	HIP_IFEL(!(entry->peer_pub = HIP_MALLOC(len, GFP_KERNEL)),
		 -ENOMEM, "Out of memory\n");

	memcpy(entry->peer_pub, peer, len);
	entry->verify =
		hip_get_host_id_algo(entry->peer_pub) == HIP_HI_RSA ?
		hip_rsa_verify : hip_dsa_verify;

	if (hip_get_host_id_algo(entry->peer_pub) == HIP_HI_RSA)
		entry->peer_pub_key = hip_key_rr_to_rsa(entry->peer_pub, 0);
	else
		entry->peer_pub_key = hip_key_rr_to_dsa(entry->peer_pub, 0);

 out_err:
	HIP_DEBUG_HIT("peer's hit", &hit);
	HIP_DEBUG_HIT("entry's hit", &entry->hit_peer);
	return err;
}


/**
 * Initializes a HIP association.
 *
 * Initializes a new allocated HIP association @c entry.
 *
 * @param  a pointer to a HIP association to be initialized.
 * @param  a pointer to a HIT value that is to be bound with the HIP association
 *         @c entry
 * @return zero if success, negative otherwise.
 */
int hip_init_us(hip_ha_t *entry, hip_hit_t *hit_our)
{
        int err = 0, len = 0, alg = 0;

	if (entry->our_pub != NULL) {
		free(entry->our_pub);
		entry->our_pub = NULL;
	}

	/* Try to fetch our private host identity first using RSA then using DSA.
	   Note, that hip_get_host_id() allocates a new buffer and this buffer
	   must be freed in out_err if an error occurs. */

	if (hip_get_host_id_and_priv_key(HIP_DB_LOCAL_HID, hit_our, HIP_HI_RSA,
				&entry->our_pub, &entry->our_priv_key)) {
		 HIP_IFEL(hip_get_host_id_and_priv_key(HIP_DB_LOCAL_HID, hit_our,
				HIP_HI_DSA, &entry->our_pub, &entry->our_priv_key),
				-1, "Local host identity not found\n");
	}

	/* RFC 4034 obsoletes RFC 2535 and flags field differ */
	/* Get RFC2535 3.1 KEY RDATA format algorithm (Integer value). */
	alg = hip_get_host_id_algo(entry->our_pub);
	/* Using this integer we get a function pointer to a function that
	   signs our host identity. */
	entry->sign = (alg == HIP_HI_RSA ? hip_rsa_sign : hip_dsa_sign);

	/* Calculate our HIT from our public Host Identifier (HI).
	   Note, that currently (06.08.2008) both of these functions use DSA */
	err = ((alg == HIP_HI_DSA) ?
		hip_dsa_host_id_to_hit(entry->our_pub, &entry->hit_our,
				       HIP_HIT_TYPE_HASH100) :
		hip_rsa_host_id_to_hit(entry->our_pub, &entry->hit_our,
				       HIP_HIT_TYPE_HASH100));
	HIP_IFEL(err, err, "Unable to digest the HIT out of public key.");
	if(err != 0) {
		HIP_ERROR("Unable to digest the HIT out of public key.");
		goto out_err;
	}

 out_err:

	if (err && entry->our_pub) {
		HIP_FREE(entry->our_pub);
		entry->our_pub = NULL;
	}

	return err;
}

/* ----------------- */

unsigned long hip_hash_ha(const hip_ha_t *ha)
{
	hip_hit_t hitpair[2];
	uint8_t hash[HIP_AH_SHA_LEN];

	if(ha == NULL || &(ha->hit_our) == NULL || &(ha->hit_peer) == NULL)
	{
		return 0;
	}

	/* The HIT fields of an host association struct cannot be assumed to be
	   alligned consecutively. Therefore, we must copy them to a temporary
	   array. */
	memcpy(&hitpair[0], &(ha->hit_our), sizeof(ha->hit_our));
	memcpy(&hitpair[1], &(ha->hit_peer), sizeof(ha->hit_peer));

	hip_build_digest(HIP_DIGEST_SHA1, (void *)hitpair, sizeof(hitpair),
			 hash);

	return *((unsigned long *)hash);
}

int hip_compare_ha(const hip_ha_t *ha1, const hip_ha_t *ha2)
{
     if(ha1 == NULL || &(ha1->hit_our) == NULL || &(ha1->hit_peer) == NULL ||
	ha2 == NULL || &(ha2->hit_our) == NULL || &(ha2->hit_peer) == NULL)
     {
	  return 1;
     }

     return (hip_hash_ha(ha1) != hip_hash_ha(ha2));
}


void hip_init_hadb(void)
{
     /** @todo Check for errors. */

     /* The next line initializes the hash table for host associations. Note
	that we are using callback wrappers IMPLEMENT_LHASH_HASH_FN and
	IMPLEMENT_LHASH_COMP_FN defined in the beginning of this file. These
	provide automagic variable casts, so that all elements stored in the
	hash table are cast to hip_ha_t. Lauri 09.10.2007 16:58. */
     hadb_hit = hip_ht_init(LHASH_HASH_FN(hip_hash_ha),
			    LHASH_COMP_FN(hip_compare_ha));

     /* initialize default function pointer sets for receiving messages*/
     default_rcv_func_set.hip_receive_i1        = hip_receive_i1;
     default_rcv_func_set.hip_receive_r1        = hip_receive_r1;
     default_rcv_func_set.hip_receive_i2        = hip_receive_i2;
     default_rcv_func_set.hip_receive_r2        = hip_receive_r2;
     default_rcv_func_set.hip_receive_update    = hip_receive_update;
     default_rcv_func_set.hip_receive_notify    = hip_receive_notify;
     default_rcv_func_set.hip_receive_bos       = hip_receive_bos;
     default_rcv_func_set.hip_receive_close     = hip_receive_close;
     default_rcv_func_set.hip_receive_close_ack = hip_receive_close_ack;

     /* initialize alternative function pointer sets for receiving messages*/
     /* insert your alternative function sets here!*/

     /* initialize default function pointer sets for handling messages*/
     default_handle_func_set.hip_handle_i1        = hip_handle_i1;
     default_handle_func_set.hip_handle_r1        = hip_handle_r1;
     default_handle_func_set.hip_handle_i2        = hip_handle_i2;
     default_handle_func_set.hip_handle_r2        = hip_handle_r2;
     default_handle_func_set.hip_handle_bos       = hip_handle_bos;
     default_handle_func_set.hip_handle_close     = hip_handle_close;
     default_handle_func_set.hip_handle_close_ack = hip_handle_close_ack;

     /* initialize alternative function pointer sets for handling messages*/
     /* insert your alternative function sets here!*/

     /* initialize default function pointer sets for misc functions*/
     default_misc_func_set.hip_solve_puzzle  	       = hip_solve_puzzle;
     default_misc_func_set.hip_produce_keying_material = hip_produce_keying_material;
     default_misc_func_set.hip_create_i2	       = hip_create_i2;
     default_misc_func_set.hip_create_r2	       = hip_create_r2;
     default_misc_func_set.hip_build_network_hdr       = hip_build_network_hdr;

     /* initialize alternative function pointer sets for misc functions*/
     /* insert your alternative function sets here!*/

     /* initialize default function pointer sets for update functions*/
     default_update_func_set.hip_handle_update_plain_locator = hip_handle_update_plain_locator;
     default_update_func_set.hip_handle_update_addr_verify   = hip_handle_update_addr_verify;
     default_update_func_set.hip_update_handle_ack	     = hip_update_handle_ack;
     default_update_func_set.hip_handle_update_established   = hip_handle_update_established;
     default_update_func_set.hip_handle_update_rekeying      = hip_handle_update_rekeying;
     default_update_func_set.hip_update_send_addr_verify     = hip_update_send_addr_verify;
     default_update_func_set.hip_update_send_echo	     = hip_update_send_echo;

     /* xmit function set */
#ifdef CONFIG_HIP_I3
     if(hip_get_hi3_status()){
	  default_xmit_func_set.hip_send_pkt = hip_send_i3;
     }
     else
#endif
	  default_xmit_func_set.hip_send_pkt = hip_send_raw;
     

     nat_xmit_func_set.hip_send_pkt = hip_send_udp;

     /* filter function sets */
     /* Compiler warning: assignment from incompatible pointer type.
	Please fix this, if you know what is the correct value.
	-Lauri 25.09.2007 15:11. */
     default_input_filter_func_set.hip_input_filter	= hip_agent_filter;
     default_output_filter_func_set.hip_output_filter   = hip_agent_filter;

     /* Tao Wan and Miika komu added, 24 Jan, 2008 for IPsec (userspace / kernel part)
      *
      * copy in user_ipsec_hipd_msg.c */
     if (hip_use_userspace_ipsec) {
	     default_ipsec_func_set.hip_add_sa = hip_userspace_ipsec_add_sa;
	     default_ipsec_func_set.hip_delete_sa = hip_userspace_ipsec_delete_sa;
	     default_ipsec_func_set.hip_setup_hit_sp_pair = hip_userspace_ipsec_setup_hit_sp_pair;
	     default_ipsec_func_set.hip_delete_hit_sp_pair = hip_userspace_ipsec_delete_hit_sp_pair;
	     default_ipsec_func_set.hip_flush_all_policy = hip_userspace_ipsec_flush_all_policy;
	     default_ipsec_func_set.hip_flush_all_sa = hip_userspace_ipsec_flush_all_sa;
	     default_ipsec_func_set.hip_acquire_spi = hip_acquire_spi;
	     default_ipsec_func_set.hip_delete_default_prefix_sp_pair = hip_userspace_ipsec_delete_default_prefix_sp_pair;
	     default_ipsec_func_set.hip_setup_default_sp_prefix_pair = hip_userspace_ipsec_setup_default_sp_prefix_pair;
     } else {
	     default_ipsec_func_set.hip_add_sa = hip_add_sa;
	     default_ipsec_func_set.hip_delete_sa = hip_delete_sa;
	     default_ipsec_func_set.hip_setup_hit_sp_pair = hip_setup_hit_sp_pair;
	     default_ipsec_func_set.hip_delete_hit_sp_pair = hip_delete_hit_sp_pair;
	     default_ipsec_func_set.hip_flush_all_policy = hip_flush_all_policy;
	     default_ipsec_func_set.hip_flush_all_sa = hip_flush_all_sa;
	     default_ipsec_func_set.hip_acquire_spi = hip_acquire_spi;
	     default_ipsec_func_set.hip_delete_default_prefix_sp_pair = hip_delete_default_prefix_sp_pair;
	     default_ipsec_func_set.hip_setup_default_sp_prefix_pair = hip_setup_default_sp_prefix_pair;
     }
}

unsigned long hip_hadb_hash_file_hits(const void *ptr){
        HIP_DEBUG("string %s\n",((hip_hosts_entry *)ptr)->hostname);
	char *fqdn = ((hip_hosts_entry *)ptr)->hostname;
        uint8_t hash[HIP_AH_SHA_LEN];

	hip_build_digest(HIP_DIGEST_SHA1, fqdn, strlen(fqdn)+1, hash);
	return *((unsigned long *)hash);
}

int hip_hadb_hash_match_file_hits(const void *ptr1, const void *ptr2){
        return (hip_hadb_hash_file_hits(ptr1) != hip_hadb_hash_file_hits(ptr2));
}

#if 0
void hip_hadb_init_db_file_hits(void){
        hadb_file_hits = hip_ht_init(hip_hadb_hash_file_hits,hip_hadb_hash_match_file_hits);
}

/*Initialize hadb with values contained in /etc/hip/hosts*/
int hip_init_hadb_hip_host(){
        int err = 0, i = 0;
	hip_hosts_entry *element = NULL;
	hip_list_t *item, *tmp;
	struct in6_addr address;

	hip_hadb_init_db_file_hits();

	/* Look up /etc/hip/host */
        gaih_inet_get_hip_hosts_file_info(hadb_file_hits);

	/* Add the information to the HADB */
	list_for_each_safe(item, tmp, hadb_file_hits, i){
	        element = list_entry(item);
		memset(&address, 0, sizeof(struct in6_addr));
		hip_find_address(element->hostname, &address);
		if ((element->lsi).s_addr == 0)
		        hip_hadb_add_peer_info(&element->hit, &address, NULL);
		else
		        hip_hadb_add_peer_info(&element->hit, &address, &element->lsi);
	}
	return err;
}
#endif

hip_xmit_func_set_t *hip_get_xmit_default_func_set() {
	return &default_xmit_func_set;
}

hip_misc_func_set_t *hip_get_misc_default_func_set() {
	return &default_misc_func_set;
}

hip_input_filter_func_set_t *hip_get_input_filter_default_func_set() {
	return &default_input_filter_func_set;
}

hip_output_filter_func_set_t *hip_get_output_filter_default_func_set() {
	return &default_output_filter_func_set;
}

hip_rcv_func_set_t *hip_get_rcv_default_func_set() {
	return &default_rcv_func_set;
}

hip_handle_func_set_t *hip_get_handle_default_func_set() {
	return &default_handle_func_set;
}

hip_update_func_set_t *hip_get_update_default_func_set() {
	return &default_update_func_set;
}

/**
 * Sets function pointer set for an hadb record. Pointer values will not be
 * copied!
 *
 * @param entry         a pointer to the hadb record
 * @param new_func_set  a pointer to the new function set
 * @return              0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_rcv_function_set(hip_ha_t * entry,
				   hip_rcv_func_set_t * new_func_set){
     /** @todo add check whether all function pointers are set */
     if( entry ){
	  entry->hadb_rcv_func = new_func_set;
	  return 0;
     }
      return -1;
}

/**
 * Sets function pointer set for an hadb record. Pointer values will not be
 * copied!
 *
 * @param entry        a pointer to the hadb record.
 * @param new_func_set a pointer to the new function set.
 * @return             0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_handle_function_set(hip_ha_t * entry,
				     hip_handle_func_set_t * new_func_set){
	/** @todo add check whether all function pointers are set. */
	if( entry ){
		entry->hadb_handle_func = new_func_set;
		return 0;
	}
	return -1;
}

/**
 * Sets function pointer set for an hadb record. Pointer values will not be
 * copied!
 *
 * @param entry        pointer to the hadb record.
 * @param new_func_set pointer to the new function set.
 * @return             0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_misc_function_set(hip_ha_t * entry,
				   hip_misc_func_set_t * new_func_set){
	/** @todo add check whether all function pointers are set. */
	if( entry ){
		entry->hadb_misc_func = new_func_set;
		return 0;
	}
	return -1;
}

int hip_hadb_set_xmit_function_set(hip_ha_t * entry,
				   hip_xmit_func_set_t * new_func_set){
	if( entry ){
		entry->hadb_xmit_func = new_func_set;
		return 0;
	}
}

int hip_hadb_set_input_filter_function_set(hip_ha_t * entry,
					   hip_input_filter_func_set_t * new_func_set)
{
	if( entry ){
		entry->hadb_input_filter_func = new_func_set;
		return 0;
	}
}

int hip_hadb_set_output_filter_function_set(hip_ha_t * entry,
					   hip_output_filter_func_set_t * new_func_set)
{
	if( entry ){
		entry->hadb_output_filter_func = new_func_set;
		return 0;
	}
}

/**
 * Sets function pointer set for an hadb record. Pointer values will not be
 * copied!
 *
 * @param entry        a pointer to the hadb record.
 * @param new_func_set a pointer to the new function set.
 * @return             0 if everything was stored successfully, otherwise < 0.
 */
int hip_hadb_set_update_function_set(hip_ha_t * entry,
				     hip_update_func_set_t * new_func_set){
     /** @todo add check whether all function pointers are set */
	if( entry ){
		entry->hadb_update_func = new_func_set;
		return 0;
	}
	//HIP_ERROR("Func pointer set malformed. Func pointer set NOT appied.");
	return -1;
}

/* NOTE! When modifying this function, remember that some control values may
   not be allowed to co-exist. Therefore the logical OR might not be enough
   for all controls. */
void hip_hadb_set_local_controls(hip_ha_t *entry, hip_controls_t mask)
{
	if(entry != NULL) {
		switch(mask) {

		case HIP_HA_CTRL_NONE:
			entry->local_controls &= mask;
		case HIP_HA_CTRL_LOCAL_REQ_UNSUP:
		case HIP_HA_CTRL_LOCAL_REQ_ESCROW:
		case HIP_HA_CTRL_LOCAL_REQ_RELAY:
		case HIP_HA_CTRL_LOCAL_REQ_RVS:
		case HIP_HA_CTRL_LOCAL_REQ_SAVAH:
#if 0
			if(mask == HIP_HA_CTRL_LOCAL_REQ_RELAY)
			{
				hip_nat_set_control(entry, 1);
				HIP_DEBUG("nat control has been reset to 1\n");
			}
#endif			
			entry->local_controls |= mask;
			break;
		default:
			HIP_ERROR("Unknown local controls given.\n");
		}
	}
}

/* NOTE! When modifying this function, remember that some control values may
   not be allowed to co-exist. Therefore the logical OR might not be enough
   for all controls. */
void hip_hadb_set_peer_controls(hip_ha_t *entry, hip_controls_t mask)
{
	if(entry != NULL) {
		switch(mask) {

		case HIP_HA_CTRL_NONE:
			entry->peer_controls &= mask;
		case HIP_HA_CTRL_PEER_UNSUP_CAPABLE:
		case HIP_HA_CTRL_PEER_ESCROW_CAPABLE:
		case HIP_HA_CTRL_PEER_RVS_CAPABLE:
		case HIP_HA_CTRL_PEER_RELAY_CAPABLE:
		case HIP_HA_CTRL_PEER_SAVAH_CAPABLE:
		case HIP_HA_CTRL_PEER_GRANTED_SAVAH:
		case HIP_HA_CTRL_PEER_GRANTED_UNSUP:
		case HIP_HA_CTRL_PEER_GRANTED_ESCROW:
		case HIP_HA_CTRL_PEER_GRANTED_RVS:			
		case HIP_HA_CTRL_PEER_GRANTED_RELAY:
		case HIP_HA_CTRL_PEER_REFUSED_UNSUP:
		case HIP_HA_CTRL_PEER_REFUSED_ESCROW:
		case HIP_HA_CTRL_PEER_REFUSED_RELAY:
		case HIP_HA_CTRL_PEER_REFUSED_RVS:
		case HIP_HA_CTRL_PEER_REFUSED_SAVAH:
#if 0
			if(mask == HIP_HA_CTRL_PEER_GRANTED_RELAY)
			{
				hip_nat_set_control(entry, 1);
				HIP_DEBUG("nat control has been reset to 1\n");
			}
#endif
			entry->peer_controls |= mask;
			break;
		default:
			HIP_ERROR("Unknown peer controls given.\n");
		}
	}
}

void hip_hadb_cancel_local_controls(hip_ha_t *entry, hip_controls_t mask)
{
	if(entry != NULL) {
		entry->local_controls &= (~mask);
	}
}

void hip_hadb_cancel_peer_controls(hip_ha_t *entry, hip_controls_t mask)
{
     if(entry != NULL) {
	     entry->peer_controls &= (~mask);
     }
}

void hip_uninit_hadb()
{
	int i;
	hip_ha_t *ha, *tmp;
	//struct hip_hit_spi *hs, *tmp_hs;

	HIP_DEBUG("\n");

	HIP_DEBUG("DEBUG: DUMP SPI LISTS\n");
//	hip_hadb_dump_hs_ht();

	/* I think this is not very safe deallocation.
	 * Locking the hadb_spi and hadb_hit could be one option, but I'm not
	 * very sure that it will work, as they are locked later in
	 * hip_hadb_remove_state() for a while.
	 *
	 * The list traversing is not safe in smp way :(
	 */
//	hip_ht_uninit(hadb_hit);
}

void hip_delete_all_sp()
{
	int i;
	hip_ha_t *ha, *tmp;
	//struct hip_hit_spi *hs, *tmp_hs;
	struct hip_spi_in_item *item, *tmp_spi;
	HIP_DEBUG("\n");

	HIP_DEBUG("DEBUG: DUMP SPI LISTS\n");
	//hip_hadb_dump_hs_ht();

	/* I think this is not very safe deallocation.
	 * Locking the hadb_spi and hadb_hit could be one option, but I'm not
	 * very sure that it will work, as they are locked later in
	 * hip_hadb_remove_state() for a while.
	 *
	 * The list traversing is not safe in smp way :(
	 */
	HIP_DEBUG("DELETING HA HT\n");

}


/**
* A private function to add an entry to the peer list. Add an IPv6 address
* (if valid) to the peer list and update the tail pointer.
*
* @param addr  IPv6 address
* @param entry peer list entry
* @param last  pointer to pointer to end of peer list linked list
* @return      zero on success, or negative error value on failure
*/
int hip_list_peers_add(struct in6_addr *address,
			      hip_peer_entry_opaque_t *entry,
			      hip_peer_addr_opaque_t **last)
{
	hip_peer_addr_opaque_t *addr;

	HIP_DEBUG_IN6ADDR("## SPI is 0, found bex address:", address);

	/* Allocate an entry for the address */
	addr = HIP_MALLOC(sizeof(hip_peer_addr_opaque_t), GFP_ATOMIC);
	if (!addr) {
		HIP_ERROR("No memory to create peer addr entry\n");
		return -ENOMEM;
	}
	addr->next = NULL;
	/* Record the peer addr */
	ipv6_addr_copy(&addr->addr, address);

	if (*last == NULL) {  /* First entry? Add to head and tail */
		entry->addr_list = addr;
	} else {             /* Otherwise, add to tail */
		(*last)->next = addr;
	}
	*last = addr;
	entry->count++;   /* Increment count in peer entry */
	return 0;
}

/**
 * A private function to process a hadb entry Process a hadb entry, extracting
 * the HOST ID, HIT, and IPv6 addresses.
 *
 * @param entry  hadb table entry
 * @param opaque private data for the function (contains record keeping
 *               structure)
 * @return       zero on success, or negative error value on failure
 */
int hip_hadb_list_peers_func(hip_ha_t *entry, void *opaque)
{
	int err = 0;
	return err;
}

/* Delete given inbound SPI, and all if spi == 0 */
void hip_hadb_delete_inbound_spi(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_in_item *spi_item;
	hip_list_t *item, *tmp;
	int i;

	/* assumes locked entry */
	HIP_DEBUG("SPI=0x%x\n", spi);
	int counter = 0;

	/** @todo check that the deletion below actually works (hits and
	    addresses are used inconsistenly). */
	list_for_each_safe(item, tmp, entry->spis_in, i)
	{
		spi_item = list_entry(item);
	  	if (!spi || spi_item->spi == spi)
	  	{
		  	HIP_DEBUG("deleting SPI_in=0x%x SPI_in_new=0x%x from "
				  "inbound list, item=0x%p addresses=0x%p\n",
				  spi_item->spi, spi_item->new_spi, item, spi_item->addresses);
		  	HIP_ERROR("remove SPI from HIT-SPI HT\n");
			//hip_hadb_remove_hs(spi_item->spi);
			HIP_DEBUG_IN6ADDR("delete", &entry->our_addr);
			default_ipsec_func_set.hip_delete_sa(spi_item->spi, &entry->our_addr,
					&entry->hit_our, HIP_SPI_DIRECTION_IN, entry);
				      //AF_INET6, 0, 0);
			// XX FIX: should be deleted like this?
			//for(i = 0; i < spi_item->addresses_n; i++)
			//  default_ipsec_func_set.hip_delete_sa(spi_item->spi,
			//    &spi_item->addresses->address + i, AF_INET6);
 			if (spi_item->spi != spi_item->new_spi)
 				default_ipsec_func_set.hip_delete_sa(spi_item->new_spi, &entry->hit_our,
 						&entry->our_addr, HIP_SPI_DIRECTION_IN, entry);
 			if (spi_item->addresses)
 			{
 				HIP_DEBUG("deleting stored addrlist 0x%p\n", spi_item->addresses);
 				HIP_FREE(spi_item->addresses);
				spi_item->addresses = NULL;
 			}
			list_del(spi_item, entry->spis_in);
			HIP_FREE(spi_item);
			break;

		}
	}
}

/* Delete given outbound SPI, and all if spi == 0 */
void hip_hadb_delete_outbound_spi(hip_ha_t *entry, uint32_t spi)
{
	struct hip_spi_out_item *spi_item;
	hip_list_t *item, *tmp;
	int i, ii;

	/* assumes locked entry */
	HIP_DEBUG("entry=0x%p SPI=0x%x\n", entry, spi);
	list_for_each_safe(item, tmp, entry->spis_out, i)
	{
		spi_item = list_entry(item);
		if ((!spi && spi != -1) || spi_item->spi == spi)
		{
			struct hip_peer_addr_list_item *addr_item;
			hip_list_t *a_item, *a_tmp;

			HIP_DEBUG("deleting SPI_out=0x%x SPI_out_new=0x%x from outbound list, item=0x%p\n",
				  spi_item->spi, spi_item->new_spi, item);
			default_ipsec_func_set.hip_delete_sa(spi_item->spi, &entry->peer_addr, &entry->peer_addr,
				      HIP_SPI_DIRECTION_OUT, entry);
			default_ipsec_func_set.hip_delete_sa(spi_item->new_spi, &entry->peer_addr,&entry->peer_addr,
				      HIP_SPI_DIRECTION_OUT, entry);
			/* delete peer's addresses */
			list_for_each_safe(a_item, a_tmp, spi_item->peer_addr_list, ii)
			{
				addr_item = list_entry(a_item);
				list_del(addr_item, spi_item->peer_addr_list);
				HIP_FREE(addr_item);
			}
			hip_ht_uninit(spi_item->peer_addr_list);
			list_del(spi_item, entry->spis_out);
			HIP_FREE(spi_item);
		}
	}
}

/**
 * Deletes a HA state (and deallocate memory) Deletes all associates IPSEC SAs
 * and frees the memory occupied by the HA state.
 *
 * @param ha HA
 * @note     ASSERT: The HA must be unlinked from the global hadb hash tables
 *           (SPI and HIT). This function should only be called when absolutely
 *           sure that nobody else has a reference to it.
 */
void hip_hadb_delete_state(hip_ha_t *ha)
{
	HIP_DEBUG("ha=0x%p\n", ha);

	/* Delete SAs */

	if (ha->spis_in) {
		hip_hadb_delete_inbound_spi(ha, 0);
		hip_ht_uninit(ha->spis_in);
	}
	if (ha->spis_out) {
		hip_hadb_delete_outbound_spi(ha, 0);
		hip_ht_uninit(ha->spis_out);
	}


	if (ha->dh_shared_key)
		HIP_FREE(ha->dh_shared_key);
	if (ha->hip_msg_retrans.buf)
		HIP_FREE(ha->hip_msg_retrans.buf);
	if (ha->peer_pub) {
		if (hip_get_host_id_algo(ha->peer_pub) == HIP_HI_RSA &&
							ha->peer_pub_key)
			RSA_free(ha->peer_pub_key);
		else if (ha->peer_pub_key)
			DSA_free(ha->peer_pub_key);
		HIP_FREE(ha->peer_pub);
	}
	if (ha->our_priv)
		HIP_FREE(ha->our_priv);
	if (ha->our_pub)
		HIP_FREE(ha->our_pub);
	if (ha->rendezvous_addr)
		HIP_FREE(ha->rendezvous_addr);

	HIP_FREE(ha);
}

/**
 * Maps function @c func to every HA in HIT hash table. The hash table is
 * LOCKED while we process all the entries. This means that the mapper function
 * MUST be very short and _NOT_ do any operations that might sleep!
 *
 * @param func a mapper function.
 * @param opaque opaque data for the mapper function.
 * @return       negative if an error occurs. If an error occurs during
 *               traversal of a the HIT hash table, then the traversal is
 *               stopped and function returns. Returns the last return value of
 *               applying the mapper function to the last element in the hash
 *               table.
 */
int hip_for_each_ha(int (*func)(hip_ha_t *entry, void *opaq), void *opaque)
{
	int i = 0, fail = 0;
	hip_ha_t *this;
	hip_list_t *item, *tmp;

	if (!func)
		return -EINVAL;

	HIP_LOCK_HT(&hadb_hit);
	list_for_each_safe(item, tmp, hadb_hit, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("list_for_each_safe\n");
		hip_hold_ha(this);
		fail = func(this, opaque);
		hip_db_put_ha(this, hip_hadb_delete_state);
		if (fail)
			goto out_err;
	}

 out_err:
	HIP_UNLOCK_HT(&hadb_hit);
	return fail;
}

/** Enumeration for hip_count_open_connections */
int hip_count_one_entry(hip_ha_t *entry, void *cntr)
{
	int *counter = cntr;
	if (entry->state == HIP_STATE_CLOSING ||
	    entry->state == HIP_STATE_ESTABLISHED)
	{
		(*counter)++;
	}
	return 0;
}

/**
 * Return number of open connections by calculating hadb entrys.
 */
int hip_count_open_connections(void)
{
	int n = 0;

	hip_for_each_ha(hip_count_one_entry, &n);

	return n;
}

int hip_handle_get_ha_info(hip_ha_t *entry, void *opaq)
{
	int err = 0;
	struct hip_hadb_user_info_state hid;
	extern int hip_icmp_interval;
	struct hip_common *msg = (struct hip_common *) opaq;
	
	memset(&hid, 0, sizeof(hid));
	hid.state = entry->state;
    	ipv6_addr_copy(&hid.hit_our, &entry->hit_our);
	ipv6_addr_copy(&hid.hit_peer, &entry->hit_peer);
	ipv6_addr_copy(&hid.ip_our, &entry->our_addr);
	ipv6_addr_copy(&hid.ip_peer, &entry->peer_addr);
	ipv4_addr_copy(&hid.lsi_our, &entry->lsi_our);
	ipv4_addr_copy(&hid.lsi_peer, &entry->lsi_peer);
	memcpy(&hid.peer_hostname, &entry->peer_hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX);

	hid.heartbeats_on = hip_icmp_interval;
	calc_statistics(&entry->heartbeats_statistics, &hid.heartbeats_received, NULL, NULL,
			&hid.heartbeats_mean, &hid.heartbeats_variance, STATS_IN_MSECS);
#if 0
	hid.heartbeats_mean = entry->heartbeats_mean;
	hid.heartbeats_variance = entry->heartbeats_variance;
	hid.heartbeats_received = entry->heartbeats_statistics.num_items;
#endif
	hid.heartbeats_sent = entry->heartbeats_sent;

	_HIP_HEXDUMP("HEXHID ", &hid, sizeof(struct hip_hadb_user_info_state));
	
	hid.nat_udp_port_peer = entry->peer_udp_port;
	hid.nat_udp_port_local = entry->local_udp_port;

	hid.peer_controls = entry->peer_controls;

	/* does not print heartbeat info, but I do not think it even should -Samu*/
	hip_print_debug_info(&hid.ip_our,   &hid.ip_peer,
			     &hid.hit_our,  &hid.hit_peer,
			     &hid.lsi_peer, &hid.peer_hostname,
			     &hid.nat_udp_port_local, &hid.nat_udp_port_peer);

	err = hip_build_param_contents(msg, &hid, HIP_PARAM_HA_INFO,
				       sizeof(hid));
	if (err)
		HIP_ERROR("Building ha info failed\n");

	_HIP_HEXDUMP("HEXHID ", &hid, sizeof(struct hip_hadb_user_info_state));

    out_err:
	return err;

}

/**
 * @todo We could scan through all of the alternative locators as well
 */
int hip_hadb_map_ip_to_hit(hip_ha_t *entry, void *id2)
{
	struct in6_addr *id = id2;
	int err = 0;

	if (ipv6_addr_cmp(&entry->peer_addr, id) == 0 &&
		!ipv6_addr_any(&entry->hit_peer) &&
		!hit_is_opportunistic_hashed_hit(&entry->hit_peer)) {
		ipv6_addr_copy(id, &entry->hit_peer);
		HIP_DEBUG_HIT("hit", &entry->hit_peer);
		HIP_DEBUG_HIT("pref", &entry->peer_addr);
		HIP_DEBUG_HIT("id", id);
		err = -1; /* break iteration */
	}

 out_err:
	return err;
}

#ifdef CONFIG_HIP_RVS
hip_ha_t *hip_hadb_find_rvs_candidate_entry(hip_hit_t *local_hit,
					    hip_hit_t *rvs_ip)
{
	int err = 0, i = 0;
	hip_ha_t *this = NULL, *result = NULL;
	hip_list_t *item = NULL, *tmp = NULL; //

	HIP_LOCK_HT(&hadb_hit);
	list_for_each_safe(item, tmp, hadb_hit, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("List_for_each_entry_safe\n");
		hip_hold_ha(this);
		if ((ipv6_addr_cmp(local_hit, &this->hit_our) == 0) &&
		    (ipv6_addr_cmp(rvs_ip, &this->peer_addr) == 0)) {
			result = this;
			break;
		}
		hip_db_put_ha(this, hip_hadb_delete_state);
		if (err)
			break;
	}
	HIP_UNLOCK_HT(&hadb_hit);

 out_err:
	if (err)
		result = NULL;

	return result;
}
#endif


#ifdef CONFIG_HIP_BLIND
/**
 * Defunct
 * @date 22.07.2008
 */
hip_ha_t *hip_hadb_find_by_blind_hits(hip_hit_t *local_blind_hit,
				      hip_hit_t *peer_blind_hit)
{
	int err = 0, i = 0;
	hip_ha_t *this = NULL, *tmp = NULL, *result = NULL;

	/*
	  This loop is disabled since &hadb_byhit[i] does not exist anymore and
	  the code won't compile with CONFIG_HIP_BLIND flag set.
	  -Lauri 22.07.2008
	  for(i = 0; i < HIP_HADB_SIZE; i++) {

	  list_for_each_entry_safe(this, tmp, &hadb_byhit[i], next_hit)
	  {
	  _HIP_DEBUG("List_for_each_entry_safe\n");
	  hip_hold_ha(this);
	  if ((ipv6_addr_cmp(local_blind_hit, &this->hit_our_blind) == 0) &&
	  (ipv6_addr_cmp(peer_blind_hit, &this->hit_peer_blind) == 0)) {
	  result = this;
	  break;
	  }
	  hip_db_put_ha(this, hip_hadb_delete_state);
	  if (err)
	  break;
	  }
	  if (err)
	  break;
	  }
	*/
 out_err:
	if (err)
		result = NULL;

	return result;
}
#endif

int hip_generate_peer_lsi(hip_lsi_t *lsi)
{
	struct in_addr lsi_prefix;
	uint8_t hostname[HOST_NAME_MAX];
	int index = 1;

	do {
		lsi_prefix.s_addr = htonl(HIP_LSI_PREFIX|index++);
	} while (lsi_assigned(lsi_prefix) ||
		 !hip_map_lsi_to_hostname_from_hosts(lsi, hostname));

	_HIP_DEBUG_LSI("lsi free final value is ", &lsi_prefix);

	*lsi = lsi_prefix;
	return 0;
}

int hip_host_file_info_exists_lsi(hip_lsi_t *lsi){
  int err = 0;
  uint8_t hostname[HOST_NAME_MAX];
  struct in6_addr mapped_lsi;
  
  memset(hostname, 0, sizeof(hostname));

  IPV4_TO_IPV6_MAP(lsi, &mapped_lsi);

  return !hip_for_each_hosts_file_line(HIPD_HOSTS_FILE,
				       hip_map_first_id_to_hostname_from_hosts,
				       &mapped_lsi, hostname);
}

/**
 * Checks if exists a local or peer lsi that matches with this prefix
 */
int lsi_assigned(struct in_addr add)
{
	int exist = 0;
	exist = hip_hidb_exists_lsi(&add);
	if (!exist)
		exist = hip_hadb_exists_lsi(&add);
	if (!exist)
	        exist = hip_host_file_info_exists_lsi(&add);
	return exist;
}

int hip_hadb_exists_lsi(hip_lsi_t *lsi)
{
	int res = 0;
	hip_lsi_t lsi_aux;

	memcpy(&lsi_aux, lsi, sizeof(hip_lsi_t));
	hip_for_each_ha(hip_hadb_find_lsi, &lsi_aux);

	if (ipv4_addr_cmp(&lsi_aux, lsi) != 0){
		res = 1;
		HIP_DEBUG("lsi exists\n");
	}
	return res;
}

int hip_hadb_find_lsi(hip_ha_t *entry, void *lsi)
{
	int exist_lsi;
	exist_lsi = hip_lsi_are_equal(&entry->lsi_peer,(hip_lsi_t *)lsi);
	if (exist_lsi)
	        memset(lsi, 0, sizeof(lsi));
    return 0;
}


/**
 * This function simply goes through all HADB to find an entry that
 * matches the given lsi pair. First matching HADB entry is then returned.
 *
 * @note This way of finding HA entries doesn't work properly if we have
 * multiple entries with the same tuple <lsi_src,lsi_dst>. Currently, that's not the case.
 * Our implementation doesn't allow repeated lsi tuples.
 */

hip_ha_t *hip_hadb_try_to_find_by_pair_lsi(hip_lsi_t *lsi_src, hip_lsi_t *lsi_dst){
        hip_list_t *item, *aux;
	hip_ha_t *tmp;
	int i;

	list_for_each_safe(item, aux, hadb_hit, i)
	{
		tmp = list_entry(item);
		if(!hip_lsi_are_equal(&tmp->lsi_peer, lsi_dst))
			continue;
		else if (hip_lsi_are_equal(&tmp->lsi_our, lsi_src))
			return tmp;
		else
		        continue;
	}
	return NULL;
}

hip_ha_t *hip_hadb_try_to_find_by_peer_lsi(hip_lsi_t *lsi_dst) {
        hip_list_t *item, *aux;
	hip_ha_t *tmp;
	int i;

	list_for_each_safe(item, aux, hadb_hit, i)
	{
		tmp = list_entry(item);
		if(hip_lsi_are_equal(&tmp->lsi_peer, lsi_dst))
			return tmp;
	}
	return NULL;
}

int hip_get_local_addr(struct hip_common *msg)
{
	hip_ha_t* entry;
	int err;
    	struct in6_addr local_address;
    	hip_hit_t* src_hit;
    	hip_hit_t* dst_hit;

    	src_hit = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT);
	dst_hit = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
	HIP_DEBUG_HIT("src_hit from local address request: ", src_hit);
	HIP_DEBUG_HIT("dst_hit from local address request: ", dst_hit);
/*	if (ptr) {
		memcpy(peer_hit, ptr, sizeof(hip_hit_t));
		HIP_DEBUG_HIT("peer_hit", peer_hit);
		*fallback = 0;
	}
*/
	memset(&local_address, 0, sizeof(struct in6_addr));
	entry = hip_hadb_find_byhits(src_hit, dst_hit);

	hip_msg_init(msg);
	//HIP_DEBUG_IN6ADDR(" local address: ", &entry->our_addr);

	if(!entry)
		HIP_DEBUG("Can't find local address because of no entry in hadb!\n");

    	ipv6_addr_copy(&local_address, &entry->our_addr);

    	//hip_build_user_hdr(msg, HIP_HIPPROXY_LOCAL_ADDRESS, 0);
	err = hip_build_param_contents(msg, &local_address, HIP_PARAM_IPV6_ADDR,
				       sizeof(struct in6_addr));
	if (err)
		HIP_ERROR("Building local address info failed\n");

	return 0;
}

//add by santtu
/* add an address belonging to the SPI list */
/* or update old values */
int hip_hadb_add_udp_addr_to_spi(hip_ha_t *entry, uint32_t spi,
			     struct in6_addr *addr,
			     int is_bex_address, uint32_t lifetime,
			     int is_preferred_addr,
			     uint16_t port,
			     uint32_t priority,
			     uint8_t kind)
{
	int err = 0, new = 1, i;
	struct hip_spi_out_item *spi_list;
	struct hip_peer_addr_list_item *new_addr = NULL;
	struct hip_peer_addr_list_item *a;
	hip_list_t *item, *tmp;
	struct in6_addr *preferred_address;
	/* Assumes already locked entry */
	HIP_DEBUG("spi=0x%x is_preferred_addr=%d\n", spi, is_preferred_addr);

	spi_list = hip_hadb_get_spi_list(entry, spi);
	if (!spi_list)
	{
		HIP_ERROR("SPI list for 0x%x not found\n", spi);
		err = -EEXIST;
		goto out_err;
	}

	/* Check if addr already exists. If yes, then just update values. */
	list_for_each_safe(item, tmp, spi_list->peer_addr_list, i)
	{
		a = list_entry(item);
		if ((!ipv6_addr_cmp(&a->address, addr) )&& a->port == port)
		{
			// Do we send a verification if state is unverified?
			// The address should be awaiting verifivation already
			HIP_DEBUG_HIT("found address: ",&a->address);
			HIP_DEBUG("found port: %d\n",a->port );

			new_addr = a;
			new = 0;
			break;
		}
	}

	if (new)
	{
		HIP_DEBUG("create new addr item to SPI list\n");
		/* SPI list does not contain the address, add the address to the SPI list */
		new_addr = (struct hip_peer_addr_list_item *)HIP_MALLOC(sizeof(struct hip_peer_addr_list_item), 0);
		if (!new_addr)
		{
			HIP_ERROR("item HIP_MALLOC failed\n");
			err = -ENOMEM;
			goto out_err;
		}
	}
	else HIP_DEBUG("update old addr item\n");

	new_addr->lifetime = lifetime;
	if (new) {
		ipv6_addr_copy(&new_addr->address, addr);
//add by santtu
		new_addr->port = port;
		new_addr->priority = priority;
		new_addr->kind = kind;
//end add
	}

	/* If the address is already bound, its lifetime is updated.
	   If the status of the address is DEPRECATED, the status is
	   changed to UNVERIFIED.  If the address is not already bound,
	   the address is added, and its status is set to UNVERIFIED. */


	/* We switch off the part that make no answer with echo response message
	   to the initiator. The reason is that we need the whole update schema work
	   for the program to run corrctly. This purely optimization part can be changed
	   latter. - Andrey.
	*/
#if 0
	if (!new)
	{
		switch (new_addr->address_state)
		{
		case PEER_ADDR_STATE_DEPRECATED:
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			HIP_DEBUG("updated address state DEPRECATED->UNVERIFIED\n");
			break;
 		case PEER_ADDR_STATE_ACTIVE:
			HIP_DEBUG("address state stays in ACTIVE\n");
			break;
		default:
			// Does this mean that unverified cant be here? Why?
			HIP_ERROR("state is UNVERIFIED, shouldn't even be here ?\n");
			break;
		}
	}
	else
	{
#endif
             if (is_bex_address)
		{
			/* workaround for special case */
 			HIP_DEBUG("address is base exchange address, setting state to ACTIVE\n");
			new_addr->address_state = PEER_ADDR_STATE_ACTIVE;
			HIP_DEBUG("setting bex addr as preferred address\n");
			ipv6_addr_copy(&entry->peer_addr, addr);
			new_addr->seq_update_id = 0;
		} else {
			HIP_DEBUG("address's state is set in state UNVERIFIED\n");
			new_addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
//modify by santtu
			if(hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP && hip_relay_get_status() != HIP_RELAY_ON){

				err = entry->hadb_update_func->hip_update_send_echo(entry, spi, new_addr);

				/** @todo: check! If not acctually a problem (during Handover). Andrey. */
				if( err==-ECOMM ) err = 0;
			}
//end modify
		}
		//}

	do_gettimeofday(&new_addr->modified_time);
	new_addr->is_preferred = is_preferred_addr;
	if(is_preferred_addr){
            //HIP_DEBUG("Since the address is preferred, we set the entry preferred_address as such\n");
              ipv6_addr_copy(&entry->peer_addr, &new_addr->address);
              entry->peer_udp_port = new_addr->port;
	}
	if (new) {
		HIP_DEBUG("adding new addr to SPI list\n");
		list_add(new_addr, spi_list->peer_addr_list);

		HIP_DEBUG("new peer list item address: %d ",new_addr);
	}

 out_err:
	HIP_DEBUG("returning, err=%d\n", err);
	return err;
}

