/** @file
 * This file defines the rendezvous extension and the UDP relay for HIP packets
 * for the Host Identity Protocol (HIP). See header file for usage
 * instructions. Version 1.1 added support for white list and configuration
 * file.
 * 
 * @author  Lauri Silvennoinen
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5204.txt">
 *          Host Identity Protocol (HIP) Rendezvous Extension</a>
 * @note    Related draft:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-nat-traversal-03.txt">
 *          draft-ietf-hip-nat-traversal-03</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see     hiprelay.h
 */ 
#include "hiprelay.h"

/** A hashtable for storing the relay records. */
static LHASH *hiprelay_ht = NULL;
/** A hashtable for storing the the HITs of the clients that are allowed to use
 *  the relay / RVS service. */
static LHASH *hiprelay_wl = NULL;

/** Minimum relay record life time as a 8-bit integer. */
uint8_t hiprelay_min_lifetime = HIP_RELREC_MIN_LIFETIME;
/** Maximum relay record life time as a 8-bit integer. */
uint8_t hiprelay_max_lifetime = HIP_RELREC_MAX_LIFETIME;
/** 
 * A boolean to indicating if the RVS / relay is enabled. User sets this value
 * using the hipconf tool.
 */
hip_relay_status_t relay_enabled = HIP_RELAY_OFF;
/** 
 * A boolean to indicating if the RVS / relay whitelist is enabled. User sets
 * this value from the relay configuration file.
 */
hip_relay_wl_status_t whitelist_enabled = HIP_RELAY_WL_ON;

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_relht_hash, const hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_relht_compare, const hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_doall(). */
static IMPLEMENT_LHASH_DOALL_FN(hip_relht_rec_free, hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_doall(). */
static IMPLEMENT_LHASH_DOALL_FN(hip_relht_rec_free_expired, hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_doall_arg(). */
static IMPLEMENT_LHASH_DOALL_ARG_FN(hip_relht_rec_free_type, hip_relrec_t *,
				    const hip_relrec_type_t *)

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_relwl_hash, const hip_hit_t *)
/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_relwl_compare, const hip_hit_t *)
/** A callback wrapper of the prototype required by @c lh_doall(). */
static IMPLEMENT_LHASH_DOALL_FN(hip_relwl_hit_free, hip_hit_t *)

hip_relay_status_t hip_relay_get_status()
{
	return relay_enabled;
}

void hip_relay_set_status(hip_relay_status_t status)
{
	relay_enabled = status;
}

int hip_relay_init()
{
	int err = 0;

	HIP_IFEL(hip_relht_init(), -1,
		 "Unable to initialize HIP relay / RVS database.\n");
	HIP_IFEL(hip_relwl_init(), -1,
		 "Unable to initialize HIP relay / RVS whitelist.\n");
	
	if(hip_relay_read_config() == -ENOENT) {
		HIP_ERROR("The configuration file \"%s\" could not be read.\n"\
			  "Trying to write a new configuration file from "\
			  "scratch.\n", HIP_RELAY_CONFIG_FILE);
		if(hip_relay_write_config() == -ENOENT) {
			HIP_ERROR("Could not create a configuration file "\
				  "\"%s\".\n", HIP_RELAY_CONFIG_FILE);
		} else {
			HIP_INFO("Created a new configuration file \"%s\".\n",
				 HIP_RELAY_CONFIG_FILE);
		}
	} else {
		HIP_INFO("Read configuration file \"%s\" successfully.\n",
			 HIP_RELAY_CONFIG_FILE);
	}
	
 out_err:
	if(hiprelay_wl == NULL) {
		hip_relht_uninit();
	}
	
	return err;
}

void hip_relay_uninit()
{
	hip_relht_uninit();
	hip_relwl_uninit();
}

int hip_relay_reinit()
{
	int err = 0;

	hip_relwl_uninit();
	HIP_IFEL(hip_relwl_init(), -1, "Could not initialize the HIP relay / ",
		 "RVS whitelist.\n");
	HIP_IFEL(hip_relay_read_config(), -1, "Could not read the ",
		 "configuration file \"%s\"\n", HIP_RELAY_CONFIG_FILE); 
	
 out_err:       
	return err;
}

int hip_relht_init()
{
	/* Check that the relay hashtable is not already initialized. */
	if(hiprelay_ht != NULL) {
		return -1;
	}
	
	hiprelay_ht = lh_new(LHASH_HASH_FN(hip_relht_hash),
			     LHASH_COMP_FN(hip_relht_compare));
	
	if(hiprelay_ht == NULL) {
		return -1;
	}
	
	return 0;
}

void hip_relht_uninit()
{
	if(hiprelay_ht == NULL)
		return;

	lh_doall(hiprelay_ht, LHASH_DOALL_FN(hip_relht_rec_free));
	lh_free(hiprelay_ht);
	hiprelay_ht = NULL;
}

unsigned long hip_relht_hash(const hip_relrec_t *rec)
{
	if(rec == NULL || &(rec->hit_r) == NULL)
		return 0;
	
	return hip_hash_func(&(rec->hit_r));
}

int hip_relht_compare(const hip_relrec_t *rec1, const hip_relrec_t *rec2)
{
	if(rec1 == NULL || &(rec1->hit_r) == NULL ||
	   rec2 == NULL || &(rec2->hit_r) == NULL)
		return 1;

	return (hip_relht_hash(rec1) != hip_relht_hash(rec2));
}

int hip_relht_put(hip_relrec_t *rec)
{
	if(hiprelay_ht == NULL || rec == NULL)
		return;
     
	/* If we are trying to insert a duplicate element (same HIT), we have to
	   delete the previous entry. If we do not do so, only the pointer in
	   the hashtable is replaced and the reference to the previous element
	   is lost resulting in a memory leak. */
	hip_relrec_t key, *match;
	memcpy(&(key.hit_r), &(rec->hit_r), sizeof(rec->hit_r));
	match = hip_relht_get(rec);

	if(match != NULL) {
		hip_relht_rec_free(&key);
		lh_insert(hiprelay_ht, rec);
		return -1;
	} else {
		lh_insert(hiprelay_ht, rec);
		return 0;
	}
}

hip_relrec_t *hip_relht_get(const hip_relrec_t *rec)
{
	if(hiprelay_ht == NULL || rec == NULL)
		return NULL;

	return (hip_relrec_t *)lh_retrieve(hiprelay_ht, rec);
}

void hip_relht_rec_free(hip_relrec_t *rec)
{
	if(hiprelay_ht == NULL || rec == NULL)
		return;

	/* Check if such element exist, and delete the pointer from the hashtable. */
	hip_relrec_t *deleted_rec = lh_delete(hiprelay_ht, rec);

	/* Free the memory allocated for the element. */
	if(deleted_rec != NULL) {
		/* We set the memory to '\0' because the user may still have a
		   reference to the memory region that is freed here. */
		memset(deleted_rec, '\0', sizeof(*deleted_rec));
		free(deleted_rec);
		HIP_DEBUG("Relay record deleted.\n");
	}
}

void hip_relht_rec_free_expired(hip_relrec_t *rec)
{
	if(rec == NULL) // No need to check hiprelay_ht
		return;

	if(time(NULL) - rec->created > rec->lifetime) {
		HIP_INFO("Relay record expired, deleting.\n");
		hip_relht_rec_free(rec);
	}
}

void hip_relht_rec_free_type(hip_relrec_t *rec, const hip_relrec_type_t *type)
{
	hip_relrec_t *fetch_record = hip_relht_get(rec);
	
	if(fetch_record != NULL && fetch_record->type == *type) {
		hip_relht_rec_free(rec);
	}
}

unsigned long hip_relht_size()
{
	if(hiprelay_ht == NULL)
		return 0;

	return hiprelay_ht->num_items;
}

void hip_relht_maintenance()
{
	if(hiprelay_ht == NULL)
		return;
     
	unsigned int tmp = hiprelay_ht->down_load;
	hiprelay_ht->down_load = 0;
	lh_doall(hiprelay_ht, LHASH_DOALL_FN(hip_relht_rec_free_expired));
	hiprelay_ht->down_load = tmp;
}

void hip_relht_free_all_of_type(const hip_relrec_type_t type)
{
	if(hiprelay_ht == NULL)
		return;
	
	unsigned int tmp = hiprelay_ht->down_load;
	hiprelay_ht->down_load = 0;
	lh_doall_arg(hiprelay_ht, LHASH_DOALL_ARG_FN(hip_relht_rec_free_type),
		     (void *)&type);
	hiprelay_ht->down_load = tmp;
}

hip_relrec_t *hip_relrec_alloc(const hip_relrec_type_t type,
			       const uint8_t lifetime,
			       const in6_addr_t *hit_r, const hip_hit_t *ip_r,
			       const in_port_t port,
			       const hip_crypto_key_t *hmac,
			       const hip_xmit_func_t func)
{
	if(hit_r == NULL || ip_r == NULL || hmac == NULL || func == NULL)
		return NULL;

	hip_relrec_t *rec = (hip_relrec_t*) malloc(sizeof(hip_relrec_t));
     
	if(rec == NULL) {
		HIP_ERROR("Error allocating memory for HIP relay record.\n");
		return NULL;
	}
	rec->type = type;
	memcpy(&(rec->hit_r), hit_r, sizeof(*hit_r));
	memcpy(&(rec->ip_r), ip_r, sizeof(*ip_r));
	rec->udp_port_r = port;
	memcpy(&(rec->hmac_relay), hmac, sizeof(*hmac));
	rec->send_fn = func;
	hip_relrec_set_lifetime(rec, lifetime);
	rec->created = time(NULL);
     
	return rec;
}

void hip_relrec_set_mode(hip_relrec_t *rec, const hip_relrec_type_t type)
{
	if(rec != NULL)
		rec->type = type;
}

void hip_relrec_set_lifetime(hip_relrec_t *rec, const uint8_t lifetime)
{
	if(rec != NULL) {
		rec->lifetime = pow(2, ((double)(lifetime-64)/8));
	}
}

void hip_relrec_set_udpport(hip_relrec_t *rec, const in_port_t port)
{
	if(rec != NULL)
		rec->udp_port_r = port;
}

void hip_relrec_info(const hip_relrec_t *rec)
{
	if(rec == NULL)
		return;
     
	char status[1024];
	char *cursor = status;
	cursor += sprintf(cursor, "Relay record info:\n");
	cursor += sprintf(cursor, " Record type: ");
	cursor += sprintf(cursor, (rec->type == HIP_FULLRELAY) ?
			  "Full relay of HIP packets\n" :
			  (rec->type == HIP_RVSRELAY) ?
			  "RVS relay of I1 packet\n" : "undefined\n");
	cursor += sprintf(cursor, " Record lifetime: %%lu seconds\n",
			  rec->lifetime);
	cursor += sprintf(cursor, " Record created: %lu seconds ago\n",
			  time(NULL) - rec->created);
	cursor += sprintf(cursor, " HIT of R: %04x:%04x:%04x:%04x:"\
			  "%04x:%04x:%04x:%04x\n",
			  ntohs(rec->hit_r.s6_addr16[0]),
			  ntohs(rec->hit_r.s6_addr16[1]),
			  ntohs(rec->hit_r.s6_addr16[2]),
			  ntohs(rec->hit_r.s6_addr16[3]),
			  ntohs(rec->hit_r.s6_addr16[4]),
			  ntohs(rec->hit_r.s6_addr16[5]),
			  ntohs(rec->hit_r.s6_addr16[6]),
			  ntohs(rec->hit_r.s6_addr16[7]));
	cursor += sprintf(cursor, " IP of R:  %04x:%04x:%04x:%04x:"\
			  "%04x:%04x:%04x:%04x\n",
			  ntohs(rec->ip_r.s6_addr16[0]),
			  ntohs(rec->ip_r.s6_addr16[1]),
			  ntohs(rec->ip_r.s6_addr16[2]),
			  ntohs(rec->ip_r.s6_addr16[3]),
			  ntohs(rec->ip_r.s6_addr16[4]),
			  ntohs(rec->ip_r.s6_addr16[5]),
			  ntohs(rec->ip_r.s6_addr16[6]),
			  ntohs(rec->ip_r.s6_addr16[7]));

	HIP_INFO("\n%s", status);
}

int hip_relwl_init()
{
	/* Check that the relay whitelist is not already initialized. */
	if(hiprelay_wl != NULL) {
		return -1;
	}

	hiprelay_wl = lh_new(LHASH_HASH_FN(hip_relwl_hash),
			     LHASH_COMP_FN(hip_relwl_compare)); 
	
	if(hiprelay_wl == NULL) {
		return -1;
	}
	
	return 0;
}

void hip_relwl_uninit()
{
	if(hiprelay_wl == NULL)
		return;

	lh_doall(hiprelay_wl, LHASH_DOALL_FN(hip_relwl_hit_free));
	lh_free(hiprelay_wl);
	hiprelay_wl = NULL;
}

unsigned long hip_relwl_hash(const hip_hit_t *hit)
{
	if(hit == NULL)
		return 0;
	
	return hip_hash_func(hit);
}

int hip_relwl_compare(const hip_hit_t *hit1, const hip_hit_t *hit2)
{
	if(hit1 == NULL || hit2 == NULL)
		return 1;

	return (hip_relwl_hash(hit1) != hip_relwl_hash(hit2));
}

int hip_relwl_put(hip_hit_t *hit)
{
	if(hiprelay_wl == NULL || hit == NULL)
		return;
     
	/* If we are trying to insert a duplicate element (same HIT), we have to
	   delete the previous entry. If we do not do so, only the pointer in
	   the hashtable is replaced and the reference to the previous element
	   is lost resulting in a memory leak. */
	hip_hit_t *dummy = hip_relwl_get(hit);
	if(dummy != NULL) {
		hip_relwl_hit_free(dummy);
		lh_insert(hiprelay_wl, hit);
		return -1;
	} else {
		lh_insert(hiprelay_wl, hit);
		return 0;
	}
}

hip_hit_t *hip_relwl_get(const hip_hit_t *hit)
{
	if(hiprelay_wl == NULL || hit == NULL)
		return NULL;

	return (hip_hit_t *)lh_retrieve(hiprelay_wl, hit);
}

unsigned long hip_relwl_size()
{
	if(hiprelay_wl == NULL)
		return 0;

	return hiprelay_wl->num_items;
}

void hip_relwl_hit_free(hip_hit_t *hit)
{
	if(hiprelay_wl == NULL || hit == NULL)
		return;
	
	/* Check if such element exist, and delete the pointer from the hashtable. */
	hip_hit_t *deleted_hit = lh_delete(hiprelay_wl, hit);

	/* Free the memory allocated for the element. */
	if(deleted_hit != NULL) {
		/* We set the memory to '\0' because the user may still have a
		   reference to the memory region that is freed here. */
		memset(deleted_hit, '\0', sizeof(*deleted_hit));
		free(deleted_hit);
		HIP_DEBUG("HIT deleted from the relay whitelist.\n");
	}
}

hip_relay_wl_status_t hip_relwl_get_status()
{
	return whitelist_enabled;
}

int hip_rvs_validate_lifetime(uint8_t requested_lifetime,
			      uint8_t *granted_lifetime)
{
	if(requested_lifetime < hiprelay_min_lifetime){
		*granted_lifetime = hiprelay_min_lifetime;
		return -1;
	}else if(requested_lifetime > hiprelay_max_lifetime){
		*granted_lifetime = hiprelay_max_lifetime;
		return -1;
	}else{
		*granted_lifetime = requested_lifetime;
		return 0;
	}
}

int hip_relay_forward(const hip_common_t *msg, const in6_addr_t *saddr,
		  const in6_addr_t *daddr, hip_relrec_t *rec,
		  const hip_portpair_t *info, const uint8_t type_hdr,
                  const hip_relrec_type_t relay_type)
{
	hip_common_t *msg_to_be_relayed = NULL;
	hip_tlv_common_t *current_param = NULL;
	int err = 0, from_added = 0;
        hip_tlv_type_t param_type = 0;
        hip_tlv_type_t hmac_param_type = 0;

	/* A function pointer to either hip_build_param_from() or
	   hip_build_param_relay_from(). */
	int (*builder_function) (struct hip_common *msg,
				 const struct in6_addr *addr,
				 const in_port_t port);

	HIP_DEBUG("hip_relay_rvs() invoked.\n");
        HIP_DEBUG("Msg type :      %s (%d)\n",
	       hip_message_type_name(hip_get_msg_type(msg)),
	       hip_get_msg_type(msg));
        HIP_DEBUG_IN6ADDR("hip_relay_rvs():  source address", saddr);
	HIP_DEBUG_IN6ADDR("hip_relay_rvs():  destination address", daddr);
	HIP_DEBUG_HIT("hip_relay_rvs(): Relay record hit", &rec->hit_r);
	HIP_DEBUG("Relay record port: %d.\n", rec->udp_port_r);
	HIP_DEBUG("source port: %u, destination port: %u\n",
		  info->src_port, info->dst_port);
		
        if (relay_type == HIP_FULLRELAY)
        {
            param_type = HIP_PARAM_RELAY_FROM;
            builder_function = hip_build_param_relay_from;
        }
        else
        {
            param_type = HIP_PARAM_FROM;
            builder_function = hip_build_param_from;
        }

	HIP_IFEL(!(msg_to_be_relayed = hip_msg_alloc()), -ENOMEM,
		 "No memory to copy original I1\n");	

	/* The packet forwarding is achieved by rewriting the source and
	   destination IP addresses. */
	hip_build_network_hdr(msg_to_be_relayed, type_hdr, 0,
			      &(msg->hits), &(msg->hitr));

	/* Adding FROM (RELAY_FROM) parameter. Loop through all the parameters in
	   the received packet, and insert a new FROM (RELAY_FROM) parameter
	   after the last found FROM (RELAY_FROM) parameter. Notice that in most
	   cases the incoming I1 has no paramaters at all, and this "while" loop
	   is skipped. Multiple rvses en route to responder is one (and only?)
	   case when the incoming I1 packet has parameters. */
	while ((current_param = hip_get_next_param(msg, current_param)) != NULL) {
		
		HIP_DEBUG("Found parameter in the packet.\n");
		/* Copy while type is smaller than or equal to FROM (RELAY_FROM)
		   or a new FROM (RELAY_FROM) has already been added. */
		if (from_added || hip_get_param_type(current_param) <= param_type) {
			HIP_DEBUG("Copying existing parameter to the packet "\
				  "to be relayed.\n");
			hip_build_param(msg_to_be_relayed,current_param);
			continue;
		}
		/* Parameter under inspection has greater type than FROM
		   (RELAY_FROM) parameter: insert a new FROM (RELAY_FROM) parameter
		   between the last found FROM (RELAY_FROM) parameter and
		   "current_param". */
		else {
			HIP_DEBUG("Created new %s and copied "\
				  "current parameter to relayed packet.\n",
				  hip_param_type_name(param_type));
			builder_function(msg_to_be_relayed, saddr,
					 info->src_port);
			hip_build_param(msg_to_be_relayed, current_param);
			from_added = 1;
		}
	}

	/* If the incoming packet had no parameters after the existing FROM (RELAY_FROM)
	   parameters, new FROM (RELAY_FROM) parameter is not added until here. */
	if (!from_added) {
		HIP_DEBUG("No parameters found, adding a new %s.\n",
			  hip_param_type_name(param_type));
		builder_function(msg_to_be_relayed, saddr, info->src_port);
	}

	/* Zero message HIP checksum. */
	hip_zero_msg_checksum(msg_to_be_relayed);

        if (relay_type == HIP_FULLRELAY)
		hmac_param_type = HIP_PARAM_RELAY_HMAC;
        else
		hmac_param_type = HIP_PARAM_RVS_HMAC;

        /* Adding RVS_HMAC or RELAY_HMAC parameter as the last parameter of the relayed
	   packet. Notice, that this presumes that there are no parameters
	   whose type value is greater than RVS_HMAC or RELAY_HMAC in the incoming I1
	   packet. */
	HIP_DEBUG("Adding a new RVS_HMAC or RELAY_HMAC parameter as the last parameter.\n");
	HIP_IFEL(hip_build_param_hmac(msg_to_be_relayed,
				      &(rec->hmac_relay),
				      hmac_param_type), -1,
		 "Building of RVS_HMAC or RELAY_HMAC failed.\n");
	
	/* If the client is behind NAT the packet is relayed on UDP. If
	   there is no NAT the packet is relayed on raw HIP. We don't have to
	   take care of which send-function to use, as the rec->send_fn was
	   initiated with correct value when the relay relay was created. Note
	   that we use NULL as source IP address instead of
	   i1_daddr. A source address is selected in the corresponding
	   send-function. */

	if (info->src_port)
        {
		// if the incoming message is via UDP, the RVS relay must use UDP also.
		HIP_IFEL(hip_send_pkt(NULL, &(rec->ip_r), hip_get_local_nat_udp_port(),
				      rec->udp_port_r, msg_to_be_relayed, NULL, 0),
			 -ECOMM, "Relaying the packet failed.\n");
	} else
        {
		HIP_IFEL(rec->send_fn(NULL, &(rec->ip_r), hip_get_local_nat_udp_port(),
				      rec->udp_port_r, msg_to_be_relayed, NULL, 0),
			 -ECOMM, "Relaying the packet failed.\n");
	}
	
	/* Once we have relayed the I1 packet successfully, we update the time of
	   last contact. */
	rec->last_contact = time(NULL);

	HIP_DEBUG_HIT("hip_relay_forward(): Relayed the packet to", &(rec->ip_r));

 out_err:
	if (msg_to_be_relayed != NULL)
            free(msg_to_be_relayed);

	return err;
}

int hip_relay_read_config(){
	FILE *fp = NULL;
	int lineerr = 0, parseerr = 0, err = 0;
	char parameter[HIP_RELAY_MAX_PAR_LEN + 1];
	hip_configvaluelist_t values;
	hip_hit_t hit, *wl_hit = NULL;
	uint8_t max = 255; /* Theoretical maximum lifetime value. */

	HIP_IFEL(((fp = fopen(HIP_RELAY_CONFIG_FILE, "r")) == NULL), -ENOENT,
		 "Cannot open file %s for reading.\n", HIP_RELAY_CONFIG_FILE);
	
	do {
		parseerr = 0;
		memset(parameter, '\0', sizeof(parameter));
		hip_cvl_init(&values);
		lineerr = hip_cf_get_line_data(fp, parameter, &values, &parseerr);
				
		if(parseerr == 0){
			_HIP_DEBUG("param: '%s'\n", parameter);
			hip_configfilevalue_t *current = NULL;
			if(strcmp(parameter, "whitelist_enabled") == 0) {
				current = hip_cvl_get_next(&values, current);
				if(strcmp(current->data, "no") == 0) {
					whitelist_enabled = HIP_RELAY_WL_OFF;
				}
			} else if(strcmp(parameter, "whitelist") == 0) {
				while((current = 
				       hip_cvl_get_next(&values, current))
				      != NULL) {
					/* Try to convert the characters to an
					   IPv6 address. */
					if(inet_pton(AF_INET6, current->data,
						     &hit) > 0)
					{
						/* store the HIT to the whitelist. */
						wl_hit = (hip_hit_t*)
							malloc(sizeof(hip_hit_t));
						if(wl_hit == NULL) {
							HIP_ERROR("Error "\
								  "allocating "\
								  "memory for "\
								  "whitelist "\
								  "HIT.\n");
							break;
						}
						memcpy(wl_hit, &hit, sizeof(hit));
						hip_relwl_put(wl_hit);
						print_node(current);
					}
				}
			} else if(strcmp(parameter, "minimum_lifetime") == 0) {
				time_t tmp = 0;
				uint8_t val = 0;
				current = hip_cvl_get_next(&values, current);
				tmp = atol(current->data);
				
				if(hip_get_lifetime_value(tmp, &val) == 0) {
					/* hip_get_lifetime_value() truncates the
					   value. We want the minimum to be at
					   least the value specified. */
					if(val < max) {
						val++;
					}
					hiprelay_min_lifetime = val;
				}
			} else if(strcmp(parameter, "maximum_lifetime") == 0) {
				time_t tmp = 0;
				uint8_t val = 0;
				current = hip_cvl_get_next(&values, current);
				tmp = atol(current->data);
				
				if(hip_get_lifetime_value(tmp, &val) == 0) {
					hiprelay_max_lifetime = val;
				}
			}
		}

		hip_cvl_uninit(&values);
		
	} while(lineerr != EOF);
	
	if(fclose(fp) != 0) {
		HIP_ERROR("Cannot close file %s.\n", HIP_RELAY_CONFIG_FILE);
	}
	
	/* Check that the read values are sane. If not, rollback to defaults. */
	if(hiprelay_min_lifetime > hiprelay_max_lifetime) {
		hiprelay_min_lifetime = HIP_RELREC_MIN_LIFETIME;
		hiprelay_max_lifetime = HIP_RELREC_MAX_LIFETIME;
	}

	HIP_DEBUG("\nRead relay configuration file with following values:\n"\
		  "Whitelist enabled: %s\nNumber of HITs in the whitelist: "\
		  "%lu\nMinimum lifetime: %ld\nMaximum lifetime: %ld\n",
		  (whitelist_enabled) ? "YES" : "NO", hip_relwl_size(),
		  hiprelay_min_lifetime, hiprelay_max_lifetime);
	
 out_err:
	
	return err;
}

int hip_relay_write_config()
{
	int err = 0;
	FILE *fp = NULL;

	HIP_IFEL(((fp = fopen(HIP_RELAY_CONFIG_FILE, "w")) == NULL), -ENOENT,
		 "Cannot open file %s for writing.\n", HIP_RELAY_CONFIG_FILE);

	fprintf(fp, HIP_RC_FILE_FORMAT_STRING, HIP_RC_FILE_CONTENT);

	if(fclose(fp) != 0) {
		HIP_ERROR("Cannot close file %s.\n", HIP_RELAY_CONFIG_FILE);
	}

 out_err:

	return err;
}

/**
 * @todo     Xiang! Please, add decent Doxygen comments, check the doxy syntax
 *           from doc/HACKING. Stick to C-coding style using LINUX indendation.
 *           No lines over 80 characters. No capital letters in funcion names
 *           (C-style). Function commmends should be in header file.
 */
int hip_relay_handle_relay_to(struct hip_common * msg,
			      int msg_type, 			      
			      struct in6_addr *src_addr,
			      struct in6_addr *dst_addr,
			      hip_portpair_t *msg_info)
{
	int err = 0;
	hip_relrec_t *rec = NULL, dummy;
	struct hip_relay_to *relay_to;
	//check if full relay service is active
	
	if(hip_relay_get_status() != HIP_RELAY_ON) {
		/* Should we set err to -1? */
		goto out_err;
	}
	
	HIP_DEBUG("handle_relay_to: full relay is on\n");
	// check if the relay has been registered
	
	/* Check if we have a relay record in our database matching the
	   I's HIT. We should find one, if the I is
	   registered to relay.*/
	HIP_DEBUG_HIT("Searching relay record on HIT:", &msg->hits);
	memcpy(&(dummy.hit_r), &msg->hits, sizeof(msg->hits));
	rec = hip_relht_get(&dummy);
	
	if(rec == NULL) {
		HIP_INFO("handle_relay_to: No matching relay record found.\n");
		goto out_err;
	} else if(rec->type != HIP_FULLRELAY) {
		goto out_err;
	}
  
	HIP_INFO("handle_relay_to: Matching relay record found:Full-Relay.\n");
	
	//check if there is a relay_to parameter	    
	relay_to = (struct hip_relay_to *) hip_get_param(msg, HIP_PARAM_RELAY_TO);
  	HIP_IFEL(!relay_to, 0, "No relay_to  found\n");
  	
  	// check msg type 	
  	switch(msg_type) {
  	case HIP_R1:
  	case HIP_R2:
  	case HIP_UPDATE:
  	case HIP_NOTIFY:
  		HIP_DEBUG_IN6ADDR("the relay to address: ", &relay_to->address);
  		HIP_DEBUG("the relay to ntohs(port): %d", ntohs(relay_to->port));
  		hip_relay_forward_response(
			msg, msg_type, src_addr, dst_addr, msg_info,
			(in6_addr_t *)&relay_to->address, ntohs(relay_to->port));
		//  state = HIP_STATE_NONE;
  		err = 1;
  		goto out_err;
  	}
  	
 out_err:
	return err;    
}

/**
 * @todo     Xiang! Please, add decent Doxygen comments, check the doxy syntax
 *           from doc/HACKING. Stick to C-coding style using LINUX indendation.
 *           No lines over 80 characters. No capital letters in funcion names
 *           (C-style). Function commmends should be in header file.
 */
int hip_relay_forward_response(const hip_common_t *r,
			       const uint8_t type_hdr, 
			       const in6_addr_t *r_saddr,
			       const in6_addr_t *r_daddr , 
			       const hip_portpair_t *r_info , 
			       const in6_addr_t *relay_to_addr,
			       const in_port_t relay_to_port)
{
	struct hip_common *r_to_be_relayed = NULL;
	struct hip_tlv_common *current_param = NULL;
	int err = 0;
	hip_tlv_type_t param_type = 0;

	HIP_DEBUG_IN6ADDR("hip_relay_forward_response:  source address", r_saddr);
	HIP_DEBUG_IN6ADDR("hip_relay_forward_response:  destination address", r_daddr);
	HIP_DEBUG_IN6ADDR("hip_relay_forward_response:  relay to address", relay_to_addr);
	HIP_DEBUG("Relay_to port: %d.\n", relay_to_port);

	HIP_IFEL(!(r_to_be_relayed = hip_msg_alloc()), -ENOMEM,
		 "No memory to copy original I1\n");	

	hip_build_network_hdr(r_to_be_relayed, type_hdr, 0,
			      &(r->hits), &(r->hitr));

	while ((current_param = hip_get_next_param(r, current_param)) != NULL){
		
		HIP_DEBUG("Found parameter in R.\n");
		HIP_DEBUG("Copying existing parameter to R packet "\
			  "to be relayed.\n");
		hip_build_param(r_to_be_relayed,current_param);
	}

	hip_zero_msg_checksum(r_to_be_relayed);

	if(relay_to_port == 0) {
		/* 
		   Xiang, compiler gives a warning, please fix:
		   hiprelay.c:1037: warning: passing argument 2 of
		   'hip_send_raw' discards qualifiers from pointer target type.
		*/
		HIP_IFEL(hip_send_pkt(NULL, relay_to_addr, hip_get_local_nat_udp_port(),
				      relay_to_port, r_to_be_relayed, NULL, 0),
			 -ECOMM, "forwarding response failed in raw\n");
	} else {
		/* 
		   Xiang, compiler gives a warning, please fix:
		   hiprelay.c:1041: warning: passing argument 2 of
		   'hip_send_udp' discards qualifiers from pointer target type.
		*/
		HIP_IFEL(hip_send_pkt(NULL, relay_to_addr, hip_get_local_nat_udp_port(),
				      relay_to_port, r_to_be_relayed, NULL, 0),
			 -ECOMM, "forwarding response failed in UDP\n");
	}
	
	HIP_DEBUG_HIT("hip_relay_forward_response: Relayed  to", relay_to_addr);
	
 out_err:
	if(r_to_be_relayed != NULL) {
		HIP_FREE(r_to_be_relayed);
	}
	return err;
}

int hip_relay_add_rvs_to_ha(hip_common_t *source_msg, hip_ha_t *entry)
{
	struct hip_via_rvs *via_rvs = NULL; 
	struct hip_esp_info *esp_info = NULL;
	struct hip_spi_out_item spi_out_data;
        int spi_out = -1;
	int err = 0;
 
	// Get rendezvous server's IP addresses
	via_rvs = (struct hip_via_rvs *)
		hip_get_param(source_msg, HIP_PARAM_VIA_RVS);
	
	if (!via_rvs)
	{
		_HIP_DEBUG("No VIA_RVS parameter.");
		return -1;
	}

        if (!entry->rendezvous_addr)
        {
            HIP_IFEL(!(entry->rendezvous_addr = malloc(sizeof(struct in6_addr))),
				-1, "Malloc failed for in6_addr\n");
        }

	memcpy(entry->rendezvous_addr, &via_rvs->address, sizeof(struct in6_addr));
	if (!entry->rendezvous_addr)
	{
		HIP_DEBUG("Couldn't get rendezvous IP address.");
		return -1;
	}
	
	HIP_DEBUG_IN6ADDR("The rvs address: ", entry->rendezvous_addr);
	
out_err:
	return err;
}

/**
 * function return -1 means error
 * return 0, means parameter not found
 * return 1, means parameter found and verified
 * @todo     Xiang! Please, add decent Doxygen comments, check the doxy syntax
 *           from doc/HACKING. Stick to C-coding style using LINUX indendation.
 *           No lines over 80 characters. No capital letters in funcion names
 *           (C-style). Function commmends should be in header file.
 * 
 */
int hip_relay_handle_from(hip_common_t *source_msg,
			  in6_addr_t *rvs_ip,
			  in6_addr_t *dest_ip, in_port_t *dest_port)
{
	hip_tlv_type_t param_type;
	//   struct hip_relay_from *relay_from = NULL;
	struct hip_from *from = NULL;
	hip_ha_t *rvs_ha_entry = NULL;
	
	/* Check if the incoming I1 packet has a FROM parameters. */
   
	from = (struct hip_from *)
		hip_get_param(source_msg, HIP_PARAM_FROM);
	
	/* Copy parameter data to target buffers. */
	if(from == NULL) {
		HIP_DEBUG("No FROM or RELAY_FROM parameters found in I1.\n");
		return 0;
	} else {
		param_type = HIP_PARAM_FROM;
		memcpy(dest_ip, &from->address, sizeof(from->address));
	} 
	
	/* The relayed I1 packet has the initiator's HIT as source HIT, and the
	   responder HIT as destination HIT. We would like to verify the HMAC
	   against the host association that was created when the responder
	   registered to the rvs. That particular host association has the
	   responder's HIT as source HIT and the rvs' HIT as destination HIT.
	   Because we do not have the HIT of RVS in the incoming I1 message, we
	   have to get the host association using the responder's HIT and the IP
	   address of the RVS as search keys. */
#ifdef CONFIG_HIP_RVS
	rvs_ha_entry =
		hip_hadb_find_rvs_candidate_entry(&source_msg->hitr, rvs_ip);
     
	if (rvs_ha_entry == NULL) {
		HIP_DEBUG_HIT("rvs hit not found in the entry table rvs_ip:",
			      rvs_ip);
		HIP_DEBUG_HIT("rvs hit not found in the entry table "\
			      "&source_msg->hitr:", &source_msg->hitr);
		HIP_DEBUG("The I1 packet was received from RVS, but the host "\
			  "association created during registration is not found. "
			  "RVS_HMAC cannot be verified.\n");
		return -1;
	}
	
	HIP_DEBUG("RVS host or relay host association found.\n");

	/* Verify the RVS hmac. */
	if(from != NULL && hip_verify_packet_rvs_hmac(
		   source_msg, &rvs_ha_entry->hip_hmac_out) != 0) {
		HIP_DEBUG("RVS_HMAC verification failed.\n");
		HIP_DEBUG("Ignoring HMAC verification\n");
		/* Notice that the HMAC is currently ignored to allow rvs/relay e.g.
		   in the following use case: I <----IPv4 ----> RVS <----IPv6---> R 
		   Otherwise we have to loop through all host associations and try
		   all HMAC keys. See bug id 753 */
		//return -1;
	}
     
	HIP_DEBUG("RVS_HMAC verified.\n");
#endif	/* CONFIG_HIP_RVS */

	return 1;
}

/**
 * function return -1 means error
 * return 0, means parameter not found
 * return 1, means parameter found and verified
 * @todo     Xiang! Please, add decent Doxygen comments, check the doxy syntax
 *           from doc/HACKING. Stick to C-coding style using LINUX indendation.
 *           No lines over 80 characters. No capital letters in funcion names
 *           (C-style). Function commmends should be in header file.
 */
int hip_relay_handle_relay_from(hip_common_t *source_msg,
				in6_addr_t *relay_ip,
				in6_addr_t *dest_ip, in_port_t *dest_port)
{
	hip_tlv_type_t param_type;
	struct hip_relay_from *relay_from = NULL;
	struct hip_from *from = NULL;
	hip_ha_t *relay_ha_entry = NULL;

	/* Check if the incoming I1 packet has  RELAY_FROM parameters. */
	relay_from = (struct hip_relay_from *)
		hip_get_param(source_msg, HIP_PARAM_RELAY_FROM);
		
	/* Copy parameter data to target buffers. */
	if(relay_from == NULL) {
		HIP_DEBUG("No RELAY_FROM parameters found in I1.\n");
		return 0;
	} else  {
		HIP_DEBUG("Found RELAY_FROM parameter in I.\n");
		// set the relay ip and port to the destination address and port.
		param_type = HIP_PARAM_RELAY_FROM;
		  
		memcpy(dest_ip, &relay_from->address, sizeof(relay_from->address));
		*dest_port = ntohs(relay_from->port);
		//	*dest_port = relay_from->port;
		HIP_DEBUG("RELAY_FROM port in I. %d \n", *dest_port);
	}
     
	/* The relayed I1 packet has the initiator's HIT as source HIT, and the
	   responder HIT as destination HIT. We would like to verify the HMAC
	   against the host association that was created when the responder
	   registered to the rvs. That particular host association has the
	   responder's HIT as source HIT and the rvs' HIT as destination HIT.
	   Because we do not have the HIT of Relay in the incoming I1 message, we
	   have to get the host association using the responder's HIT and the IP
	   address of the Relay as search keys.
	
	   the fucntion hip_hadb_find_rvs_candidate_entry is designed for RVS case, but 
	   we reuse it in Relay also.
	*/
#ifdef CONFIG_HIP_RVS
	relay_ha_entry =
		hip_hadb_find_rvs_candidate_entry(&source_msg->hitr, relay_ip);
     
	if (relay_ha_entry == NULL) {
		HIP_DEBUG_HIT("relay hit not found in the entry table rvs_ip:",
			      relay_ip);
		HIP_DEBUG_HIT("relay hit not found in the entry table "\
			      "&source_msg->hitr:", &source_msg->hitr);
		HIP_DEBUG("The I1 packet was received from Relay, but the host "\
			  "association created during registration is not found. "
			  "RVS_HMAC cannot be verified.\n");
		return -1;
	}
	
	HIP_DEBUG("RVS host or relay host association found.\n");
          
	if(relay_from != NULL &&
	   hip_verify_packet_hmac_general(source_msg,
					  &relay_ha_entry->hip_hmac_out,
					  HIP_PARAM_RELAY_HMAC ) != 0) {
		/* Notice that the HMAC is currently ignored to allow rvs/relay e.g.
		   in the following use case: I <----IPv4 ----> RVS <----IPv6---> R 
		   Otherwise we have to loop through all host associations and try
		   all HMAC keys. See bug id 753 */
		HIP_DEBUG("Full_Relay_HMAC verification failed.\n");
		HIP_DEBUG("Ignoring HMAC verification\n");
		//return -1;
	}
	
	HIP_DEBUG("RVS_HMAC or Full_Relay verified.\n");
#endif	/* CONFIG_HIP_RVS */

	return 1;
}


int hip_relay_handle_relay_to_in_client(struct hip_common * msg,
			      int msg_type, 			      
			      struct in6_addr *src_addr,
			      struct in6_addr *dst_addr,
			      hip_portpair_t *msg_info,
			      hip_ha_t *entry)
{
	int err = 0;
	hip_relrec_t *rec = NULL, dummy;
	struct hip_relay_to *relay_to;
	//check if full relay service is active
	
	if(!entry){
		HIP_DEBUG("handle relay_to in client is failed\n");
		goto out_err;
	}
	
	
	HIP_DEBUG("handle relay_to in client is on\n");
	// check if the relay has been registered
  	
	//check if there is a relay_to parameter	    
	relay_to = (struct hip_relay_to *) hip_get_param(msg, HIP_PARAM_RELAY_TO);
  	HIP_IFEL(!relay_to, 0, "No relay_to  found\n");
  	
  	// check msg type 	
  	switch(msg_type) {
  	case HIP_R1:
  	case HIP_R2:
  		//disable the update and notify message. we need to think about them later
  //	case HIP_UPDATE:
  //	case HIP_NOTIFY:
  		HIP_DEBUG_IN6ADDR("the relay to address: ", &relay_to->address);
  		HIP_DEBUG("the relay to ntohs(port): %d, local udp port %d\n", ntohs(relay_to->port),entry->local_udp_port);
  		
  		if(ipv6_addr_cmp(&relay_to->address,&entry->our_addr)){
  			HIP_DEBUG("relay_to address is saved as reflexive addr. \n");
  			entry->local_reflexive_udp_port = ntohs(relay_to->port);
  			memcpy(&entry->local_reflexive_address, &relay_to->address, sizeof(in6_addr_t));
  		}
		//  state = HIP_STATE_NONE;
  		err = 1;
  		goto out_err;
  	}
  	
 out_err:
	return err;    
}
