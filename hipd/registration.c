/** @file
 * This file defines a registration mechanism for the Host Identity Protocol
 * (HIP) that allows hosts to register with services.
 * 
 * @author  Lauri Silvennoinen
 * @note    Related RFC: <a href="http://www.rfc-editor.org/rfc/rfc5203.txt">
 *          Host Identity Protocol (HIP) Registration Extension</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @see     registration.h
 * @see     hiprelay.h
 * @see     escrow.h
 */ 
#include "registration.h"

/** An array for storing all existing services. */
hip_srv_t hip_services[HIP_TOTAL_EXISTING_SERVICES];
/** A linked list for storing pending requests on the client side.
 *  @note This assumes a single threaded model. We are not using mutexes here.
 */
hip_ll_t pending_requests;

void hip_init_services()
{
	hip_services[0].reg_type     = HIP_SERVICE_RENDEZVOUS;
	hip_services[0].status       = HIP_SERVICE_OFF;
	hip_services[0].min_lifetime = HIP_RELREC_MIN_LIFETIME;
	hip_services[0].max_lifetime = HIP_RELREC_MAX_LIFETIME;
	hip_services[1].reg_type     = HIP_SERVICE_ESCROW;
	hip_services[1].status       = HIP_SERVICE_OFF;
	hip_services[1].min_lifetime = HIP_ESCROW_MIN_LIFETIME;
	hip_services[1].max_lifetime = HIP_ESCROW_MAX_LIFETIME;
	hip_services[2].reg_type     = HIP_SERVICE_RELAY;
	hip_services[2].status       = HIP_SERVICE_OFF;
	hip_services[2].min_lifetime = HIP_RELREC_MIN_LIFETIME;
	hip_services[2].max_lifetime = HIP_RELREC_MAX_LIFETIME;
	hip_services[3].reg_type     = HIP_SERVICE_SAVAH;
	hip_services[3].status       = HIP_SERVICE_OFF;
	hip_services[3].min_lifetime = HIP_RELREC_MIN_LIFETIME;
	hip_services[3].max_lifetime = HIP_RELREC_MAX_LIFETIME;

	hip_ll_init(&pending_requests);
}

void hip_uninit_services()
{
	hip_ll_uninit(&pending_requests, free);
}

void hip_registration_maintenance()
{
	while (hip_del_pending_request_by_expiration() == 0);
}

int hip_set_srv_status(uint8_t reg_type, hip_srv_status_t status)
{
	int i = 0;
	
	for(; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
		if(hip_services[i].reg_type == reg_type) {
			hip_services[i].status = status;
			return 0;
		}
	}
	
	return -1;
}

int hip_set_srv_min_lifetime(uint8_t reg_type, uint8_t lifetime)
{
	if(lifetime = 0) {
		return -1;
	}
	
	int i = 0;
	
	for(; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
		if(hip_services[i].reg_type == reg_type) {
			hip_services[i].min_lifetime = lifetime;
			return 0;
		}
	}
	
	return -1;
}

int hip_set_srv_max_lifetime(uint8_t reg_type, uint8_t lifetime)
{
	if(lifetime = 0) {
		return -1;
	}
	
	int i = 0;
	
	for(; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
		if(hip_services[i].reg_type == reg_type) {
			hip_services[i].max_lifetime = lifetime;
			return 0;
		}
	}
	
	return -1;
}

int hip_get_active_services(hip_srv_t *active_services,
			    unsigned int *active_service_count)
{
	if(active_services == NULL) {
		return -1;
	}

	int i = 0, j = 0;
	
	memset(active_services, 0, sizeof(hip_services));

	for(; i < HIP_TOTAL_EXISTING_SERVICES; i++) {
		if(hip_services[i].status == HIP_SERVICE_ON) {
			memcpy(&active_services[j], &hip_services[i],
			       sizeof(active_services[j]));
			j++;
		}
	}
	
	*active_service_count = j;

	return 0;
} 

void hip_get_srv_info(const hip_srv_t *srv, char *information)
{
	if(srv == NULL || information == NULL)
		return;
	
	char *cursor = information;
	cursor += sprintf(cursor, "Service info:\n");
	
	cursor += sprintf(cursor, " reg_type: ");
	if(srv->reg_type == HIP_SERVICE_RENDEZVOUS){
		cursor += sprintf(cursor, "rendezvous\n");
	} else if(srv->reg_type == HIP_SERVICE_ESCROW) {
		cursor += sprintf(cursor, "escrow\n");
	} else if(srv->reg_type == HIP_SERVICE_RELAY) {
		cursor += sprintf(cursor, "relay\n");
	} else if(srv->reg_type == HIP_SERVICE_SAVAH) {
	        cursor += sprintf(cursor, "savah\n");
        } else {
		cursor += sprintf(cursor, "unknown\n");
	}

	cursor += sprintf(cursor, " status: ");
	if(srv->status == HIP_SERVICE_ON) {
		cursor += sprintf(cursor, "on\n");
	}else if(srv->status == HIP_SERVICE_OFF) {
		cursor += sprintf(cursor, "off\n");
	}else{
		cursor += sprintf(cursor, "unknown\n");
	}

	cursor += sprintf(cursor, " minimum lifetime: %u\n", srv->min_lifetime);
	cursor += sprintf(cursor, " maximum lifetime: %u\n", srv->max_lifetime);
}

int hip_add_pending_request(hip_pending_request_t *request)
{
	int err = 0;
	
	/* We don't have to check for NULL request as the linked list does that
	   for us. */
	HIP_IFEL(hip_ll_add_last(&pending_requests, request), -1,
		 "Failed to add a pending registration request.\n");

 out_err:
	return err;
}

int hip_del_pending_request(hip_ha_t *entry)
{
	int index = 0;
	hip_ll_node_t *iter = NULL;
	
	/* Iterate through the linked list. The iterator itself can't be used
	   for deleting nodes from the list. Therefore, we just get the index of
	   the element to be deleted using the iterator and then call
	   hip_ll_del() to do the actual deletion. */
	while((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
		if(((hip_pending_request_t *)(iter->ptr))->entry == entry) {
			
			HIP_DEBUG("Deleting and freeing a pending request at "\
				  "index %u.\n", index);
			hip_ll_del(&pending_requests, index, free);
			return 0;
		}
		index++;
	}

	return -1;
}

int hip_del_pending_request_by_type(hip_ha_t *entry, uint8_t reg_type)
{
	int index = 0;
	hip_ll_node_t *iter = NULL;
	hip_pending_request_t * request = NULL;

	/* See hip_del_pending_request() for a comment. */
	while((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
		request = (hip_pending_request_t *)(iter->ptr);
		if(request->entry == entry && request->reg_type == reg_type) {
			
			HIP_DEBUG("Deleting and freeing a pending request by "\
				  "type at index %u.\n", index);
			hip_ll_del(&pending_requests, index, free);
			return 0;
		}
		index++;
	}

	return -1;
}

int hip_del_pending_request_by_expiration()
{
	int index = 0;
	hip_ll_node_t *iter = NULL;
	hip_pending_request_t * request = NULL;
	time_t now = time(NULL); 

	/* See hip_del_pending_request() for a comment. */
	while((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
		request = (hip_pending_request_t *)(iter->ptr);
		if(now - request->created > HIP_PENDING_REQUEST_LIFETIME ) {
			HIP_DEBUG("Deleting and freeing a pending request by "\
				  "expiration (%u seconds) at index %u.\n",
				  now - request->created, index);
			hip_ll_del(&pending_requests, index, free);
			return 0;
		}
		index++;
	}

	return -1;
}

int hip_get_pending_requests(hip_ha_t *entry, hip_pending_request_t *requests[])
{
	if(requests == NULL) {
		return -1;
	}

	hip_ll_node_t *iter = 0;
	int request_count = 0;
	
	while((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
		if(((hip_pending_request_t *)(iter->ptr))->entry
		   == entry) {
			requests[request_count] =
				(hip_pending_request_t *)(iter->ptr);
			request_count++;
		}
	}
	
	if(request_count == 0) {
		return -1;
	}
			
	return 0;
}

int hip_get_pending_request_count(hip_ha_t *entry)
{
	hip_ll_node_t *iter = 0;
	int request_count = 0;
	
	while((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
		if(((hip_pending_request_t *)(iter->ptr))->entry
		   == entry) {
			request_count++;
		}
	}

	return request_count;
}

int hip_replace_pending_requests(hip_ha_t * entry_old, 
				hip_ha_t * entry_new) {
        hip_ll_node_t *iter = 0;
	
	while((iter = hip_ll_iterate(&pending_requests, iter)) != NULL) {
		if(((hip_pending_request_t *)(iter->ptr))->entry
		   == entry_old) {
		  ((hip_pending_request_t *)(iter->ptr))->entry	= entry_new;
		  return 0;
		}
	}

	return -1;
}

int hip_handle_param_reg_info(hip_ha_t *entry, hip_common_t *source_msg,
			      hip_common_t *target_msg)
{
	struct hip_reg_info *reg_info = NULL;
	uint8_t *reg_types = NULL, reg_type = 0;
	unsigned int type_count = 0;
	int err = 0, i = 0;
	
	reg_info = hip_get_param(source_msg, HIP_PARAM_REG_INFO);
	
	if(reg_info == NULL) {
		HIP_DEBUG("No REG_INFO parameter found. The server offers "\
			  "no services.\n");
		
#ifdef CONFIG_HIP_ESCROW
		HIP_KEA *kea = hip_kea_find(&entry->hit_our);
		if (kea != NULL) {
			hip_keadb_put_entry(kea);
		}
#endif /* CONFIG_HIP_ESCROW */

		err = -1;
		goto out_err;
	}
	
	HIP_DEBUG("REG_INFO parameter found.\n");

	HIP_DEBUG("REG INFO MIN LIFETIME %d\n", reg_info->min_lifetime);
	HIP_DEBUG("REG INFO MAX LIFETIME %d\n", reg_info->max_lifetime);
	
	/* Get a pointer registration types and the type count. */
	reg_types  = reg_info->reg_type;
	type_count = hip_get_param_contents_len(reg_info) -
		(sizeof(reg_info->min_lifetime) +
		 sizeof(reg_info->max_lifetime));
	
	/* Check RFC 5203 Chapter 3.1. */
	if(type_count == 0){
		HIP_INFO("The server is currently unable to provide services "\
			 "due to transient conditions.\n");
		err = 0;
		goto out_err;
	}
	
	/* Loop through all the registration types found in REG_INFO parameter
	   and store the information of responder's capability to offer a
	   service. */
	for(i = 0; i < type_count; i++){
		
		switch(reg_types[i]) {
		case HIP_SERVICE_RENDEZVOUS:
			HIP_INFO("Responder offers rendezvous service.\n");
			
			hip_hadb_set_peer_controls(
				entry ,HIP_HA_CTRL_PEER_RVS_CAPABLE);
			
			break;
		case HIP_SERVICE_RELAY:
			HIP_INFO("Responder offers relay service.\n");
			hip_hadb_set_peer_controls(
				entry, HIP_HA_CTRL_PEER_RELAY_CAPABLE);
			
			break;
#ifdef CONFIG_HIP_ESCROW	
		case HIP_SERVICE_ESCROW:
			/* The escrow part is just a copy paste from the
			   previous HIPL registration implementation. It is not
			   tested to work. -Lauri */
			HIP_INFO("Responder offers escrow service.\n");
			hip_hadb_set_peer_controls(
				entry, HIP_HA_CTRL_PEER_ESCROW_CAPABLE);
			HIP_KEA *kea = hip_kea_find(&entry->hit_our);
			
			if (kea != NULL) {
				if(kea->keastate != HIP_KEASTATE_REGISTERING) {
					kea->keastate = HIP_KEASTATE_INVALID;
				}
				
				hip_keadb_put_entry(kea);
			} else {
				HIP_DEBUG("No KEA found. Not doing escrow "\
					  "registration.\n");
			}
			
			break;
#endif /* CONFIG_HIP_ESCROW */
		case HIP_SERVICE_SAVAH:
		        HIP_INFO("Responder offers savah service.\n");
			memcpy(sava_serving_gateway, &entry->hit_peer, sizeof(struct in6_addr));
			hip_hadb_set_peer_controls(
				entry, HIP_HA_CTRL_PEER_SAVAH_CAPABLE);
		        break;
		default:
			HIP_INFO("Responder offers unsupported service.\n");
			hip_hadb_set_peer_controls(
				entry ,HIP_HA_CTRL_PEER_UNSUP_CAPABLE);
		}
	}

	/* This far we have stored the information of what services the server
	   offers. Next we check if we have requested any of those services from
	   command line using hipconf. If we have requested, we have pending
	   requests stored. We build a REG_REQUEST parameter containing each
	   service that we have requested and the server offers. */
	
	if(entry->local_controls & HIP_HA_CTRL_LOCAL_REQ_ANY) {
		int request_count = hip_get_pending_request_count(entry);
		if(request_count > 0) {
			int j = 0, types_to_request = 0;
			uint8_t type_array[request_count], valid_lifetime = 0;
			hip_pending_request_t *requests[request_count];
						
			i = 0;
			hip_get_pending_requests(entry, requests);
			
			/* If we have requested for a cancellation of a service
			   we use lifetime of zero. Otherwise we must check
			   that the requested lifetime falls between the offered
			   lifetime boundaries. */
			if(requests[0]->lifetime == 0) {
			        HIP_DEBUG("SERVICE CANCELATION \n");
				valid_lifetime = 0;
			} else {
				valid_lifetime = MIN(requests[0]->lifetime,
						     reg_info->max_lifetime);
				valid_lifetime = MAX(valid_lifetime,
						     reg_info->min_lifetime);
			}

			/* Copy the Reg Types to an array. Outer loop for the
			   services we have requested, inner loop for the
			   services the server offers. */
			for(i = 0; i < request_count; i++) {
				for(j = 0; j < type_count; j++) {
					if(requests[i]->reg_type ==
					   reg_types[j]) { 
						type_array[types_to_request] =
							requests[i]->reg_type;
						
						types_to_request++;
						break;
					}
				}
			}
			HIP_DEBUG("VALID SERVICE LIFETIME %d\n", valid_lifetime);
			if (types_to_request > 0) {
				HIP_IFEL(hip_build_param_reg_request(
						 target_msg, valid_lifetime,
						 type_array, types_to_request),
					 -1,
					 "Failed to build a REG_REQUEST "\
					 "parameter.\n");
				
			}
		}
		/* We do not delete the pending requests for this entry yet, but
		   only after R2 has arrived. We do not need pending requests
		   when R2 arrives, but in case the I2 is to be retransmitted,
		   we must be able to produce the REG_REQUEST parameter. */
	}

 out_err:
	return err;
}

int hip_handle_param_reg_request(hip_ha_t *entry, hip_common_t *source_msg,
				 hip_common_t *target_msg)
{
	int err = 0, type_count = 0, accepted_count = 0, refused_count = 0;
	struct hip_reg_request *reg_request = NULL;
	uint8_t *reg_types = NULL;

	reg_request = hip_get_param(source_msg, HIP_PARAM_REG_REQUEST);
	
	if(reg_request == NULL) {
		err = -1;
		/* Have to use return instead of 'goto out_err' because of
		   the arrays initialised later. Otherwise this won't compile:
		   error: jump into scope of identifier with variably modified
		   type. */
		return err;
	}
#ifdef HIP_USE_ICE
	else{	
		if(hip_nat_get_control(entry) == HIP_NAT_MODE_ICE_UDP){
			HIP_DEBUG("Found request in R2\n");
			hip_nat_set_control(entry, 1);
		}
	}
#endif	
	HIP_DEBUG("REG_REQUEST parameter found. Requested lifetime: 0x%x, "\
		  "number of service types requested: %d.\n",
		  reg_request->lifetime, type_count);
	
	/* Get the number of registration types. */
	type_count = hip_get_param_contents_len(reg_request) -
		sizeof(reg_request->lifetime);
	/* Get a pointer to the actual registration types. */
	reg_types = hip_get_param_contents_direct(reg_request) +
		sizeof(reg_request->lifetime);

	/* Check that the request has at most one value of each type. */
	if(hip_has_duplicate_services(reg_types, type_count)) {
		/* We consider this as a protocol error, and do not build
		   REG_FAILED parameters. The initiator may be rogue and
		   trying to stress the server with malformed service
		   requests. */
		err = -1;
		errno = EPROTO;
		HIP_ERROR("The REG_REQUEST parameter has duplicate services. "\
			  "The whole parameter is omitted.\n");
		/* As above. */
		return err;
	}
	
	/* Arrays for storing the type reg_types of the accepted and refused
	   request types. */
	uint8_t accepted_requests[type_count], accepted_lifetimes[type_count];
	uint8_t refused_requests[type_count], failure_types[type_count];
	
	memset(accepted_requests, 0, sizeof(accepted_requests));
	memset(accepted_lifetimes, 0, sizeof(accepted_lifetimes));
	memset(refused_requests, 0, sizeof(refused_requests));
	memset(failure_types, 0, sizeof(failure_types));
	
	if(reg_request->lifetime == 0) {
		hip_del_registration_server(
			entry, reg_types, type_count, accepted_requests,
			&accepted_count, refused_requests, failure_types,
			&refused_count);
	} else {
		hip_add_registration_server(
			entry, reg_request->lifetime, reg_types, type_count,
			accepted_requests, accepted_lifetimes, &accepted_count,
			refused_requests, failure_types, &refused_count);
	}
	
	HIP_DEBUG("Number of accepted service requests: %d, number of refused "\
		  "service requests: %d.\n", accepted_count, refused_count);

	/* The registration is now done. Next, we build the REG_RESPONSE and
	   REG_FAILED parameters. */
	if(accepted_count > 0) {
		/* There is an issue related to the building of REG_RESPONSE
		   parameters in RFC 5203. In Section 4.4 it is said: "The
		   registrar MUST NOT include more than one REG_RESPONSE
		   parameter in its R2 or UPDATE packets..." Now, how can we
		   inform the requester that it has been granted two or more
		   services with different lifetimes? We cannot. Therefore we
		   just take the first accepted lifetime and use that with all
		   services. -Lauri 20.05.2008 */
		hip_build_param_reg_response(target_msg, accepted_lifetimes[0],
					     accepted_requests, accepted_count);
	}
	if(refused_count > 0) {
		/* We must add as many REG_FAILED parameters as there are
		   different failure types. */
		int i, j, to_be_build_count;
		uint8_t reg_types_to_build[refused_count];
		uint8_t type_to_check[HIP_TOTAL_EXISTING_FAILURE_TYPES] =
			HIP_ARRAY_INIT_REG_FAILURES;
		
		/* We have to get an continuous memory region holding all the
		   registration types having the same failure type. This memory
		   region is the 'reg_types_to_build' array and it will hold
		   'to_be_build_count' elements in it. This is done for each
		   existing failure type. After each failure type check, we
		   build a REG_FAILED parameter. */
		for(i = 0; i < HIP_TOTAL_EXISTING_FAILURE_TYPES; i++) {
			to_be_build_count = 0;
			for(j = 0; j < refused_count; j++) {
				if(failure_types[j] == type_to_check[i]) {
					reg_types_to_build[to_be_build_count] =
						refused_requests[j];
					to_be_build_count++;
				}
			}
			if(to_be_build_count > 0) {
				hip_build_param_reg_failed(
					target_msg, type_to_check[i],
					reg_types_to_build, to_be_build_count);
			}
		}
	}
	
 out_err:
	return err;
}

int hip_handle_param_reg_response(hip_ha_t *entry, hip_common_t *msg)
{
	int err = 0, type_count = 0;
	struct hip_reg_response *reg_response = NULL;
	uint8_t *reg_types = NULL;
	
	reg_response = hip_get_param(msg, HIP_PARAM_REG_RESPONSE);
	
	if(reg_response == NULL) {
		err = -1;
		goto out_err;
	}
	
	HIP_DEBUG("REG_RESPONSE parameter found.\n");
	HIP_DEBUG("Lifetime %d \n", reg_response->lifetime);

	type_count = hip_get_param_contents_len(reg_response) -
		sizeof(reg_response->lifetime);
	reg_types = hip_get_param_contents_direct(reg_response) +
		sizeof(reg_response->lifetime);
	
	if(reg_response->lifetime == 0) {
		hip_del_registration_client(entry, reg_types, type_count);
	} else {
		hip_add_registration_client(entry, reg_response->lifetime,
					    reg_types, type_count);
	}	

 out_err:
	return err;
}

int hip_handle_param_reg_failed(hip_ha_t *entry, hip_common_t *msg)
{
	int err = 0, type_count = 0, i = 0;
	struct hip_reg_failed *reg_failed = NULL;
	uint8_t *reg_types = NULL;
	char reason[256];

	reg_failed = hip_get_param(msg, HIP_PARAM_REG_FAILED);
	
	if(reg_failed == NULL) {
		err = -1;
		goto out_err;
	}
	
	HIP_DEBUG("REG_FAILED parameter found.\n");

	/* There can be more than one REG_FAILED parameters in the message. We
	   have to loop through every one. */
	while(hip_get_param_type(reg_failed) == HIP_PARAM_REG_FAILED) {

		type_count = hip_get_param_contents_len(reg_failed) -
			sizeof(reg_failed->failure_type);
		reg_types = hip_get_param_contents_direct(reg_failed) +
			sizeof(reg_failed->failure_type);
		hip_get_registration_failure_string(reg_failed->failure_type,
						    reason);
	
		for(; i < type_count; i++) {
			
			switch(reg_types[i]) {
			case HIP_SERVICE_RENDEZVOUS:
			{
				HIP_DEBUG("The server has refused to grant us "\
					  "rendezvous service.\n%s\n", reason);
				hip_hadb_cancel_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_RVS); 
				hip_del_pending_request_by_type(
					entry, HIP_SERVICE_RENDEZVOUS);
				hip_hadb_set_peer_controls(
					entry, HIP_HA_CTRL_PEER_REFUSED_RVS);
				break;
			}
			case HIP_SERVICE_RELAY:
			{
				HIP_DEBUG("The server has refused to grant us "\
					  "relay service.\n%s\n", reason);
				hip_hadb_cancel_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_RELAY); 
				hip_del_pending_request_by_type(
					entry, HIP_SERVICE_RELAY);
				hip_hadb_set_peer_controls(
					entry, HIP_HA_CTRL_PEER_REFUSED_RELAY);
				break;
			}
			case HIP_SERVICE_ESCROW:
			{
				/* Not tested to work. Just moved here from an old
				   registration implementation. */
				HIP_DEBUG("The server has refused to grant us "\
					  "escrow service.\n%s\n", reason);
				hip_hadb_cancel_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_ESCROW); 
				hip_del_pending_request_by_type(
					entry, HIP_SERVICE_ESCROW);
				hip_hadb_set_peer_controls(
					entry, HIP_HA_CTRL_PEER_REFUSED_ESCROW);
				break;
			}
			case HIP_SERVICE_SAVAH:
		        {
			        HIP_DEBUG("The server has refused to grant us "\
					  "savah service.\n%s\n", reason);
				hip_hadb_cancel_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_SAVAH); 
				hip_del_pending_request_by_type(
					entry, HIP_SERVICE_SAVAH);
				hip_hadb_set_peer_controls(
					entry, HIP_HA_CTRL_PEER_REFUSED_SAVAH);
				break;
			}
			default:
				HIP_DEBUG("The server has refused to grant us "\
					  "an unknown service (%u).\n%s\n",
					  reg_types[i], reason);
				hip_del_pending_request_by_type(
					entry, reg_types[i]);
				hip_hadb_set_peer_controls(
					entry, HIP_HA_CTRL_PEER_REFUSED_UNSUP);
				break;
			}
		}
		
		/* Iterate to the next parameter and break the loop if there are
		   no more parameters left. */
		i = 0;
		reg_failed = (struct hip_reg_failed *)
			hip_get_next_param(msg, (hip_tlv_common_t *)reg_failed);
		
		if(reg_failed == NULL)
			break;
	}

 out_err:
	
	return err;
}

int hip_add_registration_server(hip_ha_t *entry, uint8_t lifetime,
				uint8_t *reg_types, int type_count,
				uint8_t accepted_requests[],
				uint8_t accepted_lifetimes[],
				int *accepted_count, uint8_t refused_requests[],
				uint8_t failure_types[], int *refused_count)
{
	int err = 0, i = 0;
	hip_relrec_t dummy, *fetch_record = NULL, *new_record = NULL;
	uint8_t granted_lifetime = 0;

	memcpy(&(dummy.hit_r), &(entry->hit_peer), sizeof(entry->hit_peer));
	
	/* Loop through all registrations types in reg_types. This loop calls
	   the actual registration functions. */
	for(; i < type_count; i++) {

		switch(reg_types[i]) {
		case HIP_SERVICE_RENDEZVOUS:
		case HIP_SERVICE_RELAY:
			HIP_DEBUG("Client is registering to rendezvous "\
				 "service or relay service.\n");
			/* Validate lifetime. */
			hip_rvs_validate_lifetime(lifetime, &granted_lifetime);

			fetch_record = hip_relht_get(&dummy);
			/* Check that
			   a) the rvs/relay is ON;
			   b) there already is no relay record for the given
			   HIT. Note that the fetched record type does not
			   matter, since the relay and RVS types cannot co-exist
			   for a single entry;
			   c) the client is whitelisted if the whitelist is on. */
			if(hip_relay_get_status() == HIP_RELAY_OFF) {
				HIP_DEBUG("RVS/Relay is not ON.\n");
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_TYPE_UNAVAILABLE;
				(*refused_count)++;
#if 0
			/* Commented this part of the code out to
			   allow consequtive registration without
			   service cancellation to support host reboots
			   -miika */
			} else if(fetch_record != NULL) {
				HIP_DEBUG("Cancellation required.\n");
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_CANCEL_REQUIRED;
				(*refused_count)++;
#endif
			} else if(hip_relwl_get_status() &&
				  hip_relwl_get(&dummy.hit_r) == NULL) {
				HIP_DEBUG("Client is not whitelisted.\n");
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_INSUFFICIENT_CREDENTIALS;
				(*refused_count)++;
			} else {
				/* Set the type of the relay record. */
				hip_relrec_type_t type =
					(reg_types[i] == HIP_SERVICE_RELAY) ?
					HIP_FULLRELAY : HIP_RVSRELAY;

				/* Allow consequtive registration without
				   service cancellation to support host
				   reboots */
				if (fetch_record != NULL) {
					HIP_DEBUG("Warning: registration exists. Overwriting old one\n");
				}
				
				/* Allocate a new relay record. */
				new_record = hip_relrec_alloc(
					type,granted_lifetime, &(entry->hit_peer),
					&(entry->peer_addr),
					entry->peer_udp_port,
					&(entry->hip_hmac_in),
					entry->hadb_xmit_func->hip_send_pkt);
				
				hip_relht_put(new_record);

				/* Check that the put was succesful. */
				if(hip_relht_get(new_record) != NULL) {
					accepted_requests[*accepted_count] =
						reg_types[i];
					accepted_lifetimes[*accepted_count] =
						granted_lifetime;
					(*accepted_count)++;
					
					HIP_DEBUG("Registration accepted.\n");
				} /* The put was unsuccessful. */
				else {
					if(new_record != NULL) {
						free(new_record);
					}
					refused_requests[*refused_count] =
						reg_types[i];
					failure_types[*refused_count] =
						HIP_REG_TRANSIENT_CONDITIONS;
					(*refused_count)++;
					HIP_ERROR("Unable to store new relay "\
						  "record. Registration "\
						  "refused.\n");
				}
			}

			break;
		case HIP_SERVICE_ESCROW:
			HIP_DEBUG("Client is registering to escrow service.\n");
			
			/* Validate lifetime. */
			hip_escrow_validate_lifetime(lifetime,
						     &granted_lifetime);
			
			if(hip_handle_escrow_registration(&entry->hit_peer)
			   == 0) {
				accepted_requests[*accepted_count] =
					reg_types[i];
				accepted_lifetimes[*accepted_count] =
					granted_lifetime;
				(*accepted_count)++;
				
				HIP_DEBUG("Registration accepted.\n");
			} else {
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_INSUFFICIENT_CREDENTIALS;
				(*refused_count)++;
				HIP_DEBUG("Registration refused.\n");
			}

			break;
		case HIP_SERVICE_SAVAH:
		        HIP_DEBUG("Client is registering to savah service.\n");
			accepted_requests[*accepted_count] =
			  reg_types[i];
			accepted_lifetimes[*accepted_count] =
			  lifetime;
			(*accepted_count)++;
				
			HIP_DEBUG("Registration accepted.\n");
		        break;
		default:
			HIP_DEBUG("Client is trying to register to an "
				  "unsupported service.\nRegistration "\
				  "refused.\n");
			refused_requests[*refused_count] = reg_types[i];
			failure_types[*refused_count] =
				HIP_REG_TYPE_UNAVAILABLE;
			(*refused_count)++;
			
			break;
		}
	}

 out_err:

	return err;
}

int hip_del_registration_server(hip_ha_t *entry, uint8_t *reg_types,
				int type_count, uint8_t accepted_requests[],
				int *accepted_count, uint8_t refused_requests[],
				uint8_t failure_types[], int *refused_count)
{
	int err = 0, i = 0;
	hip_relrec_t dummy, *fetch_record = NULL, *new_record = NULL;
	
	memcpy(&(dummy.hit_r), &(entry->hit_peer), sizeof(entry->hit_peer));
	
	/* Loop through all registrations types in reg_types. This loop calls
	   the actual registration functions. */
	for(; i < type_count; i++) {

		switch(reg_types[i]) {
		case HIP_SERVICE_RENDEZVOUS:
		case HIP_SERVICE_RELAY: {
			/* Set the type of the relay record. */
			hip_relrec_type_t type_to_delete = 0;

			/* RVS and relay deletions are identical except the
			   relay record type. */
			if(reg_types[i] == HIP_SERVICE_RENDEZVOUS) {
				HIP_DEBUG("Client is cancelling registration "\
					  "to rendezvous service.\n");
				type_to_delete = HIP_RVSRELAY;
			} else {
				HIP_DEBUG("Client is cancelling registration "\
					  "to relay service.\n");
				type_to_delete = HIP_FULLRELAY;
			}
						
			fetch_record = hip_relht_get(&dummy);
			/* Check that
			   a) the rvs/relay is ON;
			   b) there is an relay record to delete for the given
			   HIT.
			   c) the fetched record type is correct.
			   d) the client is whitelisted if the whitelist is on. */

			if(hip_relay_get_status() == HIP_RELAY_OFF) {
				HIP_DEBUG("RVS/Relay is not ON.\n");
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_TYPE_UNAVAILABLE;
				(*refused_count)++;
			} else if(fetch_record == NULL) {
				HIP_DEBUG("There is no relay record to "\
					  "cancel.\n");
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_TYPE_UNAVAILABLE;
				(*refused_count)++;
			} else if(fetch_record->type != type_to_delete) {
				HIP_DEBUG("The relay record to be cancelled "\
					  "is of wrong type.\n");
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_TYPE_UNAVAILABLE;
				(*refused_count)++; 
			} else if(hip_relwl_get_status() &&
				  hip_relwl_get(&dummy.hit_r) == NULL) {
				HIP_DEBUG("Client is not whitelisted.\n");
				refused_requests[*refused_count] = reg_types[i];
				failure_types[*refused_count] =
					HIP_REG_INSUFFICIENT_CREDENTIALS;
				(*refused_count)++;
			} else {
				/* Delete the relay record. */
				hip_relht_rec_free(&dummy);
				/* Check that the relay record really got deleted. */
				if(hip_relht_get(&dummy) == NULL) {
					accepted_requests[*accepted_count] =
						reg_types[i];
					(*accepted_count)++;
					HIP_DEBUG("Cancellation accepted.\n");
				} else {
					refused_requests[*refused_count] =
						reg_types[i];
					failure_types[*refused_count] =
						HIP_REG_TRANSIENT_CONDITIONS;
					(*refused_count)++;
					HIP_ERROR("Cancellation refused.\n");
				}
			}
			
			break;
		}
		case HIP_SERVICE_ESCROW:
			/** @todo Implement escrow cancellation. */
			HIP_DEBUG("Client is cancelling registration to "
				  "escrow service. Escrow cancellation is not "\
				  "supported yet.\n");
			refused_requests[*refused_count] = reg_types[i];
			failure_types[*refused_count] =
				HIP_REG_TYPE_UNAVAILABLE;
			(*refused_count)++;

			break;
		default:
			HIP_DEBUG("Client is trying to cancel an unsupported "\
				  "service.\nCancellation refused.\n");
			refused_requests[*refused_count] = reg_types[i];
			failure_types[*refused_count] =
				HIP_REG_TYPE_UNAVAILABLE;
			(*refused_count)++;
			
			break;
		}
	}

 out_err:

	return err;
}

int hip_add_registration_client(hip_ha_t *entry, uint8_t lifetime,
				uint8_t *reg_types, int type_count)
{
	int err = 0, i = 0;
	time_t seconds = 0;
	
	/* 'seconds' is just just for debug prints. */
	hip_get_lifetime_seconds(lifetime, &seconds);

        /* Check what services we have been granted. Cancel the local requests
	   bit, set the peer granted bit and delete the pending request. */
	/** @todo We are not storing the granted lifetime anywhere as we 
	    obviously should. */
	for(; i < type_count; i++) {
		
		switch(reg_types[i]) {
		case HIP_SERVICE_RENDEZVOUS:
		{
			HIP_DEBUG("The server has granted us rendezvous "\
				  "service for %u seconds (lifetime 0x%x.)\n",
				  seconds, lifetime);
			hip_hadb_cancel_local_controls(
				entry, HIP_HA_CTRL_LOCAL_REQ_RVS); 
			hip_hadb_set_peer_controls(
				entry, HIP_HA_CTRL_PEER_GRANTED_RVS); 
			hip_del_pending_request_by_type(
				entry, HIP_SERVICE_RENDEZVOUS);
			break;
		}
		case HIP_SERVICE_RELAY:
		{
			HIP_DEBUG("The server has granted us relay "\
				  "service for %u seconds (lifetime 0x%x.)\n",
				  seconds, lifetime);
			hip_hadb_cancel_local_controls(
				entry, HIP_HA_CTRL_LOCAL_REQ_RELAY); 
			hip_hadb_set_peer_controls(
				entry, HIP_HA_CTRL_PEER_GRANTED_RELAY); 
			hip_del_pending_request_by_type(
				entry, HIP_SERVICE_RELAY);

			break;
		}
		case HIP_SERVICE_ESCROW:
		{
			HIP_KEA *kea = NULL;
			
			HIP_DEBUG("The server has granted us escrow "\
				  "service for %u seconds (lifetime 0x%x.)\n",
				  seconds, lifetime);
			hip_hadb_cancel_local_controls(
				entry, HIP_HA_CTRL_LOCAL_REQ_ESCROW); 
			hip_hadb_set_peer_controls(
				entry, HIP_HA_CTRL_PEER_GRANTED_ESCROW); 
			hip_del_pending_request_by_type(
				entry, HIP_SERVICE_ESCROW);
			/* Not tested to work. Just moved here from an old
			   registration implementation. */
			if((kea = hip_kea_find(&entry->hit_our) ) != NULL) {
				kea->keastate = HIP_KEASTATE_VALID;
				hip_keadb_put_entry(kea);
			}

			break;
		} 
                case HIP_SERVICE_SAVAH:
		{
		        HIP_DEBUG("The server has granted us savah "\
				  "service for %u seconds (lifetime 0x%x.)\n",
				  seconds, lifetime);
			hip_hadb_cancel_local_controls(
				entry, HIP_HA_CTRL_LOCAL_REQ_SAVAH); 
			hip_hadb_set_peer_controls(
				entry, HIP_HA_CTRL_PEER_GRANTED_SAVAH); 
			hip_del_pending_request_by_type(
				entry, HIP_SERVICE_SAVAH);
		        break;
		}
		default:
		{
			HIP_DEBUG("The server has granted us an unknown "\
				  "service for %u seconds (lifetime 0x%x.)\n",
				  seconds, lifetime);
			hip_hadb_cancel_local_controls(
				entry, HIP_HA_CTRL_LOCAL_REQ_UNSUP); 
			hip_hadb_set_peer_controls(
				entry, HIP_HA_CTRL_PEER_GRANTED_UNSUP); 
			hip_del_pending_request_by_type(
				entry, reg_types[i]);
			break;
		}
		}
	}
	
 out_err:
	
	return 0;
}

int hip_del_registration_client(hip_ha_t *entry, uint8_t *reg_types,
				int type_count)
{
	int err = 0, i = 0;
	
        /* Check what service registration cancellations we have been granted.
	   Cancel the local requests and delete the pending request. */
	/** @todo We are not storing information about cancellation anywhere. */
	for(; i < type_count; i++) {
		
		switch(reg_types[i]) {
		case HIP_SERVICE_RENDEZVOUS:
		{
			HIP_DEBUG("The server has cancelled our rendezvous "\
				  "service.\n");
			hip_hadb_cancel_local_controls(
				entry, HIP_HA_CTRL_LOCAL_REQ_RVS); 
			hip_del_pending_request_by_type(
				entry, HIP_SERVICE_RENDEZVOUS);
			break;
		}
		case HIP_SERVICE_RELAY:
		{
			HIP_DEBUG("The server has cancelled our relay "\
				  "service.\n");
			hip_hadb_cancel_local_controls(
				entry, HIP_HA_CTRL_LOCAL_REQ_RELAY); 
			hip_del_pending_request_by_type(
				entry, HIP_SERVICE_RELAY);

			break;
		}
		case HIP_SERVICE_ESCROW:
		{
			HIP_DEBUG("The server has cancelled our escrow "\
				  "service.\n");
			hip_hadb_cancel_local_controls(
				entry, HIP_HA_CTRL_LOCAL_REQ_ESCROW); 
			hip_del_pending_request_by_type(
				entry, HIP_SERVICE_ESCROW);
			
			break;
		}
		case HIP_SERVICE_SAVAH:
		{
			HIP_DEBUG("The server has cancelled our savah "\
				  "service.\n");
			hip_hadb_cancel_local_controls(
				entry, HIP_HA_CTRL_LOCAL_REQ_SAVAH); 
			hip_del_pending_request_by_type(
				entry, HIP_SERVICE_SAVAH);
			
			break;
		}
		default:
		{
			HIP_DEBUG("The server has cancelled our registration "\
				  "to an unknown service.\n");
			break;
		}
		}
	}
	
 out_err:
	
	return 0;
}

int hip_has_duplicate_services(uint8_t *reg_types, int type_count)
{
	if(reg_types == NULL || type_count <= 0) {
		return -1;
	}
	
	int i = 0, j = 0;

	for(; i < type_count; i++) {
		for(j = i + 1; j < type_count; j++) {
			if(reg_types[i] == reg_types[j]) {
				return -1;
			}
		}
	}

	return 0;
}

int hip_get_registration_failure_string(uint8_t failure_type,
					char *type_string) {
	if(type_string == NULL)
		return -1;
	
	switch (failure_type) {
	case HIP_REG_INSUFFICIENT_CREDENTIALS:
		memcpy(type_string,
		       "Registration requires additional credentials.",
		       sizeof("Registration requires additional credentials."));
		break;
	case HIP_REG_TYPE_UNAVAILABLE:
		memcpy(type_string, "Registration type unavailable.",
		       sizeof("Registration type unavailable."));
		break;
	case HIP_REG_CANCEL_REQUIRED:
		memcpy(type_string,
		       "Cancellation of a previously granted service is "\
		       "required.",
		       sizeof("Cancellation of a previously granted service "\
			      "is required."));
		break;
	case HIP_REG_TRANSIENT_CONDITIONS:
		memcpy(type_string,
		       "The server is currently unable to provide services "\
		       "due to transient conditions.",
		       sizeof("The server is currently unable to provide services "\
			      "due to transient conditions."));
		break;
	default:
		memcpy(type_string, "Unknown failure type.",
		       sizeof("Unknown failure type."));
		break;
	}
	
	return 0;
}

// add by santtu from here
/* 
   Why is this not named consistelty with other parameterhandlers? Why is it not
   hip_handle_param_reg_from? We have a naming convetion in use...
   -Lauri 22.07.2008
*/
int hip_handle_reg_from(hip_ha_t *entry, struct hip_common *msg){
	int err = 0;
	uint8_t lifetime = 0;
	struct hip_reg_from *rfrom = NULL;
        
	HIP_DEBUG("Checking msg for REG_FROM parameter.\n");
	rfrom = hip_get_param(msg, HIP_PARAM_REG_FROM);
	
	if(rfrom != NULL) {
		HIP_DEBUG("received a for REG_FROM parameter \n");
		HIP_DEBUG_IN6ADDR("the received reg_from address is ", &rfrom->address);
		HIP_DEBUG_IN6ADDR("the local address is ", &entry->our_addr);
		//check if it is a local address
		if(!ipv6_addr_cmp(&rfrom->address,&entry->our_addr) ) {
			HIP_DEBUG("the host is not behind nat \n");
		} else {
			_HIP_DEBUG("found a nat @port %d \n ", ntohs(rfrom->port));
			memcpy(&entry->local_reflexive_address,rfrom->address,sizeof(struct in6_addr) );
			entry->local_reflexive_udp_port = ntohs(rfrom->port);
			HIP_DEBUG_HIT("set reflexive address:", &entry->local_reflexive_address);
			HIP_DEBUG("set reflexive port: %d \n", entry->local_reflexive_udp_port);
			_HIP_DEBUG("the entry address is %d \n", entry);
		}
	} else {
		err = 1;
	}
		
 out_err:
	return err;
     
}
