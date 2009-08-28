/** @file
 * This file defines handling functions for incoming packets for the Host
 * Identity Protocol (HIP).
 *
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author  Anthony D. Joseph
 * @author  Bing Zhou
 * @author  Tobias Heer
 * @author  Laura Takkinen (blind code)
 * @author  Rene Hummen
 * @author  Samu Varjonen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note    Doxygen comments for functions are now in the header file.
 *          Lauri 19.09.2007
 */
#include "input.h"
#include "pjnath.h"

#ifndef s6_addr
#  define s6_addr                 in6_u.u6_addr8
#  define s6_addr16               in6_u.u6_addr16
#  define s6_addr32               in6_u.u6_addr32
#endif /* s6_addr */

#ifdef CONFIG_HIP_OPPORTUNISTIC
extern unsigned int opportunistic_mode;
#endif

/** A function set for NAT travelsal. */
extern hip_xmit_func_set_t nat_xmit_func_set;
extern int hip_build_param_esp_info(struct hip_common *msg,
				    uint16_t keymat_index, uint32_t old_spi,
				    uint32_t new_spi);

/** @note Fix the packet len before calling this function! */
static int hip_verify_hmac(struct hip_common *buffer, uint16_t buf_len,
			   u8 *hmac, void *hmac_key, int hmac_type)
{
	int err = 0;
	u8 hmac_res[HIP_AH_SHA_LEN];

	HIP_HEXDUMP("HMAC data", buffer, buf_len);

	HIP_IFEL(hip_write_hmac(hmac_type, hmac_key, buffer,
				buf_len, hmac_res),
		 -EINVAL, "Could not build hmac\n");

	HIP_HEXDUMP("HMAC", hmac_res, HIP_AH_SHA_LEN);
	HIP_IFE(memcmp(hmac_res, hmac, HIP_AH_SHA_LEN), -EINVAL);

 out_err:

	return err;
}

//add by santtu
int hip_verify_packet_hmac_general(struct hip_common *msg,
				   struct hip_crypto_key *crypto_key,
				   hip_tlv_type_t parameter_type)
{
	int err = 0, len = 0, orig_len = 0;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac = NULL;
	u8 orig_checksum = 0;

	HIP_DEBUG("hip_verify_packet_hmac() invoked.\n");

	HIP_IFEL(!(hmac = hip_get_param(msg, parameter_type)),
		 -ENOMSG, "No HMAC parameter\n");

	/* hmac verification modifies the msg length temporarily, so we have
	   to restore the length */
	orig_len = hip_get_msg_total_len(msg);

	/* hmac verification assumes that checksum is zero */
	orig_checksum = hip_get_msg_checksum(msg);
	hip_zero_msg_checksum(msg);

	len = (u8 *) hmac - (u8*) msg;
	hip_set_msg_total_len(msg, len);

	_HIP_HEXDUMP("HMAC key", crypto_key->key,
		    hip_hmac_key_length(HIP_ESP_AES_SHA1));
	_HIP_HEXDUMP("HMACced data:", msg, len);

	memcpy(&tmpkey, crypto_key, sizeof(tmpkey));
	HIP_IFEL(hip_verify_hmac(msg, hip_get_msg_total_len(msg),
				 hmac->hmac_data, tmpkey.key,
				 HIP_DIGEST_SHA1_HMAC),
		 -1, "HMAC validation failed\n");

	/* revert the changes to the packet */
	hip_set_msg_total_len(msg, orig_len);
	hip_set_msg_checksum(msg, orig_checksum);

 out_err:
	return err;
}
//end add

int hip_verify_packet_hmac(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key)
{
	return hip_verify_packet_hmac_general(msg, crypto_key, HIP_PARAM_HMAC);
}

int hip_verify_packet_rvs_hmac(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key)
{
	return hip_verify_packet_hmac_general(msg, crypto_key,
					      HIP_PARAM_RVS_HMAC);
}

int hip_verify_packet_hmac2(struct hip_common *msg,
			    struct hip_crypto_key *key,
			    struct hip_host_id *host_id)
{
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;
	struct hip_common *msg_copy = NULL;
	int err = 0;

	_HIP_DEBUG("hip_verify_packet_hmac2() invoked.\n");
	HIP_IFE(!(msg_copy = hip_msg_alloc()), -ENOMEM);

	HIP_IFEL(hip_create_msg_pseudo_hmac2(msg, msg_copy, host_id), -1,
		"Pseudo hmac2 pkt failed\n");

	HIP_IFEL(!(hmac = hip_get_param(msg, HIP_PARAM_HMAC2)), -ENOMSG,
		 "Packet contained no HMAC parameter\n");
	HIP_HEXDUMP("HMAC data", msg_copy, hip_get_msg_total_len(msg_copy));
	memcpy(&tmpkey, key, sizeof(key));

	HIP_IFEL(hip_verify_hmac(msg_copy, hip_get_msg_total_len(msg_copy),
				 hmac->hmac_data, tmpkey.key,
				 HIP_DIGEST_SHA1_HMAC),
		-1, "HMAC validation failed\n");

 out_err:
	if (msg_copy)
		HIP_FREE(msg_copy);

	return err;
}

int hip_produce_keying_material(struct hip_common *msg, struct hip_context *ctx,
				uint64_t I, uint64_t J,
				struct hip_dh_public_value **dhpv)
{
	char *dh_shared_key = NULL;
	int hip_transf_length, hmac_transf_length;
	int auth_transf_length, esp_transf_length, we_are_HITg = 0;
	int hip_tfm, esp_tfm, err = 0, dh_shared_len = 1024;
	struct hip_keymat_keymat km;
	struct hip_esp_info *esp_info;
	char *keymat = NULL;
	size_t keymat_len_min; /* how many bytes we need at least for the KEYMAT */
	size_t keymat_len; /* note SHA boundary */
	struct hip_tlv_common *param = NULL;
	uint16_t esp_keymat_index, esp_default_keymat_index;
	struct hip_diffie_hellman *dhf;
	hip_ha_t *blind_entry;
	int type = 0;
	uint16_t nonce;
	struct in6_addr *plain_local_hit = NULL;

	_HIP_DEBUG("hip_produce_keying_material() invoked.\n");
	/* Perform light operations first before allocating memory or
	 * using lots of CPU time */
	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_HIP_TRANSFORM)),
		 -EINVAL,
		 "Could not find HIP transform\n");
	HIP_IFEL((hip_tfm = hip_select_hip_transform((struct hip_hip_transform *) param)) == 0,
		 -EINVAL, "Could not select HIP transform\n");
	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_ESP_TRANSFORM)),
		 -EINVAL,
		 "Could not find ESP transform\n");
	HIP_IFEL((esp_tfm = hip_select_esp_transform((struct hip_esp_transform *) param)) == 0,
		 -EINVAL, "Could not select proper ESP transform\n");

	hip_transf_length = hip_transform_key_length(hip_tfm);
	hmac_transf_length = hip_hmac_key_length(esp_tfm);
	esp_transf_length = hip_enc_key_length(esp_tfm);
	auth_transf_length = hip_auth_key_length_esp(esp_tfm);

	HIP_DEBUG("Transform lengths are:\n"\
		  "\tHIP = %d, HMAC = %d, ESP = %d, auth = %d\n",
		  hip_transf_length, hmac_transf_length, esp_transf_length,
		  auth_transf_length);

	HIP_DEBUG("I and J values from the puzzle and its solution are:\n"\
		  "\tI = 0x%llx\n\tJ = 0x%llx\n", I, J);

	/* Create only minumum amount of KEYMAT for now. From draft chapter
	   HIP KEYMAT we know how many bytes we need for all keys used in the
	   base exchange. */
	keymat_len_min = hip_transf_length + hmac_transf_length +
		hip_transf_length + hmac_transf_length + esp_transf_length +
		auth_transf_length + esp_transf_length + auth_transf_length;

	if (ctx->use_ice)
		keymat_len_min += auth_transf_length;

	/* Assume ESP keys are after authentication keys */
	esp_default_keymat_index = hip_transf_length + hmac_transf_length +
		hip_transf_length + hmac_transf_length;

	/* R1 contains no ESP_INFO */
	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);

	if (esp_info != NULL){
		esp_keymat_index = ntohs(esp_info->keymat_index);
	} else {
		esp_keymat_index = esp_default_keymat_index;
	}

	if (esp_keymat_index != esp_default_keymat_index) {
		/** @todo Add support for keying material. */
		HIP_ERROR("Varying keying material slices are not supported "\
			  "yet.\n");
		err = -1;
		goto out_err;
	}

	keymat_len = keymat_len_min;

	if (keymat_len % HIP_AH_SHA_LEN) {
		keymat_len += HIP_AH_SHA_LEN - (keymat_len % HIP_AH_SHA_LEN);
	}

	HIP_DEBUG("Keying material:\n\tminimum length = %u\n\t"\
		  "keying material length = %u.\n", keymat_len_min, keymat_len);

	HIP_IFEL(!(keymat = HIP_MALLOC(keymat_len, GFP_KERNEL)), -ENOMEM,
		 "Error on allocating memory for keying material.\n");

	/* 1024 should be enough for shared secret. The length of the shared
	   secret actually depends on the DH Group. */
	/** @todo 1024 -> hip_get_dh_size ? */
	HIP_IFEL(!(dh_shared_key = HIP_MALLOC(dh_shared_len, GFP_KERNEL)),
		 -ENOMEM,
		 "Error on allocating memory for Diffie-Hellman shared key.\n");

	memset(dh_shared_key, 0, dh_shared_len);

	HIP_IFEL(!(dhf = (struct hip_diffie_hellman*)hip_get_param(
			   msg, HIP_PARAM_DIFFIE_HELLMAN)),
		 -ENOENT,  "No Diffie-Hellman parameter found.\n");

	/* If the message has two DH keys, select (the stronger, usually) one. */
	*dhpv = hip_dh_select_key(dhf);

	_HIP_DEBUG("dhpv->group_id= %d\n",(*dhpv)->group_id);
	_HIP_DEBUG("dhpv->pub_len= %d\n", ntohs((*dhpv)->pub_len));

	HIP_IFEL((dh_shared_len = hip_calculate_shared_secret(
			  (*dhpv)->public_value, (*dhpv)->group_id,
			  ntohs((*dhpv)->pub_len), dh_shared_key,
			  dh_shared_len)) < 0,
		 -EINVAL, "Calculation of shared secret failed.\n");

	_HIP_HEXDUMP("Diffie-Hellman shared parameter:\n", param,
		    hip_get_param_total_len(param));
	_HIP_HEXDUMP("Diffie-Hellman shared key:\n", dh_shared_key,
		     dh_shared_len);

#ifdef CONFIG_HIP_BLIND
	HIP_DEBUG_HIT("key_material msg->hits (responder)", &msg->hits);
	HIP_DEBUG_HIT("key_material msg->hitr (local)", &msg->hitr);

	if (hip_blind_get_status()) {
		type = hip_get_msg_type(msg);

	  /* Initiator produces keying material for I2:
	   * uses own blinded hit and plain initiator hit
	   */
	  if (type == HIP_R1) {
		  if((blind_entry =
		      hip_hadb_find_by_blind_hits(&msg->hitr, &msg->hits))
		     == NULL){
			  err = -1;
			  HIP_ERROR("Could not found blinded hip_ha_t entry\n");
			  goto out_err;
		  }
		  hip_make_keymat(dh_shared_key, dh_shared_len,
				  &km, keymat, keymat_len,
				  &blind_entry->hit_peer, &msg->hitr,
				  &ctx->keymat_calc_index, I, J);
	  }
	  /* Responder produces keying material for handling I2:
	   * uses own plain hit and blinded initiator hit */
	  else if (type == HIP_I2) {
	    HIP_IFEL((plain_local_hit = HIP_MALLOC(sizeof(struct in6_addr), 0)) == NULL,
		     -1, "Couldn't allocate memory\n");
	    HIP_IFEL(hip_blind_get_nonce(msg, &nonce), -1, "hip_blind_get_nonce failed\n");
	    HIP_IFEL(hip_plain_fingerprint(&nonce, &msg->hitr, plain_local_hit),
		     -1, "hip_plain_fingerprint failed\n");
	    HIP_DEBUG_HIT("plain_local_hit for handling I2", plain_local_hit);
	    hip_make_keymat(dh_shared_key, dh_shared_len,
			    &km, keymat, keymat_len,
			    &msg->hits, plain_local_hit, &ctx->keymat_calc_index, I, J);
	  }
	}
#endif
	if (!hip_blind_get_status()) {
	  hip_make_keymat(dh_shared_key, dh_shared_len,
			  &km, keymat, keymat_len,
			  &msg->hits, &msg->hitr, &ctx->keymat_calc_index, I, J);
	}

	/* draw from km to keymat, copy keymat to dst, length of
	 * keymat is len */

	we_are_HITg = hip_hit_is_bigger(&msg->hitr, &msg->hits);
	HIP_DEBUG("We are %s HIT.\n", we_are_HITg ? "greater" : "lesser");

	if (we_are_HITg) {
		hip_keymat_draw_and_copy(ctx->hip_enc_out.key, &km,
					 hip_transf_length);
		hip_keymat_draw_and_copy(ctx->hip_hmac_out.key, &km,
					 hmac_transf_length);
		hip_keymat_draw_and_copy(ctx->hip_enc_in.key, &km,
					 hip_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_hmac_in.key, &km,
					 hmac_transf_length);
		hip_keymat_draw_and_copy(ctx->esp_out.key, &km,
					 esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_out.key, &km,
					 auth_transf_length);
 		hip_keymat_draw_and_copy(ctx->esp_in.key, &km,
					 esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_in.key, &km,
					 auth_transf_length);
		if (ctx->use_ice)
			hip_keymat_draw_and_copy(ctx->hip_nat_key, &km,
						 auth_transf_length);
 	} else {
 	 	hip_keymat_draw_and_copy(ctx->hip_enc_in.key, &km,
					 hip_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_hmac_in.key, &km,
					 hmac_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_enc_out.key, &km,
					 hip_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_hmac_out.key, &km,
					 hmac_transf_length);
 		hip_keymat_draw_and_copy(ctx->esp_in.key, &km,
					 esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_in.key, &km,
					 auth_transf_length);
 		hip_keymat_draw_and_copy(ctx->esp_out.key, &km,
					 esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_out.key, &km,
					 auth_transf_length);
		if (ctx->use_ice)
			hip_keymat_draw_and_copy(ctx->hip_nat_key, &km,
						 auth_transf_length);
 	}
 	HIP_HEXDUMP("HIP-gl encryption:", &ctx->hip_enc_out.key,
		    hip_transf_length);
 	HIP_HEXDUMP("HIP-gl integrity (HMAC) key:", &ctx->hip_hmac_out.key,
 		    hmac_transf_length);
 	_HIP_DEBUG("skipping HIP-lg encryption key, %u bytes\n",
		   hip_transf_length);
	HIP_HEXDUMP("HIP-lg encryption:", &ctx->hip_enc_in.key,
		    hip_transf_length);
 	HIP_HEXDUMP("HIP-lg integrity (HMAC) key:", &ctx->hip_hmac_in.key,
		    hmac_transf_length);
 	HIP_HEXDUMP("SA-gl ESP encryption key:", &ctx->esp_out.key,
		    esp_transf_length);
 	HIP_HEXDUMP("SA-gl ESP authentication key:", &ctx->auth_out.key,
		    auth_transf_length);
 	HIP_HEXDUMP("SA-lg ESP encryption key:", &ctx->esp_in.key,
		    esp_transf_length);
 	HIP_HEXDUMP("SA-lg ESP authentication key:", &ctx->auth_in.key,
		    auth_transf_length);
 	HIP_HEXDUMP("hip nat key:", &ctx->hip_nat_key,
		    auth_transf_length);

	/* the next byte when creating new keymat */
	ctx->current_keymat_index = keymat_len_min; /* offset value, so no +1 ? */
	ctx->keymat_calc_index = (ctx->current_keymat_index / HIP_AH_SHA_LEN) + 1;
	ctx->esp_keymat_index = esp_keymat_index;

	memcpy(ctx->current_keymat_K, keymat +(ctx->keymat_calc_index-1)*HIP_AH_SHA_LEN, HIP_AH_SHA_LEN);

	_HIP_DEBUG("ctx: keymat_calc_index=%u current_keymat_index=%u\n",
		   ctx->keymat_calc_index, ctx->current_keymat_index);
	_HIP_HEXDUMP("CTX CURRENT KEYMAT", ctx->current_keymat_K,
		     HIP_AH_SHA_LEN);

	/* store DH shared key */
	ctx->dh_shared_key = dh_shared_key;
	ctx->dh_shared_key_len = dh_shared_len;

	/* on success HIP_FREE for dh_shared_key is called by caller */
 out_err:
	if (err && dh_shared_key)
		HIP_FREE(dh_shared_key);
	if (keymat)
		HIP_FREE(keymat);
	if (plain_local_hit)
		HIP_FREE(plain_local_hit);
	return err;
}


/**
 * Drops a packet if necessary.
 *
 *
 * @param entry   host association entry
 * @param type    type of the packet
 * @param hitr    HIT of the destination
 *
 * @return        1 if the packet should be dropped, zero if the packet 
 *                shouldn't be dropped
 */
int hip_packet_to_drop(hip_ha_t *entry, hip_hdr_type_t type, struct in6_addr *hitr)
{
    // If we are a relay or rendezvous server, don't drop the packet
    if (!hip_hidb_hit_is_our(hitr))
        return 0;

    switch (entry->state)
    {
    case HIP_STATE_I2_SENT:
        // Here we handle the "shotgun" case. We only accept the first valid R1
        // arrived and ignore all the rest.
        HIP_DEBUG("Number of items in the addresses list: %d ", addresses->num_items);
        HIP_DEBUG("Number of items in the peer addr list: %d ", entry->peer_addr_list_to_be_added->num_items);
        if (hip_shotgun_status == SO_HIP_SHOTGUN_ON
            && type == HIP_R1
            && (entry->peer_addr_list_to_be_added->num_items > 1 || addresses->num_items > 1))
            return 1;
        break;
    case HIP_STATE_R2_SENT:
        if (type == HIP_R1 || type == HIP_R2)
            return 1;
    case HIP_STATE_ESTABLISHED:
        if (type == HIP_R1 || type == HIP_R2)
            return 1;
    }

    return 0;
}

int hip_receive_control_packet(struct hip_common *msg,
			       struct in6_addr *src_addr,
			       struct in6_addr *dst_addr,
	                       hip_portpair_t *msg_info,
                               int filter)
{
	hip_ha_t tmp, *entry = NULL;
	int err = 0, type, skip_sync = 0;

	/* Debug printing of received packet information. All received HIP
	   control packets are first passed to this function. Therefore
	   printing packet data here works for all packets. To avoid excessive
	   debug printing do not print this information inside the individual
	   receive or handle functions. */
	_HIP_DEBUG("hip_receive_control_packet() invoked.\n");
	HIP_DEBUG_IN6ADDR("Source IP", src_addr);
	HIP_DEBUG_IN6ADDR("Destination IP", dst_addr);
	HIP_DEBUG_HIT("HIT Sender", &msg->hits);
	HIP_DEBUG_HIT("HIT Receiver", &msg->hitr);
	HIP_DEBUG("source port: %u, destination port: %u\n",
		  msg_info->src_port, msg_info->dst_port);
	HIP_DUMP_MSG(msg);

//add by santtu
#if 0
	type = hip_get_msg_type(msg);
	entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	if(type == HIP_UPDATE && entry){
		hip_external_ice_receive_pkt(msg+1,msg->payload_len,entry,src_addr,msg_info->src_port);
	}
#endif
//end add

	HIP_IFEL(hip_check_network_msg(msg), -1,
		 "checking control message failed\n", -1);

	type = hip_get_msg_type(msg);

	/** @todo Check packet csum.*/

	entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

        // Check if we need to drop the packet
        if (entry && hip_packet_to_drop(entry, type, &msg->hitr) == 1)
        {
            HIP_DEBUG("Ignoring the packet sent \n");
            goto out_err;
        }

#ifdef CONFIG_HIP_OPPORTUNISTIC
	if (!entry && opportunistic_mode &&
	    (type == HIP_I1 || type == HIP_R1)) {
		entry = hip_oppdb_get_hadb_entry_i1_r1(msg, src_addr,
						       dst_addr,
						       msg_info);
		/* If agent is prompting user, let's make sure that
		   the death counter in maintenance does not expire */
		if (hip_agent_is_alive() && entry)
		    entry->hip_opp_fallback_disable = filter;
	} else {
		/* Ugly bug fix for "conntest-client hostname tcp 12345"
		   where hostname maps to HIT and IP in hosts files.
		   Why the heck the receive function points here to
		   receive_opp_r1 even though we have a regular entry? */

	     /* What is the point of having receive function pointer anyways?
		Not to mention a SET of them... */
		if (entry)
			entry->hadb_rcv_func->hip_receive_r1 = hip_receive_r1;
	}
#endif

#ifdef CONFIG_HIP_AGENT
	/** Filter packet trough agent here. */
	if ((type == HIP_I1 || type == HIP_R1) && filter)
	{
		HIP_DEBUG("Filtering packet trough agent now (packet is %s).\n",
		          type == HIP_I1 ? "I1" : "R1");
		err = hip_agent_filter(msg, src_addr, dst_addr, msg_info);
		/* If packet filtering OK, return and wait for agent reply. */
		if (err == 0) goto out_err;
	}
#endif

#ifdef CONFIG_HIP_BLIND
	HIP_DEBUG("Blind block\n");
	// Packet that was received is blinded
	if (ntohs(msg->control) & HIP_PACKET_CTRL_BLIND) {
	  HIP_DEBUG("Message is blinded\n");
	  if(type == HIP_I1) { //Responder receives
	    HIP_DEBUG("set_blind_on\n");
	    // Activate blind mode
	    hip_set_blind_on();
	  } else if (type == HIP_R1 || // Initiator receives
		     type == HIP_I2 || // Responder receives
		     type == HIP_R2) { // Initiator receives
	    if (hip_blind_get_status())
	      entry = hip_hadb_find_by_blind_hits(&msg->hitr, &msg->hits);
	    else {
	      HIP_ERROR("Blinded packet %d received, but blind is not activated, drop packet\n", type);
	      err = -ENOSYS;
	      goto out_err;
	    }
	  } else {
	    //BLIND TODO: UPDATE, NOTIFY...
	  }
	} else {
	     if(hip_blind_get_status()) {
               HIP_ERROR("Blind mode is on, but we received plain packet %d, drop packet\n", type);
               err = -ENOSYS;
               goto out_err;
             }
        }
	/* fetch the state from the hadb database to be able to choose the
	   appropriate message handling functions */
	if (!(ntohs(msg->control) & HIP_PACKET_CTRL_BLIND)) { // Normal packet received
	    entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	}
#endif
//add by santtu
#ifdef CONFIG_HIP_RVS
	//check if it a relaying msg

	//add by santtu
	//if(hip_relay_handle_relay_to(msg, type, src_addr, dst_addr, msg_info)){

	if(hip_relay_handle_relay_to(msg, type, src_addr, dst_addr, msg_info)){
	//end
		err = -ECANCELED;
		goto out_err;
	}
	else{
		HIP_DEBUG("handle relay to failed, continue the bex handler\n");
	}
#endif
//end add

	switch(type) {
	case HIP_DATA:
	case HIP_I1:
		/* No state. */
	  HIP_DEBUG("Received HIP_I1 message\n");
	  err = (hip_get_rcv_default_func_set())->hip_receive_i1(msg, src_addr,
								 dst_addr,
								 entry,
								 msg_info);
	  break;

	case HIP_I2:
		/* Possibly state. */
		if(entry){
		     err = entry->hadb_rcv_func->
			  hip_receive_i2(msg, src_addr, dst_addr, entry,
					 msg_info);
		} else {
			err = ((hip_rcv_func_set_t *)
			       hip_get_rcv_default_func_set())->
				hip_receive_i2(msg, src_addr, dst_addr, entry,
					       msg_info);
		}
		break;

	case HIP_R1:
	  	/* State. */
	        HIP_IFEL(!entry, -1, "No entry when receiving R1\n");
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_r1(msg, src_addr, dst_addr, entry,
					msg_info));
		break;

	case HIP_R2:
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_r2(msg, src_addr, dst_addr, entry,
					msg_info));
		//HIP_STOP_TIMER(KMM_GLOBAL,"Base Exchange");
		break;

	case HIP_UPDATE:
		HIP_DEBUG_HIT("received an UPDATE:  " ,src_addr );
		if(entry){
			HIP_IFCS(entry, err = entry->hadb_rcv_func->
				 hip_receive_update(msg, src_addr, dst_addr, entry,
						    msg_info));
		}
		//add the santtu
		/**to support stun from firewall**/
		else{
			HIP_DEBUG("FOUND A UPDATE FROM FIREWALL \n");
			hip_receive_update(msg, src_addr, dst_addr, entry,
				    msg_info);
		}
		//end add
		break;

	case HIP_NOTIFY:
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_notify(msg, src_addr, dst_addr, entry));
		break;

	case HIP_BOS:
	     HIP_IFCS(entry, err = entry->hadb_rcv_func->
		      hip_receive_bos(msg, src_addr, dst_addr, entry,
				      msg_info));

	     /*In case of BOS the msg->hitr is null, therefore it is replaced
	       with our own HIT, so that the beet state can also be
	       synchronized. */

	     ipv6_addr_copy(&tmp.hit_peer, &msg->hits);
	     hip_init_us(&tmp, NULL);
	     ipv6_addr_copy(&msg->hitr, &tmp.hit_our);
	     skip_sync = 0;
	     break;
	case HIP_CLOSE:
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_close(msg, entry));
		break;

	case HIP_CLOSE_ACK:
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_close_ack(msg, entry));
		break;
	case HIP_LUPDATE:
		HIP_IFCS(entry, err = esp_prot_receive_light_update(msg, src_addr, dst_addr,
				entry));
		break;

	default:
		HIP_ERROR("Unknown packet %d\n", type);
		err = -ENOSYS;
	}

	HIP_DEBUG("Done with control packet, err is %d.\n", err);

	if (err)
		goto out_err;

out_err:

	return err;
}

int hip_receive_udp_control_packet(struct hip_common *msg,
				   struct in6_addr *saddr,
				   struct in6_addr *daddr,
				   hip_portpair_t *info)
{
        hip_ha_t *entry;
        int err = 0, type, skip_sync = 0;
	struct in6_addr *saddr_public = saddr;

	_HIP_DEBUG("hip_nat_receive_udp_control_packet() invoked.\n");

        type = hip_get_msg_type(msg);
        entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

#ifndef CONFIG_HIP_RVS
	/* The ip of RVS is taken to be ip of the peer while using RVS server
	   to relay R1. Hence have removed this part for RVS --Abi */
	if (entry && (type == HIP_R1 || type == HIP_R2)) {
		/* When the responder equals to the NAT host, it can reply from
		   the private address instead of the public address. In this
		   case, the saddr will point to the private address, and using
		   it for I2 will fail the puzzle indexing (I1 was sent to the
		   public address). So, we make sure here that we're using the
		   same dst address for the I2 as for I1. Also, this address is
		   used for setting up the SAs: handle_r1 creates one-way SA and
		   handle_i2 the other way; let's make sure that they are the
		   same. */
		saddr_public = &entry->peer_addr;
	}
#endif
	HIP_IFEL(hip_receive_control_packet(msg, saddr_public, daddr,info,1), -1,
		 "receiving of control packet failed\n");
 out_err:
	return err;
}

int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle,
		  in6_addr_t *r1_saddr, in6_addr_t *r1_daddr, hip_ha_t *entry,
	          hip_portpair_t *r1_info, struct hip_dh_public_value *dhpv)
{

	hip_transform_suite_t transform_hip_suite, transform_esp_suite;
	struct hip_spi_in_item spi_in_data;
	in6_addr_t daddr;
	struct hip_param *param = NULL;
	struct hip_diffie_hellman *dh_req = NULL;
	struct hip_esp_info *esp_info = NULL;
	struct hip_host_id_entry *host_id_entry = NULL;
	hip_common_t *i2 = NULL;
	char *enc_in_msg = NULL, *host_id_in_enc = NULL;
	unsigned char *iv = NULL;
	int err = 0, host_id_in_enc_len = 0, written = 0;
	uint16_t mask = 0;
	int type_count = 0, request_rvs = 0, request_escrow = 0;
        int *reg_type = NULL;
	uint32_t spi_in = 0;
	struct hip_nat_transform *nat_tfm = NULL;
	hip_transform_suite_t nat_suite;

	_HIP_DEBUG("hip_create_i2() invoked.\n");

        HIP_DEBUG("R1 source port %u, destination port %d\n",
		  r1_info->src_port, r1_info->dst_port);

	HIP_ASSERT(entry);

	// creating inbound spi to be sent in I2
	get_random_bytes(&spi_in, sizeof(uint32_t));

	nat_suite = hip_get_nat_mode(entry);

	/* Allocate space for a new I2 message. */
	HIP_IFEL(!(i2 = hip_msg_alloc()), -ENOMEM, "Allocation of I2 failed\n");

	/* TLV sanity checks are are already done by the caller of this
	   function. Now, begin to build I2 piece by piece. */

	/* Delete old SPDs and SAs, if present */
	hip_hadb_delete_inbound_spi(entry, 0);
	hip_hadb_delete_outbound_spi(entry, 0);

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
		HIP_DEBUG("Build blinded I2\n");
		mask |= HIP_PACKET_CTRL_BLIND;
		// Build network header by using blinded HITs
		entry->hadb_misc_func->hip_build_network_hdr(
			i2, HIP_I2, mask, &entry->hit_our_blind,
			&entry->hit_peer_blind);
	}
#endif

	if (!hip_blind_get_status()) {
		HIP_DEBUG("Build normal I2.\n");
		/* create I2 */
		entry->hadb_misc_func->
			hip_build_network_hdr(i2, HIP_I2, mask, &(ctx->input->hitr),
					      &(ctx->input->hits));
	}

        /********** ESP_INFO **********/
	/* SPI is set below */
	HIP_IFEL(hip_build_param_esp_info(i2, ctx->esp_keymat_index, 0, 0),
		 -1, "building of ESP_INFO failed.\n");

	/********** R1 COUNTER (OPTIONAL) ********/
	/* we build this, if we have recorded some value (from previous R1s) */
	{
		uint64_t rtmp;

		HIP_LOCK_HA(entry);
		rtmp = entry->birthday;
		HIP_UNLOCK_HA(entry);

		HIP_IFEL(rtmp && hip_build_param_r1_counter(i2, rtmp), -1,
			 "Could not build R1 GENERATION parameter\n");
	}

	/********* LOCATOR PARAMETER ************/
        /** Type 193 **/
	/* Notice that locator building is excluded when Initiator prefers
	   ICE mode but Responder does not support it. This is a workaround
	   to the side effect of ICE turning the locators on (bug id 810) */
	HIP_DEBUG("Building LOCATOR parameter 	1\n");
        if (hip_locator_status == SO_HIP_SET_LOCATOR_ON &&
	    !(nat_suite == HIP_NAT_MODE_PLAIN_UDP &&
	      hip_get_nat_mode(entry) == HIP_NAT_MODE_ICE_UDP)) {
            HIP_DEBUG("Building LOCATOR parameter 2\n");
            if ((err = hip_build_locators(i2, spi_in, hip_get_nat_mode(entry))) < 0)
                HIP_DEBUG("LOCATOR parameter building failed\n");
        }


	/********** SOLUTION **********/
	{
		struct hip_puzzle *pz;

		HIP_IFEL(!(pz = hip_get_param(ctx->input, HIP_PARAM_PUZZLE)), -ENOENT,
			 "Internal error: PUZZLE parameter mysteriously gone\n");
		HIP_IFEL(hip_build_param_solution(i2, pz, ntoh64(solved_puzzle)), -1,
			 "Building of solution failed\n");
	}

	/********** Diffie-Hellman *********/
	HIP_IFEL(!(dh_req = hip_get_param(ctx->input, HIP_PARAM_DIFFIE_HELLMAN)),
		 -ENOENT, "Internal error\n");
	HIP_IFEL((written = hip_insert_dh(dhpv->public_value,
		 ntohs(dhpv->pub_len), dhpv->group_id)) < 0,
		 -1, "Could not extract the DH public key\n");

	HIP_IFEL(hip_build_param_diffie_hellman_contents(i2,
		 dhpv->group_id, dhpv->public_value, written,
		 HIP_MAX_DH_GROUP_ID, NULL, 0), -1,
		 "Building of DH failed.\n");

    /********** HIP transform. **********/
	HIP_IFE(!(param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM)), -ENOENT);
	HIP_IFEL((transform_hip_suite =
		  hip_select_hip_transform((struct hip_hip_transform *) param)) == 0,
		 -EINVAL, "Could not find acceptable hip transform suite\n");

	/* Select only one transform */
	HIP_IFEL(hip_build_param_transform(i2, HIP_PARAM_HIP_TRANSFORM,
					   &transform_hip_suite, 1), -1,
		 "Building of HIP transform failed\n");

	HIP_DEBUG("HIP transform: %d\n", transform_hip_suite);

       /*********** NAT parameters *******/
	
#ifdef HIP_USE_ICE
	HIP_DEBUG("nat control %d\n", hip_nat_get_control(entry));

        if (hip_get_param(ctx->input, HIP_PARAM_NAT_TRANSFORM) &&
	    nat_suite != HIP_NAT_MODE_NONE) {
		hip_build_param_nat_transform(i2, &nat_suite, 1);
		hip_build_param_nat_pacing(i2, HIP_NAT_PACING_DEFAULT);
	}
#endif
        
	/************ Encrypted ***********/
	if (hip_encrypt_i2_hi)
	{
		switch (transform_hip_suite) {
		case HIP_HIP_AES_SHA1:
			HIP_IFEL(hip_build_param_encrypted_aes_sha1(i2, (struct hip_tlv_common *)entry->our_pub),
				 -1, "Building of param encrypted failed.\n");
			enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
			HIP_ASSERT(enc_in_msg); /* Builder internal error. */
			iv = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
			get_random_bytes(iv, 16);
			host_id_in_enc = enc_in_msg +
				sizeof(struct hip_encrypted_aes_sha1);
			break;
		case HIP_HIP_3DES_SHA1:
			HIP_IFEL(hip_build_param_encrypted_3des_sha1(i2, (struct hip_tlv_common *)entry->our_pub),
				 -1, "Building of param encrypted failed.\n");
			enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
			HIP_ASSERT(enc_in_msg); /* Builder internal error. */
			iv = ((struct hip_encrypted_3des_sha1 *) enc_in_msg)->iv;
			get_random_bytes(iv, 8);
			host_id_in_enc = enc_in_msg +
				sizeof(struct hip_encrypted_3des_sha1);
			break;
		case HIP_HIP_NULL_SHA1:
			HIP_IFEL(hip_build_param_encrypted_null_sha1(i2, (struct hip_tlv_common *)entry->our_pub),
				 -1, "Building of param encrypted failed.\n");
			enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
			HIP_ASSERT(enc_in_msg); /* Builder internal error. */
			iv = NULL;
			host_id_in_enc = enc_in_msg +
				sizeof(struct hip_encrypted_null_sha1);
			break;
		default:
			HIP_IFEL(1, -ENOSYS, "HIP transform not supported (%d)\n",
				 transform_hip_suite);
		}
	} else /* add host id in plaintext without encrypted wrapper */ {
		hip_tlv_len_t hid_len;

		/* Parameter HOST_ID. Notice that hip_get_public_key overwrites
		   the argument pointer, so we have to allocate some extra memory */

		HIP_IFEL(!(host_id_entry = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID,
				&(ctx->input->hitr), HIP_ANY_ALGO, -1)), -1, "Unknown HIT\n");

		_HIP_DEBUG("This HOST ID belongs to: %s\n",
			   hip_get_param_host_id_hostname(host_id_entry->host_id));

		HIP_IFEL(hip_build_param(i2, host_id_entry->host_id), -1, "Building of host id failed\n");
	}

	/* REG_INFO parameter. This builds a REG_REQUEST parameter in the I2
	   packet. */
	hip_handle_param_reg_info(entry, ctx->input, i2);

	/********** ESP-ENC transform. **********/
	HIP_IFE(!(param = hip_get_param(ctx->input, HIP_PARAM_ESP_TRANSFORM)), -ENOENT);

	/* Select only one transform */
	HIP_IFEL((transform_esp_suite =
		  hip_select_esp_transform((struct hip_esp_transform *) param)) == 0,
		 -1, "Could not find acceptable hip transform suite\n");
	HIP_IFEL(hip_build_param_transform(i2, HIP_PARAM_ESP_TRANSFORM,
					   &transform_esp_suite, 1), -1,
		 "Building of ESP transform failed\n");

	/********** ESP-PROT anchor [OPTIONAL] **********/

	HIP_IFEL(esp_prot_i2_add_anchor(i2, entry, ctx), -1,
			"failed to add esp protection anchor\n");

	/************************************************/

	if (hip_encrypt_i2_hi)
	{
		HIP_HEXDUMP("enc(host_id)", host_id_in_enc,
				hip_get_param_total_len(host_id_in_enc));

		/* Calculate the length of the host id inside the encrypted param */
		host_id_in_enc_len = hip_get_param_total_len(host_id_in_enc);

		/* Adjust the host id length for AES (block size 16).
		   build_param_encrypted_aes has already taken care that there is
		   enough padding */
		if (transform_hip_suite == HIP_HIP_AES_SHA1) {
			int remainder = host_id_in_enc_len % 16;
			if (remainder) {
				HIP_DEBUG("Remainder %d (for AES)\n", remainder);
				host_id_in_enc_len += remainder;
			}
		}

		_HIP_HEXDUMP("hostidinmsg", host_id_in_enc,
				hip_get_param_total_len(host_id_in_enc));
		_HIP_HEXDUMP("encinmsg", enc_in_msg,
				hip_get_param_total_len(enc_in_msg));
		HIP_HEXDUMP("enc key", &ctx->hip_enc_out.key, HIP_MAX_KEY_LEN);
		_HIP_HEXDUMP("IV", iv, 16); // or 8
		HIP_DEBUG("host id type: %d\n",
			  hip_get_host_id_algo((struct hip_host_id *)host_id_in_enc));
		_HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);


		  HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv,
						transform_hip_suite,
						host_id_in_enc_len,
						&ctx->hip_enc_out.key,
						HIP_DIRECTION_ENCRYPT), -1,
			 "Building of param encrypted failed\n");

		_HIP_HEXDUMP("encinmsg 2", enc_in_msg,
				 hip_get_param_total_len(enc_in_msg));
		_HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);
	}

	/* Now that almost everything is set up except the signature, we can
	 * try to set up inbound IPsec SA, similarly as in hip_create_r2 */

	HIP_DEBUG("src %d, dst %d\n", r1_info->src_port, r1_info->dst_port);

        entry->local_udp_port = r1_info->src_port;
	entry->peer_udp_port = r1_info->dst_port;

	entry->hip_transform = transform_hip_suite;

	/* XXX: -EAGAIN */
	HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
	  HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(&entry->hit_peer,
					 &entry->hit_our,
					 r1_saddr, r1_daddr, IPPROTO_ESP, 1, 1), -1,
		   "Setting up SP pair failed\n");
	}
#endif
	if (!hip_blind_get_status()) {
	  HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(&ctx->input->hits,
					 &ctx->input->hitr,
					 r1_saddr, r1_daddr, IPPROTO_ESP, 1, 1), -1,
		   "Setting up SP pair failed\n");
	}

 	esp_info = hip_get_param(i2, HIP_PARAM_ESP_INFO);
 	HIP_ASSERT(esp_info); /* Builder internal error */
	esp_info->new_spi = htonl(spi_in);
	/* LSI not created, as it is local, and we do not support IPv4 */

#ifdef CONFIG_HIP_ESCROW
	if (hip_deliver_escrow_data(r1_saddr, r1_daddr, &ctx->input->hits,
				    &ctx->input->hitr, &spi_in,
				    transform_esp_suite, &ctx->esp_in,
				    HIP_ESCROW_OPERATION_ADD) != 0)
	{
		HIP_DEBUG("Could not deliver escrow data to server.\n");
	}
#endif //CONFIG_HIP_ESCROW

	/******** NONCE *************************/
#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
	  HIP_DEBUG("add nonce to the message\n");
	  HIP_IFEL(hip_build_param_blind_nonce(i2, entry->blind_nonce_i),
		   -1, "Unable to attach nonce to the message.\n");
	}
#endif

	/********** ECHO_RESPONSE_SIGN (OPTIONAL) **************/
	/* must reply... */
	{
		struct hip_echo_request *ping;

		ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST_SIGN);
		if (ping) {
			int ln = hip_get_param_contents_len(ping);
			HIP_IFEL(hip_build_param_echo(i2, ping + 1, ln, 1, 0), -1,
				 "Error while creating echo reply parameter\n");
		}
	}

	/************* HMAC ************/
	HIP_IFEL(hip_build_param_hmac_contents(i2, &ctx->hip_hmac_out),
		 -1, "Building of HMAC failed\n");

	/********** Signature **********/
	/* Build a digest of the packet built so far. Signature will
	   be calculated over the digest. */
	HIP_IFEL(entry->sign(entry->our_priv_key, i2), -EINVAL, "Could not create signature\n");

	/********** ECHO_RESPONSE (OPTIONAL) ************/
	/* must reply */
	{
	     struct hip_echo_request *ping;

	     ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST);
	     if (ping) {
		  int ln = hip_get_param_contents_len(ping);
		  HIP_IFEL(hip_build_param_echo(i2, (ping + 1), ln, 0, 0), -1,
			   "Error while creating echo reply parameter\n");
	     }
	}

        /********** I2 packet complete **********/
	memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
	spi_in_data.spi = spi_in;
	spi_in_data.ifindex = hip_devaddr2ifindex(r1_daddr);
	HIP_LOCK_HA(entry);
	HIP_IFEB(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data), -1, HIP_UNLOCK_HA(entry));

	entry->esp_transform = transform_esp_suite;
	HIP_DEBUG("Saving base exchange encryption data to entry \n");
	HIP_DEBUG_HIT("Our HIT: ", &entry->hit_our);
	HIP_DEBUG_HIT("Peer HIT: ", &entry->hit_peer);
	/* Store the keys until we receive R2 */
	HIP_IFEB(hip_store_base_exchange_keys(entry, ctx, 1), -1, HIP_UNLOCK_HA(entry));

	/** @todo Also store the keys that will be given to ESP later */
	HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), -1);

	/* R1 packet source port becomes the I2 packet destination port. */
	err = entry->hadb_xmit_func->
	     hip_send_pkt(r1_daddr, &daddr,
			  (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			  r1_info->src_port, i2, entry, 1);
	HIP_IFEL(err < 0, -ECOMM, "Sending I2 packet failed.\n");

 out_err:
	if (i2)
		HIP_FREE(i2);

	return err;
}

int hip_handle_r1(hip_common_t *r1, in6_addr_t *r1_saddr, in6_addr_t *r1_daddr,
		  hip_ha_t *entry, hip_portpair_t *r1_info)
{
	int err = 0, retransmission = 0;
	uint64_t solved_puzzle = 0, I = 0;
	struct hip_context *ctx = NULL;
	struct hip_host_id *peer_host_id = NULL;
	struct hip_r1_counter *r1cntr = NULL;
	struct hip_dh_public_value *dhpv = NULL;
        struct hip_locator *locator = NULL;
	struct hip_nat_transform *nat_tfm;
	hip_transform_suite_t nat_suite;

        _HIP_DEBUG("hip_handle_r1() invoked.\n");

	if (entry->state == HIP_STATE_I2_SENT) {
		HIP_DEBUG("Retransmission\n");
		retransmission = 1;
	} else {
		HIP_DEBUG("Not a retransmission\n");
	}

	HIP_IFEL(!(ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_KERNEL)),
		 -ENOMEM, "Could not allocate memory for context\n");
	memset(ctx, 0, sizeof(struct hip_context));
	ctx->input = r1;
	
	hip_relay_add_rvs_to_ha(r1, entry);
	
#ifdef HIP_USE_ICE
	hip_relay_handle_relay_to_in_client(r1,HIP_R1, r1_saddr, r1_daddr,r1_info, entry);
#endif

	/* According to the section 8.6 of the base draft, we must first check
	   signature. */

	/* Blinded R1 packets do not contain HOST ID parameters, so the
	 * verification must be delayed to the R2 */
	if (!hip_blind_get_status()) {
		/* Store the peer's public key to HA and validate it */
		/** @todo Do not store the key if the verification fails. */
		HIP_IFEL(!(peer_host_id = hip_get_param(r1, HIP_PARAM_HOST_ID)),
			 -ENOENT, "No HOST_ID found in R1\n");
		//copy hostname to hadb entry if local copy is empty
		if(strlen(entry->peer_hostname) == 0)
			memcpy(entry->peer_hostname,
			       hip_get_param_host_id_hostname(peer_host_id),
			       HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
		HIP_IFE(hip_init_peer(entry, r1, peer_host_id), -EINVAL);
		HIP_IFEL(entry->verify(entry->peer_pub_key, r1), -EINVAL,
			 "Verification of R1 signature failed\n");
        }

	/* R1 packet had destination port hip_get_nat_udp_port(), which means that the peer is
	   behind NAT. We set NAT mode "on" and set the send funtion to
	   "hip_send_udp". The client UDP port is not stored until the handling
	   of R2 packet. Don't know if the entry is already locked... */
	if(r1_info->dst_port == hip_get_peer_nat_udp_port()) {
		HIP_LOCK_HA(entry);
		if(entry->nat_mode == HIP_NAT_MODE_NONE)
			entry->nat_mode = HIP_NAT_MODE_PLAIN_UDP;
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
		HIP_UNLOCK_HA(entry);
	}

       /*********** NAT parameters *******/

	nat_tfm = hip_get_param(r1, HIP_PARAM_NAT_TRANSFORM);
	if (r1_info->src_port == 0) {
		nat_suite = HIP_NAT_MODE_NONE;
	} else if (nat_tfm) {
		nat_suite = hip_select_nat_transform(entry,
						     nat_tfm->suite_id, hip_get_param_contents_len(nat_tfm) / sizeof(hip_transform_suite_t) - 1);
	} else {
		nat_suite = HIP_NAT_MODE_PLAIN_UDP;
	}
	if (nat_suite == HIP_NAT_MODE_ICE_UDP) 
		ctx->use_ice = 1;
	hip_ha_set_nat_mode(entry, nat_suite);

        /***** LOCATOR PARAMETER ******/

        locator = hip_get_param(r1, HIP_PARAM_LOCATOR);
        if(locator)
		err = handle_locator(locator, r1_saddr, r1_daddr, entry, r1_info);
        else
            HIP_DEBUG("R1 did not have locator\n");

	/* R1 generation check */

	/* We have problems with creating precreated R1s in reasonable
	   fashion... so we don't mind about generations. */
	r1cntr = hip_get_param(r1, HIP_PARAM_R1_COUNTER);

	/* Do control bit stuff here... */

	/* We must store the R1 generation counter, _IF_ it exists. */
	if (r1cntr) {
		HIP_DEBUG("Storing R1 generation counter\n");
		HIP_LOCK_HA(entry);
		entry->birthday = r1cntr->generation;
		HIP_UNLOCK_HA(entry);
	}

        /* Solve puzzle: if this is a retransmission, we have to preserve
	   the old solution. */
	if (!retransmission) {
		struct hip_puzzle *pz = NULL;

		HIP_IFEL(!(pz = hip_get_param(r1, HIP_PARAM_PUZZLE)), -EINVAL,
			 "Malformed R1 packet. PUZZLE parameter missing\n");
		HIP_IFEL((solved_puzzle =
			  entry->hadb_misc_func->hip_solve_puzzle(
				  pz, r1, HIP_SOLVE_PUZZLE)) == 0,
			 -EINVAL, "Solving of puzzle failed\n");
		I = pz->I;
		entry->puzzle_solution = solved_puzzle;
		entry->puzzle_i = pz->I;
	} else {
		I = entry->puzzle_i;
		solved_puzzle = entry->puzzle_solution;
	}

	/* calculate shared secret and create keying material */
	ctx->dh_shared_key = NULL;
	/* note: we could skip keying material generation in the case
	   of a retransmission but then we'd had to fill ctx->hmac etc */
	HIP_IFEL(entry->hadb_misc_func->hip_produce_keying_material(r1, ctx, I,
							 solved_puzzle, &dhpv),
			 -EINVAL, "Could not produce keying material\n");
	
	//entry->hip_nat_key = ctx->hip_nat_key;
	//HIP_DEBUG("hip nat key from context %s", ctx->hip_nat_key);
	if (hip_get_nat_mode(entry) == HIP_NAT_MODE_ICE_UDP)
		memcpy(entry->hip_nat_key, ctx->hip_nat_key,HIP_MAX_KEY_LEN);
	//HIP_DEBUG("hip nat key in entry %s", entry->hip_nat_key);
	/** @todo BLIND: What is this? */
	/* Blinded R1 packets do not contain HOST ID parameters,
	 * so the saving peer's HOST ID mus be delayd to the R2
	 */
	if (!hip_blind_get_status()) {
		/* Everything ok, save host id to HA */
		char *str = NULL;
		int len;
		HIP_IFE(hip_get_param_host_id_di_type_len(
				peer_host_id, &str, &len) < 0, -1);
		HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n", str,
			  len, hip_get_param_host_id_hostname(peer_host_id));
	}

	/********* ESP protection preferred transforms [OPTIONAL] *********/

	HIP_IFEL(esp_prot_r1_handle_transforms(entry, ctx), -1,
			"failed to handle preferred esp protection transforms\n");

	/******************************************************************/

        /* We haven't handled REG_INFO parameter. We do that in hip_create_i2()
	   because we must create an REG_REQUEST parameter based on the data
	   of the REG_INFO parameter. */

 	err = entry->hadb_misc_func->
	     hip_create_i2(ctx, solved_puzzle, r1_saddr, r1_daddr, entry,
			   r1_info, dhpv);

	HIP_IFEL(err < 0, -1, "Creation of I2 failed\n");

	if (entry->state == HIP_STATE_I1_SENT) {
		entry->state = HIP_STATE_I2_SENT;
	}

out_err:
	if (ctx->dh_shared_key)
		HIP_FREE(ctx->dh_shared_key);
	if (ctx)
		HIP_FREE(ctx);
     
	return err;
}

int hip_receive_r1(hip_common_t *r1, in6_addr_t *r1_saddr, in6_addr_t *r1_daddr,
		   hip_ha_t *entry, hip_portpair_t *r1_info)
{
	int state, mask = HIP_PACKET_CTRL_ANON, err = 0;

	HIP_DEBUG("hip_receive_r1() invoked.\n");

#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* Check and remove the IP of the peer from the opp non-HIP database */
	hip_oppipdb_delentry(&(entry->peer_addr));
#endif

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status())
	  mask |= HIP_PACKET_CTRL_BLIND;
#endif
	if (ipv6_addr_any(&r1->hitr)) {
		HIP_DEBUG("Received NULL receiver HIT in R1. Not dropping\n");
	}

 	HIP_IFEL(!hip_controls_sane(ntohs(r1->control), mask), 0,
		 "Received illegal controls in R1: 0x%x Dropping\n",
		 ntohs(r1->control));
	HIP_IFEL(!entry, -EFAULT,
		 "Received R1 with no local state. Dropping\n");

	/* An implicit and insecure REA. If sender's address is different than
	 * the one that was mapped, then we will overwrite the mapping with the
	 * newer address. This enables us to use the rendezvous server, while
	 * not supporting the REA TLV. */
	{
		struct in6_addr daddr;

		hip_hadb_get_peer_addr(entry, &daddr);
		if (ipv6_addr_cmp(&daddr, r1_saddr) != 0) {
			HIP_DEBUG("Mapped address didn't match received address\n");
			HIP_DEBUG("Assuming that the mapped address was actually RVS's.\n");
			HIP_HEXDUMP("Mapping", &daddr, 16);
			HIP_HEXDUMP("Received", r1_saddr, 16);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			hip_hadb_add_peer_addr(entry, r1_saddr, 0, 0,
					       PEER_ADDR_STATE_ACTIVE);
		}
	}

	state = entry->state;

	HIP_DEBUG("Received R1 in state %s\n", hip_state_str(state));
	switch(state) {
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
	case HIP_STATE_CLOSING:
	case HIP_STATE_CLOSED:
	     /* E1. The normal case. Process, send I2, goto E2. */
	     err = entry->hadb_handle_func->
		  hip_handle_r1(r1, r1_saddr, r1_daddr, entry, r1_info);
	     HIP_LOCK_HA(entry);
	     if (err < 0)
		  HIP_ERROR("Handling of R1 failed\n");
	     HIP_UNLOCK_HA(entry);
	     break;
	case HIP_STATE_R2_SENT:
		break;
	case HIP_STATE_ESTABLISHED:
		break;
	case HIP_STATE_NONE:
	case HIP_STATE_UNASSOCIATED:
	default:
		/* Can't happen. */
		err = -EFAULT;
		HIP_ERROR("R1 received in odd state: %d. Dropping.\n", state);
		break;
	}

	hip_put_ha(entry);

 out_err:
	return err;
}

/**
 * Creates and transmits an R2 packet.
 *
 * @param  ctx      a pointer to the context of processed I2 packet.
 * @param  i2_saddr a pointer to I2 packet source IP address.
 * @param  i2_daddr a pointer to I2 packet destination IP address.
 * @param  entry    a pointer to the current host association database state.
 * @param  i2_info  a pointer to the source and destination ports (when NAT is
 *                  in use).
 * @return zero on success, negative otherwise.
 */
int hip_create_r2(struct hip_context *ctx, in6_addr_t *i2_saddr,
		  in6_addr_t *i2_daddr, hip_ha_t *entry,
		  hip_portpair_t *i2_info,
		  in6_addr_t *dest,
		  const in_port_t dest_port)
{
	hip_common_t *r2 = NULL, *i2 = NULL;
	struct hip_crypto_key hmac;
 	int err = 0;
	uint16_t mask = 0;
	uint8_t lifetime = 0;
	uint32_t spi_in = 0;

	_HIP_DEBUG("hip_create_r2() invoked.\n");
	/* Assume already locked entry */
	i2 = ctx->input;

	/* Build and send R2: IP ( HIP ( SPI, HMAC, HIP_SIGNATURE ) ) */
	HIP_IFEL(!(r2 = hip_msg_alloc()), -ENOMEM, "No memory for R2\n");

#ifdef CONFIG_HIP_BLIND
	// For blind: we must add encrypted public host id
	if (hip_blind_get_status()) {
		HIP_DEBUG("Set HIP_PACKET_CTRL_BLIND for R2\n");
		mask |= HIP_PACKET_CTRL_BLIND;

		// Build network header by using blinded HITs
		entry->hadb_misc_func->
			hip_build_network_hdr(r2, HIP_R2, mask, &entry->hit_our_blind,
					      &entry->hit_peer_blind);
	}
#endif
	/* Just swap the addresses to use the I2's destination HIT as the R2's
	   source HIT. */
	if (!hip_blind_get_status()) {
		entry->hadb_misc_func->
			hip_build_network_hdr(r2, HIP_R2, mask, &entry->hit_our,
					      &entry->hit_peer);
	}

 	/* ESP_INFO */
	spi_in = hip_hadb_get_latest_inbound_spi(entry);
	HIP_IFEL(hip_build_param_esp_info(r2, ctx->esp_keymat_index, 0, spi_in),
		 -1, "building of ESP_INFO failed.\n");

#ifdef CONFIG_HIP_BLIND
	// For blind: we must add encrypted public host id
	if (hip_blind_get_status()) {
	  HIP_IFEL(hip_blind_build_r2(i2, r2, entry, &mask),
	  	   -1, "hip_blind_build_r2 failed\n");
	}
#endif

	/********** ESP-PROT anchor [OPTIONAL] **********/

	HIP_IFEL(esp_prot_r2_add_anchor(r2, entry), -1,
			"failed to add esp protection anchor\n");

	/************************************************/

    /********* LOCATOR PARAMETER ************/
	/** Type 193 **/
	if (hip_locator_status == SO_HIP_SET_LOCATOR_ON) {
		HIP_DEBUG("Building nat LOCATOR parameter\n");
		if ((err = hip_build_locators(r2, spi_in, hip_get_nat_mode(entry))) < 0)
			HIP_DEBUG("nat LOCATOR parameter building failed\n");
	}

#if defined(CONFIG_HIP_RVS) || defined(CONFIG_HIP_ESCROW)
	/********** REG_REQUEST **********/
	/* This part should only be executed at server offering rvs, relay or
	   escrow services. Since we don't have a way to detect if we are an
	   escrow server this part is executed on I and R also.
	   -Lauri 11.06.2008

	/* Handle REG_REQUEST parameter. */
	hip_handle_param_reg_request(entry, i2, r2);
	
#endif
	
#if defined(CONFIG_HIP_RVS) 
	if(hip_relay_get_status() == HIP_RELAY_ON) {
		 	hip_build_param_reg_from(r2,i2_saddr, i2_info->src_port);
		  }
	
#endif	
	
	
 	/* Create HMAC2 parameter. */
	if (entry->our_pub == NULL) {
		HIP_DEBUG("entry->our_pub is NULL.\n");
	} else {
		_HIP_HEXDUMP("Host ID for HMAC2", entry->our_pub,
			     hip_get_param_total_len(entry->our_pub));
	}

	memcpy(&hmac, &entry->hip_hmac_out, sizeof(hmac));
	HIP_IFEL(hip_build_param_hmac2_contents(r2, &hmac, entry->our_pub), -1,
		 "Failed to build parameter HMAC2 contents.\n");

	/* Why is err reset to zero? -Lauri 11.06.2008 */
	if (err == 1) {
		err = 0;
	}

	HIP_IFEL(entry->sign(entry->our_priv_key, r2), -EINVAL, "Could not sign R2. Failing\n");

#ifdef CONFIG_HIP_RVS
	if(!ipv6_addr_any(dest))
	 { 
		//if(hip_relay_get_status() == HIP_RELAY_ON) {
		 
			HIP_INFO("create replay_to parameter in R2\n");
			hip_build_param_relay_to(
					r2, dest, dest_port);
		//}
	  }
	
#endif

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
	   err = entry->hadb_ipsec_func->hip_add_sa(
		   i2_daddr, i2_saddr, &entry->hit_our, &entry->hit_peer,
		   entry->default_spi_out, entry->esp_transform, &ctx->esp_out,
		   &ctx->auth_out, 1, HIP_SPI_DIRECTION_OUT, 0, entry);
	}
#endif
	/*if nat control is 0, then UDP (ICE) mode is off*/
	if (hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP) {
		if (!hip_blind_get_status()) {
		  err = entry->hadb_ipsec_func->hip_add_sa(i2_daddr, i2_saddr,
				   &ctx->input->hitr, &ctx->input->hits,
				   entry->default_spi_out, entry->esp_transform,
				   &ctx->esp_out, &ctx->auth_out,
				   1, HIP_SPI_DIRECTION_OUT, 0, entry);
		}
		if (err) {
			HIP_ERROR("Failed to setup outbound SA with SPI = %d.\n",
					entry->default_spi_out);

			/* delete all IPsec related SPD/SA for this entry*/
			hip_hadb_delete_inbound_spi(entry, 0);
			hip_hadb_delete_outbound_spi(entry, 0);
			goto out_err;
		}
	}else{
		HIP_DEBUG("ICE engine will be used, no sa created here\n");
	}
//end modify
	/* @todo Check if err = -EAGAIN... */
	HIP_DEBUG("Set up outbound IPsec SA, SPI=0x%x\n", entry->default_spi_out);
// end move

	err = entry->hadb_xmit_func->hip_send_pkt(i2_daddr, i2_saddr,
						  (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
	                                          entry->peer_udp_port, r2, entry, 1);

	if (err == 1)
		err = 0;

	HIP_IFEL(err, -ECOMM, "Sending R2 packet failed.\n");

	/* Send the first heartbeat. Notice that error value is ignored
	   because we want to to complete the base exchange successfully */
	/* for ICE , we do not need it*/
	if (hip_icmp_interval > 0 & hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP) {
		_HIP_DEBUG("icmp sock %d\n", hip_icmp_sock);
		hip_send_icmp(hip_icmp_sock, entry);
	}

 out_err:
	if (r2 != NULL) {
		free(r2);
	}

	return err;
}

/**
 * Handles an incoming I2 packet.
 *
 * This function is the actual point from where the processing of I2 is started
 * and corresponding R2 is created. This function also creates a new host
 * association in the host association database if no previous association
 * matching the search key (source HIT XOR destination HIT) was found.
 *
 * @param i2       a pointer to the I2 HIP packet common header with source and
 *                 destination HITs.
 * @param i2_saddr a pointer to the source address from where the I2 packet was
 *                 received.
 * @param i2_daddr a pointer to the destination address where the I2 packet was
 *                 sent to (own address).
 * @param ha       host association corresponding to the peer.
 * @param i2_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error. Success
 *                 indicates that I2 payloads are checked and R2 is created and
 *                 sent.
 * @see            Section 6.9. "Processing Incoming I2 Packets" of
 *                 <a href="http://www.rfc-editor.org/rfc/rfc5201.txt">
 *                 RFC 5201</a>.
 */
int hip_handle_i2(hip_common_t *i2, in6_addr_t *i2_saddr, in6_addr_t *i2_daddr,
		  hip_ha_t *entry, hip_portpair_t *i2_info)
{
	/* Primitive data types. */
	extern uint8_t hip_esp_prot_ext_transform;
	int err = 0, retransmission = 0, replay = 0, state = 0, item_length = 0,
		host_id_found = 0, is_loopback = 0;
	uint8_t transform = 0;
	uint16_t crypto_len = 0;
	uint32_t spi_in = 0, spi_out = 0;
	in_port_t dest_port = 0; // For the port in RELAY_FROM
	/* Pointers */
	char *tmp_enc = NULL, *enc = NULL;
	unsigned char *iv = NULL;
	unsigned char *anchor = NULL;
	struct hip_hip_transform *hip_transform = NULL;
	struct hip_host_id *host_id_in_enc = NULL;
	struct hip_r1_counter *r1cntr = NULL;
	struct hip_esp_info *esp_info = NULL;
	struct hip_dh_public_value *dhpv = NULL;
	struct hip_solution *solution = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	struct esp_prot_transform *prot_transform = NULL;
	/* Data structures. */
	in6_addr_t dest; // dest for the IP address in RELAY_FROM
	hip_transform_suite_t esp_tfm, hip_tfm, nat_suite;
	struct hip_spi_in_item spi_in_data;
	struct hip_context i2_context;
	extern int hip_icmp_interval;
	extern int hip_icmp_sock;
	struct hip_locator *locator = NULL;
	struct hip_nat_transform *nat_tfm;
	void *ice_session = NULL;
	int i = 0;
	int do_transform = 0;
	int use_blind = 0;
	uint16_t nonce = 0;
	in6_addr_t plain_peer_hit, plain_local_hit;

#ifdef CONFIG_HIP_BLIND
	memset(&plain_peer_hit, 0, sizeof(plain_peer_hit));
	memset(&plain_local_hit, 0, sizeof(plain_local_hit));

	HIP_IFEL(hip_check_whether_to_use_blind(i2, entry, &use_blind), -EINVAL,
		 "Error when checking whether to use BLIND.\n");
#endif

	_HIP_DEBUG("hip_handle_i2() invoked.\n");

	/* Initialize the statically allocated data structures. */
	memset(&dest, 0, sizeof(dest));
	memset(&esp_tfm, 0, sizeof(esp_tfm));
	memset(&hip_tfm, 0, sizeof(hip_tfm));
	memset(&spi_in_data, 0, sizeof(spi_in_data));
	memset(&i2_context, 0, sizeof(i2_context));

	/* The context structure is used to gather the context created from
	   processing the I2 packet, as well as storing the original packet.
	   From the context struct we can then access the I2 in hip_create_r2()
	   later. */
	i2_context.input = NULL;
	i2_context.output = NULL;
	i2_context.dh_shared_key = NULL;

	/* Store a pointer to the incoming i2 message in the context just
	   allocted. From the context struct we can then access the I2 in
	   hip_create_r2() later. */
	i2_context.input = i2;

	/* Check that the Responder's HIT is one of ours. According to RFC5201,
	   this MUST be done. This check was added by Lauri on 01.08.2008.
	   Note that this condition is not satisfied at the HIP relay server */
	if(!hip_hidb_hit_is_our(&i2->hitr)) {
		err = -EPROTO;
		HIP_ERROR("Responder's HIT in the received I2 packet does not"\
			  " correspond to one of our own HITs. Dropping I2"\
			  " packet.\n");
		goto out_err;
	}

	/* Fetch the R1_COUNTER parameter. */
	r1cntr = hip_get_param(i2, HIP_PARAM_R1_COUNTER);

	/* Here we should check the 'system boot counter' using the R1_COUNTER
	   parameter. However, our precreated R1 packets do not support system
	   boot counter so we do not check it. */

	/* Check solution for cookie */
	solution = hip_get_param(i2_context.input, HIP_PARAM_SOLUTION);
	if(solution == NULL) {
		err = -ENODATA;
		HIP_ERROR("SOLUTION parameter missing from I2 packet. "\
			  "Dropping the I2 packet.\n");
		goto out_err;
	}

	HIP_DEBUG_HIT("i2_saddr", i2_saddr);
	HIP_DEBUG_HIT("i2_daddr", i2_daddr);

	HIP_IFEL(hip_verify_cookie(i2_saddr, i2_daddr, i2, solution), -EPROTO,
		 "Cookie solution rejected. Dropping the I2 packet.\n");

#ifdef CONFIG_HIP_I3
	if(entry && entry->hip_is_hi3_on){
		locator = hip_get_param(i2, HIP_PARAM_LOCATOR);
		hip_do_i3_stuff_for_i2(locator, i2_info, i2_saddr, i2_daddr);
	}
#endif

	if(entry != NULL) {
		/* If the I2 packet is a retransmission, we need reuse the
		   SPI/keymat that was setup already when the first I2 was
		   received. If the Initiator is in established state (it has
		   possibly sent duplicate I2 packets), we must make sure that
		   we are reusing the old SPI as the Initiator will just drop
		   the R2, thus discarding any new SPIs we create. Notice that
		   this works also in the case when Initiator is not in
		   established state, as the initiator just picks up the SPI
		   from the R2. */
		if(entry->state == HIP_STATE_R2_SENT) {
			retransmission = 1;
		} else if (entry->state == HIP_STATE_ESTABLISHED) {
			retransmission = 1;
			spi_in = hip_hadb_get_latest_inbound_spi(entry);
		}
	}

	/****** NAT transform *********/

	nat_tfm = hip_get_param(i2_context.input,
				HIP_PARAM_NAT_TRANSFORM);
	if (i2_info->src_port == 0) {
		nat_suite = HIP_NAT_MODE_NONE;
	} else if (nat_tfm) {
		nat_suite = hip_select_nat_transform(entry,
						     nat_tfm->suite_id,
						     hip_get_param_contents_len(nat_tfm) / sizeof(hip_transform_suite_t) - 1);
	} else {
		nat_suite = HIP_NAT_MODE_PLAIN_UDP;
	}
	if (nat_suite == HIP_NAT_MODE_ICE_UDP) {
		i2_context.use_ice = 1;
		hip_nat_handle_pacing(i2, entry);
	}

	/* Check HIP and ESP transforms, and produce keying material. */

	/* Note: we could skip keying material generation in the case of a
	   retransmission but then we'd had to fill i2_context.hmac etc.
	   TH: I'm not sure if this could be replaced with a function pointer
	   which is set from haDB. Usually you shouldn't have state here,
	   right? */

	HIP_IFEL(hip_produce_keying_material(i2_context.input, &i2_context,
					     solution->I, solution->J, &dhpv),
		 -EPROTO, "Unable to produce keying material. Dropping the I2"\
		 " packet.\n");


	
	/* Verify HMAC. */
	if (hip_hidb_hit_is_our(&i2->hits) && hip_hidb_hit_is_our(&i2->hitr)) {
		is_loopback = 1;
		HIP_IFEL(hip_verify_packet_hmac(i2, &i2_context.hip_hmac_out),
			 -EPROTO, "HMAC loopback validation on I2 failed. "\
			 "Dropping the I2 packet.\n");
	} else {
		HIP_IFEL(hip_verify_packet_hmac(i2, &i2_context.hip_hmac_in),
			 -EPROTO, "HMAC validation on I2 failed. Dropping the"\
			 " I2 packet.\n");
	}

	hip_transform = hip_get_param(i2, HIP_PARAM_HIP_TRANSFORM);
	if (hip_transform == NULL) {
		err = -ENODATA;
		HIP_ERROR("HIP_TRANSFORM parameter missing from I2 packet. "\
			  "Dropping the I2 packet.\n");
		goto out_err;
	} else if ((hip_tfm =
		   hip_get_param_transform_suite_id(hip_transform, 0)) == 0) {
		err = -EPROTO;
		HIP_ERROR("Bad HIP transform. Dropping the I2 packet.\n");
		goto out_err;

	} else
	{
		do_transform = 1;
	}

	/* Decrypt the HOST_ID and verify it against the sender HIT. */
	/* @todo: the HOST_ID can be in the packet in plain text */
	enc = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
	if(enc == NULL) {
		HIP_DEBUG("ENCRYPTED parameter missing from I2 packet\n");
		host_id_in_enc = hip_get_param(i2, HIP_PARAM_HOST_ID);
		HIP_IFEL(!host_id_in_enc, -1, "No host id in i2");
		host_id_found = 1;
	} else {
		/* Little workaround...
		 * We have a function that calculates SHA1 digest and then verifies the
		 * signature. But since the SHA1 digest in I2 must be calculated over
		 * the encrypted data, and the signature requires that the encrypted
		 * data to be decrypted (it contains peer's host identity), we are
		 * forced to do some temporary copying. If ultimate speed is required,
		 * then calculate the digest here as usual and feed it to signature
		 * verifier. */
		if((tmp_enc = (char *) malloc(hip_get_param_total_len(enc))) == NULL) {
			err = -ENOMEM;
			HIP_ERROR("Out of memory when allocating memory for temporary "\
				  "ENCRYPTED parameter. Dropping the I2 packet.\n");
			goto out_err;
		}
		memcpy(tmp_enc, enc, hip_get_param_total_len(enc));


		if (do_transform) {
			/* Get pointers to:
			   1) the encrypted HOST ID parameter inside the "Encrypted
			   data" field of the ENCRYPTED parameter.
			   2) Initialization vector from the ENCRYPTED parameter.

			   Get the length of the "Encrypted data" field in the ENCRYPTED
			   parameter. */

			switch (hip_tfm) {
			case HIP_HIP_RESERVED:
				HIP_ERROR("Found HIP suite ID 'RESERVED'. Dropping "\
					  "the I2 packet.\n");
				err = -EOPNOTSUPP;
				goto out_err;
			case HIP_HIP_AES_SHA1:
				host_id_in_enc = (struct hip_host_id *)
					(tmp_enc +
					 sizeof(struct hip_encrypted_aes_sha1));
				iv = ((struct hip_encrypted_aes_sha1 *) tmp_enc)->iv;
				/* 4 = reserved, 16 = IV */
				crypto_len = hip_get_param_contents_len(enc) - 4 - 16;
				HIP_DEBUG("Found HIP suite ID "\
					  "'AES-CBC with HMAC-SHA1'.\n");
				break;
			case HIP_HIP_3DES_SHA1:
				host_id_in_enc = (struct hip_host_id *)
					(tmp_enc +
					 sizeof(struct hip_encrypted_3des_sha1));
				iv = ((struct hip_encrypted_3des_sha1 *) tmp_enc)->iv;
				/* 4 = reserved, 8 = IV */
				crypto_len = hip_get_param_contents_len(enc) - 4 - 8;
				HIP_DEBUG("Found HIP suite ID "\
					  "'3DES-CBC with HMAC-SHA1'.\n");
				break;
			case HIP_HIP_3DES_MD5:
				HIP_ERROR("Found HIP suite ID '3DES-CBC with "\
					  "HMAC-MD5'. Support for this suite ID is "\
					  "not implemented. Dropping the I2 packet.\n");
				err = -ENOSYS;
				goto out_err;
			case HIP_HIP_BLOWFISH_SHA1:
				HIP_ERROR("Found HIP suite ID 'BLOWFISH-CBC with "\
					  "HMAC-SHA1'. Support for this suite ID is "\
					  "not implemented. Dropping the I2 packet.\n");
				err = -ENOSYS;
				goto out_err;
			case HIP_HIP_NULL_SHA1:
				host_id_in_enc = (struct hip_host_id *)
					(tmp_enc +
					 sizeof(struct hip_encrypted_null_sha1));
				iv = NULL;
				/* 4 = reserved */
				crypto_len = hip_get_param_contents_len(enc) - 4;
				HIP_DEBUG("Found HIP suite ID "\
					  "'NULL-ENCRYPT with HMAC-SHA1'.\n");
				break;
			case HIP_HIP_NULL_MD5:
				HIP_ERROR("Found HIP suite ID 'NULL-ENCRYPT with "\
					  "HMAC-MD5'. Support for this suite ID is "\
					  "not implemented. Dropping the I2 packet.\n");
				err = -ENOSYS;
				goto out_err;
			default:
				HIP_ERROR("Found unknown HIP suite ID '%d'. Dropping "\
					  "the I2 packet.\n", hip_tfm);
				err = -EOPNOTSUPP;
				goto out_err;
			}
		}

		/* This far we have succesfully produced the keying material (key),
		   identified which HIP transform is use (hip_tfm), retrieved pointers
		   both to the encrypted HOST_ID (host_id_in_enc) and initialization
		   vector (iv) and we know the length of the encrypted HOST_ID
		   parameter (crypto_len). We are ready to decrypt the actual host
		   identity. If the decryption succeeds, we have the decrypted HOST_ID
		   parameter in the 'host_id_in_enc' buffer.

		   Note, that the original packet has the data still encrypted. */
		if (!host_id_found)
			HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv, hip_tfm, crypto_len,
							  (is_loopback ? &i2_context.hip_enc_out.key :
							   &i2_context.hip_enc_in.key),
							  HIP_DIRECTION_DECRYPT),
#ifdef CONFIG_HIP_OPENWRT
						  // workaround for non-included errno-base.h in openwrt
				 -EINVAL,
#else
				 -EKEYREJECTED,
#endif
				 "Failed to decrypt the HOST_ID parameter. Dropping the I2 " \
				 "packet.\n");

		/* If the decrypted data is not a HOST_ID parameter, the I2 packet is
		   silently dropped. */
		if (hip_get_param_type(host_id_in_enc) != HIP_PARAM_HOST_ID) {
			err = -EPROTO;
			HIP_ERROR("The decrypted data is not a HOST_ID parameter. "\
				  "Dropping the I2 packet.\n");
			goto out_err;
		}
	}
	HIP_HEXDUMP("Initiator host id", host_id_in_enc,
		    hip_get_param_total_len(host_id_in_enc));


#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
		HIP_IFEL(hip_host_id_to_hit(host_id_in_enc, &plain_peer_hit,
					    HIP_HIT_TYPE_HASH100), -1,
			 "hip_host_id_to_hit() failed.\n");
		HIP_IFEL(hip_blind_get_nonce(i2, &nonce), -1,
			 "hip_blind_get_nonce failed().\n");
		HIP_IFEL(hip_plain_fingerprint(&nonce, &i2->hitr,
					       &plain_local_hit), -1,
			 "hip_plain_fingerprint failed().\n");
		HIP_IFEL(hip_blind_verify(&nonce, &plain_peer_hit, &i2->hits) != 1,
			 -1, "hip_blind_verify failed\n");
	}
#endif
	/* If there is no HIP association, we must create one now. */
	if (entry == NULL) {
		int if_index = 0;
		struct sockaddr_storage ss_addr;
		struct sockaddr *addr = NULL;

		HIP_DEBUG("No HIP association found. Creating a new one.\n");

		if((entry = hip_hadb_create_state(GFP_KERNEL)) == NULL) {
			err = -ENOMEM;
			HIP_ERROR("Out of memory when allocating memory for a new "\
				  "HIP association. Dropping the I2 packet.\n");
			goto out_err;
		}
		
	//entry->hip_nat_key = i2_context.hip_nat_key;
	//HIP_DEBUG("hip nat key from context %s", i2_context.hip_nat_key);
	memcpy(entry->hip_nat_key, i2_context.hip_nat_key, HIP_MAX_KEY_LEN);
	//HIP_DEBUG("hip nat key in entry %s", entry->hip_nat_key);
	

#ifdef CONFIG_HIP_BLIND
		if (use_blind) {
			ipv6_addr_copy(&entry->hit_peer, &plain_peer_hit);
			hip_init_us(entry, &plain_local_hit);
			HIP_DEBUG("BLIND is in use.\n");
		} else {
			ipv6_addr_copy(&entry->hit_peer, &i2->hits);
			hip_init_us(entry, &i2->hitr);
			HIP_DEBUG("BLIND is not in use.\n");
		}
#else
		/* Next, we initialize the new HIP association. Peer HIT is the
		   source HIT of the received I2 packet. We can have many Host
		   Identities and using any of those Host Identities we can
		   calculate diverse HITs depending on the used algorithm. When
		   we sent one of our pre-created R1 packets, we have used one
		   of our Host Identities and thus of our HITs as source. We
		   must dig out the original Host Identity using the destination
		   HIT of the I2 packet as a key. The initialized HIP
		   association will not, however, have the I2 destination HIT as
		   source, but one that is calculated using the Host Identity
		   that we have dug out. */
		ipv6_addr_copy(&entry->hit_peer, &i2->hits);
		HIP_DEBUG("Initializing the HIP association.\n");
		hip_init_us(entry, &i2->hitr);
#endif
		HIP_DEBUG("Inserting the new HIP association in the HIP "\
			  "association database.\n");
		/* Should we handle the case where the insertion fails? */
		hip_hadb_insert_state(entry);

		ipv6_addr_copy(&entry->our_addr, i2_daddr);

		/* Get the interface index of the network device which has our
		   local IP address. */
		if((if_index =
		    hip_devaddr2ifindex(&entry->our_addr)) < 0) {
			err = -ENXIO;
			HIP_ERROR("Interface index for local IPv6 address "\
				  "could not be determined. Dropping the I2 "\
				  "packet.\n");
			goto out_err;
		}

		hip_ha_set_nat_mode(entry, nat_suite);

		/* We need our local IP address as a sockaddr because
		   add_address_to_list() eats only sockaddr structures. */
		memset(&ss_addr, 0, sizeof(struct sockaddr_storage));
		addr = (struct sockaddr*) &ss_addr;
		addr->sa_family = AF_INET6;

		memcpy(hip_cast_sa_addr(addr), &entry->our_addr,
		       hip_sa_addr_len(addr));
		add_address_to_list(addr, if_index, 0);
	}

	//hip_hadb_insert_state(entry);

	/* If there was already state, these may be uninitialized */
	entry->hip_transform = hip_tfm;
	if (!entry->our_pub) {
#ifdef CONFIG_HIP_BLIND
		if (use_blind) {
			hip_init_us(entry, &plain_local_hit);
		} else {
			hip_init_us(entry, &i2->hitr);
		}
#else
		hip_init_us(entry, &i2->hitr);
#endif
	}
	/* If the incoming I2 packet has hip_get_nat_udp_port() as destination port, NAT
	   mode is set on for the host association, I2 source port is
	   stored as the peer UDP port and send function is set to
	   "hip_send_udp()". Note that we must store the port not until
	   here, since the source port can be different for I1 and I2. */
	if(i2_info->dst_port == hip_get_local_nat_udp_port())
	{
		if (entry->nat_mode == 0) entry->nat_mode = HIP_NAT_MODE_PLAIN_UDP;
		entry->local_udp_port = i2_info->dst_port;
		entry->peer_udp_port = i2_info->src_port;
		HIP_DEBUG("entry->hadb_xmit_func: %p.\n", entry->hadb_xmit_func);
		HIP_DEBUG("Setting send func to UDP for entry %p from I2 info.\n",
			  entry);
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
	}
	HIP_DEBUG("check nat mode for ice:1: %d,%d, %d\n",hip_get_nat_mode(entry),
		     			hip_get_nat_mode(NULL),HIP_NAT_MODE_ICE_UDP);
	entry->hip_transform = hip_tfm;

#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
		memcpy(&entry->hit_our_blind, &i2->hitr, sizeof(struct in6_addr));
		memcpy(&entry->hit_peer_blind, &i2->hits, sizeof(struct in6_addr));
	  	entry->blind_nonce_i = nonce;
	  	entry->blind = 1;
	}
#endif

	/** @todo the above should not be done if signature fails...
	    or it should be cancelled. */

	/* Store peer's public key and HIT to HA */
	HIP_IFE(hip_init_peer(entry, i2, host_id_in_enc), -EINVAL);

	/* Validate signature */
	HIP_IFEL(entry->verify(entry->peer_pub_key, i2_context.input), -EINVAL,
		 "Verification of I2 signature failed\n");

	/* If we have old SAs with these HITs delete them */
	hip_hadb_delete_inbound_spi(entry, 0);
	hip_hadb_delete_outbound_spi(entry, 0);
	{
		struct hip_esp_transform *esp_tf = NULL;
		struct hip_spi_out_item spi_out_data;

		HIP_IFEL(!(esp_tf = hip_get_param(i2_context.input,
						  HIP_PARAM_ESP_TRANSFORM)),
			 -ENOENT, "Did not find ESP transform on i2\n");
		HIP_IFEL(!(esp_info = hip_get_param(i2_context.input,
						    HIP_PARAM_ESP_INFO)),
			 -ENOENT, "Did not find SPI LSI on i2\n");

		if (r1cntr)
			entry->birthday = r1cntr->generation;
		entry->peer_controls |= ntohs(i2->control);

		/* move this below setup_sa */
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = ntohl(esp_info->new_spi);
		HIP_DEBUG("Adding spi 0x%x\n", spi_out_data.spi);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT,
					 &spi_out_data), -1);
		entry->esp_transform = hip_select_esp_transform(esp_tf);
		HIP_IFEL((esp_tfm = entry->esp_transform) == 0, -1,
			 "Could not select proper ESP transform\n");
	}

	HIP_IFEL(hip_hadb_add_peer_addr(entry, i2_saddr, 0, 0,
					PEER_ADDR_STATE_ACTIVE), -1,
		 "Error while adding the preferred peer address\n");

	HIP_DEBUG("retransmission: %s\n", (retransmission ? "yes" : "no"));
	HIP_DEBUG("replay: %s\n", (replay ? "yes" : "no"));
	HIP_DEBUG("src %d, dst %d\n", i2_info->src_port, i2_info->dst_port);

	/********** ESP-PROT anchor [OPTIONAL] **********/

	HIP_IFEL(esp_prot_i2_handle_anchor(entry, &i2_context), -1,
			"failed to handle esp prot anchor\n");

	/************************************************/

	/* creating inbound spi to be sent in R2
	 * @note for some reason it can be set above in case an entry already exists,
	 * 		 so we only get a new one, if it's not set yet
	 */
	if (spi_in == 0)
	{
		HIP_DEBUG("creating new spi...\n");
		get_random_bytes(&spi_in, sizeof(uint32_t));
	}

	/* XXX: -EAGAIN */
	HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);

#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
		/* Set up IPsec associations */
		err = entry->hadb_ipsec_func->hip_add_sa(
			i2_saddr, i2_daddr, &entry->hit_peer, &entry->hit_our,
			spi_in, esp_tfm,  &i2_context.esp_in, &i2_context.auth_in,
			retransmission, HIP_SPI_DIRECTION_IN, 0, entry);
	} else if(hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP) {
		/* Set up IPsec associations */
		err = entry->hadb_ipsec_func->hip_add_sa(
			i2_saddr, i2_daddr, &i2_context.input->hits,
			&i2_context.input->hitr, spi_in, esp_tfm,
			&i2_context.esp_in, &i2_context.auth_in,
			retransmission, HIP_SPI_DIRECTION_IN, 0, entry);
	}
#else
	
	if(hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP) {
		/* Set up IPsec associations */
		err = entry->hadb_ipsec_func->hip_add_sa(
			i2_saddr, i2_daddr, &i2_context.input->hits,
			&i2_context.input->hitr, spi_in, esp_tfm,
			&i2_context.esp_in, &i2_context.auth_in,
			retransmission, HIP_SPI_DIRECTION_IN, 0, entry);
	}
#endif
	/* Remove the IPsec associations if there was an error when creating
	   them. */
	if (err) {
		err = -1;
		HIP_ERROR("Failed to setup inbound SA with SPI=%d\n", spi_in);
		hip_hadb_delete_inbound_spi(entry, 0);
		hip_hadb_delete_outbound_spi(entry, 0);
		goto out_err;
	}

#ifdef CONFIG_HIP_ESCROW
	if (hip_deliver_escrow_data(
		    i2_saddr, i2_daddr, &i2_context.input->hits, &i2_context.input->hitr,
		    spi_in, esp_tfm, &i2_context.esp_in, HIP_ESCROW_OPERATION_ADD)
	    != 0) {
		HIP_DEBUG("Could not deliver escrow data to server\n");
	}
#endif //CONFIG_HIP_ESCROW

	spi_out = ntohl(esp_info->new_spi);
	HIP_DEBUG("Setting up outbound IPsec SA, SPI=0x%x\n", spi_out);

#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
		HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(
				 &entry->hit_peer, &entry->hit_our, i2_saddr,
				 i2_daddr, IPPROTO_ESP, 1, 1), -1,
			 "Failed to set up an SP pair.\n");
	} else {
		HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(
			 &i2_context.input->hits, &i2_context.input->hitr,
			 i2_saddr, i2_daddr, IPPROTO_ESP, 1, 1), -1,
		 "Failed to set up an SP pair.\n");
	}
#else
	HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(
			 &i2_context.input->hits, &i2_context.input->hitr,
			 i2_saddr, i2_daddr, IPPROTO_ESP, 1, 1), -1,
		 "Failed to set up an SP pair.\n");
#endif
	/* Source IPv6 address is implicitly the preferred address after the
	   base exchange. */
	/* @todo port must be added */
#ifndef HIP_USE_ICE
	HIP_IFEL(hip_hadb_add_addr_to_spi(entry, spi_out, i2_saddr, 1, 0, 1),
		 -1,  "Failed to add an address to SPI list\n");
#else
	HIP_IFEL(hip_hadb_add_udp_addr_to_spi(entry, spi_out, i2_saddr, 1, 0, 1,i2_info->src_port, 
			ice_calc_priority(HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI_PRIORITY,ICE_CAND_PRE_HOST,1)- i2_info->src_port, 0),
		 -1,  "Failed to add an address to SPI list\n");
#endif

	memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
	spi_in_data.spi = spi_in;
	spi_in_data.ifindex = hip_devaddr2ifindex(i2_daddr);

	if (spi_in_data.ifindex) {
		HIP_DEBUG("spi_in_data.ifindex = %d.\n", spi_in_data.ifindex);
	} else {
		HIP_ERROR("Could not get device ifindex of address.\n");
	}

	err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data);
	if (err) {
		HIP_UNLOCK_HA(entry);
		HIP_ERROR("Adding of SPI failed. Not creating an R2 packet.\n");
		goto out_err;
	}

	entry->default_spi_out = spi_out;
	HIP_IFE(hip_store_base_exchange_keys(entry, &i2_context, 0), -1);
	//hip_hadb_insert_state(entry);

	HIP_DEBUG("\nInserted a new host association state.\n"
		  "\tHIP state: %s\n"\
		  "\tDefault outgoing SPI 0x%x.\n"
		  "\tCreating an R2 packet in response next.\n",
		  hip_state_str(entry->state), entry->default_spi_out);


#ifdef CONFIG_HIP_RVS
	ipv6_addr_copy(&dest, &in6addr_any);
	if(hip_relay_get_status() == HIP_RELAY_OFF) {
		state = hip_relay_handle_relay_from(i2, i2_saddr, &dest, &dest_port);
		if( state == -1 ){
			HIP_DEBUG( "Handling RELAY_FROM of  I2 packet failed.\n");
			goto out_err;
		}else{
			if(dest_port)
			HIP_IFEL( hip_hadb_add_udp_addr_to_spi(entry, spi_out, &dest, 0, 0, 0, dest_port, HIP_LOCATOR_LOCATOR_TYPE_REFLEXIVE_PRIORITY,2),
					 -1,  "Failed to add a reflexive address to SPI list\n");

		}
	}
#endif
//end add

	/* Note that we haven't handled the REG_REQUEST yet. This is because we
	   must create an REG_RESPONSE parameter into the R2 packet based on the
	   REG_REQUEST parameter. We handle the REG_REQUEST parameter in
	   hip_create_r2() - although that is somewhat illogical.
	   -Lauri 06.05.2008 */

	/* Create an R2 packet in response. */
	HIP_IFEL(entry->hadb_misc_func->hip_create_r2(
			 &i2_context, i2_saddr, i2_daddr, entry, i2_info, &dest, dest_port), -1,
		 "Creation of R2 failed\n");

#ifdef CONFIG_HIP_ESCROW
	if (hip_deliver_escrow_data(
		    i2_daddr, i2_saddr, &i2_context.input->hitr, &i2_context.input->hits,
		    &spi_out, esp_tfm, &i2_context.esp_out, HIP_ESCROW_OPERATION_ADD)
	    != 0) {
		HIP_DEBUG("Could not deliver escrow data to server\n");
	}
#endif //CONFIG_HIP_ESCROW

	/** @todo Should wait for ESP here or wait for implementation specific
	    time. */

	/* As for the above todo item:

	   Where is it said that we should wait for ESP or implementation
	   specific time here? This far we have succesfully verified and
	   processed the I2 message (except the LOCATOR parameter) and sent an
	   R2 as an response. We are here at state UNASSOCIATED. From Section
	   4.4.2. of RFC 5201 we learn that if I2 processing was successful, we
	   should "send R2 and go to R2-SENT" or if I2 processing failed, we
	   should "stay at UNASSOCIATED". -Lauri 29.04.2008 */

	entry->state = HIP_STATE_ESTABLISHED;

	/*For SAVA this lets to register the client on firewall once the keys are established*/
	hip_firewall_set_i2_data(SO_HIP_FW_I2_DONE, entry, &entry->hit_our,
				 &entry->hit_peer, i2_saddr, i2_daddr);

        /***** LOCATOR PARAMETER ******/
	/* Why do we process the LOCATOR parameter only after R2 has been sent?
	   -Lauri 29.04.2008.
	   We do not have valid spi_out to put the addresses into and NAT benefits
	   from the later handling ...
	   --samu
	*/

	/***** LOCATOR PARAMETER *****/
	hip_handle_locator_parameter(entry, hip_get_param(i2, HIP_PARAM_LOCATOR), esp_info);

#ifdef HIP_USE_ICE
	if (hip_get_nat_mode(entry) == HIP_NAT_MODE_ICE_UDP) {
		i2_context.esp_info = esp_info;
		entry->ice_control_role = ICE_ROLE_CONTROLLED;
		hip_nat_start_ice(entry, &i2_context);
	}
#endif

//end add

	HIP_DEBUG("Reached %s state\n", hip_state_str(entry->state));
	if (entry->hip_msg_retrans.buf) {
		free(entry->hip_msg_retrans.buf);
		entry->hip_msg_retrans.buf = NULL;
	}

 out_err:
	/* 'ha' is not NULL if hip_receive_i2() fetched the HA for us. In that
	   case we must not release our reference to it. Otherwise, if 'ha' is
	   NULL, then we created the HIP HA in this function and we should free
	   the reference. */
	/* 'entry' cannot be NULL here anymore since it has been used in this
	   function directly without NULL check. -Lauri. */
	if(entry != NULL) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	if (tmp_enc != NULL)
		free(tmp_enc);
	if (i2_context.dh_shared_key != NULL)
		free(i2_context.dh_shared_key);

	return err;
}

int hip_receive_i2(hip_common_t *i2, in6_addr_t *i2_saddr, in6_addr_t *i2_daddr,
		   hip_ha_t *entry, hip_portpair_t *i2_info)
{
	int state = 0, err = 0;
	uint16_t mask = HIP_PACKET_CTRL_ANON;
	_HIP_DEBUG("hip_receive_i2() invoked.\n");

	HIP_IFEL(ipv6_addr_any(&i2->hitr), 0,
		 "Received NULL receiver HIT in I2. Dropping\n");

	HIP_IFEL(!hip_controls_sane(ntohs(i2->control), mask), 0,
		 "Received illegal controls in I2: 0x%x. Dropping\n",
		 ntohs(i2->control));

	if (entry == NULL) {
#ifdef CONFIG_HIP_RVS
	     if(hip_relay_get_status() == HIP_RELAY_ON)
	     {
		  hip_relrec_t *rec = NULL, dummy;

		  /* Check if we have a relay record in our database matching the
		     Responder's HIT. We should find one, if the Responder is
		     registered to relay.*/
		  HIP_DEBUG_HIT("Searching relay record on HIT ", &i2->hitr);
		  memcpy(&(dummy.hit_r), &i2->hitr, sizeof(i2->hitr));
		  rec = hip_relht_get(&dummy);
		  if(rec == NULL)
 		       HIP_INFO("No matching relay record found.\n");
 		  else if(rec->type == HIP_FULLRELAY)
 		  {
 		       HIP_INFO("Matching relay record found:Full-Relay.\n");
 		       hip_relay_forward(i2, i2_saddr, i2_daddr, rec, i2_info, HIP_I2, HIP_FULLRELAY);
 		       state = HIP_STATE_NONE;
 		       err = -ECANCELED;
 		       goto out_err;

 		  }
	     }
#endif
//end
		state = HIP_STATE_UNASSOCIATED;
	} else  {
		HIP_LOCK_HA(entry);
		state = entry->state;
	}

	HIP_DEBUG("Received I2 in state %s\n", hip_state_str(state));

	switch(state) {
	case HIP_STATE_UNASSOCIATED:
		/* Possibly no state created yet, thus function pointers can't
		   be used here. */
		err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())->
			hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);

		break;
	case HIP_STATE_I2_SENT:
		if (entry->is_loopback) {
			err = hip_handle_i2(i2, i2_saddr, i2_daddr, entry,
					    i2_info);
		} else if (hip_hit_is_bigger(&entry->hit_our,
					     &entry->hit_peer)) {
			HIP_IFEL(hip_receive_i2(i2, i2_saddr, i2_daddr, entry,
						i2_info), -ENOSYS,
				 "Dropping HIP packet.\n");
		}
		break;
	case HIP_STATE_I1_SENT:
	case HIP_STATE_R2_SENT:
		err = hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);
		break;
	case HIP_STATE_ESTABLISHED:
		err = entry->hadb_handle_func->
			hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);

		break;
	case HIP_STATE_CLOSING:
	case HIP_STATE_CLOSED:
		err = entry->hadb_handle_func->
			hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);
		break;
	default:
		HIP_ERROR("Internal state (%d) is incorrect\n", state);
		break;
	}

	if (entry != NULL) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}

 out_err:
	if (err) {
		HIP_ERROR("Error (%d) occurred\n", err);
	}

	return err;
}

int hip_handle_r2(hip_common_t *r2, in6_addr_t *r2_saddr, in6_addr_t *r2_daddr,
		  hip_ha_t *entry, hip_portpair_t *r2_info)
{
	struct hip_context *ctx = NULL;
 	struct hip_esp_info *esp_info = NULL;
	struct hip_spi_out_item spi_out_data;
	int err = 0, tfm = 0, retransmission = 0, type_count = 0, idx = 0;
	uint32_t spi_recvd = 0, spi_in = 0;
	int i = 0;
	void *ice_session = 0;

#ifdef CONFIG_HIP_I3
	if(entry && entry->hip_is_hi3_on){
		if(r2_info->hi3_in_use){
			/* In hi3 real addresses should already be in entry, received on
			   r1 phase. */
			memcpy(r2_saddr, &entry->peer_addr, sizeof(struct in6_addr));
			memcpy(r2_daddr, &entry->our_addr, sizeof(struct in6_addr));
		}
	}
#endif

	if (entry->state == HIP_STATE_ESTABLISHED) {
		retransmission = 1;
		HIP_DEBUG("Retransmission\n");
	} else {
		HIP_DEBUG("Not a retransmission\n");
	}

	/* assume already locked entry */
	HIP_IFE(!(ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_ATOMIC)), -ENOMEM);
	memset(ctx, 0, sizeof(struct hip_context));
        ctx->input = r2;

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
		HIP_IFEL(hip_blind_verify_r2(r2, entry), -1,
			 "hip_blind_verify_host_id() failed.\n");
	}
#endif

	
        /* Verify HMAC /*
	if (entry->is_loopback) {
		HIP_IFEL(hip_verify_packet_hmac2(
				 r2, &entry->hip_hmac_out, entry->peer_pub), -1,
			 "HMAC validation on R2 failed.\n");
	} else {
		HIP_IFEL(hip_verify_packet_hmac2(
				 r2, &entry->hip_hmac_in, entry->peer_pub), -1,
			 "HMAC validation on R2 failed.\n");
	}

	/* Signature validation */
 	HIP_IFEL(entry->verify(entry->peer_pub_key, r2), -EINVAL,
		 "R2 signature verification failed.\n");

	/* The rest */
 	HIP_IFEL(!(esp_info = hip_get_param(r2, HIP_PARAM_ESP_INFO)), -EINVAL,
		 "Parameter SPI not found.\n");

	spi_recvd = ntohl(esp_info->new_spi);
	memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
	spi_out_data.spi = spi_recvd;
	HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT, &spi_out_data), -1);

	/* Copy SPI out value here or otherwise ICE code has zero SPI */
	entry->default_spi_out = spi_recvd;
	HIP_DEBUG("Set default SPI out = 0x%x\n", spi_recvd);

	memcpy(&ctx->esp_out, &entry->esp_out, sizeof(ctx->esp_out));
	memcpy(&ctx->auth_out, &entry->auth_out, sizeof(ctx->auth_out));
	HIP_DEBUG("entry should have only one spi_in now, test\n");

	spi_in = hip_hadb_get_latest_inbound_spi(entry);
	HIP_DEBUG("spi_in: 0x%x\n", spi_in);

	tfm = entry->esp_transform;
	HIP_DEBUG("esp_transform: %i\n", tfm);

	HIP_DEBUG("R2 packet source port: %d, destination port %d.\n",
		  r2_info->src_port, r2_info->dst_port);

	/********** ESP-PROT anchor [OPTIONAL] **********/

	HIP_IFEL(esp_prot_r2_handle_anchor(entry, ctx), -1,
			"failed to handle esp prot anchor\n");

	/************************************************/
/*comment out for draft v6
	hip_nat_handle_pacing(r2, entry);
*/	
    /***** LOCATOR PARAMETER *****/
	hip_handle_locator_parameter(entry,
			hip_get_param(r2, HIP_PARAM_LOCATOR), esp_info);
//end add

// moved from hip_create_i2
/* For the above comment. When doing fixes like the above move, please check
   that the code compiles with the affected flags. With CONFIG_HIP_BLIND we get
   five errors and two warnings. They are now fixed, but the code is not tested
   to work. I.e. the code compiles but does not neccessarily work.
    Lauri 22.07.2008
*/
#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
		/* let the setup routine give us a SPI. */
		HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(
				 r2_saddr, r2_daddr, &entry->hit_peer,
				 &entry->hit_our, spi_in, entry->esp_transform,
				 &ctx->esp_in, &ctx->auth_in, 0,
				 HIP_SPI_DIRECTION_IN, 0, entry), -1,
			 "BLIND: Failed to setup IPsec SPD/SA entries.\n");
	}
#endif

	if(hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP) {
		if (!hip_blind_get_status()) {
		  HIP_DEBUG("Blind is OFF\n");
		  HIP_DEBUG_HIT("hit our", &entry->hit_our);
		  HIP_DEBUG_HIT("hit peer", &entry->hit_peer);
		  HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(r2_saddr,
				  r2_daddr, &ctx->input->hits, &ctx->input->hitr,
				  spi_in, tfm, &entry->esp_in, &entry->auth_in, 0,
				  HIP_SPI_DIRECTION_IN, 0, entry), -1,
				  "Failed to setup IPsec SPD/SA entries, peer:src\n");
		}
	}
	else{
		//spi should be created
		HIP_DEBUG("ICE engine will be used, no sa created here\n");
	}

// end of modify

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
		err = entry->hadb_ipsec_func->hip_add_sa(
			r2_daddr, r2_saddr, &entry->hit_our, &entry->hit_peer,
			spi_recvd, tfm, &ctx->esp_out, &ctx->auth_out, 1,
			HIP_SPI_DIRECTION_OUT, 0, entry);
	}
#endif
	
	if(hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP){
		if (!hip_blind_get_status()) {
		  err = entry->hadb_ipsec_func->hip_add_sa(r2_daddr, r2_saddr,
					 &ctx->input->hitr, &ctx->input->hits,
					 spi_recvd, tfm,
					 &ctx->esp_out, &ctx->auth_out, 0,
					 HIP_SPI_DIRECTION_OUT, 0, entry);
		}

		if (err) {
			/** @todo Remove inbound IPsec SA. */
			HIP_ERROR("hip_add_sa() failed, peer:dst (err = %d).\n", err);
			err = -1;
			goto out_err;
		}
	}
	else{
		HIP_DEBUG("ICE engine will be used, no sa created here\n");
	}
//end modify




	/** @todo Check for -EAGAIN */
	HIP_DEBUG("Set up outbound IPsec SA, SPI = 0x%x (host).\n", spi_recvd);

#ifdef CONFIG_HIP_ESCROW
	if (hip_deliver_escrow_data(r2_daddr, r2_saddr, &ctx->input->hitr,
				    &ctx->input->hits, &spi_recvd, tfm,
				    &ctx->esp_out, HIP_ESCROW_OPERATION_ADD)
	    != 0) {
		HIP_DEBUG("Could not deliver escrow data to server.\n");
	}
#endif //CONFIG_HIP_ESCROW

        /* Source IPv6 address is implicitly the preferred address after the
	   base exchange. */

	/* @todo port must be added */
#ifndef HIP_USE_ICE
	err = hip_hadb_add_addr_to_spi(entry, spi_recvd, r2_saddr, 1, 0, 1);
#else
	// when ice implemenation is included
	// if ice mode is on, we do not add the current address into peer list (can be added also, but set the is_prefered off)
	err = 0;
	if(hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP)
	HIP_IFEL(hip_hadb_add_udp_addr_to_spi(entry, spi_recvd, r2_saddr, 1, 0, 1,r2_info->src_port, HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI_PRIORITY,0),
			 -1,  "Failed to add an address to SPI list\n");
#endif

	if (err) {
		HIP_ERROR("hip_hadb_add_addr_to_spi() err = %d not handled.\n",
			  err);
	}

	idx = hip_devaddr2ifindex(r2_daddr);

	if (idx != 0) {
		HIP_DEBUG("ifindex = %d\n", idx);
		hip_hadb_set_spi_ifindex(entry, spi_in, idx);
	} else {
		HIP_ERROR("Couldn't get device ifindex of address\n");
	}

#ifdef HIP_USE_ICE
	hip_relay_handle_relay_to_in_client(r2,HIP_R2, r2_saddr, r2_daddr,r2_info, entry);

	
	if (hip_get_nat_mode(entry) == HIP_NAT_MODE_ICE_UDP) {
		ctx->esp_info = esp_info;
	        entry->ice_control_role = ICE_ROLE_CONTROLLING;
	        hip_nat_start_ice(entry, ctx);
	}
#endif
        /* Copying address list from temp location in entry
	  "entry->peer_addr_list_to_be_added" */
	hip_copy_peer_addrlist_to_spi(entry);

	/* Handle REG_RESPONSE and REG_FAILED parameters. */
	hip_handle_param_reg_response(entry, r2);
	hip_handle_param_reg_failed(entry, r2);

	hip_handle_reg_from(entry, r2);

	/* These will change SAs' state from ACQUIRE to VALID, and wake up any
	   transport sockets waiting for a SA. */
	// hip_finalize_sa(&entry->hit_peer, spi_recvd);
	// hip_finalize_sa(&entry->hit_our, spi_in);

	entry->state = HIP_STATE_ESTABLISHED;
	hip_hadb_insert_state(entry);

#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* Check and remove the IP of the peer from the opp non-HIP database */
	hip_oppipdb_delentry(&(entry->peer_addr));
#endif
	HIP_DEBUG("Reached ESTABLISHED state\n");
	if (entry->hip_msg_retrans.buf) {
		free(entry->hip_msg_retrans.buf);
		entry->hip_msg_retrans.buf = NULL;
	}

	/* Send the first heartbeat. Notice that the error is ignored to complete
	   the base exchange successfully. */
	
	if (hip_icmp_interval > 0 & hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP) {
		hip_send_icmp(hip_icmp_sock, entry);
	}

	//TODO Send the R2 Response to Firewall

 out_err:
	/* if (entry->state == HIP_STATE_ESTABLISHED) { */
	/*         HIP_DEBUG("Send response to firewall \n"); */
	/*         hip_firewall_set_bex_data(SO_HIP_FW_BEX_DONE, entry, &entry->hit_our, &entry->hit_peer); */
	/* 	if (entry->peer_controls & HIP_HA_CTRL_PEER_GRANTED_SAVAH) { */
	/* 	  //Enable savah client mode on the firewall */
	/* 	  hip_set_sava_client_on(); */
	/* 	  hip_firewall_set_savah_status(SO_HIP_SET_SAVAH_CLIENT_ON); */
	/* 	} else { */
	/* 	  HIP_DEBUG("Entry control flag is not HIP_HA_CTRL_PEER_GRANTED_SAVAH. Value is %d \n", entry->local_controls); */
	/* 	} */
	/* } else { */
	/* 	hip_firewall_set_bex_data(SO_HIP_FW_BEX_DONE, entry, NULL, NULL); */
	/* } */

	if (ctx) {
		HIP_FREE(ctx);
	}
        return err;
}

int hip_handle_i1(struct hip_common *i1, struct in6_addr *i1_saddr,
		  struct in6_addr *i1_daddr, hip_ha_t *entry,
		  hip_portpair_t *i1_info)
{
     int err = 0, state;
     hip_tlv_type_t  relay_para_type = 0;
     uint16_t nonce = 0;
     in6_addr_t dest; // For the IP address in FROM/RELAY_FROM
     in_port_t  dest_port = 0; // For the port in RELAY_FROM

     HIP_DEBUG("hip_handle_i1() invoked.\n");

     ipv6_addr_copy(&dest, &in6addr_any);

#ifdef CONFIG_HIP_RVS
     if (hip_hidb_hit_is_our(&i1->hitr)) {
	     /* This is where the Responder handles the incoming relayed I1
		packet. We need two things from the relayed packet:
		1) The destination IP address and port from the FROM/RELAY_FROM
		parameters.
		2) The source address and source port of the I1 packet to build
		the VIA_RVS/RELAY_TO parameter.
		3) only one relay parameter should appear
		*/
    	 state = hip_relay_handle_from(i1, i1_saddr, &dest, &dest_port);
	     if( state == -1){
	    	 HIP_DEBUG( "Handling FROM of  I1 packet failed.\n");
	    	 goto out_err;
	     }else if(state == 1){
	    	 relay_para_type = HIP_PARAM_FROM;
	     }

    	 state = hip_relay_handle_relay_from(i1, i1_saddr, &dest, &dest_port);
	     if( state == -1 ){
	    	 HIP_DEBUG( "Handling RELAY_FROM of  I1 packet failed.\n");
	    	 goto out_err;
	     }else if(state == 1){
	    	 relay_para_type = HIP_PARAM_RELAY_FROM;
	     }

     }
#endif /* CONFIG_HIP_RVS */

     /* @todo: how to the handle the blind code with RVS?? */
#ifdef CONFIG_HIP_BLIND
     if (hip_blind_get_status()) {
	  HIP_DEBUG("Blind is on\n");
	  // We need for R2 transmission: see hip_xmit_r1 below
	  HIP_IFEL(hip_blind_get_nonce(i1, &nonce),
		   -1, "hip_blind_get_nonce failed\n");
     }
#endif
     err = hip_xmit_r1(i1, i1_saddr, i1_daddr, &dest, dest_port, i1_info,
		       relay_para_type );
 out_err:
     return err;
}


int hip_receive_i1(struct hip_common *i1, struct in6_addr *i1_saddr,
		   struct in6_addr *i1_daddr, hip_ha_t *entry,
		   hip_portpair_t *i1_info)
{
	int err = 0, state, mask = 0, src_hit_is_our;

	_HIP_DEBUG("hip_receive_i1() invoked.\n");

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status())
	  mask |= HIP_PACKET_CTRL_BLIND;
#endif

	HIP_ASSERT(!ipv6_addr_any(&i1->hitr));

	HIP_DEBUG_IN6ADDR("Source IP", i1_saddr);
	HIP_DEBUG_IN6ADDR("Destination IP", i1_daddr);

	/* In some environments, a copy of broadcast our own I1 packets
	   arrive at the local host too. The following variable handles
	   that special case. Since we are using source HIT (and not
           destination) it should handle also opportunistic I1 broadcast */
	src_hit_is_our = hip_hidb_hit_is_our(&i1->hits);

	/* check i1 for broadcast/multicast addresses */
	if (IN6_IS_ADDR_V4MAPPED(i1_daddr))
        {
		struct in_addr addr4;

		IPV6_TO_IPV4_MAP(i1_daddr, &addr4);

		if (addr4.s_addr == INADDR_BROADCAST)
		{
			HIP_DEBUG("Received i1 broadcast\n");
			HIP_IFEL(src_hit_is_our, -1,
				 "Received a copy of own broadcast, dropping\n");
			HIP_IFEL(hip_select_source_address(i1_daddr, i1_saddr), -1,
				 "Could not find source address\n");
		}

	} else if (IN6_IS_ADDR_MULTICAST(i1_daddr)) {
			HIP_IFEL(src_hit_is_our, -1,
				 "Received a copy of own broadcast, dropping\n");
			HIP_IFEL(hip_select_source_address(i1_daddr, i1_saddr), -1,
				 "Could not find source address\n");
	}

 	HIP_IFEL(!hip_controls_sane(ntohs(i1->control), mask), -1,
		 "Received illegal controls in I1: 0x%x. Dropping\n", ntohs(i1->control));

	if (entry) {
		state = entry->state;
		hip_put_ha(entry);
	}
	else {

#ifdef CONFIG_HIP_RVS
	  if (hip_relay_get_status() == HIP_RELAY_ON &&
	      !hip_hidb_hit_is_our(&i1->hitr))
	     {
		  hip_relrec_t *rec = NULL, dummy;

		  /* Check if we have a relay record in our database matching the
		     Responder's HIT. We should find one, if the Responder is
		     registered to relay.*/
		  HIP_DEBUG_HIT("Searching relay record on HIT ", &i1->hitr);
		  memcpy(&(dummy.hit_r), &i1->hitr, sizeof(i1->hitr));
		  rec = hip_relht_get(&dummy);
		  if(rec == NULL)
 		       HIP_INFO("No matching relay record found.\n");
 		  else if (rec->type == HIP_FULLRELAY || rec->type == HIP_RVSRELAY)
 		  {
 		       HIP_INFO("Matching relay record found:Full-Relay.\n");
 		       hip_relay_forward(i1, i1_saddr, i1_daddr, rec, i1_info, HIP_I1, rec->type);
 		       state = HIP_STATE_NONE;
 		       err = -ECANCELED;
 		       goto out_err;
 		  }
	     }
#endif
		state = HIP_STATE_NONE;
	}

	HIP_DEBUG("Received I1 in state %s\n", hip_state_str(state));

	switch(state) {
	case HIP_STATE_NONE:
	     err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())
		  ->hip_handle_i1(i1, i1_saddr, i1_daddr, entry, i1_info);
	     break;
	case HIP_STATE_I1_SENT:
	     	if (src_hit_is_our || /* loopback */
		    hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer)) {
			err = ((hip_handle_func_set_t *)
			       hip_get_handle_default_func_set())->
				hip_handle_i1(i1, i1_saddr, i1_daddr, entry,
					      i1_info);
	     	}
	     break;
	case HIP_STATE_UNASSOCIATED:
	case HIP_STATE_I2_SENT:
	case HIP_STATE_R2_SENT:
	case HIP_STATE_ESTABLISHED:
	case HIP_STATE_CLOSED:
	case HIP_STATE_CLOSING:
	     err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())
		  ->hip_handle_i1(i1, i1_saddr, i1_daddr, entry, i1_info);
	     break;
	default:
	     /* should not happen */
	     HIP_IFEL(1, -EINVAL, "DEFAULT CASE, UNIMPLEMENTED STATE HANDLING OR A BUG\n");
	}

 out_err:
	return err;
}

int hip_receive_r2(struct hip_common *hip_common,
		   struct in6_addr *r2_saddr,
		   struct in6_addr *r2_daddr,
		   hip_ha_t *entry,
		   hip_portpair_t *r2_info)
{
	int err = 0, state;
	uint16_t mask = 0;

	_HIP_DEBUG("hip_receive_r2() invoked.\n");

	HIP_IFEL(ipv6_addr_any(&hip_common->hitr), -1,
		 "Received NULL receiver HIT in R2. Dropping\n");

	HIP_IFEL(!hip_controls_sane(ntohs(hip_common->control), mask), -1,
		 "Received illegal controls in R2: 0x%x. Dropping\n", ntohs(hip_common->control));
	//HIP_IFEL(!(entry = hip_hadb_find_byhits(&hip_common->hits,
	//					&hip_common->hitr)), -EFAULT,
	//	 "Received R2 by unknown sender\n");

	HIP_IFEL(!entry, -EFAULT,
		 "Received R2 by unknown sender\n");

	HIP_LOCK_HA(entry);
	state = entry->state;
	
	// if the NAT mode is used, update the port numbers of the host association 
	if (r2_info->dst_port == hip_get_local_nat_udp_port())
	{
		entry->local_udp_port = r2_info->dst_port;
		entry->peer_udp_port = r2_info->src_port;
	}

	HIP_DEBUG("Received R2 in state %s\n", hip_state_str(state));
 	switch(state) {
 	case HIP_STATE_I2_SENT:
 		/* The usual case. */
 		err = entry->hadb_handle_func->hip_handle_r2(hip_common,
							     r2_saddr,
							     r2_daddr,
							     entry,
							     r2_info);
		if (err) {
			HIP_ERROR("hip_handle_r2 failed (err=%d)\n", err);
			goto out_err;
 		}
	break;

 	case HIP_STATE_ESTABLISHED:
		if (entry->is_loopback)
		    err = entry->hadb_handle_func->hip_handle_r2(hip_common,
								 r2_saddr,
								 r2_daddr,
								 entry,
								 r2_info);
		break;
	case HIP_STATE_R2_SENT:
	case HIP_STATE_UNASSOCIATED:
 	case HIP_STATE_I1_SENT:
 	default:
		HIP_IFEL(1, -EFAULT, "Dropping\n");
 	}

 out_err:
	if (entry) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	return err;
}

int hip_receive_notify(const struct hip_common *notify,
		       const struct in6_addr *notify_saddr,
		       const struct in6_addr *notify_daddr, hip_ha_t* entry)
{
	int err = 0;
	struct hip_notification *notify_param;
	uint16_t mask = HIP_PACKET_CTRL_ANON, notify_controls = 0;

	_HIP_DEBUG("hip_receive_notify() invoked.\n");

	HIP_IFEL(entry == NULL , -EFAULT,
		 "Received a NOTIFY packet from an unknown sender, ignoring "\
		 "the packet.\n");

	notify_controls = ntohs(notify->control);

	HIP_IFEL(!hip_controls_sane(notify_controls, mask), -EPROTO,
		 "Received a NOTIFY packet with illegal controls: 0x%x, ignoring "\
		 "the packet.\n", notify_controls);

	err = hip_handle_notify(notify, notify_saddr, notify_daddr, entry);

 out_err:
	if (entry != NULL)
		hip_put_ha(entry);

	return err;
}

int hip_handle_notify(const struct hip_common *notify,
		      const struct in6_addr *notify_saddr,
		      const struct in6_addr *notify_daddr, hip_ha_t* entry)
{
	int err = 0;
	struct hip_common i1;
	struct hip_tlv_common *current_param = NULL;
	struct hip_notification *notification = NULL;
	struct in6_addr responder_ip, responder_hit;
	hip_tlv_type_t param_type = 0, response;
	hip_tlv_len_t param_len = 0;
	uint16_t msgtype = 0;
	in_port_t port = 0;

	/* draft-ietf-hip-base-06, Section 6.13: Processing NOTIFY packets is
	   OPTIONAL. If processed, any errors in a received NOTIFICATION parameter
	   SHOULD be logged. */

	_HIP_DEBUG("hip_receive_notify() invoked.\n");

	/* Loop through all the parameters in the received I1 packet. */
	while ((current_param =
		hip_get_next_param(notify, current_param)) != NULL) {

		param_type = hip_get_param_type(current_param);

		if (param_type == HIP_PARAM_NOTIFICATION) {
			HIP_INFO("Found NOTIFICATION parameter in NOTIFY "\
				 "packet.\n");
			notification = (struct hip_notification *)current_param;

			param_len = hip_get_param_contents_len(current_param);
			msgtype = ntohs(notification->msgtype);

			switch(msgtype) {
			case HIP_NTF_UNSUPPORTED_CRITICAL_PARAMETER_TYPE:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "UNSUPPORTED_CRITICAL_PARAMETER_"\
					 "TYPE.\n");
				break;
			case HIP_NTF_INVALID_SYNTAX:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "INVALID_SYNTAX.\n");
				break;
			case HIP_NTF_NO_DH_PROPOSAL_CHOSEN:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "NO_DH_PROPOSAL_CHOSEN.\n");
				break;
			case HIP_NTF_INVALID_DH_CHOSEN:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "INVALID_DH_CHOSEN.\n");
				break;
			case HIP_NTF_NO_HIP_PROPOSAL_CHOSEN:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "NO_HIP_PROPOSAL_CHOSEN.\n");
				break;
			case HIP_NTF_INVALID_HIP_TRANSFORM_CHOSEN:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "INVALID_HIP_TRANSFORM_CHOSEN.\n");
				break;
			case HIP_NTF_AUTHENTICATION_FAILED:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "AUTHENTICATION_FAILED.\n");
				break;
			case HIP_NTF_CHECKSUM_FAILED:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "CHECKSUM_FAILED.\n");
				break;
			case HIP_NTF_HMAC_FAILED:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "HMAC_FAILED.\n");
				break;
			case HIP_NTF_ENCRYPTION_FAILED:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "ENCRYPTION_FAILED.\n");
				break;
			case HIP_NTF_INVALID_HIT:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "INVALID_HIT.\n");
				break;
			case HIP_NTF_BLOCKED_BY_POLICY:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "BLOCKED_BY_POLICY.\n");
				break;
			case HIP_NTF_SERVER_BUSY_PLEASE_RETRY:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "SERVER_BUSY_PLEASE_RETRY.\n");
				break;
			case HIP_NTF_I2_ACKNOWLEDGEMENT:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "I2_ACKNOWLEDGEMENT.\n");
				break;
			case HIP_PARAM_RELAY_TO:
			case HIP_PARAM_RELAY_FROM:
				response = ((msgtype == HIP_PARAM_RELAY_TO) ? HIP_I1 : HIP_NOTIFY);
				HIP_INFO("NOTIFICATION parameter type is "\
					 "RVS_NAT.\n");

				/* responder_hit is not currently used. */
				ipv6_addr_copy(&responder_hit, (struct in6_addr *)
					       notification->data);
				ipv6_addr_copy(&responder_ip, (struct in6_addr *)
					       &(notification->
						 data[sizeof(struct in6_addr)]));
				memcpy(&port, &(notification->
						data[2 * sizeof(struct in6_addr)]),
				       sizeof(in_port_t));

				/* If port is zero (the responder is not behind
				   a NAT) we use hip_get_nat_udp_port() as the destination
				   port. */
				if(port == 0) {
					port = hip_get_peer_nat_udp_port();
				}

				/* We don't need to use hip_msg_alloc(), since
				   the I1 packet is just the size of struct
				   hip_common. */
				memset(&i1, 0, sizeof(i1));

				entry->hadb_misc_func->
					hip_build_network_hdr(&i1,
							      response,
							      entry->local_controls,
							      &entry->hit_our,
							      &entry->hit_peer);

				/* Calculate the HIP header length */
				hip_calc_hdr_len(&i1);

				//sleep(3);

				/* This I1 packet must be send only once, which
				   is why we use NULL entry for sending. */
				err = entry->hadb_xmit_func->
					hip_send_pkt(&entry->our_addr, &responder_ip,
						     (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
						     port,
						     &i1, NULL, 0);

				break;
			default:
				HIP_INFO("Unrecognized NOTIFICATION parameter "\
					 "type.\n");
				break;
			}
			HIP_HEXDUMP("NOTIFICATION parameter notification data:",
				    notification->data,
				    param_len
				    - sizeof(notification->reserved)
				    - sizeof(notification->msgtype)
				);
			msgtype = 0;
		}
		else {
			HIP_INFO("Found unsupported parameter in NOTIFY "\
				 "packet.\n");
		}
	}

	return err;
}

int hip_receive_bos(struct hip_common *bos,
		    struct in6_addr *bos_saddr,
		    struct in6_addr *bos_daddr,
		    hip_ha_t *entry,
		    hip_portpair_t *bos_info)
{
	int err = 0, state = 0;

	_HIP_DEBUG("hip_receive_bos() invoked.\n");

	HIP_IFEL(ipv6_addr_any(&bos->hits), 0,
		 "Received NULL sender HIT in BOS.\n");
	HIP_IFEL(!ipv6_addr_any(&bos->hitr), 0,
		 "Received non-NULL receiver HIT in BOS.\n");
	HIP_DEBUG("Entered in hip_receive_bos...\n");
	state = entry ? entry->state : HIP_STATE_UNASSOCIATED;

	/** @todo If received BOS packet from already known sender should return
	    right now */
	HIP_DEBUG("Received BOS packet in state %s\n", hip_state_str(state));
 	switch(state) {
 	case HIP_STATE_UNASSOCIATED:
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
		/* Possibly no state created yet */
		err = entry->hadb_handle_func->hip_handle_bos(bos, bos_saddr, bos_daddr, entry, bos_info);
		break;
	case HIP_STATE_R2_SENT:
 	case HIP_STATE_ESTABLISHED:
		HIP_DEBUG("BOS not handled in state %s\n", hip_state_str(state));
		break;
	default:
		HIP_IFEL(1, 0, "Internal state (%d) is incorrect\n", state);
	}

	if (entry)
		hip_put_ha(entry);
 out_err:
	return err;
}

int hip_handle_firewall_i1_request(struct hip_common *msg,
				   struct in6_addr *i1_saddr,
				   struct in6_addr *i1_daddr)
{
	int err = 0, if_index = 0, is_ipv4_locator,
		reuse_hadb_local_address = 0, ha_nat_mode = hip_nat_status,
                old_global_nat_mode = hip_nat_status;
	in_port_t ha_local_port, ha_peer_port;
	hip_ha_t *entry;
	hip_hit_t *src_hit, *dst_hit;
	hip_lsi_t *lsi = NULL;
	int is_loopback = 0;
	struct in6_addr src_addr;
//	struct xfrm_user_acquire *acq;
	struct in6_addr dst_addr, ha_match;
	struct sockaddr_storage ss_addr;
	struct sockaddr *addr;
	addr = (struct sockaddr*) &ss_addr;

	HIP_DEBUG("Acquire from Firewall: sending I1! \n");

	src_hit = &(msg->hits);
	dst_hit = &(msg->hitr);

	HIP_DEBUG_HIT("src HIT", src_hit);
	HIP_DEBUG_HIT("dst HIT", dst_hit);

	/* Sometimes we get deformed HITs from kernel, skip them */
	HIP_IFEL(!(ipv6_addr_is_hit(src_hit) && ipv6_addr_is_hit(dst_hit) &&
		   hip_hidb_hit_is_our(src_hit) &&
		   hit_is_real_hit(dst_hit)), -1,
		 "Received rubbish from firewall, skip\n");

	entry = hip_hadb_find_byhits(src_hit, dst_hit);
	if (entry) {
		reuse_hadb_local_address = 1;
		goto skip_entry_creation;
	}


	/* No entry found; find first IP matching to the HIT and then
	   create the entry */
#ifdef CONFIG_HIP_I3
	if(hip_get_hi3_status()){
		struct in_addr lpback = { htonl(INADDR_LOOPBACK) };
		IPV4_TO_IPV6_MAP(&lpback, &dst_addr);
		err = 0;
	}
	else
#endif
		err = hip_map_id_to_addr(dst_hit, NULL, &dst_addr);


	if (err) {
		/* Search HADB for existing entries */
		entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);
		if (entry) {
			HIP_DEBUG_IN6ADDR("reusing HA",
					  &entry->peer_addr);
			ipv6_addr_copy(&dst_addr, &entry->peer_addr);
			ha_local_port = entry->local_udp_port;
			ha_peer_port = entry->peer_udp_port;
			ha_nat_mode = entry->nat_mode;
			err = 0;
		}
	}

	/* map to loopback if hit is ours  */
	if (err && hip_hidb_hit_is_our(dst_hit)) {
		struct in6_addr lpback = IN6ADDR_LOOPBACK_INIT;
		ipv6_addr_copy(&dst_addr, &lpback);
		ipv6_addr_copy(&src_addr, &lpback);
		is_loopback = 1;
		reuse_hadb_local_address = 1;
		err = 0;
	}

	/* broadcast I1 as a last resource */
	if (err) {
		struct in_addr bcast = { INADDR_BROADCAST };
		/* IPv6 multicast (see bos.c) failed to bind() to link local,
		   so using IPv4 here -mk */
		HIP_DEBUG("No information of peer found, trying broadcast\n");
		IPV4_TO_IPV6_MAP(&bcast, &dst_addr);
		/* Broadcast did not work with UDP packets -mk */
		ha_nat_mode = 0;
		err = 0;
	}

	/* @fixme: changing global state won't work with threads */
	hip_nat_status = ha_nat_mode;

	if (entry) {
		lsi = &(entry->lsi_peer);
	}

	HIP_IFEL(hip_hadb_add_peer_info(dst_hit, &dst_addr, lsi, NULL), -1,
		 "map failed\n");

	hip_nat_status = old_global_nat_mode; /* restore nat status */

	HIP_IFEL(!(entry = hip_hadb_find_byhits(src_hit, dst_hit)), -1,
		 "Internal lookup error\n");

	if (is_loopback)
		ipv6_addr_copy(&(entry->our_addr), &src_addr);

	/* Preserve NAT status with peer */
	entry->local_udp_port = ha_local_port;
	entry->peer_udp_port = ha_peer_port;
	entry->nat_mode = ha_nat_mode;

	reuse_hadb_local_address = 1;

skip_entry_creation:

	if (entry->state == HIP_STATE_ESTABLISHED) {
		HIP_DEBUG("Acquire from firewall in established state (hard handover?), skip\n");
		goto out_err;
	} else if (entry->state == HIP_STATE_NONE ||
	    entry->state == HIP_STATE_UNASSOCIATED) {
		HIP_DEBUG("State is %d, sending i1\n", entry->state);
	} else if (entry->hip_msg_retrans.buf == NULL) {
		HIP_DEBUG("Expired retransmissions, sending i1\n");
	} else {
		HIP_DEBUG("I1 was already sent, ignoring\n");
		goto out_err;
	}

	is_ipv4_locator = IN6_IS_ADDR_V4MAPPED(&entry->peer_addr);

	memset(addr, 0, sizeof(struct sockaddr_storage));
	addr->sa_family = (is_ipv4_locator ? AF_INET : AF_INET6);

	if (!reuse_hadb_local_address)
		if (is_ipv4_locator) {
			IPV4_TO_IPV6_MAP((struct in_addr*) i1_saddr,
					&entry->our_addr);
//			IPV4_TO_IPV6_MAP(((struct in_addr *)&acq->id.daddr),
//					 &entry->our_addr);
		} else {
			ipv6_addr_copy(&entry->our_addr,
					(struct in6_addr*) i1_saddr);
//			ipv6_addr_copy(&entry->our_addr,
//				       ((struct in6_addr*)&acq->id.daddr));

		}

	memcpy(hip_cast_sa_addr(addr), &entry->our_addr,
	       hip_sa_addr_len(addr));

	HIP_DEBUG_HIT("our hit", &entry->hit_our);
        HIP_DEBUG_HIT("peer hit", &entry->hit_peer);
	HIP_DEBUG_IN6ADDR("peer locator", &entry->peer_addr);
	HIP_DEBUG_IN6ADDR("our locator", &entry->our_addr);

	if_index = hip_devaddr2ifindex(&entry->our_addr);
	HIP_IFEL((if_index < 0), -1, "if_index NOT determined\n");
        /* we could try also hip_select_source_address() here on failure,
	   but it seems to fail too */

	HIP_DEBUG("Using ifindex %d\n", if_index);

	//add_address_to_list(addr, if_index /*acq->sel.ifindex*/);

	HIP_IFEL(hip_send_i1(&entry->hit_our, &entry->hit_peer, entry), -1,
		 "Sending of I1 failed\n");

out_err:
	return err;
}


int handle_locator(struct hip_locator *locator,
		   in6_addr_t         *r1_saddr,
		   in6_addr_t         *r1_daddr,
		   hip_ha_t           *entry,
		   hip_portpair_t     *r1_info){
	int n_addrs = 0, loc_size = 0, err = 0;
	struct hip_locator_info_addr_item* first = NULL;
	struct netdev_address *n = NULL;
	hip_list_t *item = NULL, *tmp = NULL;
	int ii = 0, use_ip4 = 1;

	// Lets save the LOCATOR to the entry 'till we
        //   get the esp_info in r2 then handle it
        n_addrs = hip_get_locator_addr_item_count(locator);
        loc_size = sizeof(struct hip_locator) +
            (n_addrs * sizeof(struct hip_locator_info_addr_item));
        HIP_IFEL(!(entry->locator = malloc(loc_size)),
               -1, "Malloc for entry->locators failed\n");
        memcpy(entry->locator, locator, loc_size);

#ifdef CONFIG_HIP_I3
	if(entry && entry->hip_is_hi3_on){
		if( r1_info->hi3_in_use && n_addrs > 0 ){
			first = (char*)locator+sizeof(struct hip_locator);
			memcpy(r1_saddr, &first->address, sizeof(struct in6_addr));

			list_for_each_safe(item, tmp, addresses, ii){
				n = list_entry(item);
				if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
					continue;
				if (!hip_sockaddr_is_v6_mapped(&n->addr)){
					memcpy(r1_daddr, hip_cast_sa_addr(&n->addr),
					       hip_sa_addr_len(&n->addr));
					ii = -1;
					use_ip4 = 0;
					break;
				}
			}
			if( use_ip4 ){
				list_for_each_safe(item, tmp, addresses, ii){
					n = list_entry(item);
					if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
						continue;
					if (hip_sockaddr_is_v6_mapped(&n->addr)){
						memcpy(r1_daddr, hip_cast_sa_addr(&n->addr),
						       hip_sa_addr_len(&n->addr));
						ii = -1;
						break;
					}
				}
			}

			struct in6_addr daddr;

			memcpy(&entry->our_addr, r1_daddr, sizeof(struct in6_addr));

			hip_hadb_get_peer_addr(entry, &daddr);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			hip_hadb_add_peer_addr(entry, r1_saddr, 0, 0,
					       PEER_ADDR_STATE_ACTIVE);
		}
	}
#endif
out_err:
	return err;
}
