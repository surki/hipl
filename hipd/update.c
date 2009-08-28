/**
 * @file
 * This file defines various functions for sending, handling and receiving
 * UPDATE packets for the Host Identity Protocol (HIP).
 *
 * @author  Mika Kousa <mkousa#iki.fi>
 * @author  Tobias Heer <tobi#tobibox.de>
 * @author  Abhijit Bagri <abagri#gmail.com>
 * @author  Miika Komu <miika#iki.fi>
 * @author  Samu Varjonen <samu.varjonen#hiit.fi>
 * @author	Rene Hummen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * @note    Based on
 *          <a href="http://www1.ietf.org/mail-archive/web/hipsec/current/msg01745.html">Simplified state machine</a>
 */
#include "update.h"
#include "pjnath.h"

#ifndef s6_addr
#  define s6_addr                 in6_u.u6_addr8
#  define s6_addr16               in6_u.u6_addr16
#  define s6_addr32               in6_u.u6_addr32
#endif /* s6_addr */

/* All Doxygen function comments are now moved to the header file. Some comments
   are inadequate. */

/** A transmission function set for NAT traversal. */
extern hip_xmit_func_set_t nat_xmit_func_set;
/** A transmission function set for sending raw HIP packets. */
extern hip_xmit_func_set_t default_xmit_func_set;

int hip_for_each_locator_addr_item(
	int (*func) 
	(hip_ha_t *entry, struct hip_locator_info_addr_item *i, void *opaq),
	hip_ha_t *entry, struct hip_locator *locator, void *opaque)
{
	int i = 0, err = 0, n_addrs;
	struct hip_locator_info_addr_item *locator_address_item = NULL;

	n_addrs = hip_get_locator_addr_item_count(locator);
	HIP_IFEL((n_addrs < 0), -1, "Negative address count\n");

	HIP_DEBUG("LOCATOR has %d address(es), loc param len=%d\n",
		  n_addrs, hip_get_param_total_len(locator));

	HIP_IFE(!func, -1);

	locator_address_item = hip_get_locator_first_addr_item(locator);
	for (i = 0; i < n_addrs; i++ ) {
		locator_address_item = hip_get_locator_item(locator_address_item, i);
		HIP_IFEL(func(entry, locator_address_item, opaque), -1,
			 "Locator handler function returned error\n");
	}

 out_err:
	return err;
}

int hip_update_for_each_peer_addr(
	int (*func)
	(hip_ha_t *entry, struct hip_peer_addr_list_item *list_item,
	 struct hip_spi_out_item *spi_out, void *opaq),
	hip_ha_t *entry, struct hip_spi_out_item *spi_out, void *opaq)
{
	hip_list_t *item, *tmp;
	struct hip_peer_addr_list_item *addr;
	int i = 0, err = 0;

	HIP_IFE(!func, -EINVAL);

	list_for_each_safe(item, tmp, spi_out->peer_addr_list, i)
		{
			addr = list_entry(item);
			HIP_IFE(func(entry, addr, spi_out, opaq), -1);
		}

 out_err:
	return err;
}

int hip_update_for_each_local_addr(int (*func)
				   (hip_ha_t *entry,
				    struct hip_spi_in_item *spi_in,
				    void *opaq), hip_ha_t *entry,
                                   void *opaq)
{
	hip_list_t *item, *tmp;
	struct hip_spi_in_item *e;
	int i = 0, err = 0;

	HIP_IFE(!func, -EINVAL);

	list_for_each_safe(item, tmp, entry->spis_in, i)
		{
			e = list_entry(item);
			HIP_IFE(func(entry, e, opaq), -1);
		}

 out_err:
	return err;
}

int hip_update_get_sa_keys(hip_ha_t *entry, uint16_t *keymat_offset_new,
			   uint8_t *calc_index_new, uint8_t *Kn_out,
			   struct hip_crypto_key *espkey_gl,
			   struct hip_crypto_key *authkey_gl,
			   struct hip_crypto_key *espkey_lg,
			   struct hip_crypto_key *authkey_lg)
{
	unsigned char Kn[HIP_AH_SHA_LEN];
	uint16_t k = *keymat_offset_new, Kn_pos;
	uint8_t c = *calc_index_new;
	int err = 0, esp_transform, esp_transf_length = 0,
		auth_transf_length = 0;

	esp_transform = entry->esp_transform;
	esp_transf_length = hip_enc_key_length(esp_transform);
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	_HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length,
		   auth_transf_length);

	bzero(espkey_gl, sizeof(struct hip_crypto_key));
	bzero(espkey_lg, sizeof(struct hip_crypto_key));
	bzero(authkey_gl, sizeof(struct hip_crypto_key));
	bzero(authkey_lg, sizeof(struct hip_crypto_key));

	HIP_IFEL(*keymat_offset_new +
		 2*(esp_transf_length+auth_transf_length) > 0xffff, -EINVAL,
		 "Can not draw requested amount of new KEYMAT, keymat index=%u, "\
		 "requested amount=%d\n",
		 *keymat_offset_new, 2*(esp_transf_length+auth_transf_length));
	memcpy(Kn, Kn_out, HIP_AH_SHA_LEN);

	/* SA-gl */
	Kn_pos = entry->current_keymat_index -
		(entry->current_keymat_index % HIP_AH_SHA_LEN);
	HIP_IFE(hip_keymat_get_new(
			espkey_gl->key, esp_transf_length,entry->dh_shared_key,
			entry->dh_shared_key_len, &k, &c, Kn, &Kn_pos), -1);
	_HIP_HEXDUMP("ENC KEY gl", espkey_gl->key, esp_transf_length);
	k += esp_transf_length;

	HIP_IFE(hip_keymat_get_new(authkey_gl->key, auth_transf_length,
				   entry->dh_shared_key, entry->dh_shared_key_len,
				   &k, &c, Kn, &Kn_pos), -1);
	_HIP_HEXDUMP("AUTH KEY gl", authkey_gl->key, auth_transf_length);
	k += auth_transf_length;

	/* SA-lg */
	HIP_IFE(hip_keymat_get_new(espkey_lg->key, esp_transf_length,
				   entry->dh_shared_key, entry->dh_shared_key_len,
				   &k, &c, Kn, &Kn_pos), -1);
	_HIP_HEXDUMP("ENC KEY lg", espkey_lg->key, esp_transf_length);
	k += esp_transf_length;
	HIP_IFE(hip_keymat_get_new(authkey_lg->key, auth_transf_length,
				   entry->dh_shared_key, entry->dh_shared_key_len,
				   &k, &c, Kn, &Kn_pos), -1);
	_HIP_HEXDUMP("AUTH KEY lg", authkey_lg->key, auth_transf_length);
	k += auth_transf_length;

	_HIP_DEBUG("at end: k=%u c=%u\n", k, c);
	*keymat_offset_new = k;
	*calc_index_new = c;
	memcpy(Kn_out, Kn, HIP_AH_SHA_LEN);
 out_err:
	return err;
}

int hip_update_test_locator_addr(in6_addr_t *addr)
{
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(ss));
	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		struct sockaddr_in *sin = (struct sockaddr_in *) &ss;
		IPV6_TO_IPV4_MAP(addr, &sin->sin_addr);
		sin->sin_family = AF_INET;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &ss;
		memcpy(&sin6->sin6_addr, addr, sizeof(in6_addr_t));
		sin6->sin6_family = AF_INET6;
	}

	return filter_address((struct sockaddr *) &ss);
}

int hip_update_add_peer_addr_item(
	hip_ha_t *entry, struct hip_locator_info_addr_item *locator_address_item,
	void *_spi)
{
	in6_addr_t *locator_address; 
	uint32_t lifetime = ntohl(locator_address_item->lifetime);
	int is_preferred = htonl(locator_address_item->reserved) == (1 << 7);
	int err = 0, i, locator_is_ipv4, local_is_ipv4;
	uint32_t spi = *((uint32_t *) _spi);
	uint16_t port = hip_get_locator_item_port(locator_address_item);
	uint32_t priority = hip_get_locator_item_priority(locator_address_item);	
	uint8_t kind = 0;

	HIP_DEBUG("LOCATOR priority: %ld \n", priority);
	
	HIP_DEBUG("LOCATOR type %d \n", locator_address_item->locator_type);
	if (locator_address_item->locator_type == HIP_LOCATOR_LOCATOR_TYPE_UDP) {
		
		locator_address = 
			&((struct hip_locator_info_addr_item2 *)locator_address_item)->address;
		kind = ((struct hip_locator_info_addr_item2 *)locator_address_item)->kind;
	} else {
		locator_address = &locator_address_item->address;
		//hip_get_locator_item_address(hip_get_locator_item_as_one(locator_address_item, 0));
	}
	HIP_DEBUG_IN6ADDR("LOCATOR address", locator_address);
	HIP_DEBUG(" address: is_pref=%s reserved=0x%x lifetime=0x%x\n",
		  is_preferred ? "yes" : "no",
		  ntohl(locator_address_item->reserved),
		  lifetime);

	/* Removed this because trying to get interfamily handovers to work --Samu */
	// Check that addresses match, we doesn't support IPv4 <-> IPv6 update
	// communnications locator_is_ipv4 = IN6_IS_ADDR_V4MAPPED(locator_address);
	//local_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&entry->our_addr);

	//if( locator_is_ipv4 != local_is_ipv4 ) {
	// One of the addresses is IPv4 another is IPv6
	//  goto out_err;
	//}

	/* Check that the address is a legal unicast or anycast
	   address */
	if (!hip_update_test_locator_addr(locator_address)) {
		err = -1;
		HIP_DEBUG_IN6ADDR("Bad locator type", locator_address);
		goto out_err;
	}

	/* Check if the address is already bound to the SPI +
	   add/update address */
//add by santtu
	//both address and port will be the key to compare
	//UDP port is supported in the peer_list_item
	if (ipv6_addr_cmp(locator_address, &entry->peer_addr) == 0
			&& port == entry->peer_udp_port) {
		HIP_IFE(hip_hadb_add_udp_addr_to_spi(entry, spi, locator_address,
						 0,
						 lifetime, 1, port,priority,kind), -1);
	} else {
		HIP_IFE(hip_hadb_add_udp_addr_to_spi(entry, spi, locator_address,
						 0,
						 lifetime, is_preferred, port,priority, kind), -1);
	}
//end add
/*
 // new interface is used for updating the address
	if (ipv6_addr_cmp(locator_address, &entry->peer_addr) == 0) {
		HIP_IFE(hip_hadb_add_addr_to_spi(entry, spi, locator_address,
						 0,
						 lifetime, 1), -1);
	} else {
		HIP_IFE(hip_hadb_add_addr_to_spi(entry, spi, locator_address,
						 0,
						 lifetime, is_preferred), -1);
	}
*/
#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* Check and remove the IP of the peer from the opp non-HIP database */
	hip_oppipdb_delentry(&(entry->peer_addr));
#endif

 out_err:
	return err;
}
#if 0
int hip_update_locator_match(hip_ha_t *unused,
			     struct hip_locator_info_addr_item *item1,
			     void *_item2)
{
	struct hip_locator_info_addr_item *item2 = _item2;
	return !ipv6_addr_cmp(&item1->address, &item2->address);
}

int hip_update_locator_item_match(hip_ha_t *unused,
				  struct hip_locator_info_addr_item *item1,
				  void *_item2)
{
	struct hip_peer_addr_list_item *item2 = _item2;
	return !ipv6_addr_cmp(&item1->address, &item2->address);
}
#endif
//add by santtu
//we add the support for type2 locator
int hip_update_locator_match(hip_ha_t *unused,
			     struct hip_locator_info_addr_item *item1,
			     void *_item2) {
	struct hip_locator_info_addr_item *item2 = _item2;
	return !ipv6_addr_cmp(hip_get_locator_item_address(item1), hip_get_locator_item_address(item2))
		&& hip_get_locator_item_port(item1) == hip_get_locator_item_port(item2) ;
}

int hip_update_locator_item_match(hip_ha_t *unused,
				  struct hip_locator_info_addr_item *item1,
				  void *_item2)
{
     struct hip_peer_addr_list_item *item2 = _item2;
     return !ipv6_addr_cmp(hip_get_locator_item_address(item1), &item2->address)
     	&& hip_get_locator_item_port(item1) == item2->port;;
}
//end add
int hip_update_locator_contains_item(struct hip_locator *locator,
				     struct hip_peer_addr_list_item *item)
{
	return hip_for_each_locator_addr_item(hip_update_locator_item_match,
					      NULL, locator, item);
}

int hip_update_deprecate_unlisted(hip_ha_t *entry,
				  struct hip_peer_addr_list_item *list_item,
				  struct hip_spi_out_item *spi_out,
				  void *_locator)
{
	int err = 0;
	uint32_t spi_in;
	struct hip_locator *locator = (void *) _locator;

	if (hip_update_locator_contains_item(locator, list_item))
		goto out_err;

	HIP_DEBUG_HIT("Deprecating address", &list_item->address);

	list_item->address_state = PEER_ADDR_STATE_DEPRECATED;
	spi_in = hip_get_spi_to_update_in_established(entry,
						      &entry->our_addr);

	default_ipsec_func_set.hip_delete_sa(entry->default_spi_out, &list_item->address,
					     &entry->our_addr, HIP_SPI_DIRECTION_OUT, entry);
	default_ipsec_func_set.hip_delete_sa(spi_in, &entry->our_addr, &list_item->address,
					     HIP_SPI_DIRECTION_IN, entry);

	list_del(list_item, entry->spis_out);
 out_err:
	return err;
}

int hip_update_set_preferred(hip_ha_t *entry,
			     struct hip_peer_addr_list_item *list_item,
			     struct hip_spi_out_item *spi_out,
			     void *pref)
{
	int *preferred = pref;
	list_item->is_preferred =  *preferred;
	return 0;
}

int hip_handle_update_established(hip_ha_t *entry, hip_common_t *msg,
				  in6_addr_t *src_ip,
				  in6_addr_t *dst_ip,
				  hip_portpair_t *update_info)
{
	int err = -1;
#if 0
	in6_addr_t *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_esp_info *esp_info;
	struct hip_seq *seq;
	struct hip_locator *locator;
	struct hip_dh_fixed *dh;
	uint32_t update_id_out = 0;
	uint32_t prev_spi_in = 0, new_spi_in = 0;
	uint16_t keymat_index = 0, mask = 0;
	hip_common_t *update_packet = NULL;
	int esp_info_i = 1, need_to_generate_key = 0,
		dh_key_generated = 0;

	HIP_DEBUG("\n");

	HIP_IFEL(!(seq = hip_get_param(msg, HIP_PARAM_SEQ)), -1,
		 "No SEQ parameter in packet\n");

	/* 1.  The system consults its policy to see if it needs to generate a
	   new Diffie-Hellman key, and generates a new key if needed. */
	if (need_to_generate_key) {
		_HIP_DEBUG("would generate new D-H keys\n");
		/* generate_dh_key(); */
		dh_key_generated = 1;
		/** @todo The system records any newly generated or received
		    Diffie-Hellman keys, for use in KEYMAT generation upon
		    leaving the REKEYING state. */
	} else {
		dh_key_generated = 0;
	}

	/* 4. The system creates a UPDATE packet, which contains an SEQ
	   parameter (with the current value of Update ID), ESP_INFO parameter
	   and the optional DIFFIE_HELLMAN parameter. The UPDATE packet also
	   includes the ACK of the Update ID found in the received UPDATE
	   SEQ parameter. */
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Update_packet alloc failed\n");
	entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
						     mask, hitr, hits);

	/*  3. The system increments its outgoing Update ID by one. */
	entry->update_id_out++;
	update_id_out = entry->update_id_out;
	/** @todo handle this case. */
	HIP_IFEL(!update_id_out, -EINVAL,
		 "Outgoing UPDATE ID overflowed back to 0, bug ?\n");

	/* test: handle multiple ESP_INFO, not tested well yet */
 handle_esp_info:
	if (!(esp_info = hip_get_nth_param(msg, HIP_PARAM_ESP_INFO,
					   esp_info_i))) {
		HIP_DEBUG("no more ESP_INFO params found\n");
		goto esp_info_params_handled;
	}
	HIP_DEBUG("Found ESP_INFO parameter [%d]\n", esp_info_i);

	/* 2. If the system generated new Diffie-Hellman key in the previous
	   step, or it received a DIFFIE_HELLMAN parameter, it sets ESP_INFO
	   Keymat Index to zero. */
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh || dh_key_generated) {
		HIP_DEBUG("would generate new keymat\n");
		/** @todo generate_new_keymat(); */
		keymat_index = 0;
	} else {
		/* Otherwise, the ESP_INFO Keymat Index MUST be larger or
		   equal to the index of the next byte to be drawn from the
		   current KEYMAT. */
		HIP_IFEL(ntohs(esp_info->keymat_index) <
			 entry->current_keymat_index, -1,
			 "ESP_INFO Keymat Index (%u) < current KEYMAT %u\n",
			 ntohs(esp_info->keymat_index),
			 entry->current_keymat_index);

		/* In this case, it is RECOMMENDED that the host use the
		   Keymat Index requested by the peer in the received
		   ESP_INFO. Here we could set the keymat index to use, but we
		   follow the recommendation */
		_HIP_DEBUG("Using Keymat Index from ESP_INFO\n");
		keymat_index = ntohs(esp_info->keymat_index);
	}

	/* Set up new incoming IPsec SA, (Old SPI value to put in ESP_INFO) */
	HIP_IFE(!(prev_spi_in =
		  hip_get_spi_to_update_in_established(entry, dst_ip)), -1);

	HIP_IFEL(!(new_spi_in = entry->hadb_ipsec_func->hip_acquire_spi(hits, hitr)), -1,
		 "Error while acquiring a SPI\n");


	HIP_DEBUG("Acquired inbound SPI 0x%x\n", new_spi_in);
	hip_update_set_new_spi_in(entry, prev_spi_in, new_spi_in,
				  ntohl(esp_info->old_spi));

	if (esp_info->old_spi == esp_info->new_spi) {
		struct hip_spi_out_item spi_out_data;

		_HIP_DEBUG("peer has a new SA, create a new outbound SA\n");
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = ntohl(esp_info->new_spi);
		spi_out_data.seq_update_id = ntohl(seq->update_id);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT,
					 &spi_out_data), -1);
		HIP_DEBUG("added SPI=0x%x to list of outbound SAs (SA not created "\
			  "yet)\n", ntohl(esp_info->new_spi));
	}

	/* testing LOCATOR parameters in UPDATE */
	locator = hip_get_nth_param(msg, HIP_PARAM_LOCATOR, esp_info_i);
	if (locator && esp_info) {
		HIP_DEBUG("Found LOCATOR parameter [%d]\n", esp_info_i);
		if (esp_info->old_spi != esp_info->new_spi) {
			HIP_ERROR("SPI 0x%x in LOCATOR is not equal to the New SPI 0x%x"\
				  "in ESP_INFO\n", ntohl(esp_info->old_spi),
				  ntohl(esp_info->new_spi));
		} else {
			err = hip_handle_locator_parameter(
				entry, locator, esp_info);
			_HIP_DEBUG("locator param handling ret %d\n", err);
			err = 0;
		}
	}

	/* associate Old SPI with Update ID, ESP_INFO received, store
	   received ESP_INFO and proposed keymat index value used in the
	   reply ESP_INFO */
	hip_update_set_status(entry, prev_spi_in, 0x1 | 0x2 | 0x4 | 0x8,
			      update_id_out, 0x2, esp_info, keymat_index);
	esp_info_i++;
	goto handle_esp_info;

 esp_info_params_handled:

	/* 5.  The system sends the UPDATE packet and transitions to state
	   REKEYING.  The system stores any received ESP_INFO and
	   DIFFIE_HELLMAN parameters. */
	HIP_IFEL(hip_build_param_esp_info(update_packet, keymat_index,
					  prev_spi_in, new_spi_in), -1,
		 "Building of ESP_INFO failed\n");
	HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1,
		 "Building of SEQ failed\n");

	/* ACK the received UPDATE SEQ */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1,
		 "Building of ACK failed\n");

	/** @todo hmac/signature to common functions */
	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					       &entry->hip_hmac_out),
		 -1, "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv_key, update_packet),
		 -EINVAL, "Could not sign UPDATE. Failing\n");

	/* 5.  The system sends the UPDATE packet and transitions to state
	   REKEYING. */
	entry->update_state = HIP_UPDATE_STATE_REKEYING;

	/* Destination port of the received packet becomes the source
	   port of the UPDATE packet. */
	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(dst_ip, src_ip,
			      (entry->nat_mode ? hip_get_nat_udp_port() : 0),
			      entry->peer_udp_port, update_packet, entry, 1),
		 -ECOMM, "Sending UPDATE packet failed.\n");

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	if (err) {
		hip_set_spi_update_status(entry, prev_spi_in, 0);
		if (new_spi_in)
			hip_hadb_delete_inbound_spi(entry, new_spi_in);
	}

#endif
	return err;
}

int hip_update_finish_rekeying(hip_common_t *msg, hip_ha_t *entry,
			       struct hip_esp_info *esp_info)
{
	int err = 0, we_are_HITg = 0, esp_transform = -1;
	int esp_transf_length = 0, auth_transf_length = 0;
	uint8_t calc_index_new;
	uint16_t kmindex_saved;
	uint16_t keymat_index;
	uint32_t new_spi_in = 0;  /* inbound IPsec SA SPI */
	uint32_t new_spi_out = 0; /* outbound IPsec SA SPI */
	uint32_t prev_spi_in = 0, prev_spi_out = 0;
	unsigned char Kn[HIP_AH_SHA_LEN];
	in6_addr_t *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_spi_in_item spi_in_data;
	struct hip_ack *ack;
	struct hip_crypto_key espkey_gl, authkey_gl;
	struct hip_crypto_key espkey_lg, authkey_lg;

	HIP_DEBUG("\n");
	ack = hip_get_param(msg, HIP_PARAM_ACK);

	HIP_DEBUG("handled ESP_INFO: Old SPI: 0x%x\n", ntohl(esp_info->old_spi));
	HIP_DEBUG("handled ESP_INFO: New SPI: 0x%x\n", ntohl(esp_info->new_spi));
	HIP_DEBUG("handled ESP_INFO: Keymat Index: %u\n",
		  ntohs(esp_info->keymat_index));

	prev_spi_out = ntohl(esp_info->old_spi);
	new_spi_out = ntohl(esp_info->new_spi) ? ntohl(esp_info->new_spi) : prev_spi_out;

	_HIP_DEBUG("new_spi_out: 0x%x\n",
		   new_spi_out);

	HIP_ASSERT(prev_spi_out != 0 && new_spi_out != 0);

	prev_spi_in = hip_update_get_prev_spi_in(entry, ntohl(ack->peer_update_id));

	/* use the new inbound IPsec SA created when rekeying started */
	HIP_IFEL(!(new_spi_in = hip_update_get_new_spi_in(
			   entry, ntohl(ack->peer_update_id))), -1,
		 "Did not find related New SPI for peer Update ID %u\n",
		 ntohl(ack->peer_update_id));
	HIP_DEBUG("prev_spi_in=0x%x new_spi_in=0x%x prev_spi_out=0x%x "\
		  "new_spi_out=0x%x\n",
		  prev_spi_in, new_spi_in, prev_spi_out, new_spi_out);

	HIP_IFEL(!(kmindex_saved = hip_update_get_spi_keymat_index(
			   entry, ntohl(ack->peer_update_id))),
		 -1, "Saved kmindex is 0\n");

	_HIP_DEBUG("saved kmindex for ESP_INFO is %u\n", kmindex_saved);

	/* 2. .. If the system did not generate new KEYMAT, it uses
	   the lowest Keymat Index of the two ESP_INFO parameters. */
	_HIP_DEBUG("entry keymat index=%u\n", entry->current_keymat_index);
	keymat_index = kmindex_saved < ntohs(esp_info->keymat_index) ?
		kmindex_saved : ntohs(esp_info->keymat_index);
	_HIP_DEBUG("lowest keymat_index=%u\n", keymat_index);

	/* 3. The system draws keys for new incoming and outgoing ESP
	   SAs, starting from the Keymat Index, and prepares new incoming
	   and outgoing ESP SAs. */
	we_are_HITg = hip_hit_is_bigger(hitr, hits);
	HIP_DEBUG("we are: HIT%c\n", we_are_HITg ? 'g' : 'l');

	esp_transform = entry->esp_transform;
	esp_transf_length = hip_enc_key_length(esp_transform);
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	_HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length,
		   auth_transf_length);
	calc_index_new = entry->keymat_calc_index;
	memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);
	HIP_IFE(hip_update_get_sa_keys(entry, &keymat_index, &calc_index_new, Kn,
				       &espkey_gl, &authkey_gl, &espkey_lg,
				       &authkey_lg), -1);
	/** @todo update entry keymat later. */
	hip_update_entry_keymat(entry, keymat_index, calc_index_new,
				keymat_index - esp_transf_length * 2 -
				auth_transf_length * 2, Kn);

	/* XFRM API doesn't support multiple SA for one SP */
	entry->hadb_ipsec_func->hip_delete_hit_sp_pair(hits, hitr, IPPROTO_ESP, 1);

	default_ipsec_func_set.hip_delete_sa(prev_spi_out, &entry->peer_addr,
					     &entry->our_addr, HIP_SPI_DIRECTION_OUT, entry);
	default_ipsec_func_set.hip_delete_sa(prev_spi_in, &entry->our_addr,
					     &entry->peer_addr, HIP_SPI_DIRECTION_IN, entry);

	/* SP and SA are always added, not updated, due to the xfrm api limitation */
	HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(hits, hitr,
				       &entry->peer_addr, &entry->our_addr,
				       IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");

	/* set up new outbound IPsec SA */
	HIP_DEBUG("Setting up new outbound SA, SPI=0x%x\n", new_spi_out);
	/** @todo Currently NULLing the stateless info. Send port info through
	    entry parameter --Abi */
	entry->local_udp_port = entry->nat_mode ? hip_get_local_nat_udp_port() : 0;

	err = entry->hadb_ipsec_func->hip_add_sa(&entry->peer_addr, &entry->our_addr, hits,
			 hitr,  &new_spi_in, esp_transform,
			 (we_are_HITg ? &espkey_lg : &espkey_gl),
			 (we_are_HITg ? &authkey_lg : &authkey_gl),
			 1, HIP_SPI_DIRECTION_IN, 0, entry);

	//"Setting up new outbound IPsec SA failed\n");
	HIP_DEBUG("New outbound SA created with SPI=0x%x\n", new_spi_out);
	HIP_DEBUG("Setting up new inbound SA, SPI=0x%x\n", new_spi_in);

	err = entry->hadb_ipsec_func->hip_add_sa(&entry->our_addr, &entry->peer_addr, hitr,
			 hits, &new_spi_out, esp_transform,
			 (we_are_HITg ? &espkey_gl : &espkey_lg),
			 (we_are_HITg ? &authkey_gl : &authkey_lg),
			 1, HIP_SPI_DIRECTION_OUT, 0, entry);

	HIP_DEBUG("err=%d\n", err);
	if (err)
		HIP_DEBUG("Setting up new inbound IPsec SA failed\n");

	HIP_DEBUG("New inbound SA created with SPI=0x%x\n", new_spi_in);

	if (prev_spi_in == new_spi_in) {
		memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
		spi_in_data.spi = new_spi_in;
		/* Already set? */
		spi_in_data.ifindex = hip_hadb_get_spi_ifindex(entry, prev_spi_in);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data),
			-1);
	} else
		_HIP_DEBUG("Old SPI <> New SPI, not adding a new inbound SA\n");

	/* Activate the new inbound and outbound SAs */
	//hip_finalize_sa(hitr, new_spi_in);
	//hip_finalize_sa(hits, new_spi_out);

	hip_update_switch_spi_in(entry, prev_spi_in);
	/* temporary fix */
	hip_update_set_new_spi_out(entry, prev_spi_out, new_spi_out);
	hip_update_switch_spi_out(entry, prev_spi_out);

	hip_set_spi_update_status(entry, new_spi_in, 0);
	hip_update_clear_status(entry, new_spi_in);

	// if (is not mm update) ?
	hip_hadb_set_default_out_addr(
		entry, hip_hadb_get_spi_list(entry, new_spi_out), NULL);

	/* 4. The system cancels any timers protecting the UPDATE and
	   transitions to ESTABLISHED. */
	entry->state = HIP_STATE_ESTABLISHED;

	HIP_DEBUG("Went back to ESTABLISHED state\n");

	/* delete old SAs */
	if (prev_spi_out != new_spi_out) {
		HIP_DEBUG("REMOVING OLD OUTBOUND IPsec SA, SPI=0x%x\n", prev_spi_out);
		/* SA is bounded to IP addresses! */
		//default_ipsec_func_set.hip_delete_sa(prev_spi_out, hits, hitr, AF_INET6);
		HIP_DEBUG("TODO: set new spi to 0\n");
		_HIP_DEBUG("delete_sa out retval=%d\n", err);
		err = 0;
	} else
		HIP_DEBUG("prev SPI_out = new SPI_out, not deleting the outbound "\
			  "SA\n");

	if (prev_spi_in != new_spi_in) {
		HIP_DEBUG("REMOVING OLD INBOUND IPsec SA, SPI=0x%x\n", prev_spi_in);
		/* SA is bounded to IP addresses! */
		/////default_ipsec_func_set.hip_delete_sa(prev_spi_in, hitr, hits, AF_INET6);
		/* remove old HIT-SPI mapping and add a new mapping */

		/* actually should change hip_hadb_delete_inbound_spi
		 * somehow, but we do this or else delete_inbound_spi
		 * would delete both old and new SPIs */
		//hip_hadb_remove_hs(prev_spi_in);
		/*err = hip_hadb_insert_state_spi_list(&entry->hit_peer,
		  &entry->hit_our,
		  new_spi_in);
		  if (err == -EEXIST) {
		  HIP_DEBUG("HIT-SPI mapping already exists, hmm ..\n");
		  err = 0;
		  } else if (err) {
		  HIP_ERROR("Could not add a HIT-SPI mapping for SPI 0x%x (err=%d)\n",
		  new_spi_in, err);
		  }*/
	} else
		_HIP_DEBUG("prev SPI_in = new SPI_in, not deleting the inbound SA\n");

	/* start verifying addresses */
	HIP_DEBUG("start verifying addresses for new spi 0x%x\n", new_spi_out);
	err = entry->hadb_update_func->hip_update_send_addr_verify(
		entry, msg, NULL, new_spi_out);
	if (err)
		HIP_DEBUG("address verification had errors, err=%d\n", err);
	err = 0;

 out_err:
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int hip_update_do_finish_rekey(hip_ha_t *entry, struct hip_spi_in_item *item,
			       void *_msg)
{
	hip_common_t *msg = _msg;
	int err = 0;

	_HIP_DEBUG("test item: spi_in=0x%x seq=%u updflags=0x%x\n",
		   item->spi, item->seq_update_id, item->update_state_flags);

	if (item->update_state_flags != 0x3)
		goto out_err;

	HIP_IFEL(hip_update_finish_rekeying(
			 msg, entry, &item->stored_received_esp_info), -1,
		 "Finish rekeying failed\n");

 out_err:

	HIP_DEBUG("update_finish handling ret err=%d\n", err);
	return err;
}

int hip_handle_update_rekeying(hip_ha_t *entry, hip_common_t *msg,
			       in6_addr_t *src_ip)
{
	int err = 0;
	uint16_t mask = 0;
	in6_addr_t *hits = &msg->hits, *hitr = &msg->hitr;
	in6_addr_t daddr;
	hip_common_t *update_packet = NULL;
	struct hip_esp_info *esp_info = NULL;
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	//u8 signature[HIP_RSA_SIGNATURE_LEN]; /* RSA sig > DSA sig */

	/* 8.11.2  Processing an UPDATE packet in state REKEYING */

	HIP_DEBUG("\n");

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	ack = hip_get_param(msg, HIP_PARAM_ACK);

	if (seq && esp_info) {
		/* 1. If the packet contains a SEQ and ESP_INFO parameters, then the
		   system generates a new UPDATE packet with an ACK of the peer's
		   Update ID as received in the SEQ parameter. .. */
		HIP_IFE(!(update_packet = hip_msg_alloc()), -ENOMEM);
		entry->hadb_misc_func->hip_build_network_hdr(
			update_packet, HIP_UPDATE, mask, hitr, hits);
		HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)),
			 -1, "Building of ACK param failed\n");
	}

	if (esp_info && ack) { /* kludge */
		uint32_t s = hip_update_get_prev_spi_in(
			entry, ntohl(ack->peer_update_id));
		hip_update_set_status(entry, s, 0x4, 0, 0, esp_info, 0);
	}
	/* .. Additionally, if the UPDATE packet contained an ACK of the
	   outstanding Update ID, or if the ACK of the UPDATE packet that
	   contained the ESP_INFO has already been received, the system stores
	   the received ESP_INFO and (optional) DIFFIE_HELLMAN parameters and
	   finishes the rekeying procedure as described in Section
	   8.11.3. If the ACK of the outstanding Update ID has not been
	   received, stay in state REKEYING after storing the recived ESP_INFO
	   and (optional) DIFFIE_HELLMAN. */

	if (ack) /* breaks if packet has no ack but esp_info exists ? */
		hip_update_handle_ack(entry, ack, esp_info ? 1 : 0);
	/* if (esp_info)
	   hip_update_handle_esp_info(entry, puid); kludge */

	/* finish SAs if we have received ACK and ESP_INFO */
	HIP_IFEL(hip_update_for_each_local_addr(hip_update_do_finish_rekey,
						entry, msg),
		 -1, "Rekeying failure\n");

	HIP_IFEL(!update_packet, 0, "UPDATE packet NULL\n");

	/* Send ACK */

	/** @todo hmac/signature to common functions */
	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(
			 update_packet, &entry->hip_hmac_out), -1,
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv_key, update_packet), -EINVAL,
		 "Could not sign UPDATE. Failing\n");
	HIP_IFEL(hip_hadb_get_peer_addr(entry, &daddr), -1,
		 "Failed to get peer address\n");

	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(&entry->our_addr, &daddr,
			      (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			      entry->peer_udp_port,
			      update_packet, entry, 1),
		 -ECOMM, "Sending UPDATE packet failed.\n");

 out_err:
	/* if (err)
	   TODO: REMOVE IPSEC SAs
	   move to state = ?
	*/
	if (update_packet)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int hip_build_verification_pkt(hip_ha_t *entry, hip_common_t *update_packet,
			       struct hip_peer_addr_list_item *addr,
			       in6_addr_t *hits, in6_addr_t *hitr)
{
	int err = 0;
	uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
	uint16_t mask = 0;
	HIP_DEBUG("building verification packet\n");
	hip_msg_init(update_packet);
	entry->hadb_misc_func->hip_build_network_hdr(
		update_packet, HIP_UPDATE, mask, hitr, hits);
	entry->update_id_out++;
	addr->seq_update_id = entry->update_id_out;

	_HIP_DEBUG("outgoing UPDATE ID for LOCATOR addr check=%u\n",
		   addr->seq_update_id);

	/* Reply with UPDATE(ESP_INFO, SEQ, ACK, ECHO_REQUEST) */

	/* ESP_INFO */
	esp_info_old_spi = hip_hadb_get_latest_inbound_spi(entry);
	esp_info_new_spi = esp_info_old_spi;
	HIP_IFEL(hip_build_param_esp_info(update_packet,
					  entry->current_keymat_index,
					  esp_info_old_spi,
					  esp_info_new_spi),
		 -1, "Building of ESP_INFO param failed\n");
	/* @todo Handle overflow if (!update_id_out) */
	/* Add SEQ */
	HIP_IFEBL2(hip_build_param_seq(update_packet,
				       addr->seq_update_id), -1,
		   return , "Building of SEQ failed\n");

	/* TODO: NEED TO ADD ACK */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(addr->seq_update_id)),
		 -1, "Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEBL2(hip_build_param_hmac_contents(update_packet,
						 &entry->hip_hmac_out),
		   -1, return , "Building of HMAC failed\n");
	/* Add SIGNATURE */
	HIP_IFEBL2(entry->sign(entry->our_priv_key, update_packet),
		   -EINVAL, return , "Could not sign UPDATE\n");
	get_random_bytes(addr->echo_data, sizeof(addr->echo_data));

	/* Add ECHO_REQUEST */
	HIP_HEXDUMP("ECHO_REQUEST in LOCATOR addr check",
		    addr->echo_data, sizeof(addr->echo_data));
	HIP_IFEBL2(hip_build_param_echo(update_packet, addr->echo_data,
					sizeof(addr->echo_data), 0, 1),
		   -1, return , "Building of ECHO_REQUEST failed\n");
	HIP_DEBUG("sending addr verify pkt\n");

 out_err:
	if (update_packet && err)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;


}

int hip_update_send_addr_verify_packet(hip_ha_t *entry,
				       struct hip_peer_addr_list_item *addr,
				       struct hip_spi_out_item *spi_out,
				       void *saddr)
{
	in6_addr_t *src_ip = saddr;
	/** @todo Make this timer based:
	 * 	 If its been too long before active addresses were verfied,
	 * 	 	verify them as well
	 * 	 else
	 * 	 	verify only unverified addresses
	 */
//modify by sanntu when ice is choosen, not update message is needed
	if(hip_nat_get_control(entry) != HIP_NAT_MODE_ICE_UDP)
		return hip_update_send_addr_verify_packet_all(entry, addr, spi_out,
						      src_ip, 0);
	else return 0;
//end modify
}

int hip_update_send_addr_verify_packet_all(hip_ha_t *entry,
					   struct hip_peer_addr_list_item *addr,
					   struct hip_spi_out_item *spi_out,
					   in6_addr_t *src_ip,
					   int verify_active_addresses)
{
	int err = 0;
	hip_common_t *update_packet = NULL;
	in6_addr_t *hits = &entry->hit_our, *hitr = &entry->hit_peer;

	HIP_DEBUG_HIT("new addr to check", &addr->address);
	HIP_DEBUG("address state=%d\n", addr->address_state);

	if (addr->address_state == PEER_ADDR_STATE_DEPRECATED) {
		HIP_DEBUG("addr state is DEPRECATED, not verifying\n");
		goto out_err;
	}

	if ((addr->address_state == PEER_ADDR_STATE_ACTIVE)){
		if(verify_active_addresses){
			HIP_DEBUG("Verifying already active address. Setting as "\
				  "unverified\n");
			addr->address_state = PEER_ADDR_STATE_UNVERIFIED;
			if (addr->is_preferred) {
				HIP_DEBUG("TEST (maybe should not do this yet?): setting "\
					  "already active address and set as preferred to "\
					  "default addr\n");
				/** @todo Is this the correct function? -Bagri */
				hip_hadb_set_default_out_addr(
					entry, spi_out, &addr->address);
			}
		}
		else
			goto out_err;
	}

	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Update_packet alloc failed\n");

	HIP_IFEL(hip_build_verification_pkt(entry, update_packet, addr, hits,
					    hitr),
		 -1, "Building Verification Packet failed\n");

	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(src_ip, &addr->address,
			      (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			      entry->peer_udp_port, update_packet, entry, 1),
		 -ECOMM, "Sending UPDATE packet failed.\n");

 out_err:
	return err;
}

int hip_update_send_addr_verify(hip_ha_t *entry, hip_common_t *msg,
				in6_addr_t *src_ip, uint32_t spi)
{
	int err = 0;
	struct hip_spi_out_item *spi_out;
	uint16_t mask = 0;

	HIP_DEBUG("SPI=0x%x\n", spi);

	HIP_IFEL(!(spi_out = hip_hadb_get_spi_list(entry, spi)), -1,
		 "SPI 0x%x not in SPI list\n");

	/** @todo Compiler warning; warning: passing argument 1 of
	    'hip_update_for_each_peer_addr' from incompatible pointer type. */
	HIP_IFEL(hip_update_for_each_peer_addr(hip_update_send_addr_verify_packet,
					       entry, spi_out, src_ip), -1,
		 "Sending addr verify failed\n");

 out_err:
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int hip_update_find_address_match(hip_ha_t *entry,
				  struct hip_locator_info_addr_item *item,
				  void *opaque)
{
	in6_addr_t *addr = (in6_addr_t *) opaque;

	HIP_DEBUG_IN6ADDR("addr1", addr);
	HIP_DEBUG_IN6ADDR("addr2", &item->address);

	return !ipv6_addr_cmp(addr, &item->address);
}

int hip_update_check_simple_nat(in6_addr_t *peer_ip,
				struct hip_locator *locator)
{
	int err = 0, found;
	struct hip_locator_info_addr_item *item;

	found = hip_for_each_locator_addr_item(hip_update_find_address_match,
					       NULL, locator, peer_ip);
	HIP_IFEL(found, 0, "No address translation\n");

	/** @todo Should APPEND the address to locator. */

	HIP_IFEL(!(item = hip_get_locator_first_addr_item(locator)), -1,
		 "No addresses in locator\n");
	ipv6_addr_copy(&item->address, peer_ip);
	HIP_DEBUG("Assuming NATted peer, overwrote first locator\n");

 out_err:

	return err;
}

int hip_handle_update_plain_locator(hip_ha_t *entry, hip_common_t *msg,
				    in6_addr_t *src_ip,
				    in6_addr_t *dst_ip,
				    struct hip_esp_info *esp_info,
				    struct hip_seq *seq)
{
	int err = 0;
	uint16_t mask = 0;
	in6_addr_t *hits = &msg->hits, *hitr = &msg->hitr;
	hip_common_t *update_packet = NULL;
	struct hip_locator *locator;
	struct hip_peer_addr_list_item *list_item;
	u32 spi_in;
	u32 spi_out = ntohl(esp_info->new_spi);

	HIP_DEBUG("\n");

	locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
	HIP_IFEL(locator == NULL, -1, "No locator!\n");
	HIP_IFEL(esp_info == NULL, -1, "No esp_info!\n");

	/* return value currently ignored, no need to abort on error? */
	/** @todo We should ADD the locator, not overwrite. */
	if (entry->nat_mode)
		hip_update_check_simple_nat(src_ip, locator);

	/* remove unused addresses from peer addr list */
	list_item = malloc(sizeof(struct hip_peer_addr_list_item));
	if (!list_item)
		goto out_err;
	ipv6_addr_copy(&list_item->address, &entry->peer_addr);
	HIP_DEBUG_HIT("Checking if preferred address was in locator",
		      &list_item->address);
	if (!hip_update_locator_contains_item(locator, list_item)) {
		HIP_DEBUG("Preferred address was not in locator, so changing it "\
			  "and removing SAs\n");
		spi_in = hip_hadb_get_latest_inbound_spi(entry);
		default_ipsec_func_set.hip_delete_sa(spi_in, &entry->our_addr,
						     &entry->peer_addr, HIP_SPI_DIRECTION_IN, entry);
		default_ipsec_func_set.hip_delete_sa(entry->default_spi_out, &entry->peer_addr,
						     &entry->our_addr, HIP_SPI_DIRECTION_OUT, entry);
		ipv6_addr_copy(&entry->peer_addr, src_ip);
	}

	if (!hip_hadb_get_spi_list(entry, spi_out)) {
		struct hip_spi_out_item spi_out_data;

		HIP_DEBUG("peer has a new SA, create a new outbound SA\n");
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = spi_out;
		spi_out_data.seq_update_id = ntohl(seq->update_id);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT,
					 &spi_out_data), -1);
		HIP_DEBUG("added SPI=0x%x to list of outbound SAs (SA not created "\
			  "yet)\n", spi_out);
	}

	HIP_IFEL(hip_handle_locator_parameter(entry, locator, esp_info),
		 -1, "hip_handle_locator_parameter failed\n");

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	if (list_item)
		HIP_FREE(list_item);
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int set_address_state(hip_ha_t *entry, in6_addr_t *src_ip)
{
	int err = 0;
	/* struct hip_spi_in_item *spi_in = NULL;
	   spi_in = hip_hadb_get_spi_in_list(entry, esp_info_old_spi);*/
	// For setting status of src_addresses to ACTIVE after echo req is obtained
	return err;
}

int hip_handle_update_addr_verify(hip_ha_t *entry, hip_common_t *msg,
				  in6_addr_t *src_ip, in6_addr_t *dst_ip)
{
	int err = 0;
	uint16_t mask = 0;
	hip_common_t *update_packet = NULL;
	in6_addr_t *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_seq *seq = NULL;
	struct hip_echo_request *echo = NULL;

	HIP_DEBUG("\n");

	/* Assume already locked entry */
	HIP_IFEL(!(echo = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST)), -1,
		 "ECHO not found\n");
	HIP_IFEL(!(seq = hip_get_param(msg, HIP_PARAM_SEQ)), -1,
		 "SEQ not found\n");
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Out of memory\n");

	entry->hadb_misc_func->hip_build_network_hdr(
		update_packet, HIP_UPDATE, mask, hitr, hits);

	/* reply with UPDATE(ACK, ECHO_RESPONSE) */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1,
		 "Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(
			 update_packet, &entry->hip_hmac_out), -1,
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv_key, update_packet), -EINVAL,
		 "Could not sign UPDATE. Failing\n");

	/* ECHO_RESPONSE (no sign) */
	HIP_DEBUG("echo opaque data len=%d\n",
		  hip_get_param_contents_len(echo));

	HIP_HEXDUMP("ECHO_REQUEST in LOCATOR addr check",
		    (void *)echo +
		    sizeof(struct hip_tlv_common),
		    hip_get_param_contents_len(echo));

	HIP_IFEL(hip_build_param_echo(update_packet,
				      (void *)echo +
				      sizeof(struct hip_tlv_common),
				      hip_get_param_contents_len(echo), 0, 0),
		 -1, "Building of ECHO_RESPONSE failed\n");

	HIP_DEBUG("Sending ECHO RESPONSE/UPDATE packet (address check).\n");
	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(dst_ip, src_ip,
			      (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			      entry->peer_udp_port, update_packet, entry, 0),
		 -ECOMM, "Sending UPDATE packet failed.\n");

	HIP_IFEL(set_address_state(entry, src_ip),
		 -1, "Setting Own address status to ACTIVE failed\n");

	entry->update_state = 0; /* No retransmissions */

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int hip_handle_update_seq(hip_ha_t *entry, hip_common_t *msg)
{
	int err = 0;
	uint32_t pkt_update_id = 0; /* UPDATE ID in packet */
	uint32_t update_id_in = 0;  /* stored incoming UPDATE ID */
	int is_retransmission = 0;
	struct hip_seq *seq = NULL;
	struct hip_hmac *hmac = NULL;
	struct hip_dh_fixed *dh;

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	pkt_update_id = ntohl(seq->update_id);
	HIP_DEBUG("SEQ: UPDATE ID: %u\n", pkt_update_id);

	update_id_in = entry->update_id_in;
	_HIP_DEBUG("previous incoming update id=%u\n", update_id_in);

	/* 1. If the SEQ parameter is present, and the Update ID in the
	   received SEQ is smaller than the stored Update ID for the host,
	   the packet MUST BE dropped. */
	if (pkt_update_id < update_id_in) {
		HIP_DEBUG("SEQ param present and received UPDATE ID (%u) < stored "\
			  "incoming UPDATE ID (%u). Dropping\n",
			  pkt_update_id, update_id_in);
		err = -EINVAL;
		goto out_err;
	} else if (pkt_update_id == update_id_in) {
		/* 2. If the SEQ parameter is present, and the Update ID in the
		   received SEQ is equal to the stored Update ID for the host, the
		   packet is treated as a retransmission. */
		is_retransmission = 1;
		HIP_DEBUG("Retransmitted UPDATE packet (?), continuing\n");
		/** @todo Ignore this packet or process anyway? */

	}

	hmac = hip_get_param(msg, HIP_PARAM_HMAC);
	HIP_IFEL(hmac == NULL, -1, "HMAC not found. Dropping packet\n");

	/*
	 * 3. The system MUST verify the HMAC in the UPDATE packet.
	 * If the verification fails, the packet MUST be dropped.
	 * **Moved to receive_update due to commonality with ack processing**
	 *
	 * 4. The system MAY verify the SIGNATURE in the UPDATE
	 * packet. If the verification fails, the packet SHOULD be
	 * dropped and an error message logged.
	 * **Moved to receive_update due to commonality with ack processing**
	 */

	/* 5.  If a new SEQ parameter is being processed,
	   the system MUST record the Update ID in the
	   received SEQ parameter, for replay protection. */
	if (seq && !is_retransmission) {
		entry->update_id_in = pkt_update_id;
		_HIP_DEBUG("Stored peer's incoming UPDATE ID %u\n", pkt_update_id);
	}
 out_err:
	if (err)
		HIP_ERROR("SEQUENCE handler failed, err=%d\n", err);

	return err;


}

int hip_set_rekeying_state(hip_ha_t *entry,
			   struct hip_esp_info *esp_info)
{
	int err = 0;
	uint32_t old_spi, new_spi;

	old_spi = esp_info->old_spi;
	new_spi = esp_info->new_spi;

	if(hip_update_exists_spi(entry, ntohl(old_spi),
				 HIP_SPI_DIRECTION_OUT, 0) ||
	   old_spi == 0){
		/* old SPI is the existing SPI or is zero*/
		if(old_spi == new_spi)
			/* mm-04 5.3 1. old SPI is equal to new SPI */
			entry->update_state = 0; //no rekeying
		/* FFT: Do we need a sanity check that both old_spi and new_spi cant
		   be zero. */
		else if(new_spi != 0){
			/* mm-04 5.3 2. Old SPI is existing SPI and new SPI is non-zero
			   3. Old SPI is zero and new SPI is non-zero. */
			entry->update_state = HIP_UPDATE_STATE_REKEYING;
		}
		else {
			/* mm-04 5.3 4. Old SPI is existing, new SPI is zero */
			entry->update_state = HIP_UPDATE_STATE_DEPRECATING;
		}
	}
	return entry->update_state;
}

int hip_handle_esp_info(hip_common_t *msg, hip_ha_t *entry)
{
	int err = 0, keying_state = 0;
	struct hip_esp_info *esp_info;
	uint16_t keymat_index = 0;
	struct hip_dh_fixed *dh;

	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	keymat_index = ntohs(esp_info->keymat_index);

	keying_state = hip_set_rekeying_state(entry, esp_info);

	switch(keying_state){
	case HIP_UPDATE_STATE_REKEYING:
		/** @todo: rekeying stuff goes here */
		break;
	case HIP_UPDATE_STATE_DEPRECATING:
		break;
	default:
		// No rekeying
		return 0;
	}

	/* esp-02 6.9 1. If the received UPDATE contains a
	 * Diffie-Hellman parameter, the received Keymat
	 * Index MUST be zero. If this test fails, the packet
	 *  SHOULD be dropped and the system SHOULD log an
	 *  error message. */

	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh) {
		HIP_DEBUG("packet contains DH\n");
		HIP_IFEL(!esp_info, -1, "Packet contains DH but not ESP_INFO\n");
		HIP_IFEL(keymat_index != 0, -EINVAL,
			 "UPDATE contains Diffie-Hellman parameter with non-zero"
			 "keymat value %u in ESP_INFO. Dropping\n", keymat_index);
	}
	/* esp-02 6.9 2. if no outstanding request, process as in sec 6.9.1 */

	/** @todo Check for outstanding rekeying request. */

	/* esp-02 6.9 3. If there is an outstanding rekeying request,
	 * UPDATE must be acked, save ESP_INFO, DH params, continue
	 * processing as stated in 6.10 */
 out_err:
	if(err)
		HIP_DEBUG("Error while processing Rekeying for update packet err=%d",
			  err);
	return err;
}

#ifdef CONFIG_HIP_ESCROW
int hip_handle_escrow_parameter(hip_ha_t * entry, struct hip_keys * keys)
{
	int err = 0;
	int accept = 0;
	uint32_t spi, spi_old;
	uint16_t op, len, alg;
	HIP_KEA * kea = NULL;
	HIP_KEA_EP * ep = NULL;
	in6_addr_t * hit, * peer_hit, * ip;

	HIP_IFEL(!(kea = hip_kea_find(&entry->hit_peer)), -1,
		 "No KEA found: Could not add escrow endpoint info");

	hit = (in6_addr_t *)&keys->hit;
	peer_hit = (in6_addr_t *)&keys->peer_hit;
	ip = (in6_addr_t *)&keys->address;

	HIP_DEBUG_HIT("handle escrow param hit:", hit);

	op = ntohs(keys->operation);
	spi = ntohl(keys->spi);
	spi_old = ntohl(keys->spi_old);
	len = ntohs(keys->key_len);
	alg = ntohs(keys->alg_id);

	switch (op) {

	case HIP_ESCROW_OPERATION_ADD:
		HIP_IFEL(!(ep = hip_kea_ep_create(hit, peer_hit, ip, alg,
						  spi, len, &keys->enc)), -1,
			 "Error creating kea endpoint");
		HIP_IFEBL(hip_kea_add_endpoint(kea, ep), -1, hip_kea_put_ep(ep),
			  "Error while adding endpoint");
		break;

	case HIP_ESCROW_OPERATION_MODIFY:
		HIP_IFEL(!(ep = hip_kea_ep_find(ip, spi_old)), -1,
			 "Could not find endpoint to be modified");
		hip_kea_remove_endpoint(ep);
		HIP_IFEL(!(ep = hip_kea_ep_create(hit, peer_hit, ip, alg,
						  spi, len, &keys->enc)), -1,
			 "Error creating kea endpoint");
		HIP_IFEBL(hip_kea_add_endpoint(kea, ep), -1, hip_kea_put_ep(ep),
			  "Error while adding endpoint");
		break;

	case HIP_ESCROW_OPERATION_DELETE:
		HIP_IFEL(!(ep = hip_kea_ep_find(ip, spi_old)), -1,
			 "Could not find endpoint to be deleted");
		hip_kea_remove_endpoint(ep);
		break;

	default:
		HIP_ERROR("Unknown operation type in escrow parameter %d",
			  op);
		accept = -1;
	}
	/** @todo a better place for this? If firewall is used, the received
	    information should be delivered to it. */
	if (accept == 0) {
		if (hip_firewall_is_alive()) {
			HIP_DEBUG("Firewall alive!\n");
			if (hip_firewall_add_escrow_data(entry, hit, peer_hit, keys))
				HIP_DEBUG("Sent data to firewall\n");
		}
	}

 out_err:
	if (kea)
		hip_keadb_put_entry(kea);
	if (err)
		HIP_DEBUG("Error while handlling escrow parameter");
	return err;
}
#endif //CONFIG_HIP_ESCROW

int hip_handle_encrypted(hip_ha_t *entry, struct hip_tlv_common *enc)
{
	int err = 0;
	int param_type;
	uint16_t crypto_len;
	char *tmp_enc = NULL;
	unsigned char *iv;
	struct hip_tlv_common * enc_param = NULL;

	HIP_DEBUG("hip_handle_encrypted\n");

	HIP_IFEL(!(tmp_enc = HIP_MALLOC(hip_get_param_total_len(enc),
					GFP_KERNEL)), -ENOMEM,
		 "No memory for temporary parameter\n");

	memcpy(tmp_enc, enc, hip_get_param_total_len(enc));

	/* Decrypt ENCRYPTED field*/
	_HIP_HEXDUMP("Recv. Key", &entry->hip_enc_in.key, 24);

	switch (entry->hip_transform) {
	case HIP_HIP_AES_SHA1:
		enc_param = (struct hip_tlv_common *)
			(tmp_enc + sizeof(struct hip_encrypted_aes_sha1));
		iv = ((struct hip_encrypted_aes_sha1 *) tmp_enc)->iv;
		/* 4 = reserved, 16 = iv */
		crypto_len = hip_get_param_contents_len(enc) - 4 - 16;
		HIP_DEBUG("aes crypto len: %d\n", crypto_len);
		break;
	case HIP_HIP_3DES_SHA1:
		enc_param = (struct hip_tlv_common *)
			(tmp_enc + sizeof(struct hip_encrypted_3des_sha1));
		iv = ((struct hip_encrypted_3des_sha1 *) tmp_enc)->iv;
		/* 4 = reserved, 8 = iv */
		crypto_len = hip_get_param_contents_len(enc) - 4 - 8;
		break;
	case HIP_HIP_NULL_SHA1:
		enc_param = (struct hip_tlv_common *)
			(tmp_enc + sizeof(struct hip_encrypted_null_sha1));
		iv = NULL;
		/* 4 = reserved */
		crypto_len = hip_get_param_contents_len(enc) - 4;
		break;
	default:
		HIP_IFEL(1, -EINVAL, "Unknown HIP transform: %d\n",
			 entry->hip_transform);
	}

	HIP_DEBUG("Crypto encrypted\n");
	_HIP_HEXDUMP("IV: ", iv, 16); /* Note: iv can be NULL */

	HIP_IFEL(hip_crypto_encrypted(enc_param, iv, entry->hip_transform,
				      crypto_len, &entry->hip_enc_in.key,
				      HIP_DIRECTION_DECRYPT), -EINVAL,
		 "Decryption of encrypted parameter failed\n");

	param_type = hip_get_param_type(enc_param);

	/* Handling contents */
	switch (param_type) {
	case HIP_PARAM_KEYS:
#ifdef CONFIG_HIP_ESCROW
		HIP_IFEL(hip_handle_escrow_parameter(
				 entry, (struct hip_keys *)enc_param), -1,
			 "Error while handling hip_keys parameter\n");
#endif
		break;
	default:
		HIP_IFEL(1, -EINVAL, "Unknown update paramer type in encrypted %d\n",
			 param_type);
	}

 out_err:
	if (err)
		HIP_DEBUG("Error while handling encrypted parameter\n");
	if (tmp_enc)
		HIP_FREE(tmp_enc);
	return err;
}

int hip_update_peer_preferred_address(hip_ha_t *entry,
				      struct hip_peer_addr_list_item *addr,
				      uint32_t spi_in)
{
	int err = 0, i = 0;
	struct hip_spi_in_item *item, *tmp;
	hip_list_t *item_nd = NULL, *tmp_nd = NULL;
	struct netdev_address *n;
	in6_addr_t local_addr;

	HIP_DEBUG("Checking spi setting 0x%x\n",spi_in);

	HIP_DEBUG_HIT("hit our", &entry->hit_our);
	HIP_DEBUG_HIT("hit peer", &entry->hit_peer);
	HIP_DEBUG_IN6ADDR("local", &entry->our_addr);
	HIP_DEBUG_IN6ADDR("peer", &addr->address);

	/* spi_in = hip_get_spi_to_update_in_established(
	   entry, &entry->our_addr); */
	HIP_IFEL(spi_in == 0, -1, "No inbound SPI found for daddr\n");

	if (IN6_IS_ADDR_V4MAPPED(&entry->our_addr)
	    != IN6_IS_ADDR_V4MAPPED(&addr->address)) {
		HIP_DEBUG("AF difference in addrs, checking if possible to choose "\
			  "same AF\n");
		list_for_each_safe(item_nd, tmp_nd, addresses, i) {
			n = list_entry(item_nd);
			if (hip_sockaddr_is_v6_mapped(&n->addr)
			    == IN6_IS_ADDR_V4MAPPED(&addr->address) & 
			    (ipv6_addr_is_teredo(hip_cast_sa_addr(&n->addr)) == 
			     ipv6_addr_is_teredo(&addr->address))) {
				HIP_DEBUG("Found addr with same AF\n");
				memset(&local_addr, 0, sizeof(in6_addr_t));
				memcpy(&local_addr, hip_cast_sa_addr(&n->addr),
				       sizeof(in6_addr_t));
				HIP_DEBUG_HIT("Using addr for SA", &local_addr);
				break;
			}
		}
	} else {
		/* same AF as in addr, use &entry->our_addr */
		memset(&local_addr, 0, sizeof(in6_addr_t));
		memcpy(&local_addr, &entry->our_addr, sizeof(in6_addr_t));
	}

	/** @todo Enabling 1s makes hard handovers work, but softhandovers fail. */
#if 1
	entry->hadb_ipsec_func->hip_delete_hit_sp_pair(&entry->hit_our,
                                                       &entry->hit_peer, IPPROTO_ESP, 1);

	default_ipsec_func_set.hip_delete_sa(entry->default_spi_out, &addr->address, &local_addr,
		      HIP_SPI_DIRECTION_OUT, entry);
#endif

#if 1
	entry->hadb_ipsec_func->hip_delete_hit_sp_pair(&entry->hit_peer,
                                                       &entry->hit_our, IPPROTO_ESP, 1);
#endif

	default_ipsec_func_set.hip_delete_sa(spi_in, &addr->address, &local_addr, HIP_SPI_DIRECTION_IN, entry);

	HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(&entry->hit_our,
                                                               &entry->hit_peer,
				       &local_addr, &addr->address,
				       IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");

	entry->local_udp_port = entry->nat_mode ? hip_get_local_nat_udp_port() : 0;

	HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(&local_addr, &addr->address,
                                                    &entry->hit_our,
			    &entry->hit_peer, entry->default_spi_out,
			    entry->esp_transform, &entry->esp_out,
			    &entry->auth_out, 1, HIP_SPI_DIRECTION_OUT, 0, entry), -1,
		 "Error while changing outbound security association for new "\
		 "peer preferred address\n");

#if 1
	HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(&entry->hit_peer,
                                                               &entry->hit_our,
				       &addr->address, &local_addr,
				       IPPROTO_ESP, 1, 0), -1,
		 "Setting up SP pair failed\n");
#endif

	HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(&addr->address, &local_addr,
			    &entry->hit_peer, &entry->hit_our,
			    spi_in, entry->esp_transform,
			    &entry->esp_in, &entry->auth_in, 1,
			    HIP_SPI_DIRECTION_IN, 0, entry), -1,
		 "Error while changing inbound security association for new "\
		 "preferred address\n");

 out_err:
	return err;
}

int hip_update_handle_echo_response(hip_ha_t *entry,
				    struct hip_echo_response *echo_resp,
                                    in6_addr_t *src_ip) {
	int err = 0, i;
	hip_list_t *item, *tmp;
	struct hip_spi_out_item *out_item;

	HIP_DEBUG("\n");

	list_for_each_safe(item, tmp, entry->spis_out, i) {
		int ii;
		hip_list_t *a_item, *a_tmp;
		struct hip_peer_addr_list_item *addr;
		out_item = list_entry(item);

		list_for_each_safe(a_item, a_tmp, out_item->peer_addr_list, ii) {
			addr = list_entry(a_item);
			_HIP_DEBUG("checking address, seq=%u\n",
				   addr->seq_update_id);
			if (memcmp(&addr->address, src_ip, sizeof(in6_addr_t)) == 0) {
				if (hip_get_param_contents_len(echo_resp)
				    != sizeof(addr->echo_data))
				{
					HIP_ERROR("echo data len mismatch\n");
					continue;
				}
				if (memcmp(addr->echo_data,
					   (void *)echo_resp +
					   sizeof(struct hip_tlv_common),
					   sizeof(addr->echo_data)) != 0)
				{
					HIP_ERROR("ECHO_RESPONSE differs from "	\
						  "ECHO_REQUEST\n");
					continue;
				}
				HIP_DEBUG("address verified successfully, " \
					  "setting state to ACTIVE\n");
				addr->address_state = PEER_ADDR_STATE_ACTIVE;
				HIP_DEBUG("Changing Security Associations for "	\
					  "the new peer address\n");
				/* if bex address then otherwise no */
				if (ipv6_addr_cmp(&entry->peer_addr,
						  &addr->address) == 0)
				{
					uint32_t spi = hip_hadb_get_spi(entry, -1);
					HIP_DEBUG("Setting SA for bex locator\n");
					HIP_IFEL(hip_update_peer_preferred_address(
							 entry, addr, spi), -1,
						 "Error while changing SAs for " \
						 "mobility\n");
				}
				do_gettimeofday(&addr->modified_time);
				if (addr->is_preferred)
				{
					/* maybe we should do this default address
					   selection after handling the LOCATOR. */
					hip_hadb_set_default_out_addr(
						entry,out_item, &addr->address);
				}
				else HIP_DEBUG("address was not set as " \
					       "preferred address\n");
			}
		}
	}

 out_err:
	return err;
}

int hip_receive_update(hip_common_t *msg, in6_addr_t *update_saddr,
		       in6_addr_t *update_daddr, hip_ha_t *entry,
		       hip_portpair_t *sinfo)
{
	int err = 0, has_esp_info = 0, pl = 0, send_ack = 0;
	in6_addr_t *hits = NULL;
	in6_addr_t *src_ip = NULL , *dst_ip = NULL;
	struct hip_esp_info *esp_info = NULL;
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	struct hip_locator *locator = NULL;
	struct hip_echo_request *echo_request = NULL;
	struct hip_echo_response *echo_response = NULL;
	struct hip_tlv_common *encrypted = NULL;
	uint32_t spi = 0;
	struct hip_stun *stun = NULL;

	HIP_DEBUG("\n");


        /** For debugging
        hip_print_locator_addresses(msg);
        if (entry)
            hip_print_peer_addresses(entry); */

        _HIP_DEBUG_HIT("receive a stun from: ", update_saddr);

#ifdef CONFIG_HIP_RVS
        if (hip_relay_get_status() == HIP_RELAY_ON)
        {
              hip_relrec_t *rec = NULL;
              hip_relrec_t dummy;

              /* Check if we have a relay record in our database matching the
                 Responder's HIT. We should find one, if the Responder is
                 registered to relay.*/
              HIP_DEBUG_HIT("Searching relay record on HIT ", &msg->hitr);
              memcpy(&(dummy.hit_r), &msg->hitr, sizeof(msg->hitr));
              rec = hip_relht_get(&dummy);
              if (rec == NULL)
              {
                  HIP_INFO("No matching relay record found.\n");
              }
              else if (rec->type == HIP_FULLRELAY || rec->type == HIP_RVSRELAY)
              {
                   hip_relay_forward(msg, update_saddr, update_daddr, rec, sinfo, HIP_UPDATE, rec->type);
                   goto out_err;
              }
         }
     else
#endif
        /* RFC 5201: If there is no corresponding HIP association, the
	 * implementation MAY reply with an ICMP Parameter Problem. */
	if(entry == NULL) {
		HIP_ERROR("No host association database entry found.\n");
		err = -1;
		goto out_err;

	}
	/* RFC 5201: An UPDATE packet is only accepted if the state is only
	   processed in state ESTABLISHED. However, if the state machine is in
	   state R2-SENT and an UPDATE is received, the state machine should
	   move to state ESTABLISHED (see table 5 under section 4.4.2. HIP
	   State Processes). */
	else if(entry->state == HIP_STATE_R2_SENT) {
		entry->state == HIP_STATE_ESTABLISHED;
		HIP_DEBUG("Received UPDATE in state %s, moving to "\
			  "ESTABLISHED.\n", hip_state_str(entry->state));
	} else if(entry->state != HIP_STATE_ESTABLISHED) {
		HIP_ERROR("Received UPDATE in illegal state %s.\n",
			  hip_state_str(entry->state));
		err = -EPROTO;
		goto out_err;
	}

	src_ip = update_saddr;
	dst_ip = update_daddr;
	hits = &msg->hits;

	/* RFC 5201: The UPDATE packet contains mandatory HMAC and HIP_SIGNATURE
	   parameters, and other optional parameters. The UPDATE packet contains
	   zero or one SEQ parameter. An UPDATE packet contains zero or one ACK
	   parameters. (see section 5.3.5). A single UPDATE packet may contain
	   both a sequence number and one or more acknowledgment numbers. (see
	   section 4.2).

	   Thus, we first have to verify the HMAC and HIP_SIGNATURE parameters
	   and only after successful verification, we can move to handling the
	   optional parameters. */

	/* RFC 5201: The system MUST verify the HMAC in the UPDATE packet. If
	   the verification fails, the packet MUST be dropped. */
	HIP_IFEL(hip_verify_packet_hmac(msg, &entry->hip_hmac_in), -1,
		 "HMAC validation on UPDATE failed.\n");

	/* RFC 5201: The system MAY verify the SIGNATURE in the UPDATE packet.
	   If the verification fails, the packet SHOULD be dropped and an error
	   message logged. */
	HIP_IFEL(entry->verify(entry->peer_pub_key, msg), -1,
		 "Verification of UPDATE signature failed.\n");

	/* RFC 5201: If both ACK and SEQ parameters are present, first ACK is
	   processed, then the rest of the packet is processed as with SEQ. */
	ack = hip_get_param(msg, HIP_PARAM_ACK);
	if (ack != NULL) {
		HIP_DEBUG("ACK parameter found with peer Update ID %u.\n",
			  ntohl(ack->peer_update_id));
		entry->hadb_update_func->hip_update_handle_ack(
			entry, ack, has_esp_info);
	}

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	if (seq != NULL) {
		HIP_DEBUG("SEQ parameter found with  Update ID %u.\n",
			  ntohl(seq->update_id));
		HIP_IFEL(hip_handle_update_seq(entry, msg), -1,
			 "Error when handling parameter SEQ.\n");
	}

	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	if (esp_info != NULL){
		HIP_DEBUG("ESP INFO parameter found with new SPI %u.\n",
			  ntohl(esp_info->new_spi));
		has_esp_info = 1;
		HIP_IFEL(hip_handle_esp_info(msg, entry), -1,
			 "Error in processing esp_info\n");
	}

	/* RFC 5206: End-Host Mobility and Multihoming. */
	locator = hip_get_param(msg, HIP_PARAM_LOCATOR);
	echo_request = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST);
	echo_response = hip_get_param(msg, HIP_PARAM_ECHO_RESPONSE);
	if (locator != NULL) {
		HIP_DEBUG("LOCATOR parameter found.\n");
		err = entry->hadb_update_func->hip_handle_update_plain_locator(
			entry, msg, src_ip, dst_ip, esp_info, seq);
	} else {
		if (echo_request != NULL) {
			HIP_DEBUG("ECHO_REQUEST parameter found.\n");
			err = entry->hadb_update_func->hip_handle_update_addr_verify(
				entry, msg, src_ip, dst_ip);
			/* Check the peer learning case. Can you find the src_ip
			   from spi_out->peer_addr_list if the addr is not found add it
			   -- SAMU */
			if (!err) {
				hip_print_peer_addresses(entry);
				pl = hip_peer_learning(esp_info, entry, src_ip);
				/* pl left unchecked because currently we are not
				   that interested in the success of PL */
				hip_print_peer_addresses(entry);
			}
		}
		if (echo_response != NULL) {
			HIP_DEBUG("ECHO_RESPONSE parameter found.\n");
			hip_update_handle_echo_response(entry, echo_response, src_ip);
		}
	}

	encrypted = hip_get_param(msg, HIP_PARAM_ENCRYPTED);
	if (encrypted != NULL) {
		HIP_DEBUG("ENCRYPTED found\n");
		HIP_IFEL(hip_handle_encrypted(entry, encrypted), -1,
			 "Error in processing encrypted parameter\n");
		send_ack = 1;
	}

	/* Node moves within public Internet or from behind a NAT to public
	   Internet.

	   Should this be moved inside the LOCATOR parameter handling? Does node
	   movement mean that we should expect a LOCATOR parameter?
	   -Lauri 01.07.2008. */
	if(sinfo->dst_port == 0){
		HIP_DEBUG("UPDATE packet src port %d\n", sinfo->src_port);
		entry->nat_mode = 0;
		entry->peer_udp_port = 0;
		entry->hadb_xmit_func->hip_send_pkt = hip_send_raw;
		hip_hadb_set_xmit_function_set(entry, &default_xmit_func_set);
	} else {
		/* Node moves from public Internet to behind a NAT, stays
		   behind the same NAT or moves from behind one NAT to behind
		   another NAT. */
		HIP_DEBUG("UPDATE packet src port %d\n", sinfo->src_port);

		if (!entry->nat_mode)
			entry->nat_mode = HIP_NAT_MODE_PLAIN_UDP;

		entry->peer_udp_port = sinfo->src_port;
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
		ipv6_addr_copy(&entry->our_addr, dst_ip);
		ipv6_addr_copy(&entry->peer_addr, src_ip);
	}

	/* RFC 5203: Registration Extension
	   When there is a REG_INFO parameter present and in the parameter are
	   listed changes that affect the set of requester's services, we must
	   response with an UPDATE packet containing a REG_REQUEST parameter.

	   When there is a REG_REQUEST parameter present and in the parameter
	   are listed services that the registrar is able to provide, we must
	   response with an UPDATE packet containing a REG_RESPONSE parameter.

	   When REG_INFO or REG_REQUEST is present, we just set the send_ack
	   bit and build the response parameter in the hip_update_send_ack().
	   This may lead to acking SEQs more than once, but since the update
	   implementation is currently being revised, we settle for this
	   arrangement for now.

	   REG_RESPONSE or REG_FAILED parametes do not need any response.
	   -Lauri 01.07.2008. */
	if(hip_get_param(msg, HIP_PARAM_REG_INFO) != NULL) {
		send_ack = 1;
	} else if(hip_get_param(msg, HIP_PARAM_REG_REQUEST) != NULL) {
		send_ack = 1;
	} else {
		hip_handle_param_reg_response(entry, msg);
		hip_handle_param_reg_failed(entry, msg);
	}

	/********** ESP-PROT anchor (OPTIONAL) **********/

	/* RFC 5201: presence of a SEQ parameter indicates that the
	 * receiver MUST ACK the UPDATE
	 *
	 * should be added above in handling of SEQ, but this breaks
	 * UPDATE as it might send duplicates the way ACKs are
	 * implemented right now */
	HIP_IFEL(esp_prot_handle_update(msg, entry, src_ip, dst_ip), -1,
			"failed to handle received esp prot anchor\n");

	/************************************************/

	if(send_ack) {
		HIP_IFEL(hip_update_send_ack(entry, msg, src_ip, dst_ip), -1,
			 "Error sending UPDATE ACK.\n");
	}

 out_err:
	if (err != 0)
		HIP_ERROR("UPDATE handler failed, err=%d\n", err);

	if (entry != NULL) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}

	//empty the oppipdb
	empty_oppipdb();

        /** For debugging
        if (entry)
            hip_print_peer_addresses(entry); */

	return err;
}

int hip_copy_spi_in_addresses(struct hip_locator_info_addr_item *src,
			      struct hip_spi_in_item *spi_in, int count)
{
	size_t s = count * sizeof(struct hip_locator_info_addr_item);
	void *p = NULL;

	HIP_DEBUG("src=0x%p count=%d\n", src, count);
	if (!spi_in || (src && count <= 0)) {
		HIP_ERROR("!spi_in or src & illegal count (%d)\n", count);
		return -EINVAL;
	}

	if (src) {
		p = HIP_MALLOC(s, GFP_ATOMIC);
		if (!p) {
			HIP_ERROR("kmalloc failed\n");
			return -ENOMEM;
		}
		memcpy(p, src, s);
	} else
		count = 0;

	_HIP_DEBUG("prev addresses_n=%d\n", spi_in->addresses_n);
	if (spi_in->addresses) {
		HIP_DEBUG("kfreeing old address list at 0x%p\n",
			  spi_in->addresses);
		HIP_FREE(spi_in->addresses);
	}

	spi_in->addresses_n = count;
	spi_in->addresses = p;

	return 0;
}

int hip_update_preferred_address(struct hip_hadb_state *entry,
				 in6_addr_t *new_pref_addr, in6_addr_t *daddr,
				 uint32_t *_spi_in)
{
     int err = 0;
     struct hip_spi_in_item *item, *tmp;
     uint32_t spi_in = *_spi_in;
     struct in6_addr srcaddr;
     struct in6_addr destaddr;
     HIP_DEBUG("Checking spi setting %x\n",spi_in);
     memcpy(&srcaddr, new_pref_addr, sizeof(struct in6_addr));
     memcpy(&destaddr, daddr, sizeof(struct in6_addr));

     HIP_DEBUG_HIT("hit our", &entry->hit_our);
     HIP_DEBUG_HIT("hit peer", &entry->hit_peer);
     HIP_DEBUG_IN6ADDR("saddr", new_pref_addr);
     HIP_DEBUG_IN6ADDR("daddr", daddr);

     entry->hadb_ipsec_func->hip_delete_hit_sp_pair(&entry->hit_our, &entry->hit_peer, IPPROTO_ESP, 1);

     default_ipsec_func_set.hip_delete_sa(entry->default_spi_out, daddr, &entry->our_addr,
		   HIP_SPI_DIRECTION_OUT, entry);
#if 1
     entry->hadb_ipsec_func->hip_delete_hit_sp_pair(&entry->hit_peer, &entry->hit_our, IPPROTO_ESP, 1);
#endif
     /** @todo Check that this works with the pfkey API. */
     default_ipsec_func_set.hip_delete_sa(spi_in, &entry->our_addr, &entry->hit_our, HIP_SPI_DIRECTION_IN, entry);

     /* THIS IS JUST A GRUDE FIX -> FIX THIS PROPERLY LATER
        check for a mismatch in addresses and fix the situation
        at least one case comes here with wrong addrs
        MN has IPv4 CN IPv4 and IPv6 addresses MN does hard interfamily handover.
        MN loses IPv4 addr and obtains IPv6 addr. As a result this code tries to add
        saddr(6) daddr(4) SA ... BUG ID 458
      */
     if ((IN6_IS_ADDR_V4MAPPED(&srcaddr) != IN6_IS_ADDR_V4MAPPED(&destaddr)) || 
	     (ipv6_addr_is_teredo(&srcaddr) != ipv6_addr_is_teredo(&destaddr))) {
             hip_list_t *item = NULL, *tmp = NULL, *item_outer = NULL, *tmp_outer = NULL;
             struct hip_peer_addr_list_item *addr_li;
             struct hip_spi_out_item *spi_out;
             int i = 0, ii = 0;
             list_for_each_safe(item_outer, tmp_outer, entry->spis_out, i) {
                     spi_out = list_entry(item_outer);
                     ii = 0;
                     tmp = NULL;
                     item = NULL;
                     list_for_each_safe(item, tmp, spi_out->peer_addr_list, ii) {
                             addr_li = list_entry(item);
                             HIP_DEBUG_HIT("SPI out addresses", &addr_li->address);
                             if (IN6_IS_ADDR_V4MAPPED(&addr_li->address) ==
                                 IN6_IS_ADDR_V4MAPPED(&srcaddr) & 
				 (ipv6_addr_is_teredo(&addr_li->address) == 
				  ipv6_addr_is_teredo(&srcaddr))) {
                                     HIP_DEBUG("Found matching addr\n");
                                     ipv6_addr_copy(&destaddr, &addr_li->address);
                                     goto out_of_loop;
                             }
                     }
             }
     }
 out_of_loop:

     HIP_IFEL((IN6_IS_ADDR_V4MAPPED(&srcaddr) != IN6_IS_ADDR_V4MAPPED(&destaddr)), -1,
	     "Different address families, not adding SAs\n");

     HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(&entry->hit_our, &entry->hit_peer,
				    &srcaddr, &destaddr, IPPROTO_ESP, 1, 0),
	      -1, "Setting up SP pair failed\n");

     entry->local_udp_port = entry->nat_mode ? hip_get_local_nat_udp_port() : 0;

     _HIP_DEBUG("SPI out =0x%x\n", entry->default_spi_out);
     _HIP_DEBUG("SPI in =0x%x\n", spi_in);

     HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(&srcaddr, &destaddr, &entry->hit_our,
			 &entry->hit_peer, entry->default_spi_out,
			 entry->esp_transform, &entry->esp_out,
			 &entry->auth_out, 1, HIP_SPI_DIRECTION_OUT, 0, entry), -1,
	      "Error while changing outbound security association for new "\
	      "preferred address\n");

     /* hip_delete_sp_pair(&entry->hit_peer, &entry->hit_our, IPPROTO_ESP,
	1);
        default_ipsec_func_set.hip_delete_sa(spi_in, &entry->our_addr, HIP_SPI_DIRECTION_OUT, entry); */

	HIP_IFEL(_spi_in == NULL, -1, "No inbound SPI found for daddr\n");

#if 1
     HIP_IFEL(entry->hadb_ipsec_func->hip_setup_hit_sp_pair(&entry->hit_peer,&entry->hit_our,
				    &destaddr, &srcaddr, IPPROTO_ESP, 1, 0),
	      -1, "Setting up SP pair failed\n");
#endif

     HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(&destaddr, &srcaddr,
			 &entry->hit_peer, &entry->hit_our,
			 spi_in, entry->esp_transform,
			 &entry->esp_in, &entry->auth_in, 1,
			 HIP_SPI_DIRECTION_IN, 0, entry), -1,
	      "Error while changing inbound security association for new "\
	      "preferred address\n");

     //ipv6_addr_copy(&entry->our_addr, &srcaddr);

 out_err:
	return err;

}

int hip_update_src_address_list(struct hip_hadb_state *entry,
				struct hip_locator_info_addr_item *addr_list,
				in6_addr_t *daddr, int addr_count,
				int esp_info_old_spi, int is_add,
				struct sockaddr* addr)
{
	int err = 0, i = 0, ii = 0, preferred_address_found = 0;
	int choose_random = 0, change_preferred_address = 0;
	struct hip_spi_in_item *spi_in = NULL;
	struct hip_locator_info_addr_item *loc_addr_item = addr_list;
	in6_addr_t *saddr, *comp_addr = hip_cast_sa_addr(addr);
	hip_list_t *item = NULL, *tmp = NULL, *item_outer = NULL,
		*tmp_outer = NULL;
	struct hip_peer_addr_list_item *addr_li;
	struct hip_spi_out_item *spi_out;

	HIP_DEBUG("\n");

	/* Peer's preferred address. Can be changed by the source address
	   selection below if we don't find any addresses of the same family
	   as peer's preferred address (intrafamily handover).

	   Address that is currently used with the peer, as far we know it might
	   have chaned in a double jump for example. -samu
	*/
	HIP_IFE(hip_hadb_get_peer_addr(entry, daddr), -1);

	/*
	   Gets a pointer to the inbound SPI list. "copy failed", what copy?
	   Has this call been "hip_copy_spi_in_addresses", but it is done
	   in the end of this function.
	   -samu
	*/

	spi_in = hip_hadb_get_spi_in_list(entry, esp_info_old_spi);
	if (!spi_in) {
		HIP_ERROR("SPI listaddr list copy failed\n");
		goto out_err;
	}
#if 0
        /*
	   avoid advertising the same address set
	   (currently assumes that lifetime or reserved field do not
	   change, later store only addresses)

	   This just checked that if the addresses list is exactly the
	   same as the inbound SPI addresses list then lets not send
	   send any UPDATES. At least Dongsu has some problems with this
	   one. There might be problems in situations , like slower
	   networks where this can go wrong. In gereral I do not think
	   this matters so much, it is just one UPDATE once in a while
	   -samu
	*/

	if (addr_count == spi_in->addresses_n &&
	    addr_list && spi_in->addresses &&
	    memcmp(addr_list, spi_in->addresses,
		   addr_count *
		   sizeof(struct hip_locator_info_addr_item)) == 0) {
		HIP_DEBUG("Same address set as before, return\n");
		return GOTO_OUT;
	} else {
		HIP_DEBUG("Address set has changed, continue\n");
	}
#endif

	/*
	   dont go to out_err but to ...

	   Did not have addresses listed, addr_list should contain
	   all the addresses from the addresses table just after a
	   netdev event, that lead us here. If we do not have addresses
	   what is the point in updating the preferred address

	   And if we do not have any addresses we have to clear the local
	   address from the entry and then remember a empty set of addresses
	   see bottom of this function.
	   -samu

	*/
	if(!addr_list) {
		HIP_DEBUG("No address list\n");
		goto skip_pref_update;
	}

	/*
	   spi_in->spi is equal to esp_info_old_spi. In the loop below, we make
	   sure that the source and destination address families match.

	   Looks like this pointer is already assigned to the same place
	   so this line is not really needed -samu
	 */
	loc_addr_item = addr_list;

	/*
	  Just checks that all the addresses given are in the same format.
	  Internally and in LOCATOR all addresses are in IPv4 mapped to
	  IPv6 format ...00FFFF1234
	  -samu
	 */

	HIP_IFEL((addr->sa_family == AF_INET), -1,
		 "all addresses in update should be mapped");

	/*
	   If we have deleted the old address and it was preferred than we should
	   make new preferred address. Now, we chose it as random address in list.

	   Yes this comment has some meaning to it. We should actually choose a
	   address to be our new local address, NATs and stuff will have their
	   say into this matter also.

	   Happens if netlink event was RTM_DELADDR and the removed address
	   was our currently used address. The random is just, choose the next
	   address that is not the address removed (inside a family if not possible
	   change family).
	   -samu
	*/
	if( !is_add && ipv6_addr_cmp(&entry->our_addr, comp_addr) == 0 ) {
		choose_random = 1;
	}

	/*
	  If address was an addition and active handovers are on, then we want
	  to do the handover to the new address right now and we force the functionality
	  below to make the change. Do NOT really know if this works correctly any more
	  -samu
	 */
	if( is_add && is_active_handover ) {
		change_preferred_address = 1;/* comp_addr = hip_cast_sa_addr(addr); */
	} else {
		comp_addr = &entry->our_addr;
	}

	/* Lets choose a random address this loop is gone through twice thats why
	   there is that been_here variable

	   NOTE: This changes our address in use

	   -samu
	 */
	if (choose_random) {
		int been_here = 0;
	choose_random:
		/*
		  First we will go through the current addresses looking for an
		  address that has the same family as the removed one (addr from RTM_DELADDR).
		  -samu
		 */
		loc_addr_item = addr_list;
		
		//changed to read global counter
		//for(i = 0; i < addr_count; i++, loc_addr_item++) {
		for (i = 0; i < address_count; i++) {
/*
		comp_af = IN6_IS_ADDR_V4MAPPED(hip_get_locator_item_address(hip_get_locator_item(locator_address_item, i)))

 */			
			HIP_DEBUG("I is now %d\n", i);
			 
			saddr = hip_get_locator_item_address(hip_get_locator_item_as_one(loc_addr_item, i));
//			saddr = &loc_addr_item->address;
			HIP_DEBUG_IN6ADDR("Saddr: ", saddr);
			HIP_DEBUG_IN6ADDR("Daddr: ", daddr);

			if (memcmp(comp_addr, saddr, sizeof(in6_addr_t)) == 0) {
				/*
				   If both are mapped in the same manner then they are
				   the same family -samu
				*/
				if (IN6_IS_ADDR_V4MAPPED(saddr) ==
				    IN6_IS_ADDR_V4MAPPED(daddr) && 
				    (ipv6_addr_is_teredo(saddr) == 
				     ipv6_addr_is_teredo(daddr)))
				{
					/*
					   Select the first match

					   This works for now but this really should be done more wisely
					   Like with ICE data or something similar. This would choose
					   a natted IPv4 over globally routable IPv4 if the order was
					   correct
					   -samu
					 */
					loc_addr_item->reserved = ntohl(1 << 7);
					preferred_address_found = 1;
					/*
					  We want to change the new address and it was RTM_NEWADDR
					  This belongs to the active handover stuff
					 */
					if( change_preferred_address && is_add) {
						/*
						   basically just sets the SAs correctly
						*/
						HIP_IFEL(hip_update_preferred_address(
								 entry, saddr, daddr, &spi_in->spi),
							 -1, "Setting new preferred address "\
							 "failed.\n");
					} else {
						/*
						  Do not change the preferred address and was a delete
						  This comment has no sensible meaning to me
						  -samu
						 */
						HIP_DEBUG("Preferred Address is the old "\
							  "preferred address\n");
					}
					HIP_DEBUG_IN6ADDR("saddr: ", saddr);
					break;
				}
			}
		}
		/*
		  We did not find a suitable address in the same family as the removed
		  one and we are on the first pass of this code.

		  So we will start looking for a address from a different family and if found
		  we will skip back to choose_random.

		  On the second round this will be skipped

		  If the first round searched for another IPv4 address this will change the address to IPv6
		  if possible and try again  to look for another IPv6 address.

		  NOTE: This changes the peers address in use
		  -samu
		 */
		if ((preferred_address_found == 0) && (been_here == 0)) {
			item = NULL;
			tmp = NULL;
			item_outer = NULL;
			tmp_outer = NULL;
		        i = 0, ii = 0;
			list_for_each_safe(item_outer, tmp_outer, entry->spis_out, i) {
				spi_out = list_entry(item_outer);
				ii = 0;
				tmp = NULL;
				item = NULL;
				list_for_each_safe(item, tmp, spi_out->peer_addr_list, ii) {
					addr_li = list_entry(item);
					HIP_DEBUG_HIT("SPI out addresses", &addr_li->address);
					if ((IN6_IS_ADDR_V4MAPPED(&addr_li->address) !=
					    IN6_IS_ADDR_V4MAPPED(daddr)) || 
					    (ipv6_addr_is_teredo(&addr_li->address) != 
					     ipv6_addr_is_teredo(daddr))) {
						HIP_DEBUG("Found other family than BEX address "\
							  "family\n");
						ipv6_addr_copy(daddr, &addr_li->address);
						ipv6_addr_copy(&entry->peer_addr,
							       &addr_li->address);
						/** @todo Or just break? Fix later. */
						goto break_list_for_loop;
					}
				}
			}
		break_list_for_loop:
			been_here = 1;
			goto choose_random; 
		}
	}
	if (preferred_address_found) {
		HIP_DEBUG("Suitable peer address found, skipping\n");
		ipv6_addr_copy(&entry->our_addr, saddr);	       
		goto skip_pref_update;
	}

	loc_addr_item = addr_list;
	/* Select the first match

	   if the loops above say that the preferred address is found, it means
	   there is a "suitable" address pair from IPv4 or IPv6 and here it is copied to
	   the correct place. In my opinion this could be done differently...
	   -samu
	 */

	for(i = 0; i < addr_count; i++ /*, loc_addr_item++*/)
	{
		saddr = hip_get_locator_item_address(hip_get_locator_item_as_one(loc_addr_item, i));
		//saddr = &loc_addr_item->address;
		HIP_DEBUG_IN6ADDR("Saddr: ", saddr);
		HIP_DEBUG_IN6ADDR("Daddr: ", daddr);
		if (IN6_IS_ADDR_V4MAPPED(saddr) ==
		    IN6_IS_ADDR_V4MAPPED(daddr) && !is_add && 
		    (ipv6_addr_is_teredo(saddr) == 
		     ipv6_addr_is_teredo(daddr)))
		{
			loc_addr_item->reserved = ntohl(1 << 7);
			HIP_DEBUG_IN6ADDR("first match: ", saddr);
			/*
			   basically just sets the SAs correctly
			 */
			HIP_IFEL(hip_update_preferred_address(
					 entry, saddr, daddr, &spi_in->spi), -1,
				 "Setting New Preferred Address Failed\n");
			preferred_address_found = 1;
			HIP_DEBUG_IN6ADDR("New local address\n", saddr);
			ipv6_addr_copy(&entry->our_addr, saddr);
			break;
		}
	}

 skip_pref_update:

	if(!preferred_address_found && !is_add){
		memset(&entry->our_addr, 0, sizeof(in6_addr_t));
		HIP_IFEL(1, GOTO_OUT, "Did not find src address matching peers address family\n");
	}

	/*
	   remember the address set we have advertised to the peer
	*/
	err = hip_copy_spi_in_addresses(addr_list, spi_in, addr_count);
#if 0
	/* Do not need anymore -samu*/
	loc_addr_item = addr_list;
	for(i = 0; i < addr_count; i++, loc_addr_item++) {
		int j, addr_exists = 0;
		in6_addr_t *iter_addr = &loc_addr_item->address;
		for(j = 0; j < spi_in->addresses_n; j++){
			struct hip_locator_info_addr_item *spi_addr_item =
				(struct hip_locator_info_addr_item *) spi_in->addresses + j;
			if(ipv6_addr_cmp(&spi_addr_item->address, iter_addr)) {
				//loc_addr_item->state = spi_addr_item->state;
				addr_exists = 1;
			}
		}
		//if(!addr_exists) {
			//loc_addr_item->state = ADDR_STATE_WAITING_ECHO_REQ;
		//}
	}
#endif

 out_err:
	HIP_DEBUG_IN6ADDR("Saddr: ", &entry->our_addr);
	HIP_DEBUG_IN6ADDR("Daddr: ", &entry->peer_addr);
	return err;
}

int hip_send_update(struct hip_hadb_state *entry,
		    struct hip_locator_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags,
		    int is_add, struct sockaddr* addr)
{
	int err = 0, make_new_sa = 0, add_locator;
	int was_bex_addr = -1;
	int i = 0;
	uint32_t update_id_out = 0;
	uint32_t mapped_spi = 0; /* SPI of the SA mapped to the ifindex */
	uint32_t new_spi_in = 0, old_spi;
	uint32_t esp_info_old_spi = 0, esp_info_new_spi = 0;
	uint16_t mask = 0;
	hip_list_t *tmp_li = NULL, *item = NULL;
	hip_common_t *update_packet = NULL;
	in6_addr_t zero_addr = IN6ADDR_ANY_INIT;
	in6_addr_t saddr = { 0 }, daddr = { 0 };
	struct netdev_address *n;
	struct hip_own_addr_list_item *own_address_item, *tmp;
	int anchor_update = 0;
	struct hip_spi_out_item *spi_out = NULL;

	HIP_DEBUG("\n");

	HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), -1);

	HIP_IFEL(entry->is_loopback, 0, "Skipping loopback\n");

	// used to distinguish anchor-update from other message types
	anchor_update = flags & SEND_UPDATE_ESP_ANCHOR;

	old_spi = hip_hadb_get_spi(entry, -1);

	add_locator = flags & SEND_UPDATE_LOCATOR;
	HIP_DEBUG("addr_list=0x%p addr_count=%d ifindex=%d flags=0x%x\n",
		  addr_list, addr_count, ifindex, flags);
	if (!ifindex)
		_HIP_DEBUG("base draft UPDATE\n");

	if (add_locator)
		HIP_DEBUG("mm UPDATE, %d addresses in LOCATOR\n", addr_count);
	else
		HIP_DEBUG("Plain UPDATE\n");

	/* Start building UPDATE packet */
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Out of memory.\n");
	HIP_DEBUG_HIT("sending UPDATE to HIT", &entry->hit_peer);
	entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
						     mask, &entry->hit_our,
						     &entry->hit_peer);

	if (add_locator) {
		/* mm stuff, per-ifindex SA
		   reuse old SA if we have one, else create a new SA.
		   miika: changing of spi is not supported, see bug id 434 */
		/* mapped_spi = hip_hadb_get_spi(entry, ifindex); */
		mapped_spi = hip_hadb_get_spi(entry, -1);
		HIP_DEBUG("mapped_spi=0x%x\n", mapped_spi);
		if (mapped_spi) {
			make_new_sa = 0;
			HIP_DEBUG("Mobility with single SA pair, readdress with no "\
				  "rekeying\n");
			HIP_DEBUG("Reusing old SA\n");
			/* Mobility with single SA pair */
		} else {
			HIP_DEBUG("Host multihoming\n");
			make_new_sa = 1;
			_HIP_DEBUG("TODO\n");
		}
	} else {
		/* base draft UPDATE, create a new SA anyway */
		_HIP_DEBUG("base draft UPDATE, create a new SA\n");

		// we reuse the old spi for the ANCHOR update
		mapped_spi = hip_hadb_get_spi(entry, -1);
	}

	/* If this is mm-UPDATE (ifindex should be then != 0) avoid
	   sending empty LOCATORs to the peer if we have not sent previous
	   information on this ifindex/SPI yet */
	if (ifindex != 0 && mapped_spi == 0 && addr_count == 0) {
		HIP_DEBUG("NETDEV_DOWN and ifindex not advertised yet, returning\n");
		goto out;
	}

	HIP_DEBUG("make_new_sa=%d\n", make_new_sa);

	if (make_new_sa) {
		HIP_IFEL(!(new_spi_in = entry->hadb_ipsec_func->hip_acquire_spi(&entry->hit_peer,
							&entry->hit_our)),
			 -1, "Error while acquiring a SPI\n");
		HIP_DEBUG("Got SPI value for the SA 0x%x\n", new_spi_in);

		/** @todo move to rekeying_finish */
		if (!mapped_spi) {
			struct hip_spi_in_item spi_in_data;

			_HIP_DEBUG("previously unknown ifindex, creating a new item "\
				   "to inbound spis_in\n");
			memset(&spi_in_data, 0,
			       sizeof(struct hip_spi_in_item));
			spi_in_data.spi = new_spi_in;
			spi_in_data.ifindex = ifindex;
			spi_in_data.updating = 1;
			HIP_IFEL(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN,
						  &spi_in_data), -1,
				 "Add_spi failed\n");
		} else {
			_HIP_DEBUG("is previously mapped ifindex\n");
		}
	} else {
		HIP_DEBUG("not creating a new SA\n");
		new_spi_in = mapped_spi;
	}

	_HIP_DEBUG("entry->current_keymat_index=%u\n",
		   entry->current_keymat_index);

	if (addr_list) {
		if (make_new_sa) {
			/* mm Host multihoming. Currently simultaneous SAs are not
			   supported. Neither is changing of SPI (see bug id 434) */
			esp_info_old_spi = old_spi;
			esp_info_new_spi = old_spi; // new_spi_in;
			HIP_DEBUG("Multihoming, new SA: old=%x new=%x\n",
				  esp_info_old_spi, esp_info_new_spi);
		} else {
			HIP_DEBUG("Reusing old SPI\n");
			esp_info_old_spi = mapped_spi;
			esp_info_new_spi = mapped_spi;
		}
	//} else /* hack to prevent sending of ESP-update when only ANCHOR-update */
	} else if (!anchor_update)
	{
		HIP_DEBUG("adding ESP_INFO, Old SPI <> New SPI\n");
		/* plain UPDATE or readdress with rekeying */
		/* update the SA of the interface which caused the event */
		HIP_IFEL(!(esp_info_old_spi =
			   hip_hadb_get_spi(entry, ifindex)), -1,
			 "Could not find SPI to use in Old SPI\n");
		/* here or later ? */
		hip_set_spi_update_status(entry, esp_info_old_spi, 1);
		//esp_info_new_spi = new_spi_in; /* see bug id 434 */
		esp_info_new_spi = esp_info_old_spi;
	} else
	{
		HIP_DEBUG("Reusing old SPI\n");
		esp_info_old_spi = mapped_spi;
		esp_info_new_spi = mapped_spi;
	}

	/* this if is another hack to make sure we don't send ESP-update
	 * when we only want a pure ANCHOR-update */
	if (addr != NULL)
	{
		/* if del then we have to remove SAs for that address */
		was_bex_addr = ipv6_addr_cmp(hip_cast_sa_addr(addr),
						 &entry->our_addr);
	}

	/* Some address was added and BEX address is nulled */
	if (is_add && !ipv6_addr_cmp(&entry->our_addr, &zero_addr))
	{
		ipv6_addr_copy(&entry->our_addr, hip_cast_sa_addr(addr));
		err = hip_update_src_address_list(entry, addr_list, &daddr,
						  addr_count, esp_info_new_spi,
						  is_add, addr);
		if(err == GOTO_OUT)
			goto out;
		else if(err)
			goto out_err;

		HIP_IFEL(err = hip_update_preferred_address(
				 entry, hip_cast_sa_addr(addr),
				 &entry->peer_addr, &esp_info_new_spi), -1,
			 "Updating peer preferred address failed\n");
	}

	if (!is_add && (was_bex_addr == 0)) {
		HIP_DEBUG("Netlink event was del, removing SAs for the address for "\
			  "this entry\n");
		default_ipsec_func_set.hip_delete_sa(esp_info_old_spi, hip_cast_sa_addr(addr),
						     &entry->peer_addr, HIP_SPI_DIRECTION_IN, entry);
		default_ipsec_func_set.hip_delete_sa(entry->default_spi_out, &entry->peer_addr,
						     hip_cast_sa_addr(addr), HIP_SPI_DIRECTION_OUT, entry);

		/* and we have to do it before this changes the local_address */
		err = hip_update_src_address_list(entry, addr_list, &daddr,
						  addr_count, esp_info_old_spi,
						  is_add, addr);
 		if(err == GOTO_OUT)
			goto out;
		else if(err)
			goto out_err;
	}

	if (!anchor_update)
	{
		/* Send UPDATE(ESP_INFO, LOCATOR, SEQ) */
		HIP_DEBUG("esp_info_old_spi=0x%x esp_info_new_spi=0x%x\n",
			  esp_info_old_spi, esp_info_new_spi);
		HIP_IFEL(hip_build_param_esp_info(
				 update_packet, entry->current_keymat_index,
				 esp_info_old_spi, esp_info_new_spi),
			 -1, "Building of ESP_INFO param failed\n");

		if (add_locator)
		{
			err = hip_build_param_locator(update_packet, addr_list,
							  addr_count);
		  HIP_IFEL(err, err, "Building of LOCATOR param failed\n");
		} else
		  HIP_DEBUG("not adding LOCATOR\n");

		 hip_update_set_new_spi_in(entry, esp_info_old_spi,
					   esp_info_new_spi, 0);
	}

	/*************** SEQ (OPTIONAL) ***************/

     entry->update_id_out++;
     update_id_out = entry->update_id_out;
     _HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
     /** @todo Handle this case. */
     HIP_IFEL(!update_id_out, -EINVAL,
	      "Outgoing UPDATE ID overflowed back to 0, bug ?\n");
     HIP_IFEL(hip_build_param_seq(update_packet, update_id_out), -1,
	      "Building of SEQ param failed\n");

     /* remember the update id of this update */
     hip_update_set_status(entry, esp_info_old_spi,
			   0x1 | 0x2 | 0x8, update_id_out, 0, NULL,
			   entry->current_keymat_index);

     /********** ESP-PROT anchor (OPTIONAL) **********/

     /* @note params mandatory for this UPDATE type are the generally mandatory
      *       params HMAC and HIP_SIGNATURE as well as this ESP_PROT_ANCHOR and
      *       the SEQ in the signed part of the message
      * @note SEQ has to be set in the message before calling this function. It
      * 	  is the hook saying if we should add the anchors or not
      * @note the received acknowledgement should trigger an add_sa where
      * 	  update = 1 and direction = OUTBOUND
      * @note combination with other UPDATE types is possible */
	 HIP_IFEL(esp_prot_update_add_anchor(update_packet, entry), -1,
			 "failed to add esp prot anchor\n");

     /************************************************/

     /* Add HMAC */
     HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					    &entry->hip_hmac_out), -1,
	      "Building of HMAC failed\n");


	 /* Add SIGNATURE */
	 HIP_IFEL(entry->sign(entry->our_priv_key, update_packet), -EINVAL,
		  "Could not sign UPDATE. Failing\n");

     /* Send UPDATE */
     hip_set_spi_update_status(entry, esp_info_old_spi, 1);


     /* before sending check if the AFs match and do something about it
	so it doesn't fail in raw send */

     /* If it was add and the address_count was larger than one
	we presumably have the bex address so why change src_addr :)

	One reason to do it is the following:
	BEX over ipv4.
	HO to other IF.
	rtm del addr to ipv4 and ipv6 address we got.
	rtm new addr to ipv6 addr which gets to be the src addr and first update
	fails because we do not know peers ipv6 addr.
	rtm new addr to ipv4 addr
	This is not added now

	Now if add and address_count > 1 it should check first
	if there is same address family in peer_addr_list
	if there is no addresses that belong to same af change the src addr
     */

     if (is_add && (address_count > 1)) {
	     hip_list_t *itemj = NULL, *tmpj = NULL, *item_outerj = NULL,
                     *tmp_outerj = NULL;
             struct hip_peer_addr_list_item *addr_lij;
             struct hip_spi_out_item *spi_outj;
             int ij = 0, iij = 0;
	     HIP_DEBUG("is add and address count > 1\n");
             list_for_each_safe(item_outerj, tmp_outerj, entry->spis_out, ij) {
                     spi_outj = list_entry(item_outerj);
                     iij = 0;
                     tmpj = NULL;
                     itemj = NULL;
                     list_for_each_safe(itemj, tmpj, spi_outj->peer_addr_list, iij) {
                             addr_lij = list_entry(itemj);
                             HIP_DEBUG_HIT("SPI out addresses", &addr_lij->address);
                             if (IN6_IS_ADDR_V4MAPPED(&addr_lij->address) ==
                                 IN6_IS_ADDR_V4MAPPED(&saddr) && 
				 (ipv6_addr_is_teredo(&addr_lij->address) == 
				  ipv6_addr_is_teredo(&saddr))) {
                                     HIP_DEBUG("Found matching addr\n");
 				     goto skip_src_addr_change;
                             }
                     }
             }
     }

     if(IN6_IS_ADDR_V4MAPPED(&entry->our_addr)
	== IN6_IS_ADDR_V4MAPPED(&daddr)) {
	     HIP_DEBUG_IN6ADDR("saddr", &saddr);
	     HIP_DEBUG_IN6ADDR("daddr", &daddr);
	     HIP_DEBUG("Same address family\n");
	     memcpy(&saddr, &entry->our_addr, sizeof(saddr));
     } else {
	  HIP_DEBUG("Different address family\n");
	  list_for_each_safe(item, tmp_li, addresses, i) {
	       n = list_entry(item);
	       if (IN6_IS_ADDR_V4MAPPED(&daddr) ==
		   hip_sockaddr_is_v6_mapped(&n->addr)) {
		    HIP_DEBUG_IN6ADDR("chose address", hip_cast_sa_addr(&n->addr));
                    memcpy(&saddr, hip_cast_sa_addr(&n->addr), sizeof(saddr));
                    ipv6_addr_copy(&entry->our_addr, &saddr);
                    break;
	       }
	  }
     }

skip_src_addr_change:

     /* needs to check also that if entry->our_addr differed from
        entry->peer_addr. This because of case where CN has 4 and 6 addrs
        and MN has initially 4 and it does a hard handover 6. This results into
        mismatch of addresses that possibly could be fixed by checking the peer_addr_list
        SEE ALSO BZ ID 458 */
     if (IN6_IS_ADDR_V4MAPPED(&entry->our_addr)
         != IN6_IS_ADDR_V4MAPPED(&entry->peer_addr)) {
             hip_list_t *item = NULL, *tmp = NULL, *item_outer = NULL,
                     *tmp_outer = NULL;
             struct hip_peer_addr_list_item *addr_li;
             struct hip_spi_out_item *spi_out;
             int i = 0, ii = 0;
             list_for_each_safe(item_outer, tmp_outer, entry->spis_out, i) {
                     spi_out = list_entry(item_outer);
                     ii = 0;
                     tmp = NULL;
                     item = NULL;
                     list_for_each_safe(item, tmp, spi_out->peer_addr_list, ii) {
                             addr_li = list_entry(item);
                             HIP_DEBUG_HIT("SPI out addresses", &addr_li->address);
                             if (IN6_IS_ADDR_V4MAPPED(&addr_li->address) ==
                                 IN6_IS_ADDR_V4MAPPED(&entry->our_addr) && 
				 (ipv6_addr_is_teredo(&addr_li->address) == 
				  ipv6_addr_is_teredo(&entry->our_addr))) {
                                     HIP_DEBUG("Found matching addr\n");
                                     ipv6_addr_copy(&daddr, &addr_li->address);
                                     ipv6_addr_copy(&entry->peer_addr,
                                                    &addr_li->address);
                                     /** @todo Or just break? Fix later. */
                                     goto out_of_loop;
                             }
                     }
             }
     }
 out_of_loop:

     HIP_DEBUG("Sending initial UPDATE packet.\n");
     /* guarantees retransmissions */
     entry->update_state = HIP_UPDATE_STATE_REKEYING;

     HIP_DEBUG_IN6ADDR("ha local addr", &entry->our_addr);
     HIP_DEBUG_IN6ADDR("ha peer addr", &entry->peer_addr);
     HIP_DEBUG_IN6ADDR("saddr", &saddr);
     HIP_DEBUG_IN6ADDR("daddr", &daddr);
    
     if (is_add || (was_bex_addr != 0))
     {
	     saddr = entry->our_addr;
	     daddr = entry->peer_addr;
     };
		     
     err = entry->hadb_xmit_func->
	     hip_send_pkt(&saddr, &daddr,
		    (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
		    entry->peer_udp_port, update_packet, entry, 1);
     
     HIP_DEBUG("Send_pkt returned %d\n", err);    
     
     // Send update to the rendezvous server as well, if there is one available
     if (entry->rendezvous_addr)
     {
	  err = entry->hadb_xmit_func->
	       hip_send_pkt(&saddr, entry->rendezvous_addr,
			    (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			    entry->peer_udp_port, update_packet, entry, 1);
	  
	  HIP_DEBUG("Send_pkt returned %d\n", err);    		  
     }
     
     err = 0;
     /** @todo 5. The system SHOULD start a timer whose timeout value
	 should be ..*/
     goto out;

 out_err:
     entry->state = HIP_STATE_ESTABLISHED;
     _HIP_DEBUG("fallbacked to state ESTABLISHED (ok ?)\n");

     hip_set_spi_update_status(entry, esp_info_old_spi, 0);
     /* delete IPsec SA on failure */
     HIP_ERROR("TODO: delete SA\n");
 out:

	HIP_UNLOCK_HA(entry);
	if (update_packet)
		HIP_FREE(update_packet);
	return err;
}

static int hip_update_get_all_valid(hip_ha_t *entry, void *op)
{
	struct hip_update_kludge *rk = op;

	if (rk->count >= rk->length)
		return -1;

	if (entry->hastate == HIP_HASTATE_HITOK &&
	    entry->state == HIP_STATE_ESTABLISHED) {
		hip_hadb_hold_entry(entry);
		rk->array[rk->count] = entry;
		rk->count++;
	} else
		_HIP_DEBUG("skipping HA entry 0x%p (state=%s)\n",
			  entry, hip_state_str(entry->state));

	return 0;
}

void hip_send_update_all(struct hip_locator_info_addr_item *addr_list,
			 int addr_count, int ifindex, int flags, int is_add,
			 struct sockaddr *addr)
{
	int err = 0, i;
	hip_ha_t *entries[HIP_MAX_HAS] = {0};
	struct hip_update_kludge rk;
	struct sockaddr_in * p = NULL;
	struct sockaddr_in6 addr_sin6;
	struct in_addr ipv4;
	struct in6_addr ipv6;

	HIP_DEBUG_SOCKADDR("addr", addr);

	if (hip_get_nsupdate_status())
		nsupdate(0);

	/** @todo check UPDATE also with radvd (i.e. same address is added
	    twice). */

	HIP_DEBUG("ifindex=%d\n", ifindex);
	if (!ifindex) {
		HIP_DEBUG("test: returning, ifindex=0 (fix this for non-mm "\
			  "UPDATE)\n");
		return;
	}

	if (addr->sa_family == AF_INET)
		HIP_DEBUG_LSI("Addr", hip_cast_sa_addr(addr));
	else if (addr->sa_family == AF_INET6)
		HIP_DEBUG_HIT("Addr", hip_cast_sa_addr(addr));
	else
		HIP_DEBUG("Unknown addr family in addr\n");

	if (addr->sa_family == AF_INET) {
		memset(&addr_sin6, 0, sizeof(struct sockaddr_in6));
		memset(&ipv4, 0, sizeof(struct in_addr));
		memset(&ipv6, 0, sizeof(struct in6_addr));
		p = (struct sockaddr_in *)addr;
		memcpy(&ipv4, &p->sin_addr, sizeof(struct in_addr));
		IPV4_TO_IPV6_MAP(&ipv4, &ipv6);
		memcpy(&addr_sin6.sin6_addr, &ipv6, sizeof(struct in6_addr));
		addr_sin6.sin6_family = AF_INET6;
	} else if (addr->sa_family == AF_INET6) {
		memcpy(&addr_sin6, addr, sizeof(addr_sin6));
	} else {
		HIP_ERROR("Bad address family %d\n", addr->sa_family);
		return;
	}

	rk.array = entries;
	rk.count = 0;
	rk.length = HIP_MAX_HAS;
	/* AB: rk.length = 100 rk is NULL next line populates rk with all valid
	   ha entries */
	HIP_IFEL(hip_for_each_ha(hip_update_get_all_valid, &rk), 0,
		 "for_each_ha err.\n");
	for (i = 0; i < rk.count; i++) {
		if (rk.array[i] != NULL) {
                        // in6_addr_t *local_addr = &((rk.array[i])->our_addr);

#if 0
			if (is_add && !ipv6_addr_cmp(local_addr, &zero_addr)) {
				HIP_DEBUG("Zero addresses, adding new default\n");
				ipv6_addr_copy(local_addr, addr_sin6);
			}
#endif
                        HIP_DEBUG_HIT("ADDR_SIN6",&addr_sin6.sin6_addr);
			hip_send_update(rk.array[i], addr_list, addr_count,
					ifindex, flags, is_add,
					(struct sockaddr *) &addr_sin6);

#if 0
			if (!is_add && addr_count == 0) {
				HIP_DEBUG("Deleting last address\n");
				memset(local_addr, 0, sizeof(in6_addr_t));
			}
#endif
			hip_hadb_put_entry(rk.array[i]);
		}
	}

	//empty the oppipdb
	empty_oppipdb();

 out_err:

	return;
}


int hip_update_send_ack(hip_ha_t *entry, hip_common_t *msg,
			in6_addr_t *src_ip, in6_addr_t *dst_ip)
{
	int err = 0;
	in6_addr_t *hits = &msg->hits, *hitr = &msg->hitr;
	hip_common_t *update_packet = NULL;
	struct hip_seq *seq = NULL;
	struct hip_echo_request *echo = NULL;
	uint16_t mask = 0;

	/* Assume already locked entry */
	echo = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST);
	HIP_IFEL(!(seq = hip_get_param(msg, HIP_PARAM_SEQ)), -1,
		 "SEQ not found\n");
	HIP_IFEL(!(update_packet = hip_msg_alloc()), -ENOMEM,
		 "Out of memory\n");


	entry->hadb_misc_func->hip_build_network_hdr(update_packet, HIP_UPDATE,
						     mask, hitr, hits);

	/* reply with UPDATE(ACK, [ECHO_RESPONSE]) */
	HIP_IFEL(hip_build_param_ack(update_packet, ntohl(seq->update_id)), -1,
		 "Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(update_packet,
					       &entry->hip_hmac_out), -1,
		 "Building of HMAC failed\n");

	/* Add SIGNATURE */
	HIP_IFEL(entry->sign(entry->our_priv_key, update_packet), -EINVAL,
		 "Could not sign UPDATE. Failing\n");

	/* ECHO_RESPONSE (no sign) */
	if (echo) {
		HIP_DEBUG("echo opaque data len=%d\n",
			  hip_get_param_contents_len(echo));
		HIP_HEXDUMP("ECHO_REQUEST ",
			    (void *)echo +
			    sizeof(struct hip_tlv_common),
			    hip_get_param_contents_len(echo));
		HIP_IFEL(hip_build_param_echo(update_packet, (void *) echo +
					      sizeof(struct hip_tlv_common),
					      hip_get_param_contents_len(echo), 0, 0),
			 -1, "Building of ECHO_RESPONSE failed\n");
	}

	HIP_DEBUG("Sending reply UPDATE packet (ack)\n");
	HIP_IFEL(entry->hadb_xmit_func->hip_send_pkt(
			 dst_ip, src_ip, 0, 0, update_packet, entry, 0),
		 -1, "csum_send failed\n");

 out_err:
	if (update_packet)
		HIP_FREE(update_packet);
	HIP_DEBUG("end, err=%d\n", err);
	return err;
}

int hip_peer_learning(struct hip_esp_info * esp_info,
		      hip_ha_t *entry, in6_addr_t * src_ip) {
	hip_list_t *item = NULL, *tmp = NULL;
	hip_list_t *item_outer = NULL, *tmp_outer = NULL;
	struct hip_peer_addr_list_item *addr_li;
	struct hip_spi_out_item *spi_out;
	int i = 0, ii = 0, err = 0;

	HIP_DEBUG("Enter\n");
	list_for_each_safe(item_outer, tmp_outer, entry->spis_out, i) {
		spi_out = list_entry(item_outer);
		ii = 0;
		tmp = NULL;
		item = NULL;
		list_for_each_safe(item, tmp, spi_out->peer_addr_list, ii) {
			addr_li = list_entry(item);
			//HIP_DEBUG_HIT("SPI out addresses", &addr_li->address);
			if (!ipv6_addr_cmp(&addr_li->address, src_ip)) {
				HIP_DEBUG_HIT("Peer learning: Found the address "
					      "in peer_addr_list", src_ip);
				return (-1);
			}
		} // inner
	} // outer

	HIP_DEBUG_HIT("Peer learning: Did not find the address,"
		      " adding it", src_ip);
	HIP_IFE(hip_hadb_add_addr_to_spi(entry, spi_out->spi, src_ip,
					 0, 0, 0), -1);
	//lifetime is 0 in above figure out what it should be
	return (0);
out_err:
	HIP_DEBUG("Peer learning: Adding of address failed\n");
	return (-1);
}


/**
 * handles locator parameter in msg and in entry.
 *
 *
 * */
int hip_handle_locator_parameter(hip_ha_t *entry,
		struct hip_locator *loc,
		struct hip_esp_info *esp_info) {
	uint32_t old_spi = 0, new_spi = 0, i = 0, err = 0, index = 0;
	int zero = 0, n_addrs = 0, ii = 0;
	int same_af = 0, local_af = 0, comp_af = 0, tmp_af = 0;
	hip_list_t *item = NULL, *tmplist = NULL;
	struct hip_locator_info_addr_item *locator_address_item;
	struct hip_locator_info_addr_item2 *locator_address_item2;
	struct hip_spi_out_item *spi_out;
	struct hip_peer_addr_list_item *a, *tmp, addr;
	struct netdev_address *n;
	struct hip_locator *locator = NULL;

	if ((locator = loc) == NULL) {
		HIP_DEBUG("No locator as input\n");
		locator = entry->locator;
                HIP_DEBUG("Using entry->locator\n");
	}

	HIP_INFO_LOCATOR("in handle locator", locator);

	HIP_IFEL(!locator, -1, "No locator to handle\n");

	old_spi = ntohl(esp_info->new_spi);
	new_spi = ntohl(esp_info->new_spi);
	HIP_DEBUG("LOCATOR SPI old=0x%x new=0x%x\n", old_spi, new_spi);

	/* If following does not exit, its a bug: outbound SPI must have been
	already created by the corresponding ESP_INFO in the same UPDATE
	packet */
	HIP_IFEL(!(spi_out = hip_hadb_get_spi_list(entry, new_spi)), -1,
			"Bug: outbound SPI 0x%x does not exist\n", new_spi);

	/* Set all peer addresses to unpreferred */

	/** @todo Compiler warning; warning: passing argument 1 of
	 * 'hip_update_for_each_peer_addr' from incompatible pointer type.
	 *  What is the real point with this one anyway?
	 */

#if 0
	HIP_IFE(hip_update_for_each_peer_addr(hip_update_set_preferred,
				   entry, spi_out, &zero), -1);
#endif
	if(locator)
		HIP_IFEL(hip_update_for_each_peer_addr(hip_update_deprecate_unlisted,
					 entry, spi_out, locator), -1,
					 "Depracating a peer address failed\n");

	/* checking did the locator have any address with the same family as
	entry->our_addr, if not change local address to address that
	has same family as the address(es) in locator, if possible */

	if (! locator || hip_nat_get_control(entry) == HIP_NAT_MODE_ICE_UDP) {
		goto out_of_loop;
	}

	locator_address_item = hip_get_locator_first_addr_item(locator);
	local_af =
		IN6_IS_ADDR_V4MAPPED(&entry->our_addr) ? AF_INET :AF_INET6;
	if (local_af == 0) {
		HIP_DEBUG("Local address is invalid, skipping\n");
		goto out_err;
	}

	n_addrs = hip_get_locator_addr_item_count(locator);
	for (i = 0; i < n_addrs; i++) {
		/* check if af same as in entry->local_af */
        /* TODO Fix me Surki */
        comp_af = IN6_IS_ADDR_V4MAPPED((struct in6_addr *)hip_get_locator_item_address(hip_get_locator_item(locator_address_item, i)))
			? AF_INET : AF_INET6;
		if (comp_af == local_af) {
			HIP_DEBUG("LOCATOR contained same family members as "\
					"local_address\n");
			same_af = 1;

			break;
		}
	}
	if (same_af != 0) {
		HIP_DEBUG("Did not find any address of same family\n");
		goto out_of_loop;
	}

	/* look for local address with family == comp_af */
	list_for_each_safe(item, tmplist, addresses, ii) {
		n = list_entry(item);
		tmp_af = hip_sockaddr_is_v6_mapped(&n->addr) ?
			AF_INET : AF_INET6;
		if (tmp_af == comp_af) {
			HIP_DEBUG("LOCATOR contained same family members "
					"as local_address, changing our_addr and "
					"peer_addr\n");
			/* Replace the local address to match the family */
			memcpy(&entry->our_addr,
					hip_cast_sa_addr(&n->addr),
					sizeof(in6_addr_t));
			/* Replace the peer preferred address to match the family */
			locator_address_item = hip_get_locator_first_addr_item(locator);
			/* First should be OK, no opposite family in LOCATOR */

			memcpy(&entry->peer_addr,
					hip_get_locator_item_address(locator_address_item),
					sizeof(in6_addr_t));
			memcpy(&addr.address,
					hip_get_locator_item_address(locator_address_item),
					sizeof(in6_addr_t));
			HIP_IFEL(hip_update_peer_preferred_address(
					entry, &addr, new_spi), -1,
					"Setting peer preferred address failed\n");

			goto out_of_loop;
		}
	}

out_of_loop:
	if(locator)
		HIP_IFEL(hip_for_each_locator_addr_item(hip_update_add_peer_addr_item,
						  entry, locator, &new_spi), -1,
						  "Locator handling failed\n");

#if 0 /* Let's see if this is really needed -miika */
	if (n_addrs == 0) /* our own extension, use some other SPI */
		(void)hip_hadb_relookup_default_out(entry);
	/* relookup always ? */
#endif

out_err:
	return err;
}

/**
 * Builds udp and raw locator items into locator list to msg
 * this is the extension of hip_build_locators in output.c
 * type2 locators are collected also
 *
 * @param msg          a pointer to hip_common to append the LOCATORS
 * @return             len of LOCATOR2 on success, or negative error value on error
 */
int hip_build_locators(struct hip_common *msg, uint32_t spi, hip_transform_suite_t ice)
{
    int err = 0, i = 0, count1 = 0, count2 = 0, UDP_relay_count = 0;
    int addr_max1, addr_max2;
    struct netdev_address *n;
    hip_list_t *item = NULL, *tmp = NULL;
    struct hip_locator_info_addr_item *locs1 = NULL;
    struct hip_locator_info_addr_item2 *locs2 = NULL;
    hip_ha_t *ha_n;

    //TODO count the number of UDP relay servers.
    // check the control state of every hatb_state.

    if (address_count == 0) {
	    HIP_DEBUG("Host has only one or no addresses no point "
		      "in building LOCATOR2 parameters\n");
	    goto out_err;
    }

    //TODO check out the count for UDP and hip raw.
    addr_max1 = address_count;
    // let's put 10 here for now. anyhow 10 additional type 2 addresses should be enough
    addr_max2 = HIP_REFLEXIVE_LOCATOR_ITEM_AMOUNT_MAX + 10;

    HIP_IFEL(!(locs1 = malloc(addr_max1 *
			      sizeof(struct hip_locator_info_addr_item))),
	     -1, "Malloc for LOCATORS type1 failed\n");
    HIP_IFEL(!(locs2 = malloc(addr_max2 *
			      sizeof(struct hip_locator_info_addr_item2))),
                 -1, "Malloc for LOCATORS type2 failed\n");


    memset(locs1,0,(addr_max1 *
		    sizeof(struct hip_locator_info_addr_item)));

    memset(locs2,0,(addr_max2 *
		    sizeof(struct hip_locator_info_addr_item2)));

    HIP_DEBUG("there are %d type 1 locator item\n" , addr_max1);

    if (ice == HIP_NAT_MODE_ICE_UDP)
	    goto build_ice_locs;

    list_for_each_safe(item, tmp, addresses, i) {
            n = list_entry(item);
 	    HIP_DEBUG_IN6ADDR("Add address:",hip_cast_sa_addr(&n->addr));
            HIP_ASSERT(!ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)));
	    memcpy(&locs1[count1].address, hip_cast_sa_addr(&n->addr),
		   sizeof(struct in6_addr));
	    if (n->flags & HIP_FLAG_CONTROL_TRAFFIC_ONLY)
		    locs1[count1].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL;
	    else
		    locs1[count1].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
	    locs1[count1].locator_type = HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI;
	    locs1[count1].locator_length = sizeof(struct in6_addr) / 4;
	    locs1[count1].reserved = 0;
	    count1++;
    }

    if (ice != HIP_NAT_MODE_ICE_UDP)
	    goto skip_ice;

build_ice_locs:

    HIP_DEBUG("Looking for reflexive addresses from a HA of a relay\n");
    i = 0;

    list_for_each_safe(item, tmp, hadb_hit, i) {
            ha_n = list_entry(item);
            if (count2 >= addr_max2)
	    	    break;
            HIP_DEBUG_IN6ADDR("Looking for reflexive, preferred address: ",
			      &ha_n->peer_addr );
            HIP_DEBUG_IN6ADDR("Looking for reflexive, local address: ",
			      &ha_n->our_addr );
            HIP_DEBUG("Looking for reflexive port: %d \n",
		      ha_n->local_reflexive_udp_port);
            HIP_DEBUG("Looking for reflexive addr: ",
		      &ha_n->local_reflexive_address);
            /* Check if this entry has reflexive port */
            if(ha_n->local_reflexive_udp_port) {
		    memcpy(&locs2[count2].address, &ha_n->local_reflexive_address,
			   sizeof(struct in6_addr));
		    locs2[count2].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
		    locs2[count2].locator_type = HIP_LOCATOR_LOCATOR_TYPE_UDP;
		    locs2[count2].locator_length = 7;
		    locs2[count2].reserved = 0;
		    // for IPv4 we add UDP information
		    locs2[count2].port = htons(ha_n->local_reflexive_udp_port);
                    locs2[count2].transport_protocol = 0;
                    locs2[count2].kind = ICE_CAND_TYPE_SRFLX;  // 2 for peer reflexive
                    locs2[count2].spi = htonl(spi);
                    locs2[count2].priority = htonl(ice_calc_priority(HIP_LOCATOR_LOCATOR_TYPE_REFLEXIVE_PRIORITY,ICE_CAND_PRE_SRFLX,1) - ha_n->local_reflexive_udp_port);
		    HIP_DEBUG("build a locator at priority : %d\n", ntohl(locs2[count2].priority));
                    HIP_DEBUG_HIT("Created one reflexive locator item: ",
                                  &locs1[count2].address);
                    count2++;
                    if (count2 >= addr_max2)
                            break;
            }
    }

skip_ice:
    
    HIP_DEBUG("locator count %d\n", count1, count2);

    err = hip_build_param_locator2(msg, locs1, locs2, count1, count2);

 out_err:

    if (locs1)
	    free(locs1);
    if (locs2)
	    free(locs2);

    return err;
}

#if 0
int hip_update_handle_stun(void* pkg, int len,
	 in6_addr_t *src_addr, in6_addr_t * dst_addr,
	 hip_ha_t *entry,
	 hip_portpair_t *sinfo)
{
	if(entry){
		HIP_DEBUG_HIT("receive a stun  from 2:  " ,src_addr );
		hip_external_ice_receive_pkt(pkg, len, entry, src_addr, sinfo->src_port);
	}
	else{
		HIP_DEBUG_HIT("receive a stun  from 1:   " ,src_addr );
		hip_external_ice_receive_pkt_all(pkg, len, src_addr, sinfo->src_port);
	}
}
#endif

void empty_oppipdb(){
	hip_for_each_oppip(hip_oppipdb_del_entry_by_entry, NULL);
}
