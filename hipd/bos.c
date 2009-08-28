#include "bos.h"

/**
 * hip_create_signature - Calculate SHA1 hash over the data and sign it.
 * @param buffer_start Pointer to start of the buffer over which the hash is
 *                calculated.
 * @param buffer_length Length of the buffer.
 * @param host_id DSA private key.
 * @param signature Place for signature.
 *
 * Signature size for DSA is 41 bytes.
 *
 * Returns 1 if success, otherwise 0.
 */
int hip_create_bos_signature(void *priv, int algo, struct hip_common *bos)
{
	int err = 0;
	
	if (algo == HIP_HI_DSA) {
		HIP_DEBUG("Creating DSA signature\n");
		err = hip_dsa_sign(priv, bos);
	} else if (algo == HIP_HI_RSA) {
		HIP_DEBUG("Creating RSA signature\n");
		err = hip_rsa_sign(priv, bos);
	} else {
		HIP_ERROR("Unsupported algorithm:%d\n", algo);
		err = -1;
	}

	return err;
}


/** hip_socket_send_bos - send a BOS packet
 * @param msg input message (should be empty)
 *
 * Generate a signed HIP BOS packet containing our HIT, and send
 * the packet out each network device interface.
 *
 * @return zero on success, or negative error value on failure
 */
int hip_send_bos(const struct hip_common *msg)
{
	int err = 0, i;
	struct hip_common *bos = NULL;
	struct in6_addr hit_our;
	struct in6_addr daddr;
 	struct hip_host_id  *host_id_pub = NULL;
	//struct hip_host_id *host_id_private = NULL;
	//u8 signature[HIP_RSA_SIGNATURE_LEN]; // assert RSA > DSA
	//struct net_device *saddr_dev;
	//struct inet6_dev *idev;
	//int addr_count = 0;
	//struct inet6_ifaddr *ifa = NULL;
	//struct hip_xfrm_t *x;
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	void *private_key;
	
	HIP_DEBUG("\n");
	
	/* Extra consistency test */
	if (hip_get_msg_type(msg) != SO_HIP_BOS)
	{
		err = -EINVAL;
		HIP_ERROR("Bad message type\n");
		goto out_err;
	}
	
	/* allocate space for new BOS */
	bos = hip_msg_alloc();
	if (!bos)
	{
		HIP_ERROR("Allocation of BOS failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* Determine our HIT */
	if (hip_get_any_localhost_hit(&hit_our, HIP_HI_DEFAULT_ALGO, 0) < 0)
	{
		HIP_ERROR("Our HIT not found\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG_IN6ADDR("hit_our = ", &hit_our);

	/* Get our public host ID and private key */
	err = hip_get_host_id_and_priv_key(HIP_DB_LOCAL_HID, NULL,
				HIP_HI_DEFAULT_ALGO, &host_id_pub, &private_key);
	if (err) {
		HIP_ERROR("No local host ID found\n");
		goto out_err;
	}

 	/* Ready to begin building the BOS packet */
	/*! \todo TH: hip_build_network_hdr has to be replaced with an appropriate function pointer */
 	hip_build_network_hdr(bos, HIP_BOS, HIP_HA_CTRL_NONE, &hit_our, NULL);

	/********** HOST_ID *********/
	_HIP_DEBUG("This HOST ID belongs to: %s\n",
		   hip_get_param_host_id_hostname(host_id_pub));
	err = hip_build_param(bos, host_id_pub);
 	if (err)
 	{
 		HIP_ERROR("Building of host id failed\n");
 		goto out_err;
 	}

 	/********** SIGNATURE **********/
	HIP_ASSERT(private_key);
	/* HIP_HI_DEFAULT_ALGO corresponds to HIP_HI_DSA therefore the
	   signature will be dsa */
	/* Build a digest of the packet built so far. Signature will
	   be calculated over the digest. */

	if (hip_create_bos_signature(private_key, HIP_HI_DEFAULT_ALGO, bos))
	{
		HIP_ERROR("Could not create signature\n");
		err = -EINVAL;
		goto out_err;
	}

 	/************** BOS packet ready ***************/

	/**************SENDING ON IPv6*****************/
	/* Use All Nodes Addresses (link-local) from RFC2373 */
	daddr.s6_addr32[0] = htonl(0xFF020000);
	daddr.s6_addr32[1] = 0;
	daddr.s6_addr32[2] = 0;
	daddr.s6_addr32[3] = htonl(0x1);
	HIP_HEXDUMP("dst addr:", &daddr, 16);

	list_for_each_safe(item, tmp, addresses, i)
	{
		n = list_entry(item);
		HIP_HEXDUMP("BOS src address:", hip_cast_sa_addr(&n->addr), hip_sa_addr_len(&n->addr));
		/* Packet is send on raw HIP no matter what is the global NAT
		   status, because NAT travelsal is not supported for IPv6. */
		err = hip_send_raw(hip_cast_sa_addr(&n->addr), &daddr, 0 ,0, bos, NULL, 0);
		if (err)
		        HIP_ERROR("sending of BOS failed, err=%d\n", err);
	}
	err = 0;

	/** @todo: Miika, please test this. I doubt there are some extra packets
	    sent. --Abi */

	/**************SENDING ON IPv4*****************/
	/* Use All Nodes Addresses (link-local) from RFC2373 */
	daddr.s6_addr32[0] = 0;
	daddr.s6_addr32[1] = 0;
	daddr.s6_addr32[2] = htonl(0xffff);
	daddr.s6_addr32[3] = htonl(0xffffffff);
	HIP_HEXDUMP("dst addr:", &daddr, 16);

	list_for_each_safe(item, tmp, addresses, i)
	{
		n = list_entry(item);
		HIP_HEXDUMP("BOS src address:", hip_cast_sa_addr(&n->addr), hip_sa_addr_len(&n->addr));
		/* If global NAT status is "on", the packet is send on UDP. */
		if(hip_nat_status) {
			err = hip_send_udp(hip_cast_sa_addr(&n->addr), &daddr,
					   hip_get_local_nat_udp_port(), hip_get_peer_nat_udp_port(),
					   bos, NULL, 0);
		}
		else err = hip_send_raw(hip_cast_sa_addr(&n->addr), &daddr,0,0, bos, NULL, 0);
		if (err) HIP_ERROR("sending of BOS failed, err=%d\n", err);
	}
	err = 0;



out_err:
	if (host_id_pub)
		HIP_FREE(host_id_pub);
	if (bos)
		HIP_FREE(bos);
	return err;
}


/** hip_verify_packet_signature - verify the signature in the bos packet
 * @param bos the bos packet
 * @param peer_host_id peer host id
 *
 * Depending on the algorithm it checks whether the signature is correct
 *
 * @return zero on success, or negative error value on failure
 */
int hip_verify_packet_signature(struct hip_common *bos, 
				struct hip_host_id *peer_host_id)
{
	int err;
	if (peer_host_id->rdata.algorithm == HIP_HI_DSA){
		err = hip_dsa_verify(peer_host_id, bos);
	} else if(peer_host_id->rdata.algorithm == HIP_HI_RSA){
		err = hip_rsa_verify(peer_host_id, bos);
	} else {
		HIP_ERROR("Unknown algorithm\n");
		err = -1;
	}
	return err;
}

/**
 * hip_handle_bos - handle incoming BOS packet
 * @param skb sk_buff where the HIP packet is in
 * @param entry HA
 *
 * This function is the actual point from where the processing of BOS
 * is started.
 *
 * On success (BOS payloads are checked) 0 is returned, otherwise < 0.
 */

int hip_handle_bos(struct hip_common *bos,
		   struct in6_addr *bos_saddr,
		   struct in6_addr *bos_daddr,
		   hip_ha_t *entry,
		   hip_portpair_t *stateless_info)
{
	int err = 0, len;
	struct hip_host_id *peer_host_id;
	hip_lsi_t lsi;
	//struct hip_lhi peer_lhi;
	struct in6_addr peer_hit;
	char *str;
	struct in6_addr *dstip;
	char src[INET6_ADDRSTRLEN];

	/* according to the section 8.6 of the base draft,
	 * we must first check signature
	 */
	HIP_IFEL(!(peer_host_id = hip_get_param(bos, HIP_PARAM_HOST_ID)), -ENOENT,
		 "No HOST_ID found in BOS\n");

	HIP_IFEL(hip_verify_packet_signature(bos, peer_host_id), -EINVAL,
		 "Verification of BOS signature failed\n");


	/* Validate HIT against received host id */	
	hip_host_id_to_hit(peer_host_id, &peer_hit, HIP_HIT_TYPE_HASH100);
	HIP_IFEL(ipv6_addr_cmp(&peer_hit, &bos->hits) != 0, -EINVAL,
		 "Sender HIT does not match the advertised host_id\n");
	
	HIP_HEXDUMP("Advertised HIT:", &bos->hits, 16);
	
	/* Everything ok, first save host id to db */
	HIP_IFE(hip_get_param_host_id_di_type_len(peer_host_id, &str, &len) < 0, -1);
	HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n",
		  str, len, hip_get_param_host_id_hostname(peer_host_id));

	/* Now save the peer IP address */
	dstip = bos_saddr;
	hip_in6_ntop(dstip, src);
	HIP_DEBUG("BOS sender IP: saddr %s\n", src);

	if (entry) {
		struct in6_addr daddr;

		HIP_DEBUG("I guess we should not even get here ...\n");
		HIP_DEBUG("I think so!\n");

		/* The entry may contain the wrong address mapping... */
		HIP_DEBUG("Updating existing entry\n");
		hip_hadb_get_peer_addr(entry, &daddr);
		if (ipv6_addr_cmp(&daddr, dstip) != 0) {
			HIP_DEBUG("Mapped address doesn't match received address\n");
			HIP_DEBUG("Assuming that the mapped address was actually RVS's.\n");
			HIP_HEXDUMP("Mapping", &daddr, 16);
			HIP_HEXDUMP("Received", dstip, 16);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			HIP_ERROR("assuming we are doing base exchange\n");
			hip_hadb_add_peer_addr(entry, dstip, 0, 0, 0);
		}
	} else {
		// FIXME: just add it here and not via workorder.

		/* we have no previous infomation on the peer, create
		 * a new HIP HA */
		HIP_IFEL((hip_hadb_add_peer_info(&bos->hits, dstip, &lsi, NULL)<0), -1,
			 "Failed to insert new peer info");
		HIP_DEBUG("HA entry created.\n");

	}

 out_err:
	return err;
}

