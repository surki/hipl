/**
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "user_ipsec_fw_msg.h"
#include "user_ipsec_sadb.h"
#include "esp_prot_api.h"

int send_userspace_ipsec_to_hipd(int activate)
{
	int err = 0;
	struct hip_common *msg = NULL;
	extern int hip_kernel_ipsec_fallback;

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");

	hip_msg_init(msg);

	// send this message on activation or for deactivation when -I is specified
	if (activate || hip_kernel_ipsec_fallback)
	{
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_USERSPACE_IPSEC, 0), -1,
			 "build hdr failed\n");

		HIP_IFEL(hip_build_param_contents(msg, (void *)&activate, HIP_PARAM_INT,
						  sizeof(unsigned int)), -1,
						  "build param contents failed\n");

		HIP_DEBUG("sending userspace ipsec (de-)activation to hipd...\n");
	} else
	{
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_RST, 0), -1,
					 "build hdr failed\n");

		HIP_DEBUG("sending close all connections to hipd...\n");
	}

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
	HIP_DEBUG("send_recv msg succeeded\n");

	HIP_DEBUG("userspace ipsec activated\n");

 out_err:
	if (msg)
		free(msg);
	return err;
}

int handle_sa_add_request(struct hip_common * msg)
{
	struct hip_tlv_common *param = NULL;
	struct in6_addr *src_addr = NULL, *dst_addr = NULL;
	struct in6_addr *src_hit = NULL, *dst_hit = NULL;
	uint32_t spi = 0;
	int ealg = 0, err = 0;
	struct hip_crypto_key *enc_key = NULL, *auth_key = NULL;
	int retransmission = 0, direction = 0, update = 0;
	uint16_t local_port = 0, peer_port = 0;
	uint8_t encap_mode = 0, esp_prot_transform = 0;
	unsigned char *esp_prot_anchor = NULL;
	uint32_t e_keylen = 0, a_keylen = 0, e_type = 0, a_type = 0;
	uint32_t hash_item_length = 0;

	// get all attributes from the message

	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_IPV6_ADDR);
	src_addr = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_IN6ADDR("Source IP address: ", src_addr);

	param = hip_get_next_param(msg, param);
	dst_addr = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_IN6ADDR("Destination IP address : ", dst_addr);

	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_HIT);
	src_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Source Hit: ", src_hit);

	param = hip_get_next_param(msg, param);
	dst_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Destination HIT: ", dst_hit);

	param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_UINT);
	spi = *((uint32_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the spi value is : 0x%lx \n", spi);

	param = hip_get_next_param(msg, param);
	encap_mode = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the nat_mode value is %u \n", encap_mode);

	param = hip_get_next_param(msg, param);
	local_port = *((uint16_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the local_port value is %u \n", local_port);

	param = hip_get_next_param(msg, param);
	peer_port = *((uint16_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the peer_port value is %u \n", peer_port);

	// parse the esp protection extension parameters
	esp_prot_anchor = esp_prot_handle_sa_add_request(msg, &esp_prot_transform,
			&hash_item_length);

	param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_KEYS);
	enc_key = (struct hip_crypto_key *) hip_get_param_contents_direct(param);
	HIP_HEXDUMP("crypto key:", enc_key, sizeof(struct hip_crypto_key));

	param = hip_get_next_param(msg, param);
	auth_key = (struct hip_crypto_key *)hip_get_param_contents_direct(param);
	HIP_HEXDUMP("auth key:", auth_key, sizeof(struct hip_crypto_key));

	param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_INT);
	ealg = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("ealg value is %d \n", ealg);

	param =  hip_get_next_param(msg, param);
	retransmission = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("already_acquired value is %d \n", retransmission);

	param =  hip_get_next_param(msg, param);
	direction = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the direction value is %d \n", direction);

	param =  hip_get_next_param(msg, param);
	update = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("the update value is %d \n", update);

	HIP_IFEL(hip_sadb_add(direction, spi, BEET_MODE, src_addr, dst_addr,
			src_hit, dst_hit, encap_mode, local_port, peer_port, ealg,
			auth_key, enc_key, DEFAULT_LIFETIME, esp_prot_transform,
			hash_item_length, esp_prot_anchor, retransmission, update), -1,
			"failed to add user_space IPsec security association\n");

  out_err:
	return err;
}

int handle_sa_delete_request(struct hip_common * msg)
{
	struct hip_tlv_common *param = NULL;
	uint32_t spi = 0;
	struct in6_addr *peer_addr = NULL;
	struct in6_addr *dst_addr = NULL;
	int family = 0, src_port = 0, dst_port = 0;
	int err = 0;

	// get all attributes from the message

	param = hip_get_param(msg, HIP_PARAM_UINT);
	spi = *((uint32_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("spi value: 0x%lx \n", spi);

	param = hip_get_param(msg, HIP_PARAM_IPV6_ADDR);
	peer_addr = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_IN6ADDR("peer address: ", peer_addr);

	param = hip_get_next_param(msg, param);
	dst_addr = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_IN6ADDR("dst address: ", dst_addr);

	param = hip_get_param(msg, HIP_PARAM_INT);
	family = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("family: %i\n", family);

	param = hip_get_next_param(msg, param);
	src_port = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("src_port: %i\n", src_port);

	param = hip_get_next_param(msg, param);
	dst_port = *((int *) hip_get_param_contents_direct(param));
	HIP_DEBUG("dst_port: %i\n", dst_port);

	// work-around due to broken sa_delete in hipd
	// XX TODO remove when fixed
	if (ipv6_addr_is_hit(peer_addr) || spi == 0)
	{
		// drop these cases
		HIP_DEBUG("this is an inconsistent case, DROP\n");

		err = 0;
		goto out_err;
	}

	// the only useful information here are the spi and peer address
	hip_sadb_delete(peer_addr, spi);

  out_err:
	return err;
}

int handle_sa_flush_all_request(struct hip_common * msg)
{
	int err = 0;

	// this message does not have any parameters, only triggers flushing
	HIP_IFEL(hip_sadb_flush(), -1, "failed to flush sadb\n");

  out_err:
	return err;
}
