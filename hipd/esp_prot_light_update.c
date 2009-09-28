/**
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#include "esp_prot_light_update.h"
#include "esp_prot_anchordb.h"
#include "esp_prot_hipd_msg.h"

int esp_prot_send_light_update(hip_ha_t *entry, int *anchor_offset,
		unsigned char **secret, int *secret_length,
		unsigned char **branch_nodes, int *branch_length)
{
	extern int esp_prot_num_parallel_hchains;
	hip_common_t *light_update = NULL;
	int hash_length = 0;
	uint16_t mask = 0;
	int num_anchors = 0;
	int err = 0, i;

	HIP_IFEL(!(light_update = hip_msg_alloc()), -ENOMEM,
		 "failed to allocate memory\n");

	entry->hadb_misc_func->hip_build_network_hdr(light_update, HIP_LUPDATE,
						     mask, &entry->hit_our, &entry->hit_peer);

	/********************* add SEQ *********************/

	entry->light_update_id_out++;
	HIP_DEBUG("outgoing light UPDATE ID=%u\n", entry->light_update_id_out);

	HIP_IFEL(hip_build_param_seq(light_update, entry->light_update_id_out), -1,
			"building of SEQ param failed\n");

	/********** add ESP-PROT anchor, branch, secret, root **********/

	hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

	for (i = 0; i < esp_prot_num_parallel_hchains; i++)
	{
		HIP_IFEL(hip_build_param_esp_prot_anchor(light_update,
				entry->esp_prot_transform, &entry->esp_local_anchors[i][0],
				&entry->esp_local_update_anchors[i][0], hash_length, entry->hash_item_length),
				-1, "building of ESP protection ANCHOR failed\n");
	}

	for (i = 0; i < esp_prot_num_parallel_hchains; i++)
	{
		HIP_IFEL(hip_build_param_esp_prot_branch(light_update,
				anchor_offset[i], branch_length[i], branch_nodes[i]), -1,
				"building of ESP BRANCH failed\n");
	}

	for (i = 0; i < esp_prot_num_parallel_hchains; i++)
	{
		 HIP_IFEL(hip_build_param_esp_prot_secret(light_update, secret_length[i], secret[i]),
				 -1, "building of ESP SECRET failed\n");
	}

	for (i = 0; i < esp_prot_num_parallel_hchains; i++)
	{
		// only send root if the update hchain has got a link_tree
		if (entry->esp_root_length > 0)
		{
			HIP_IFEL(hip_build_param_esp_prot_root(light_update, entry->esp_root_length,
					entry->esp_root[i]), -1, "building of ESP ROOT failed\n");
		}
	}

	/******************** add HMAC **********************/
	HIP_IFEL(hip_build_param_hmac_contents(light_update, &entry->hip_hmac_out), -1,
			"building of HMAC failed\n");

	/* send the packet with retransmission enabled */
	entry->light_update_retrans = 1;

	HIP_IFEL(entry->hadb_xmit_func->
			hip_send_pkt(&entry->our_addr, &entry->peer_addr,
			(entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
			entry->peer_udp_port, light_update, entry, entry->light_update_retrans),
			-1, "failed to send light anchor update\n");

  out_err:
	if (err)
		entry->light_update_retrans = 1;

	if (light_update)
		free(light_update);

	return err;
}

int esp_prot_receive_light_update(hip_common_t *msg, in6_addr_t *src_addr,
	       in6_addr_t *dst_addr, hip_ha_t *entry)
{
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	uint32_t seq_no = 0;
	uint32_t ack_no = 0;
	uint32_t spi = 0;
	int err = 0;

	HIP_IFEL(hip_verify_packet_hmac(msg, &entry->hip_hmac_in), -1,
			"HMAC validation on UPDATE failed.\n");

	ack = hip_get_param(msg, HIP_PARAM_ACK);
	seq = hip_get_param(msg, HIP_PARAM_SEQ);

	if (seq != NULL)
	{
		/********** SEQ ***********/
		seq_no = ntohl(seq->update_id);

		HIP_DEBUG("SEQ parameter found with update ID: %u\n", seq_no);
		HIP_DEBUG("previous incoming update id=%u\n", entry->light_update_id_in);

		if (seq_no < entry->light_update_id_in) {
			HIP_DEBUG("old SEQ, dropping...\n");

			err = -EINVAL;
			goto out_err;

		} else if (seq_no == entry->light_update_id_in) {

			HIP_DEBUG("retransmitted UPDATE packet (?), continuing\n");

		} else
		{
			HIP_DEBUG("new SEQ, storing...\n");
			entry->light_update_id_in = seq_no;
		}

		/********** ANCHOR ***********/
		HIP_IFEL(esp_prot_update_handle_anchor(msg, entry, src_addr, dst_addr, &spi),
				-1, "failed to handle anchors\n");

		// send ACK
		esp_prot_send_light_ack(entry, dst_addr, src_addr, spi);

	} else if (ack != NULL)
	{
		/********** ACK ***********/
		ack_no = ntohl(ack->peer_update_id);

		HIP_DEBUG("ACK found with peer update ID: %u\n", ack_no);

		HIP_IFEL(ack_no != entry->light_update_id_out, -1,
				"received non-matching ACK\n");

		// stop retransmission
		entry->light_update_retrans = 0;

		// notify sadb about next anchor
		HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(dst_addr, src_addr,
				&entry->hit_our, &entry->hit_peer, entry->default_spi_out,
				entry->esp_transform, &entry->esp_out, &entry->auth_out, 0,
				HIP_SPI_DIRECTION_OUT, 1, entry), -1,
				"failed to notify sadb about next anchor\n");

	} else
	{
		HIP_ERROR("light update message received, but no SEQ or ACK found\n");

		err = -1;
	}

  out_err:
	return err;
}

int esp_prot_send_light_ack(hip_ha_t *entry, in6_addr_t *src_addr, in6_addr_t *dst_addr,
		uint32_t spi)
{
	hip_common_t *light_ack = NULL;
	uint16_t mask = 0;
	int err = 0;

	HIP_IFEL(!(light_ack = hip_msg_alloc()), -ENOMEM,
		 "failed to allocate memory\n");

	entry->hadb_misc_func->hip_build_network_hdr(light_ack, HIP_LUPDATE,
							 mask, &entry->hit_our,
							 &entry->hit_peer);

	/* Add ESP_INFO */
	HIP_IFEL(hip_build_param_esp_info(light_ack, entry->current_keymat_index,
			spi, spi), -1, "Building of ESP_INFO failed\n");

	/* Add ACK */
	HIP_IFEL(hip_build_param_ack(light_ack, entry->light_update_id_in), -1,
			"Building of ACK failed\n");

	/* Add HMAC */
	HIP_IFEL(hip_build_param_hmac_contents(light_ack, &entry->hip_hmac_out), -1,
			"Building of HMAC failed\n");

	HIP_IFEL(entry->hadb_xmit_func->hip_send_pkt(src_addr, dst_addr,
				(entry->nat_mode ? hip_get_local_nat_udp_port() : 0), entry->peer_udp_port,
				light_ack, entry, 0), -1, "failed to send ANCHOR-UPDATE\n");

  out_err:
	return err;

}
