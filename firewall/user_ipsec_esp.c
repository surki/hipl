/**
 * Host Identity Protocol
 * Copyright (C) 2004-06 the Boeing Company
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  hip_esp.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *           René Hummen    <rene.hummen@rwth-aachen.de>
 *           (ported to HIPL project and major rewrite)
 *
 * User-mode HIP ESP implementation.
 *
 */

#include "user_ipsec_esp.h"
#include "esp_prot_api.h"
#include "libhipcore/utils.h"

/* for some reason the ICV for ESP authentication is truncated to 12 bytes */
#define ICV_LENGTH 12


int hip_beet_mode_output(hip_fw_context_t *ctx, hip_sa_entry_t *entry,
		struct in6_addr *preferred_local_addr, struct in6_addr *preferred_peer_addr,
		unsigned char *esp_packet, uint16_t *esp_packet_len)
{
	// some pointers to packet headers
	struct ip *out_ip_hdr = NULL;
	struct ip6_hdr *out_ip6_hdr = NULL;
	struct udphdr *out_udp_hdr = NULL;
	struct hip_esp *out_esp_hdr = NULL;
	unsigned char *in_transport_hdr = NULL;
	uint8_t in_transport_type = 0;
	int next_hdr_offset = 0;
	// length of the data to be encrypted
	uint16_t elen = 0;
	// length of the esp payload
	uint16_t encryption_len = 0;
	// length of the hash value used by the esp protection extension
	int esp_prot_hash_length = 0;
	int err = 0;

	_HIP_DEBUG("original packet length: %i \n", ctx->ipq_packet->data_len);

	// distinguish IPv4 and IPv6 output
	if (IN6_IS_ADDR_V4MAPPED(preferred_peer_addr))
	{
		// calculate offset at which esp data should be located
		// NOTE: this does _not_ include IPv4 options for the original packet
		out_ip_hdr = (struct ip *)esp_packet;
		next_hdr_offset = sizeof(struct ip);

		// check whether to use UDP encapsulation or not
		if (entry->encap_mode == 1)
		{
			out_udp_hdr = (struct udphdr *) (esp_packet + next_hdr_offset);
			next_hdr_offset += sizeof(struct udphdr);
		}

		// set up esp header
		out_esp_hdr = (struct hip_esp *) (esp_packet + next_hdr_offset);
		out_esp_hdr->esp_spi = htonl(entry->spi);
		out_esp_hdr->esp_seq = htonl(entry->sequence++);

		// packet to be re-inserted into network stack has at least
		// length of all defined headers
		*esp_packet_len += next_hdr_offset + sizeof(struct hip_esp);

		/* put the esp protection extension hash right behind the header
		 * (virtual header extension)
		 *
		 * @note we are not putting the hash into the actual header definition
		 *       in order to be more flexible about the hash length */
		HIP_IFEL(esp_prot_add_hash(esp_packet + *esp_packet_len, &esp_prot_hash_length,
					entry), -1, "failed to add the esp protection extension hash\n");
		HIP_DEBUG("esp prot hash_length: %i\n", esp_prot_hash_length);
		HIP_HEXDUMP("esp prot hash: ", esp_packet + *esp_packet_len, esp_prot_hash_length);

		// ... and the eventual hash
		*esp_packet_len += esp_prot_hash_length;

		/***** Set up information needed for ESP encryption *****/

		/* get pointer to data, right behind IPv6 header
		 *
		 * NOTE: we are only dealing with HIT-based (-> IPv6) data traffic */
		in_transport_hdr = ((unsigned char *) ctx->ipq_packet->payload)
								+ sizeof(struct ip6_hdr);

		in_transport_type = ((struct ip6_hdr *)ctx->ipq_packet->payload)->ip6_nxt;

		/* length of data to be encrypted is length of the original packet
		 * starting at the transport layer header */
		elen = ctx->ipq_packet->data_len - sizeof(struct ip6_hdr);

		/* encrypt data now */
		pthread_mutex_lock(&entry->rw_lock);

		HIP_DEBUG("encrypting data...\n");

		/* encrypts the payload and puts the encrypted data right
		 * behind the ESP header
		 *
		 * NOTE: we are implicitely passing the previously set up ESP header */
		HIP_IFEL(hip_payload_encrypt(in_transport_hdr, in_transport_type, elen,
				      esp_packet + next_hdr_offset, &encryption_len, entry),
				      -1, "failed to encrypt data");

		pthread_mutex_unlock(&entry->rw_lock);

		// this also includes the ESP tail
		*esp_packet_len += encryption_len;

		// finally we have all the information to set up the missing headers
		if (entry->encap_mode == 1) {
			// the length field covers everything starting with UDP header
			add_udp_header(out_udp_hdr, *esp_packet_len - sizeof(struct ip), entry,
					preferred_local_addr, preferred_peer_addr);

			// now we can also calculate the csum of the new packet
			add_ipv4_header(out_ip_hdr, preferred_local_addr, preferred_peer_addr,
								*esp_packet_len, IPPROTO_UDP);
		} else
		{
			add_ipv4_header(out_ip_hdr, preferred_local_addr, preferred_peer_addr,
								*esp_packet_len, IPPROTO_ESP);
		}

	} else
	{
		/* this is IPv6 */

		/* calculate offset at which esp data should be located
		 *
		 * NOTE: this does _not_ include IPv6 extension headers for the original packet */
		out_ip6_hdr = (struct ip6_hdr *)esp_packet;
		next_hdr_offset = sizeof(struct ip6_hdr);

		/*
		 * NOTE: we don't support UDP encapsulation for IPv6 right now.
		 * 		 this would be the place to add it
		 */

		// set up esp header
		out_esp_hdr = (struct hip_esp *) (esp_packet + next_hdr_offset);
		out_esp_hdr->esp_spi = htonl(entry->spi);
		out_esp_hdr->esp_seq = htonl(entry->sequence++);

		// packet to be re-inserted into network stack has at least
		// length of defined headers
		*esp_packet_len += next_hdr_offset + sizeof(struct hip_esp);

		/* put the esp protection extension hash right behind the header
		 * (virtual header extension)
		 *
		 * @note we are not putting the hash into the actual header definition
		 *       in order to be more flexible about the hash length */
		HIP_IFEL(esp_prot_add_hash(esp_packet + *esp_packet_len, &esp_prot_hash_length,
					entry), -1, "failed to add the esp protection extension hash\n");
		HIP_DEBUG("esp prot hash_length: %i\n", esp_prot_hash_length);
		HIP_HEXDUMP("esp prot hash: ", esp_packet + *esp_packet_len, esp_prot_hash_length);

		// ... and the eventual hash
		*esp_packet_len += esp_prot_hash_length;


		/* Set up information needed for ESP encryption */

		/* get pointer to data, right behind IPv6 header
		 *
		 * NOTE: we are only dealing with HIT-based (-> IPv6) data traffic */
		in_transport_hdr = ((unsigned char *) ctx->ipq_packet->payload)
								+ sizeof(struct ip6_hdr);

		in_transport_type = ((struct ip6_hdr *) ctx->ipq_packet->payload)->ip6_nxt;

		/* length of data to be encrypted is length of the original packet
		 * starting at the transport layer header */
		elen = ctx->ipq_packet->data_len - sizeof(struct ip6_hdr);

		pthread_mutex_lock(&entry->rw_lock);

		HIP_DEBUG("encrypting data...\n");

		/* encrypts the payload and puts the encrypted data right
		 * behind the ESP header
		 *
		 * NOTE: we are implicitely passing the previously set up ESP header */
		HIP_IFEL(hip_payload_encrypt(in_transport_hdr, in_transport_type, elen,
				      esp_packet + next_hdr_offset, &encryption_len, entry), -1,
				      "failed to encrypt data");

		pthread_mutex_unlock(&entry->rw_lock);

		// this also includes the ESP tail
		*esp_packet_len += encryption_len;

		// now we know the packet length
		add_ipv6_header(out_ip6_hdr, preferred_local_addr, preferred_peer_addr,
							*esp_packet_len, IPPROTO_ESP);
	}

	// this is a hook for caching packet hashes for the cumulative authentication
	// of the token-based packet-level authentication scheme
	HIP_IFEL(esp_prot_cache_packet_hash((unsigned char *)out_esp_hdr, *esp_packet_len - next_hdr_offset, entry), -1,
			"failed to cache hash of packet for cumulative authentication extension\n");

  out_err:
    // needed in case something breaks during encryption -> unlock for next packet
  	pthread_mutex_unlock(&entry->rw_lock);

  	return err;
}

int hip_beet_mode_input(hip_fw_context_t *ctx, hip_sa_entry_t *entry,
			unsigned char *decrypted_packet,
			uint16_t *decrypted_packet_len)
{
	int next_hdr_offset = 0;
	uint16_t esp_len = 0;
	uint16_t decrypted_data_len = 0;
	uint8_t next_hdr = 0;
	int err = 0;

	// the decrypted data will be placed behind the HIT-based IPv6 header
	next_hdr_offset = sizeof(struct ip6_hdr);

	*decrypted_packet_len += next_hdr_offset;

	// calculate esp data length
	if (ctx->ip_version == 4)
	{
		esp_len = ctx->ipq_packet->data_len - sizeof(struct ip);
		// check if ESP packet is UDP encapsulated
		if (ctx->udp_encap_hdr)
			esp_len -= sizeof(struct udphdr);
	} else
	{
		esp_len = ctx->ipq_packet->data_len - sizeof(struct ip6_hdr);
	}

	// decrypt now
	pthread_mutex_lock(&entry->rw_lock);

	HIP_DEBUG("decrypting ESP packet...\n");

	HIP_IFEL(hip_payload_decrypt((unsigned char *)ctx->transport_hdr.esp, esp_len,
			decrypted_packet + next_hdr_offset, &next_hdr,
			&decrypted_data_len, entry), -1, "ESP decryption is not successful\n");

	pthread_mutex_unlock(&entry->rw_lock);

	*decrypted_packet_len += decrypted_data_len;

	// now we know the next_hdr and can set up the IPv6 header
	add_ipv6_header((struct ip6_hdr *)decrypted_packet, entry->inner_src_addr,
			entry->inner_dst_addr, *decrypted_packet_len, next_hdr);

	HIP_DEBUG("original packet length: %i \n", *decrypted_packet_len);

  out_err:
    // needed in case something breaks during decryption -> unlock for next packet
	pthread_mutex_unlock(&entry->rw_lock);

  	return err;
}

int hip_payload_encrypt(unsigned char *in, uint8_t in_type, uint16_t in_len,
			unsigned char *out, uint16_t *out_len,
			hip_sa_entry_t *entry)
{
	/* elen is length of data to encrypt */
	uint16_t elen = in_len;
	/* length of auth output */
	uint16_t alen = 0;
	/* initialization vector */
	uint16_t iv_len = 0;
	// TODO make this a static allocation
	unsigned char cbc_iv[16];
	/* ESP tail information */
	uint16_t pad_len = 0;
	struct hip_esp_tail *esp_tail = NULL;
	// offset of the payload counting from the beginning of the esp header
	uint16_t esp_data_offset = 0;
	int i = 0;
	int err = 0;

	esp_data_offset = esp_prot_get_data_offset(entry);

	/*
	 * Encryption
	 */

	/* Check keys and set initialisation vector length */
	switch (entry->ealg)
	{
		case HIP_ESP_3DES_SHA1:
			// same encryption chiper as next transform
		case HIP_ESP_3DES_MD5:
			iv_len = 8;
			if (!entry->enc_key) {
				HIP_ERROR("3-DES key missing.\n");

				err = -1;
				goto out_err;
			}
			break;
#ifndef ANDROID_CHANGES
		case HIP_ESP_BLOWFISH_SHA1:
			iv_len = 8;
			if (!entry->enc_key) {
				HIP_ERROR("BLOWFISH key missing.\n");

				err = -1;
				goto out_err;
			}
			break;
#endif
		case HIP_ESP_NULL_SHA1:
			// same encryption chiper as next transform
		case HIP_ESP_NULL_MD5:
			iv_len = 0;
			break;
		case HIP_ESP_AES_SHA1:
			// initalisation vector has the same size as the aes block size
			iv_len = AES_BLOCK_SIZE;
			if (!entry->enc_key) {
				HIP_ERROR("AES key missing.\n");

				err = -1;
				goto out_err;
			}
			break;
		default:
			HIP_ERROR("Unsupported encryption transform: %i\n", entry->ealg);

			err = -1;
			goto out_err;
		}

	/* Add initialization vector (random value) in the beginning of
	 * out and calculate padding
	 *
	 * NOTE: IV will _NOT_ be encrypted */
	if (iv_len > 0) {
		RAND_bytes(cbc_iv, iv_len);
		memcpy(&out[esp_data_offset], cbc_iv, iv_len);
		pad_len = iv_len - ((elen + sizeof(struct hip_esp_tail)) % iv_len);
	} else {
		/* Padding with NULL encryption is not based on IV length */
		pad_len = 4 - ((elen + sizeof(struct hip_esp_tail)) % 4);
	}

	// FIXME this can cause buffer overflows
	/* add padding to the end of input data and set esp_tail */
	for (i = 0; i < pad_len; i++)
	{
		in[in_len + i] = i + 1;
	}
	// add meta-info to input
	esp_tail = (struct hip_esp_tail *) &in[elen + pad_len];
	esp_tail->esp_padlen = pad_len;
	esp_tail->esp_next = in_type;

	HIP_DEBUG("esp_tail->esp_padlen: %u \n", esp_tail->esp_padlen);
	HIP_DEBUG("esp_tail->esp_next: %u \n", esp_tail->esp_next);

	/* padding and esp_tail are encrypted too */
	elen += pad_len + sizeof(struct hip_esp_tail);

	_HIP_HEXDUMP("data to be encrypted: ", in, elen);

	/* Apply the encryption cipher directly into out buffer
	 * to avoid extra copying */
	switch (entry->ealg)
	{
		case HIP_ESP_3DES_SHA1:
			// same encryption chiper as next transform
		case HIP_ESP_3DES_MD5:
			des_ede3_cbc_encrypt(in, &out[esp_data_offset + iv_len], elen,
					     entry->ks[0], entry->ks[1], entry->ks[2],
					     (des_cblock *) cbc_iv, DES_ENCRYPT);

			break;
#ifndef ANDROID_CHANGES
		case HIP_ESP_BLOWFISH_SHA1:
			BF_cbc_encrypt(in, &out[esp_data_offset + iv_len], elen,
					&entry->bf_key, cbc_iv, BF_ENCRYPT);

			break;
#endif
		case HIP_ESP_NULL_SHA1:
		case HIP_ESP_NULL_MD5:
			// NOTE: in this case there is no IV
			memcpy(out, in, elen);

			break;
		case HIP_ESP_AES_SHA1:
			AES_cbc_encrypt(in, &out[esp_data_offset + iv_len], elen,
					&entry->aes_key, cbc_iv, AES_ENCRYPT);

			break;
		default:
			HIP_ERROR("Unsupported encryption transform: %i\n", entry->ealg);

			err = -1;
			goto out_err;
	}

	/* auth will include IV */
	elen += iv_len;
	*out_len += elen;


	/*
	 * Authentication
	 */

	/* the authentication covers the whole esp part starting with the header */
	elen += esp_data_offset;

	/* Check keys and calculate hashes */
	switch (entry->ealg)
	{
		case HIP_ESP_3DES_MD5:
			// same authentication chiper as next transform
		case HIP_ESP_NULL_MD5:
			if (!entry->auth_key) {
				HIP_ERROR("authentication keys missing\n");

				err = -1;
				goto out_err;
			}

			HMAC(EVP_md5(), entry->auth_key->key,
					hip_auth_key_length_esp(entry->ealg),
					out, elen, &out[elen], &alen);

			HIP_DEBUG("alen: %i \n", alen);

			break;
		case HIP_ESP_3DES_SHA1:
		case HIP_ESP_NULL_SHA1:
		case HIP_ESP_AES_SHA1:
			if (!entry->auth_key) {
				HIP_ERROR("authentication keys missing\n");

				err = -1;
				goto out_err;
			}

			HMAC(EVP_sha1(), entry->auth_key->key,
					hip_auth_key_length_esp(entry->ealg),
					out, elen, &out[elen], &alen);

			HIP_DEBUG("alen: %i \n", alen);

			break;
		default:
			HIP_DEBUG("Unsupported authentication algorithm: %i\n", entry->ealg);

			err = -1;
			goto out_err;
	}

	// cut off eventual longer digests
	*out_len += ICV_LENGTH;

  out_err:
	return err;
}

int hip_payload_decrypt(unsigned char *in, uint16_t in_len, unsigned char *out,
		uint8_t *out_type, uint16_t *out_len, hip_sa_entry_t *entry)
{
	/* elen is length of data to encrypt */
	uint16_t elen = 0;
	// length of authentication protection field
	uint16_t alen = 0;
	// authentication data
	unsigned int hmac_md_len;
	// TODO make this a static allocation
	unsigned char hmac_md[EVP_MAX_MD_SIZE];
	/* initialization vector */
	uint16_t iv_len = 0;
	// TODO directly use the iv in the packet buffer
	unsigned char cbc_iv[16];
	/* ESP tail information */
	uint16_t pad_len = 0;
	struct hip_esp_tail *esp_tail = NULL;
	// offset of the payload counting from the beginning of the esp header
	uint16_t esp_data_offset = 0;
	int err = 0;

	// different offset if esp extension used or not
	esp_data_offset = esp_prot_get_data_offset(entry);

	/*
	 *   Authentication
	 */

	/* check keys, set up auth environment and finally auth */
	switch (entry->ealg) {
		case HIP_ESP_3DES_MD5:
			// same authentication chiper as next transform
		case HIP_ESP_NULL_MD5:
			// even if hash digest might be longer, we are only using this much here
			alen = ICV_LENGTH;
			//alen = MD5_DIGEST_LENGTH;

			// length of the authenticated payload, includes ESP header
			elen = in_len - alen;

			if (!entry->auth_key) {
				HIP_ERROR("authentication keys missing\n");

				err = -1;
				goto out_err;
			}

			HMAC(EVP_md5(), entry->auth_key->key,
					hip_auth_key_length_esp(entry->ealg),
					in, elen, hmac_md, &hmac_md_len);

			// actual auth verification
			if (memcmp(&in[elen], hmac_md, hmac_md_len) != 0)
			{
				HIP_DEBUG("ESP packet could not be authenticated\n");

				err = 1;
				goto out_err;
			}
			break;
		case HIP_ESP_3DES_SHA1:
		case HIP_ESP_NULL_SHA1:
		case HIP_ESP_AES_SHA1:
			// even if hash digest might be longer, we are only using this much here
			alen = ICV_LENGTH;
			//alen = SHA_DIGEST_LENGTH;

			// length of the encrypted payload
			elen = in_len - alen;

			if (!entry->auth_key) {
				HIP_ERROR("authentication keys missing\n");

				err = -1;
				goto out_err;
			}

			HMAC(EVP_sha1(), entry->auth_key->key,
					hip_auth_key_length_esp(entry->ealg),
					in, elen, hmac_md, &hmac_md_len);

			// actual auth verification
			//if (memcmp(&in[elen], hmac_md, hmac_md_len) != 0)
			if (memcmp(&in[elen], hmac_md, alen) != 0)
			{
				HIP_DEBUG("ESP packet could not be authenticated\n");

				err = 1;
				goto out_err;
			}

			break;
		default:
			HIP_ERROR("Unsupported authentication algorithm: %i\n", entry->ealg);

			err = -1;
			goto out_err;
	}

	HIP_DEBUG("esp packet successfully authenticated\n");


	/*
	 *   Decryption
	 */

	elen -= esp_data_offset;

	/* Check keys and set initialisation vector length */
	switch (entry->ealg) {
		case HIP_ESP_3DES_SHA1:
			// same encryption chiper as next transform
		case HIP_ESP_3DES_MD5:
			iv_len = 8;
			if (!entry->enc_key) {
				HIP_ERROR("3-DES key missing.\n");

				err = -1;
				goto out_err;
			}
			break;
#ifndef ANDROID_CHANGES
		case HIP_ESP_BLOWFISH_SHA1:
			iv_len = 8;
			if (!entry->enc_key) {
				HIP_ERROR("BLOWFISH key missing.\n");

				err = -1;
				goto out_err;
			}
			break;
#endif
		case HIP_ESP_NULL_SHA1:
		case HIP_ESP_NULL_MD5:
			iv_len = 0;
			break;
		case HIP_ESP_AES_SHA1:
			iv_len = 16;
			if (!entry->enc_key) {
				HIP_ERROR("AES key missing.\n");

				err = -1;
				goto out_err;
			}
			break;
		default:
			HIP_ERROR("Unsupported decryption algorithm: %i\n", entry->ealg);

			err = -1;
			goto out_err;
	}

	/* get the initialisation vector located right behind the ESP header */
	memcpy(cbc_iv, in + esp_data_offset, iv_len);

	/* also don't include IV as part of ciphertext */
	elen -= iv_len;

	switch (entry->ealg) {
		case HIP_ESP_3DES_SHA1:
		case HIP_ESP_3DES_MD5:
			des_ede3_cbc_encrypt(&in[esp_data_offset + iv_len], out, elen,
					     entry->ks[0], entry->ks[1], entry->ks[2],
					     (des_cblock *) cbc_iv, DES_DECRYPT);
			break;
		case HIP_ESP_BLOWFISH_SHA1:
			BF_cbc_encrypt(&in[esp_data_offset + iv_len], out, elen,
					&entry->bf_key, cbc_iv, BF_DECRYPT);
			break;
		case HIP_ESP_NULL_SHA1:
		case HIP_ESP_NULL_MD5:
			memcpy(out, &in[esp_data_offset], elen);
			break;
		case HIP_ESP_AES_SHA1:
			AES_cbc_encrypt(&in[esp_data_offset + iv_len], out, elen,
					&entry->aes_key, cbc_iv, AES_DECRYPT);
			break;
		default:
			HIP_ERROR("Unsupported decryption algorithm: %i\n", entry->ealg);

			err = -1;
			goto out_err;
	}

	HIP_DEBUG("esp payload successfully decrypted\n");

	/* remove padding */
	esp_tail = (struct hip_esp_tail *) &out[elen - sizeof(struct hip_esp_tail)];
	*out_type = esp_tail->esp_next;
	*out_len = elen - (esp_tail->esp_padlen + sizeof(struct hip_esp_tail));

  out_err:
	return err;
}

/* XX TODO copy as much header information as possible */

void add_ipv4_header(struct ip *ip_hdr, struct in6_addr *src_addr,
		struct in6_addr *dst_addr, uint16_t packet_len, uint8_t next_hdr)
{
	struct in_addr src_in_addr;
	struct in_addr dst_in_addr;
	IPV6_TO_IPV4_MAP(src_addr, &src_in_addr);
	IPV6_TO_IPV4_MAP(dst_addr, &dst_in_addr);

	// set changed values
	ip_hdr->ip_v = 4;
	/* assume no options */
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = packet_len;
	/* assume that we have no fragmentation */
	ip_hdr->ip_id  = 0;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 255;
	ip_hdr->ip_p = next_hdr;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_src.s_addr = src_in_addr.s_addr;
	ip_hdr->ip_dst.s_addr = dst_in_addr.s_addr;

	/* recalculate the header checksum, does not include payload */
	ip_hdr->ip_sum = checksum_ip(ip_hdr, ip_hdr->ip_hl);
}

void add_ipv6_header(struct ip6_hdr *ip6_hdr, struct in6_addr *src_addr,
		struct in6_addr *dst_addr, uint16_t packet_len, uint8_t next_hdr)
{
	ip6_hdr->ip6_flow = 0; /* zero the version (4), TC (8) and flow-ID (20) */
	/* set version to 6 and leave first 4 bits of TC at 0 */
	ip6_hdr->ip6_vfc = 0x60;
	ip6_hdr->ip6_plen = htons(packet_len - sizeof(struct ip6_hdr));
	ip6_hdr->ip6_nxt = next_hdr;
	ip6_hdr->ip6_hlim = 255;
	memcpy(&ip6_hdr->ip6_src, src_addr, sizeof(struct in6_addr));
	memcpy(&ip6_hdr->ip6_dst, dst_addr, sizeof(struct in6_addr));
}

void add_udp_header(struct udphdr *udp_hdr, uint16_t packet_len, hip_sa_entry_t *entry,
		struct in6_addr *src_addr, struct in6_addr *dst_addr)
{
	//udp_hdr->source = htons(HIP_ESP_UDP_PORT);
	udp_hdr->source = htons(entry->src_port);

	if ((udp_hdr->dest = htons(entry->dst_port)) == 0) {
		HIP_ERROR("bad UDP dst port number: %u\n", entry->dst_port);
	}

	udp_hdr->len = htons((uint16_t)packet_len);

	// this will create a pseudo header using some information from the ip layer

#if 0
	/* Disabled checksum because it is incorrect. My NAT drops the packets
	   and wireshark complains about bad checksum */
	udp_hdr->check = checksum_udp(udp_hdr, src_addr, dst_addr);
#endif

	udp_hdr->check = 0;
}

/* XX TODO create one generic checksum function */

uint16_t checksum_ip(struct ip *ip_hdr, unsigned int ip_hl)
{
	uint16_t checksum;
	unsigned long sum = 0;
	int count = ip_hl*4;
	unsigned short *p = (unsigned short *) ip_hdr;

	/*
	 * this checksum algorithm can be found
	 * in RFC 1071 section 4.1
	 */

	/* one's complement sum 16-bit words of data */
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */
	checksum = (uint16_t)(~sum);

	return checksum;
}

uint16_t checksum_udp(struct udphdr *udp_hdr, struct in6_addr *src_addr,
		struct in6_addr *dst_addr)
{
	uint16_t checksum = 0;
	unsigned long sum = 0;
	int count = 0;
	unsigned short *p; /* 16-bit */
	pseudo_header pseudo_hdr;
	struct in_addr src_in_addr;
	struct in_addr dst_in_addr;

	/* IPv4 checksum based on UDP -- Section 6.1.2 */

	// setting up pseudo header
	memset(&pseudo_hdr, 0, sizeof(pseudo_header));
	IPV6_TO_IPV4_MAP(src_addr, &src_in_addr);
	IPV6_TO_IPV4_MAP(dst_addr, &dst_in_addr);
	/* assume host byte order */
	pseudo_hdr.src_addr = src_in_addr.s_addr;
	pseudo_hdr.dst_addr = dst_in_addr.s_addr;
	//pseudo_hdr.src_addr = htonl(src_in_addr.s_addr);
	//pseudo_hdr.dst_addr = htonl(dst_in_addr.s_addr);
	pseudo_hdr.protocol = IPPROTO_UDP;
	pseudo_hdr.packet_length = udp_hdr->len;

	count = sizeof(pseudo_header); /* count always even number */
	p = (unsigned short*) &pseudo_hdr;

	/*
	 * this checksum algorithm can be found
	 * in RFC 1071 section 4.1
	 */

	/* sum the psuedo-header */
	/* count and p are initialized above per protocol */
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}

	/* one's complement sum 16-bit words of data */
	/* log_(NORM, "checksumming %d bytes of data.\n", length); */
	count = ntohs(udp_hdr->len);
	p = (unsigned short*) udp_hdr;
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */
	checksum = (u_int16_t)(~sum);

	return checksum;
}
