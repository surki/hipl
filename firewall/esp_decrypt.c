/*
 * 
 * 
 */


#include "esp_decrypt.h"

int decrypt_packet(const struct in6_addr * dst_addr, 
	struct esp_tuple *esp_tuple, struct hip_esp_packet * esp)
{
	int err = 0;
	char * enc = NULL;
	uint32_t esp_hdr_len;
	uint32_t auth_len;
	uint32_t enc_len, enc_len2;
	char * iv = NULL;
	char * key = NULL;
	struct hip_esp_tail * tail = NULL; 
	uint32_t spi;
	uint32_t seq;

	spi = ntohl(esp->esp_data->esp_spi);
	seq = ntohl(esp->esp_data->esp_seq);

	HIP_DEBUG("Decrypting ESP packet: spi = %d, seq = %d\n", spi, seq);
	HIP_ASSERT(esp_tuple != NULL);
	HIP_ASSERT(esp_tuple->dec_data != NULL);
	
	if (esp_tuple->dec_data->dec_alg == HIP_ESP_3DES_SHA1) {
		
		HIP_DEBUG("Algorithm 3DES-SHA1\n\n");
		esp_hdr_len = sizeof(struct hip_esp) + sizeof(des_cblock);
		auth_len = esp_tuple->dec_data->auth_len; 
		enc_len = esp->packet_length/* - esp_hdr_len*/ - auth_len; 
		
		enc = (char *)esp->esp_data + esp_hdr_len;
		
		HIP_IFEL(!(iv = (char *)malloc(sizeof(des_cblock))), -1, "Out of memory\n");
		memcpy(iv, (char *)esp->esp_data + sizeof(struct hip_esp), sizeof(des_cblock)); 
		 
		_HIP_DEBUG("packet_len %d, esp_hdr_len %d, auth_len %d, data_len %d\n", esp->packet_length, esp_hdr_len, auth_len, enc_len);
		_HIP_HEXDUMP("Encrypted data: \n", enc, enc_len); 
		 _HIP_HEXDUMP("IV: \n", iv, sizeof(des_cblock)); 
		 
		 HIP_IFEL(!(key = (char *)malloc(esp_tuple->dec_data->key_len)), -1, "Out of memory\n");
		 memcpy(key, &esp_tuple->dec_data->dec_key, esp_tuple->dec_data->key_len);
		enc_len2 = enc_len; 
		 _HIP_HEXDUMP("Key: \n", key, esp_tuple->dec_data->key_len); 
		 
		err =  hip_crypto_encrypted((void *)enc, (const void *)iv, 
			esp_tuple->dec_data->dec_alg, enc_len,
			 (void *)key, HIP_DIRECTION_DECRYPT);
	}
	else if (esp_tuple->dec_data->dec_alg == HIP_ESP_AES_SHA1) {
		HIP_DEBUG("Algorithm: AES-SHA1\n\n");
		esp_hdr_len = sizeof(struct hip_esp) + 16;
		auth_len = esp_tuple->dec_data->auth_len; 
		enc_len = esp->packet_length - auth_len; 
		
		enc = (char *)esp->esp_data + esp_hdr_len;
		
		HIP_IFEL(!(iv = (char *)malloc(16)), -1, "Out of memory\n");
		memcpy(iv, (char *)esp->esp_data + sizeof(struct hip_esp), 16); 
		 
		_HIP_DEBUG("packet_len %d, esp_hdr_len %d, auth_len %d, data_len %d\n", esp->packet_length, esp_hdr_len, auth_len, enc_len);
		_HIP_HEXDUMP("Encrypted data: \n", enc, enc_len); 
		_HIP_HEXDUMP("IV: \n", iv, 16); 
		 
		HIP_IFEL(!(key = (char *)malloc(esp_tuple->dec_data->key_len)), -1, "Out of memory\n");
		 memcpy(key, &esp_tuple->dec_data->dec_key, esp_tuple->dec_data->key_len);
		enc_len2 = enc_len; 
		 _HIP_HEXDUMP("Key: \n", key, esp_tuple->dec_data->key_len); 
		 
		err =  hip_crypto_encrypted((void *)enc, (const void *)iv, 
			esp_tuple->dec_data->dec_alg, enc_len,
			 (void *)key, HIP_DIRECTION_DECRYPT);
	}
	else if (esp_tuple->dec_data->dec_alg == HIP_ESP_NULL_SHA1) {
		HIP_DEBUG("Encryption algorithm NULL with SHA1 authentication\n");
		
		esp_hdr_len = sizeof(struct hip_esp);
		auth_len = esp_tuple->dec_data->auth_len; 
		enc_len = esp->packet_length - auth_len; 
		enc = (char *)esp->esp_data + esp_hdr_len;
		enc_len2 = enc_len; 
	}
	else {
		HIP_DEBUG("decrypt_packet: Encryption algorithm not supported!\n");
	}
	
	if (err < 0) {
			HIP_DEBUG("Decryption unsuccesfull\n");
		}
		else {
		 	_HIP_DEBUG("Decryption succesfull!\n");
		 	tail = (struct hip_esp_tail *)(enc + (enc_len - sizeof(struct hip_esp_tail) - 4));// What are the four bytes need to be removed?
		 	_HIP_DEBUG("esp_tail: padlen %d, esp_nxt %d\n", (uint32_t)tail->esp_padlen, (uint32_t)tail->esp_next);
		 	enc_len2 = enc_len - (sizeof(struct hip_esp_tail) /*+ tail->esp_padlen*/) - 4;
		 	_HIP_HEXDUMP("\nDecrypted data: \n\n", enc, enc_len2); 
		 	print_decrypted_content(tail->esp_next, enc, enc_len2);
		}
	
out_err:	
	
	//if (enc) 
	//	free(enc);
	if (iv) 
		free(iv);
	if (key) 
		free(key);
		
	return err;	
}


int print_decrypted_content(int proto, char * content, int content_len)
{
	_HIP_DEBUG("print_decryted_content\n");
	_HIP_HEXDUMP("Decrypted data without padding: \n", content, content_len);
	/* HIP_DUMP_PACKET won't compile when configure script is run with
	   --disable-debug. -Lauri 13.08.2008 */
	//HIP_DUMP_PACKET("\nPacket contents: \n", content, content_len);

    return 0;
}


