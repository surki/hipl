#include <stdio.h>		/* printf & co */
#include <stdlib.h>		/* exit & co */
#include <unistd.h>
#include "hip_statistics.h"
#include "crypto.h"
#ifdef CONFIG_HIP_ECDSA
#include <openssl/ecdsa.h>
#endif /* CONFIG_HIP_ECDSA  */

#define PACKET_LENGTH 1280

int num_measurements = 100;
int key_pool_size = 5;

int rsa_key_len = 1024;
int dsa_key_len = 1024;
#define ECDSA_CURVE NID_sect163r1

/*!
 * \brief 	Determine and print the gettimeofday time resolution.
 *
 * \author	Tobias Heer
 *
 * Determine the time resolution of gettimeofday.
 *
 * \return void
 */
void print_timeres(){

	struct timeval tv1, tv2;
	int i;
	printf(	"-------------------------------\n"
		"Determine gettimeofday resolution:\n");


	for(i = 0; i < 10; i++){
		gettimeofday(&tv1, NULL);
		do {
			gettimeofday(&tv2, NULL);
		} while (tv1.tv_usec == tv2.tv_usec);

		printf("Resolution: %d us\n", tv2.tv_usec - tv1.tv_usec +
			1000000 * (tv2.tv_sec - tv1.tv_sec));
	}

	printf(	"-------------------------------\n\n");
}

int main(int argc, char ** argv)
{
	int i;
	int err = 0;
	struct timeval start_time;
	struct timeval stop_time;
	uint64_t timediff = 0;
#if 0
	statistics_data_t creation_stats;
	statistics_data_t verify_stats;
	uint32_t num_items = 0;
	double min = 0.0, max = 0.0, avg = 0.0;
	double std_dev = 0.0;
#endif

	int sig_len = 0;
	unsigned char data[PACKET_LENGTH * num_measurements];
	unsigned char hashed_data[SHA_DIGEST_LENGTH * num_measurements];

	char key[HIP_MAX_KEY_LEN];
	unsigned int hashed_data_len = 0;

	AES_KEY *aes_enc_key = NULL;
	AES_KEY *aes_dec_key = NULL;
	unsigned char cbc_iv[AES_BLOCK_SIZE];
	unsigned char enc_data[num_measurements * PACKET_LENGTH];
	unsigned char dec_data[num_measurements * PACKET_LENGTH];

	RSA * rsa_key_pool[key_pool_size];
	unsigned char * rsa_sig_pool[num_measurements];

	DSA * dsa_key_pool[key_pool_size];
	DSA_SIG * dsa_sig_pool[num_measurements];

#ifdef CONFIG_HIP_ECDSA
	EC_KEY * ecdsa_key_pool[key_pool_size];
	ECDSA_SIG * ecdsa_sig_pool[num_measurements];
#endif /* CONFIG_HIP_ECDSA  */

	hip_set_logdebug(LOGDEBUG_NONE);

#if 0
	memset(&creation_stats, 0, sizeof(statistics_data_t));
	memset(&verify_stats, 0, sizeof(statistics_data_t));
#endif

	print_timeres();

	// data to be signed
	printf("generating payload data for %i packets (packet length %i bytes)...\n\n",
			num_measurements, PACKET_LENGTH);
	RAND_bytes(data, PACKET_LENGTH * num_measurements);

	printf("-------------------------------\n"
			"SHA1 performance test (20 byte input)\n"
			"-------------------------------\n");

	printf("Calculating hashes over %d inputs...\n", num_measurements);

	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * 20], 20, &hashed_data[i * SHA_DIGEST_LENGTH]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&creation_stats, timediff);
		printf("%i. sha1-20: %.3f ms\n", i + 1, timediff / 1000.0);
	}

	printf("-------------------------------\n"
			"SHA1 performance test (40 byte input)\n"
			"-------------------------------\n");

	printf("Calculating hashes over %d inputs...\n", num_measurements);

	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * 40], 40, &hashed_data[i * SHA_DIGEST_LENGTH]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&creation_stats, timediff);
		printf("%i. sha1-40: %.3f ms\n", i + 1, timediff / 1000.0);
	}

	printf("-------------------------------\n"
			"SHA1 performance test (1280 byte input)\n"
			"-------------------------------\n");

	printf("Calculating hashes over %d packets...\n", num_measurements);

	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&creation_stats, timediff);
		printf("%i. sha1-1280: %.3f ms\n", i + 1, timediff / 1000.0);
	}


	printf("-------------------------------\n"
			"SHA1-HMAC performance test\n"
			"-------------------------------\n");

	printf("Calculating hashes over %d packets...\n", num_measurements);

	RAND_bytes(key, 20);

	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		// HMAC on data
		HMAC(EVP_sha1(), key, 20, &data[i * PACKET_LENGTH], PACKET_LENGTH,
				&hashed_data[i * SHA_DIGEST_LENGTH], &hashed_data_len);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&creation_stats, timediff);
		printf("%i. sha1-hmac: %.3f ms\n", i + 1, timediff / 1000.0);
	}

#if 0
	calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
					STATS_IN_MSECS);
	printf("generation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);
#endif


	printf("\n-------------------------------\n"
			"AES performance test\n"
			"-------------------------------\n");

	// create a key pool
	aes_enc_key = malloc(sizeof(AES_KEY));
	aes_dec_key = malloc(sizeof(AES_KEY));
	AES_set_encrypt_key(key, 8 * hip_enc_key_length(HIP_ESP_AES_SHA1), aes_enc_key);
	AES_set_decrypt_key(key, 8 * hip_enc_key_length(HIP_ESP_AES_SHA1), aes_dec_key);
	RAND_bytes(cbc_iv, AES_BLOCK_SIZE);

	printf("\nCalculating %d AES encryption\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		AES_cbc_encrypt(&data[i * PACKET_LENGTH], &enc_data[i * PACKET_LENGTH],
				PACKET_LENGTH, aes_enc_key, cbc_iv, AES_ENCRYPT);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&creation_stats, timediff);

		printf("%i. AES encrypt: %.3f ms\n", i + 1, timediff / 1000.0);

	}

	printf("\nCalculating %d AES decryption\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		AES_cbc_encrypt(&enc_data[i * PACKET_LENGTH], &dec_data[i * PACKET_LENGTH],
				PACKET_LENGTH, aes_dec_key, cbc_iv, AES_DECRYPT);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&creation_stats, timediff);


		printf("%i. AES decrypt: %.3f ms\n", i + 1, timediff / 1000.0);
	}

	// reinitialize statistics
#if 0
	memset(&creation_stats, 0, sizeof(statistics_data_t));
	memset(&verify_stats, 0, sizeof(statistics_data_t));
#endif



	printf("\n-------------------------------\n"
			"RSA performance test\n"
			"-------------------------------\n");

	// create a key pool
	printf("Creating key pool of %d keys of length %d.\n", key_pool_size, rsa_key_len);
	for(i = 0; i < key_pool_size; i++)
	{
		rsa_key_pool[i] = create_rsa_key(rsa_key_len);
	}

	printf("\nCalculating %d RSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		sig_len = RSA_size(rsa_key_pool[i % key_pool_size]);

		rsa_sig_pool[i] = malloc(sig_len);

		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		// sign
		err = RSA_sign(NID_sha1, &hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				rsa_sig_pool[i], &sig_len, rsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&creation_stats, timediff);

		if(err <= 0)
		{
			printf("RSA signature unsuccessful\n");
		}
		else
		{
			printf("%i. rsa signature: %.3f ms\n", i + 1, timediff / 1000.0);
		}
	}
#if 0
	calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
					STATS_IN_MSECS);
	printf("generation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);
#endif

#if 0
	printf("\n");
	printf("Signature generation took %.3f sec (%.5f sec per key)\n",
		bench_secs, bench_secs / sw_bench_loops);
	printf("%4.2f signatures per sec, %4.2f signatures per min\n\n",
		sw_bench_loops/bench_secs, sw_bench_loops/bench_secs*60);
#endif


	printf("\nVerifying %d RSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		err = RSA_verify(NID_sha1, &hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				rsa_sig_pool[i], RSA_size(rsa_key_pool[i % key_pool_size]),
				rsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&verify_stats, timediff);

		if(err <= 0)
		{
			printf("Verification failed\n");
		}
		else
		{
			printf("%i. rsa verification: %.3f ms\n", i + 1, timediff / 1000.0);
		}
	}

#if 0
	calc_statistics(&verify_stats, &num_items, &min, &max, &avg, &std_dev,
			STATS_IN_MSECS);
	printf("verification statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);
#endif


	// reinitialize statistics
#if 0
	memset(&creation_stats, 0, sizeof(statistics_data_t));
	memset(&verify_stats, 0, sizeof(statistics_data_t));
#endif



	printf("\n-------------------------------\n"
			"DSA performance test\n"
			"-------------------------------\n");

	printf("Creating key pool of %d keys of length %d...\n", key_pool_size, dsa_key_len);
	for(i = 0; i < key_pool_size; i++)
	{
		dsa_key_pool[i] = create_dsa_key(dsa_key_len);
	}

	printf("\nCalculating %d DSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		sig_len = sizeof(DSA_SIG *);

		dsa_sig_pool[i] = malloc(sig_len);

		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		// sign
		dsa_sig_pool[i] = DSA_do_sign(&hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				dsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&creation_stats, timediff);

		if(!dsa_sig_pool[i]){
			printf("DSA signature not successful\n");
		}
		else
		{
			printf("%i. dsa signature: %.3f ms\n", i + 1, timediff / 1000.0);
		}
	}
#if 0
	calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
					STATS_IN_MSECS);
	printf("generation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);
#endif

	printf("\nVerifying %d DSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		err = DSA_do_verify(&hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				dsa_sig_pool[i], dsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&verify_stats, timediff);

		if(err <= 0)
		{
			printf("Verification failed\n");
		}
		else
		{
			printf("%i. dsa verification: %.3f ms\n", i + 1, timediff / 1000.0);
		}
	}
#if 0
	calc_statistics(&verify_stats, &num_items, &min, &max, &avg, &std_dev,
			STATS_IN_MSECS);
	printf("verification statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);
#endif



	// reinitialize statistics
#if 0
	memset(&creation_stats, 0, sizeof(statistics_data_t));
	memset(&verify_stats, 0, sizeof(statistics_data_t));
#endif


#ifdef CONFIG_HIP_ECDSA
	printf("\n-------------------------------\n"
			"ECDSA performance test\n"
			"-------------------------------\n");

	printf("Creating key pool of %d keys for curve ECDSA_CURVE...\n", key_pool_size);
	for(i = 0; i < key_pool_size; i++)
	{
		ecdsa_key_pool[i] = EC_KEY_new_by_curve_name(ECDSA_CURVE);
		if (!ecdsa_key_pool[i])
		{
			printf("ec key setup failed!\n");
		}

		if (!EC_KEY_generate_key(ecdsa_key_pool[i]))
		{
			printf("ec key generation failed!\n");
		}
	}

	printf("\nCalculating %d ECDSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		sig_len = ECDSA_size(ecdsa_key_pool[i % key_pool_size]);

		ecdsa_sig_pool[i] = malloc(sig_len);

		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		// sign
		ecdsa_sig_pool[i] = ECDSA_do_sign(&hashed_data[i * SHA_DIGEST_LENGTH],
				SHA_DIGEST_LENGTH, ecdsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&creation_stats, timediff);

		if(!ecdsa_sig_pool[i])
		{
			printf("ECDSA signature not successful\n");
		}
		else
		{
			printf("%i. ecdsa signature: %.3f ms\n", i + 1, timediff / 1000.0);
		}
	}
#endif /* CONFIG_HIP_ECDSA  */
#if 0
	calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
					STATS_IN_MSECS);
	printf("generation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);

	printf("\nVerifying %d ECDSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		err = ECDSA_do_verify(&hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				ecdsa_sig_pool[i], ecdsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		//add_statistics_item(&verify_stats, timediff);

		if(err <= 0)
		{
			printf("Verification failed\n");
		}
		else
		{
			printf("%i. ecdsa verification: %.3f ms\n", i + 1, timediff / 1000.0);
		}
	}
#endif

#if 0
	calc_statistics(&verify_stats, &num_items, &min, &max, &avg, &std_dev,
			STATS_IN_MSECS);
	printf("verification statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);
#endif
}
