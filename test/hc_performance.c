#include <stdio.h>		/* printf & co */
#include <stdlib.h>		/* exit & co */
#include <unistd.h>
#include "hip_statistics.h"
#include "hashchain.h"
#include "hashtree.h"

const hash_function_t hash_functions[2] = {SHA1, MD5};

int count = 100;
// this is supported by both md5 and sha1
int hash_length = 16;
int hchain_length = 100000;
int verify_length = 64;
hash_function_t hash_function;
int test_hc = 0;
int test_ht = 0;


void print_usage()
{
	printf( "Usage: hc_performance -c|t -s|m [-lhvn NUM]\n"
		"-c = do hash-chain performance tests\n"
		"-t = do hash-tree performance tests\n"
		"-s = use SHA1 hash-function\n"
		"-m = use MD5 hash-function\n"
		"-l [NUM] = create hash-chain with length NUM\n"
		"-h [NUM] = create hash elements of length NUM\n"
		"-v [NUM] = verify NUM elements\n"
		"-n [NUM] = do NUM measurements\n");
}

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

	printf(	"-------------------------------\n\n\n");
}

int main(int argc, char ** argv)
{
	int i;
	char c;
	int err = 0;
	struct timeval start_time;
	struct timeval stop_time;
	hash_chain_t *hchain = NULL;
	hash_tree_t *htree = NULL;
	statistics_data_t creation_stats;
	statistics_data_t verify_stats;
	uint64_t timediff = 0;
	uint32_t num_items = 0;
	double min = 0.0, max = 0.0, avg = 0.0;
	double std_dev = 0.0;
	unsigned char *branch_nodes = NULL;
	int branch_length = 0;
	unsigned char *secret = NULL;
	int secret_length = 0;
	hash_chain_t *hchains[8];
	unsigned char *data = NULL;
	int data_length = 0;
	unsigned char *root = NULL;
	int root_length = 0;

	hash_function = NULL;


	while ((c=getopt(argc, argv, "ctsml:h:v:n:")) != -1)
	{
		switch (c)
		{
			case 'c':
				test_hc = 1;
				break;
			case 't':
				test_ht = 1;
				break;
			case 's':
				hash_function = hash_functions[0];
				break;
			case 'm':
				hash_function = hash_functions[1];
				break;
			case 'l':
				hchain_length = atoi(optarg);
				break;
			case 'h':
				hash_length = atoi(optarg);
				break;
			case 'v':
				verify_length = atoi(optarg);
				break;
			case 'n':
				count = atoi(optarg);
				break;
			case ':':
				printf("Missing argument %c\n", optopt);
				print_usage();
				exit(1);
			case '?':
				printf("Unknown option %c\n", optopt);
				print_usage();
				exit(1);
		}
	}

	if (hash_function == NULL)
	{
		printf("no hash function selected!\n");
		print_usage();
		exit(1);
	}

	hip_set_logdebug(LOGDEBUG_NONE);

	memset(&creation_stats, 0, sizeof(statistics_data_t));
	memset(&verify_stats, 0, sizeof(statistics_data_t));

	print_timeres();

	if (test_hc)
	{
		printf(	"-------------------------------\n"
			"Hash chain performance test\n"
			"-------------------------------\n\n");

		printf("Creating %d hash chains of length %d with element length %d\n",
				count, hchain_length, hash_length);

		for(i = 0; i < count; i++)
		{
			gettimeofday(&start_time, NULL);
			if (hchain = hchain_create(hash_function, hash_length, hchain_length, 0,
					NULL))
			{
				gettimeofday(&stop_time, NULL);
				timediff = calc_timeval_diff(&start_time, &stop_time);
				add_statistics_item(&creation_stats, timediff);
				hchain_free(hchain);
			} else
			{
				printf("ERROR creating hchain!\n");
				exit(1);
			}
		}

		calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
				STATS_IN_MSECS);
		printf("creation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
					num_items, min, max, avg, std_dev);

		printf("\n");

		printf("Verifying %d hash chains of length %d with element length %d\n",
				count, verify_length, hash_length);

		for(i = 0; i < count; i++)
		{
			if (!(hchain = hchain_create(hash_function, hash_length, verify_length, 0,
					NULL)))
			{
				printf("ERROR creating hchain!");
				exit(1);
			}

			gettimeofday(&start_time, NULL);
			if(hchain_verify(hchain->source_element->hash, hchain->anchor_element->hash,
					hash_function, hash_length, verify_length, NULL, 0))
			{
				gettimeofday(&stop_time, NULL);
				timediff = calc_timeval_diff(&start_time, &stop_time);
				add_statistics_item(&verify_stats, timediff);
				hchain_free(hchain);
			} else
			{
				printf("ERROR verifying hchain!\n");
				exit(1);
			}
		}

		calc_statistics(&verify_stats, &num_items, &min, &max, &avg, &std_dev,
				STATS_IN_MSECS);
		printf("verification statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
					num_items, min, max, avg, std_dev);
	}

	if (test_ht)
	{
		printf(	"\n-------------------------------\n"
			"Hash tree performance test\n"
			"-------------------------------\n\n");

		memset(&creation_stats, 0, sizeof(statistics_data_t));
		memset(&verify_stats, 0, sizeof(statistics_data_t));

		printf("Creating %d hash trees of length %d with element length %d\n",
				count, hchain_length, hash_length);

		for(i = 0; i < count; i++)
		{
			HIP_DEBUG("number of leaves: %i\n", hchain_length);
			HIP_DEBUG("hash_length: %i\n", hash_length);
			HIP_DEBUG("data_length: %i\n", hash_length);

			gettimeofday(&start_time, NULL);
			htree = htree_init(hchain_length, hash_length, hash_length, 0, NULL, 0);
			htree_add_random_data(htree, hchain_length);
			htree_calc_nodes(htree, htree_leaf_generator, htree_node_generator, NULL);
			gettimeofday(&stop_time, NULL);
			timediff = calc_timeval_diff(&start_time, &stop_time);
			add_statistics_item(&creation_stats, timediff);

			htree_free(htree);
		}

		calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
				STATS_IN_MSECS);
		printf("creation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
					num_items, min, max, avg, std_dev);

		for(i = 0; i < count; i++)
		{
			htree = htree_init(hchain_length, hash_length, hash_length, hash_length, NULL, 0);
			htree_add_random_data(htree, hchain_length);
			htree_add_random_secrets(htree);
			htree_calc_nodes(htree, htree_leaf_generator, htree_node_generator, NULL);

			root = htree_get_root(htree, &root_length);
			htree_get_branch(htree, i, branch_nodes, &branch_length);
			data = htree_get_data(htree, i, &data_length);
			secret = htree_get_secret(htree, i, &secret_length);

			gettimeofday(&start_time, NULL);
			if (!htree_verify_branch(root, root_length,
					branch_nodes, branch_length,
					data, data_length, i,
					secret, secret_length,
					htree_leaf_generator, htree_node_generator, NULL))
			{
				gettimeofday(&stop_time, NULL);
				timediff = calc_timeval_diff(&start_time, &stop_time);
				add_statistics_item(&verify_stats, timediff);

				HIP_DEBUG("branch verified\n");

			} else
			{
				printf("ERROR verifying htree!\n");
				exit(1);
			}

			htree_free(htree);
		}

		calc_statistics(&verify_stats, &num_items, &min, &max, &avg, &std_dev,
				STATS_IN_MSECS);
		printf("verification statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
					num_items, min, max, avg, std_dev);



		printf("\n\ntrying out hchain linking...\n");

		// simulate level 0 creation
		htree = htree_init(8, hash_length, hash_length, hash_length, NULL, 0);
		htree_add_random_secrets(htree);

		for (i = 0; i < 8; i++)
		{
			hchains[i] = hchain_create(hash_function, hash_length, hchain_length, 0,
								NULL);
			htree_add_data(htree, hchains[i]->anchor_element->hash, hash_length);
		}

		htree_calc_nodes(htree, htree_leaf_generator, htree_node_generator, NULL);

		// simulate level 1 creation
		hchain = hchain_create(hash_function, hash_length, hchain_length, 1,
				htree);

		// simulate BEX
		// get hchain anchor
		root = htree_get_root(htree, &root_length);

		// simulate level 1 hchain verification
		if(!hchain_verify(hchain->source_element->hash, hchain->anchor_element->hash,
				hash_function, hash_length, verify_length, root, root_length))
		{
			printf("hchain level 1 verfied\n");

		} else
		{
			printf("ERROR verifying hchain level 1!\n");
			exit(1);
		}

		// simulate update
		htree_get_branch(htree, 0, branch_nodes, &branch_length);
		secret = htree_get_secret(htree, 0, &secret_length);
		data = htree_get_data(htree, 0, &data_length);

		if (!htree_verify_branch(root, root_length,
				branch_nodes, branch_length,
				data, data_length, i,
				secret, secret_length,
				htree_leaf_generator, htree_node_generator, NULL))
		{
			printf("anchor verified\n");

		} else
		{
			printf("ERROR verifying anchor!\n");
			exit(1);
		}

		if (!memcmp(data, hchains[0]->anchor_element->hash, hash_length))
		{
			printf("yes, this is the anchor we verified!\n");
		} else
		{
			printf("ERROR no this is not the anchor we verified!\n");
			exit(1);
		}
		hchain_free(hchain);

		// simulate level 0 hchain verification
		if(!hchain_verify(hchains[0]->source_element->hash, data,
				hash_function, hash_length, verify_length, NULL, 0))
		{
			printf("hchain level 0 verfied\n");

		} else
		{
			printf("ERROR verifying hchain level 0!\n");
			exit(1);
		}
	}
}
