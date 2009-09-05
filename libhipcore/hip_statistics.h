#ifndef HIP_STATISTICS_H_
#define HIP_STATISTICS_H_

#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include "debug.h"

#define STATS_NO_CONV	1
#define STATS_IN_MSECS	1000
#define STATS_IN_USECS	1000000

typedef struct statistics_data
{
	uint32_t num_items;
	uint64_t added_values;
	uint64_t added_squared_values;
	uint64_t min_value;
	uint64_t max_value;
} statistics_data_t;

#ifdef CONFIG_HIP_MEASUREMENTS
typedef struct hcupdate_track
{
	unsigned char update_anchor[MAX_HASH_LENGTH];
	struct timeval time_start;
	int soft_update;
} hcupdate_track_t;
#endif

uint64_t timeval_to_uint64(struct timeval *timeval);
uint64_t calc_timeval_diff(struct timeval *timeval_start,
		struct timeval *timeval_end);
double calc_avg(statistics_data_t *statistics_data, double scaling_factor);
double calc_std_dev(statistics_data_t *statistics_data, double scaling_factor);
void add_statistics_item(statistics_data_t *statistics_data, uint64_t item_value);
void calc_statistics(statistics_data_t *statistics_data, uint32_t *num_items,
		double *min, double *max, double *avg, double *std_dev, double scaling_factor);
//static long llsqrt(long long a);

#endif /* HIP_STATISTICS_H_ */
