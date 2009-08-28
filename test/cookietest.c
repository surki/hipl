#include "debug.h"
#include "misc.h"
#include <sys/time.h>
#include <time.h>

void hip_create_puzzle(struct hip_puzzle *puzzle, uint8_t val_K,
		       uint32_t opaque, uint64_t random_i) {
	/* only the random_j_k is in host byte order */
	puzzle->K = val_K;
	puzzle->lifetime = 0;
	puzzle->opaque[0] = opaque & 0xFF;
	puzzle->opaque[1] = (opaque & 0xFF00) >> 8;
	/* puzzle.opaque[2] = (opaque & 0xFF0000) >> 16; */
	puzzle->I = random_i;
}

int hip_verify_puzzle(struct hip_common *hdr, struct hip_puzzle *puzzle,
		      struct hip_solution *solution) {
	int err = 1; /* Not really an error: 1=success, 0=failure */

	if (solution->K != puzzle->K) {
		HIP_INFO("Solution's K (%d) does not match sent K (%d)\n",
			 solution->K, puzzle->K);
		
		HIP_IFEL(solution->K != puzzle->K, 0,
			"Solution's K did not match any sent Ks.\n");
		HIP_IFEL(solution->I != puzzle->I, 0, 
			 "Solution's I did not match the sent I\n");
		HIP_IFEL(memcmp(solution->opaque, puzzle->opaque, HIP_PUZZLE_OPAQUE_LEN), 0,
			 "Solution's opaque data does not match sent opaque data\n");
		HIP_DEBUG("Received solution to an old puzzle\n");

	} else {
		HIP_HEXDUMP("solution", solution, sizeof(*solution));
		HIP_HEXDUMP("puzzle", puzzle, sizeof(*puzzle));
		HIP_IFEL(solution->I != puzzle->I, 0,
			 "Solution's I did not match the sent I\n");
		HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
				HIP_PUZZLE_OPAQUE_LEN), 0, 
			 "Solution's opaque data does not match the opaque data sent\n");
	}
	HIP_IFEL(!hip_solve_puzzle(solution, hdr, HIP_VERIFY_PUZZLE), 0, 
		 "Puzzle incorrectly solved\n");
 out_err:
	return err;

}

int main(int argc, char *argv[]) {
	struct hip_puzzle pz;
	struct hip_solution sol;
	struct hip_common hdr = { 0 };
        struct timeval stats_before, stats_after, stats_res;
        unsigned long stats_diff_sec, stats_diff_usec;
	uint64_t solved_puzzle;
	uint8_t k;

	if (argc != 2) {
		printf("usage: cookietest k\n");
		exit(-1);
	}

	k = atoi(argv[1]);
	HIP_DEBUG("k=%d\n", k);

	hip_create_puzzle(&pz, k, 0, 0);

	gettimeofday(&stats_before, NULL);

	if ((solved_puzzle =
	     hip_solve_puzzle(&pz, &hdr, HIP_SOLVE_PUZZLE)) == 0) {
		HIP_ERROR("Puzzle not solved\n");
	}

	gettimeofday(&stats_after, NULL);

	hip_timeval_diff(&stats_after, &stats_before, &stats_res);
	HIP_INFO("puzzle solved in %ld.%06ld secs\n",
		 stats_res.tv_sec, stats_res.tv_usec);

	memcpy(&sol, &pz, sizeof(pz));
	sol.J = solved_puzzle;

	if (!hip_verify_puzzle(&hdr, &pz, &sol)) {
		HIP_ERROR("Verifying of puzzle failed\n");
	}

	HIP_DEBUG("Puzzle solved correctly\n");
}
