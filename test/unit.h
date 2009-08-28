#ifndef HIP_UNIT
#define HIP_UNIT

#include "debug.h"

#include <stdio.h>
#include <stdint.h>

/*
 * A maximum amount of test spaces, suites and cases have be fixed because they
 * are created statically at compile time. A dynamic method can cause
 * other side effects (dynamic allocation of memory), so it was not used.
 * Each MAX variable has to include also the NULL element in the contained
 * structure.
 */
#define HIP_UNIT_TEST_SPACE_MAX     3
#define HIP_UNIT_TEST_SUITE_MAX     10
#define HIP_UNIT_TEST_CASE_MAX      50

#define HIP_UNIT_TEST_NAME_MAX      15

#define HIP_UNIT_ASSERT(s) \
  do { \
    if (!(s)) { \
      (*__hip_unit_err)++; \
      *__hip_unit_err_len = \
        snprintf(__hip_unit_err_msg, __hip_unit_err_msg_max_len, \
          "HIP unit assertion failed in %s in %s line %d\n", \
          __FILE__, __FUNCTION__, __LINE__); \
      return; \
    } else { \
      *__hip_unit_err_len = 0; \
    } \
  } while (0)

#define HIP_UNIT_TEST_CASE(name) \
   void name(uint16_t *__hip_unit_err, void *__hip_unit_err_msg, \
             size_t *__hip_unit_err_len, \
             const uint16_t __hip_unit_err_msg_max_len)

typedef void (*hip_unit_test_case)(uint16_t *, void *,
				   size_t *, const uint16_t);

struct hip_unit_test_suite {
	uint16_t nbr;
	hip_unit_test_case test_case[HIP_UNIT_TEST_CASE_MAX];
};

struct hip_unit_test_suite_list {
	uint16_t nbr;
	struct hip_unit_test_suite *test_suite[HIP_UNIT_TEST_SUITE_MAX];
};

/*
 * This structure is used for separating kernel and userspace test suites.
 * It is require for making a three level hierarchy: testspace / testsuite /
 * testcase. Kernel does not this structure but it is include here for
 * consistency.
 */
struct hip_unit_test_space {
	uint16_t nbr;
	struct hip_unit_test_suite_list *test_suite_list[HIP_UNIT_TEST_SPACE_MAX];
};

uint16_t hip_run_unit_test_case(struct hip_unit_test_suite_list *list,
				uint16_t suiteid, uint16_t caseid,
				void *err_log, size_t err_max);


uint16_t hip_run_unit_test_space(struct hip_unit_test_space *unit_space,
				 uint16_t spaceid, uint16_t suiteid,
				 uint16_t caseid, void *err_log,
				 size_t err_max);

#endif /* HIP_UNIT */
